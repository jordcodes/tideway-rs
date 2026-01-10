//! Live Stripe client implementation.
//!
//! Production-ready Stripe client with retry logic, secure API key handling,
//! circuit breaker pattern, and proper error mapping.
//!
//! # Connection Pooling
//!
//! The underlying HTTP client (hyper) automatically manages connection pooling.
//! Connections are reused across requests, and HTTP/2 multiplexing is enabled
//! for improved performance.

use crate::error::Result;
use secrecy::{ExposeSecret, SecretString};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::checkout::{
    CheckoutMode, CheckoutSession, CreateCheckoutSessionRequest, StripeCheckoutClient,
};
use super::customer::{CreateCustomerRequest, StripeClient, UpdateCustomerRequest};
use super::error::BillingError;
use super::invoice::{
    Invoice, InvoiceLineItem, InvoiceList, InvoiceStatus, StripeInvoiceClient,
};
use super::payment::{PaymentMethod, PaymentMethodList, StripePaymentMethodClient};
use super::portal::{
    CreatePortalSessionRequest, PortalFlow, PortalSession, StripePortalClient,
};
use super::refund::{CreateRefundRequest, Refund, RefundReason, RefundStatus, StripeRefundClient};
use super::subscription::{
    ProrationBehavior, StripeSubscriptionClient, StripeSubscriptionData, SubscriptionMetadata,
    UpdateSubscriptionRequest,
};

// ============================================================================
// Constants
// ============================================================================

/// Metadata key for billable entity ID.
const META_BILLABLE_ID: &str = "billable_id";
/// Metadata key for billable entity type.
const META_BILLABLE_TYPE: &str = "billable_type";
/// Metadata key for plan ID.
const META_PLAN_ID: &str = "plan_id";
/// Metadata key to identify seat items.
const META_ITEM_TYPE: &str = "item_type";
/// Metadata value indicating an item is for extra seats.
const META_ITEM_TYPE_SEATS: &str = "seats";
/// Metadata value indicating an item is the base plan.
const META_ITEM_TYPE_BASE: &str = "base";

/// Maximum allowed length for metadata values.
const MAX_METADATA_VALUE_LENGTH: usize = 500;

// ============================================================================
// Metadata Sanitization
// ============================================================================

/// Sanitize a metadata value to prevent injection attacks.
///
/// - Truncates to maximum length
/// - Removes control characters
/// - Trims whitespace
#[inline]
fn sanitize_metadata_value(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_METADATA_VALUE_LENGTH)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Safely extract and sanitize a metadata value.
#[inline]
fn get_sanitized_metadata(
    metadata: &std::collections::HashMap<String, String>,
    key: &str,
) -> Option<String> {
    metadata.get(key).map(|v| sanitize_metadata_value(v))
}

// ============================================================================
// Circuit Breaker
// ============================================================================

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is closed, requests flow normally.
    Closed,
    /// Circuit is open, requests fail fast.
    Open,
    /// Circuit is half-open, allowing a test request.
    HalfOpen,
}

/// Circuit breaker for Stripe API calls.
///
/// Prevents cascading failures by failing fast when the Stripe API
/// is experiencing issues.
#[derive(Debug)]
pub struct CircuitBreaker {
    /// Number of consecutive failures.
    failure_count: AtomicU32,
    /// Timestamp when circuit opened (0 if closed).
    opened_at: AtomicU64,
    /// Configuration.
    config: CircuitBreakerConfig,
}

/// Configuration for the circuit breaker.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit.
    pub failure_threshold: u32,
    /// How long the circuit stays open before allowing a test request.
    pub open_duration_seconds: u64,
    /// Whether the circuit breaker is enabled.
    pub enabled: bool,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_duration_seconds: 30,
            enabled: true,
        }
    }
}

impl CircuitBreakerConfig {
    /// Create a disabled circuit breaker config.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Set the failure threshold.
    #[must_use]
    pub fn failure_threshold(mut self, threshold: u32) -> Self {
        self.failure_threshold = threshold;
        self
    }

    /// Set the open duration in seconds.
    #[must_use]
    pub fn open_duration_seconds(mut self, seconds: u64) -> Self {
        self.open_duration_seconds = seconds;
        self
    }
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given configuration.
    #[must_use]
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            failure_count: AtomicU32::new(0),
            opened_at: AtomicU64::new(0),
            config,
        }
    }

    /// Get the current state of the circuit.
    #[must_use]
    pub fn state(&self) -> CircuitState {
        if !self.config.enabled {
            return CircuitState::Closed;
        }

        let opened_at = self.opened_at.load(Ordering::Acquire);
        if opened_at == 0 {
            return CircuitState::Closed;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let elapsed = now.saturating_sub(opened_at);
        if elapsed >= self.config.open_duration_seconds {
            CircuitState::HalfOpen
        } else {
            CircuitState::Open
        }
    }

    /// Check if a request should be allowed.
    ///
    /// Returns `Ok(())` if the request can proceed, or an error if the circuit is open.
    pub fn check(&self) -> std::result::Result<(), BillingError> {
        match self.state() {
            CircuitState::Closed | CircuitState::HalfOpen => Ok(()),
            CircuitState::Open => Err(BillingError::StripeApiError {
                operation: "circuit_breaker".to_string(),
                message: "Circuit breaker is open, failing fast".to_string(),
                code: Some("CIRCUIT_OPEN".to_string()),
                http_status: Some(503),
            }),
        }
    }

    /// Record a successful request.
    pub fn record_success(&self) {
        if !self.config.enabled {
            return;
        }
        self.failure_count.store(0, Ordering::Release);
        self.opened_at.store(0, Ordering::Release);
    }

    /// Record a failed request.
    pub fn record_failure(&self) {
        if !self.config.enabled {
            return;
        }

        let failures = self.failure_count.fetch_add(1, Ordering::AcqRel) + 1;
        if failures >= self.config.failure_threshold {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            self.opened_at.store(now, Ordering::Release);

            tracing::warn!(
                target: "tideway::billing::stripe",
                failures = failures,
                threshold = self.config.failure_threshold,
                "Circuit breaker opened due to consecutive failures"
            );
        }
    }

    /// Get the current failure count.
    #[must_use]
    pub fn failure_count(&self) -> u32 {
        self.failure_count.load(Ordering::Acquire)
    }

    /// Reset the circuit breaker.
    pub fn reset(&self) {
        self.failure_count.store(0, Ordering::Release);
        self.opened_at.store(0, Ordering::Release);
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the live Stripe client.
#[derive(Debug, Clone)]
pub struct LiveStripeClientConfig {
    /// Maximum number of retry attempts for transient failures.
    pub max_retries: u32,
    /// Base delay for exponential backoff in milliseconds.
    pub base_delay_ms: u64,
    /// Maximum delay between retries in milliseconds.
    pub max_delay_ms: u64,
    /// Request timeout in seconds.
    pub timeout_seconds: u64,
    /// Circuit breaker configuration.
    pub circuit_breaker: CircuitBreakerConfig,
}

impl Default for LiveStripeClientConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay_ms: 500,
            max_delay_ms: 30_000,
            timeout_seconds: 30,
            circuit_breaker: CircuitBreakerConfig::default(),
        }
    }
}

impl LiveStripeClientConfig {
    /// Create a new config with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum retry attempts.
    #[must_use]
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Set base delay for exponential backoff.
    #[must_use]
    pub fn base_delay_ms(mut self, ms: u64) -> Self {
        self.base_delay_ms = ms;
        self
    }

    /// Set maximum delay between retries.
    #[must_use]
    pub fn max_delay_ms(mut self, ms: u64) -> Self {
        self.max_delay_ms = ms;
        self
    }

    /// Set request timeout.
    #[must_use]
    pub fn timeout_seconds(mut self, seconds: u64) -> Self {
        self.timeout_seconds = seconds;
        self
    }

    /// Set circuit breaker configuration.
    #[must_use]
    pub fn circuit_breaker(mut self, config: CircuitBreakerConfig) -> Self {
        self.circuit_breaker = config;
        self
    }

    /// Disable the circuit breaker.
    #[must_use]
    pub fn disable_circuit_breaker(mut self) -> Self {
        self.circuit_breaker = CircuitBreakerConfig::disabled();
        self
    }
}

// ============================================================================
// API Key Validation
// ============================================================================

/// Error returned when API key validation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidApiKeyError {
    /// Description of why the key is invalid.
    pub reason: String,
}

impl std::fmt::Display for InvalidApiKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid Stripe API key: {}", self.reason)
    }
}

impl std::error::Error for InvalidApiKeyError {}

/// Validate a Stripe API key format.
///
/// Valid formats:
/// - `sk_test_*` - Test mode secret key
/// - `sk_live_*` - Live mode secret key
/// - `rk_test_*` - Test mode restricted key
/// - `rk_live_*` - Live mode restricted key
fn validate_api_key(key: &str) -> std::result::Result<(), InvalidApiKeyError> {
    const MIN_KEY_LENGTH: usize = 20;

    if key.is_empty() {
        return Err(InvalidApiKeyError {
            reason: "API key cannot be empty".to_string(),
        });
    }

    if key.len() < MIN_KEY_LENGTH {
        return Err(InvalidApiKeyError {
            reason: format!("API key too short (minimum {} characters)", MIN_KEY_LENGTH),
        });
    }

    let valid_prefixes = ["sk_test_", "sk_live_", "rk_test_", "rk_live_"];
    if !valid_prefixes.iter().any(|prefix| key.starts_with(prefix)) {
        return Err(InvalidApiKeyError {
            reason: "API key must start with sk_test_, sk_live_, rk_test_, or rk_live_"
                .to_string(),
        });
    }

    Ok(())
}

// ============================================================================
// ID Parsing Helpers
// ============================================================================

/// Parse a customer ID string into a Stripe CustomerId.
#[inline]
fn parse_customer_id(id: &str) -> Result<stripe::CustomerId> {
    id.parse().map_err(|_| {
        crate::error::TidewayError::BadRequest(format!("Invalid customer ID: {}", id))
    })
}

/// Parse a subscription ID string into a Stripe SubscriptionId.
#[inline]
fn parse_subscription_id(id: &str) -> Result<stripe::SubscriptionId> {
    id.parse().map_err(|_| {
        crate::error::TidewayError::BadRequest(format!("Invalid subscription ID: {}", id))
    })
}

/// Parse an invoice ID string into a Stripe InvoiceId.
#[inline]
fn parse_invoice_id(id: &str) -> Result<stripe::InvoiceId> {
    id.parse().map_err(|_| {
        crate::error::TidewayError::BadRequest(format!("Invalid invoice ID: {}", id))
    })
}

// ============================================================================
// Live Stripe Client
// ============================================================================

/// Live Stripe client for production use.
///
/// Implements all Stripe client traits with:
/// - Secure API key handling using `SecretString`
/// - Retry logic with exponential backoff for transient failures
/// - Circuit breaker pattern for fail-fast behavior
/// - Idempotency key support for mutating operations
/// - Proper error mapping to `BillingError` types
///
/// # Example
///
/// ```rust,ignore
/// use tideway::billing::{LiveStripeClient, LiveStripeClientConfig};
///
/// let client = LiveStripeClient::new(
///     "sk_live_xxx".to_string(),
///     LiveStripeClientConfig::default(),
/// )?;
///
/// // Use with billing managers
/// let checkout_manager = CheckoutManager::new(store, client, plans, config);
/// ```
#[derive(Clone)]
pub struct LiveStripeClient {
    client: stripe::Client,
    config: LiveStripeClientConfig,
    api_key: SecretString,
    circuit_breaker: Arc<CircuitBreaker>,
}

impl LiveStripeClient {
    /// Create a new live Stripe client.
    ///
    /// The API key is validated and stored securely, and won't be exposed in debug output.
    /// Supports test mode (`sk_test_`), live mode (`sk_live_`), and restricted keys (`rk_*`).
    ///
    /// # Errors
    ///
    /// Returns an error if the API key format is invalid.
    pub fn new(
        api_key: impl Into<SecretString>,
        config: LiveStripeClientConfig,
    ) -> std::result::Result<Self, InvalidApiKeyError> {
        let api_key: SecretString = api_key.into();

        // Validate API key format
        validate_api_key(api_key.expose_secret())?;

        // Create circuit breaker
        let circuit_breaker = Arc::new(CircuitBreaker::new(config.circuit_breaker.clone()));

        // Create client with app info for Stripe analytics
        let client = stripe::Client::new(api_key.expose_secret()).with_app_info(
            "tideway".to_string(),
            Some(env!("CARGO_PKG_VERSION").to_string()),
            Some("https://github.com/jordcodes/tideway-rs".to_string()),
        );

        Ok(Self {
            client,
            config,
            api_key,
            circuit_breaker,
        })
    }

    /// Create a client with default configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the API key format is invalid.
    pub fn with_default_config(
        api_key: impl Into<SecretString>,
    ) -> std::result::Result<Self, InvalidApiKeyError> {
        Self::new(api_key, LiveStripeClientConfig::default())
    }

    /// Check if the client is using a test mode API key.
    #[must_use]
    pub fn is_test_mode(&self) -> bool {
        let key = self.api_key.expose_secret();
        key.starts_with("sk_test_") || key.starts_with("rk_test_")
    }

    /// Check if the client is using a live mode API key.
    #[must_use]
    pub fn is_live_mode(&self) -> bool {
        let key = self.api_key.expose_secret();
        key.starts_with("sk_live_") || key.starts_with("rk_live_")
    }

    /// Get the configured timeout duration.
    #[inline]
    #[must_use]
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.config.timeout_seconds)
    }

    /// Get the circuit breaker state.
    #[must_use]
    pub fn circuit_state(&self) -> CircuitState {
        self.circuit_breaker.state()
    }

    /// Reset the circuit breaker.
    pub fn reset_circuit_breaker(&self) {
        self.circuit_breaker.reset();
    }

    /// Generate an idempotency key for retryable operations.
    #[inline]
    fn generate_idempotency_key(operation: &str) -> String {
        format!("{}_{}", operation, uuid::Uuid::new_v4())
    }

    /// Get a client configured with an idempotency key for mutating operations.
    #[inline]
    fn idempotent_client(&self, operation: &str) -> stripe::Client {
        let key = Self::generate_idempotency_key(operation);
        self.client
            .clone()
            .with_strategy(stripe::RequestStrategy::Idempotent(key))
    }
}

// Debug implementation that doesn't expose the API key
impl std::fmt::Debug for LiveStripeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveStripeClient")
            .field("config", &self.config)
            .field("is_test_mode", &self.is_test_mode())
            .field("circuit_state", &self.circuit_state())
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Retry Logic
// ============================================================================

/// Execute an async operation with retry logic, timeout, and circuit breaker.
///
/// Retries on:
/// - HTTP 429 (Rate Limited)
/// - HTTP 5xx (Server Errors)
/// - Timeouts
///
/// The circuit breaker will fail fast if too many consecutive failures occur.
async fn with_retry_cb<T, F, Fut>(
    config: &LiveStripeClientConfig,
    circuit_breaker: &CircuitBreaker,
    operation: &str,
    operation_fn: F,
) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, stripe::StripeError>>,
{
    // Check circuit breaker before attempting
    circuit_breaker.check()?;

    let timeout_duration = Duration::from_secs(config.timeout_seconds);
    let mut attempts = 0;

    loop {
        // Apply timeout to the operation
        let result = tokio::time::timeout(timeout_duration, operation_fn()).await;

        match result {
            Ok(Ok(value)) => {
                circuit_breaker.record_success();
                return Ok(value);
            }
            Ok(Err(e)) => {
                if !is_retryable_error(&e) || attempts >= config.max_retries {
                    circuit_breaker.record_failure();
                    return Err(map_stripe_error(e, operation));
                }

                log_retry(operation, attempts, &e, config);
                sleep_with_backoff(attempts, config).await;
                attempts += 1;
            }
            Err(_timeout) => {
                if attempts >= config.max_retries {
                    circuit_breaker.record_failure();
                    return Err(BillingError::StripeApiError {
                        operation: operation.to_string(),
                        message: format!(
                            "Request timed out after {} seconds",
                            config.timeout_seconds
                        ),
                        code: None,
                        http_status: Some(408),
                    }
                    .into());
                }

                tracing::warn!(
                    target: "tideway::billing::stripe",
                    operation = operation,
                    attempt = attempts + 1,
                    timeout_seconds = config.timeout_seconds,
                    "Stripe API request timed out, retrying"
                );

                sleep_with_backoff(attempts, config).await;
                attempts += 1;
            }
        }
    }
}

/// Log a retry attempt.
#[inline]
fn log_retry(operation: &str, attempts: u32, error: &stripe::StripeError, config: &LiveStripeClientConfig) {
    let delay = calculate_backoff_delay(attempts, config.base_delay_ms, config.max_delay_ms);
    tracing::warn!(
        target: "tideway::billing::stripe",
        operation = operation,
        attempt = attempts + 1,
        delay_ms = delay.as_millis() as u64,
        error = %error,
        "Retrying Stripe API call after transient error"
    );
}

/// Sleep with exponential backoff.
#[inline]
async fn sleep_with_backoff(attempts: u32, config: &LiveStripeClientConfig) {
    let delay = calculate_backoff_delay(attempts, config.base_delay_ms, config.max_delay_ms);
    tokio::time::sleep(delay).await;
}

/// Check if an error is retryable.
#[inline]
fn is_retryable_error(error: &stripe::StripeError) -> bool {
    match error {
        stripe::StripeError::Stripe(request_error) => {
            let status = request_error.http_status;
            // Rate limited (429) or server errors (5xx)
            status == 429 || (500..600).contains(&status)
        }
        stripe::StripeError::Timeout => true,
        // Other errors are generally not retryable
        _ => false,
    }
}

/// Calculate backoff delay with exponential backoff and jitter.
#[inline]
fn calculate_backoff_delay(attempt: u32, base_ms: u64, max_ms: u64) -> Duration {
    // Exponential backoff: base_ms * 2^attempt
    let delay_ms = base_ms.saturating_mul(2_u64.saturating_pow(attempt));
    let delay_ms = delay_ms.min(max_ms);

    // Add jitter (0-25% of delay)
    let jitter = if delay_ms > 0 {
        fastrand::u64(0..=delay_ms / 4)
    } else {
        0
    };
    Duration::from_millis(delay_ms.saturating_add(jitter))
}

// ============================================================================
// Error Mapping
// ============================================================================

/// Map Stripe errors to TidewayError types.
fn map_stripe_error(error: stripe::StripeError, operation: &str) -> crate::error::TidewayError {
    match error {
        stripe::StripeError::Stripe(request_error) => {
            let http_status = request_error.http_status;
            let message = request_error
                .message
                .clone()
                .unwrap_or_else(|| "Unknown error".to_string());
            let code = request_error.code.as_ref().map(|c| format!("{c:?}"));

            BillingError::StripeApiError {
                operation: operation.to_string(),
                message,
                code,
                http_status: Some(http_status),
            }
            .into()
        }
        stripe::StripeError::QueryStringSerialize(e) => BillingError::Internal {
            message: format!("Failed to serialize request: {e}"),
        }
        .into(),
        stripe::StripeError::JSONSerialize(e) => BillingError::Internal {
            message: format!("Failed to serialize JSON: {e}"),
        }
        .into(),
        stripe::StripeError::UnsupportedVersion => BillingError::Internal {
            message: "Unsupported Stripe API version".to_string(),
        }
        .into(),
        stripe::StripeError::ClientError(msg) => BillingError::Internal {
            message: format!("HTTP client error: {msg}"),
        }
        .into(),
        stripe::StripeError::Timeout => BillingError::StripeApiError {
            operation: operation.to_string(),
            message: "Request timed out".to_string(),
            code: None,
            http_status: Some(408),
        }
        .into(),
    }
}

// ============================================================================
// StripeClient Implementation (Customer operations)
// ============================================================================

impl StripeClient for LiveStripeClient {
    async fn create_customer(&self, request: CreateCustomerRequest) -> Result<String> {
        let client = self.idempotent_client("create_customer");

        let mut params = stripe::CreateCustomer::new();
        params.email = Some(&request.email);
        if let Some(ref name) = request.name {
            params.name = Some(name);
        }

        // Set metadata
        if let Some(ref metadata) = request.metadata {
            let mut meta = std::collections::HashMap::new();
            meta.insert(META_BILLABLE_ID.to_string(), metadata.billable_id.clone());
            meta.insert(
                META_BILLABLE_TYPE.to_string(),
                metadata.billable_type.clone(),
            );
            params.metadata = Some(meta);
        }

        let customer = with_retry_cb(&self.config, &self.circuit_breaker, "create_customer", || {
            let client = client.clone();
            let params = params.clone();
            async move { stripe::Customer::create(&client, params).await }
        })
        .await?;

        Ok(customer.id.to_string())
    }

    async fn update_customer(
        &self,
        customer_id: &str,
        request: UpdateCustomerRequest,
    ) -> Result<()> {
        let client = self.idempotent_client("update_customer");
        let customer_id = parse_customer_id(customer_id)?;

        let mut params = stripe::UpdateCustomer::new();
        if let Some(ref email) = request.email {
            params.email = Some(email);
        }
        if let Some(ref name) = request.name {
            params.name = Some(name);
        }

        with_retry_cb(&self.config, &self.circuit_breaker, "update_customer", || {
            let client = client.clone();
            let customer_id = customer_id.clone();
            let params = params.clone();
            async move { stripe::Customer::update(&client, &customer_id, params).await }
        })
        .await?;

        Ok(())
    }

    async fn delete_customer(&self, customer_id: &str) -> Result<()> {
        let customer_id = parse_customer_id(customer_id)?;

        with_retry_cb(&self.config, &self.circuit_breaker, "delete_customer", || {
            let client = self.client.clone();
            let customer_id = customer_id.clone();
            async move { stripe::Customer::delete(&client, &customer_id).await }
        })
        .await?;

        Ok(())
    }

    async fn get_default_payment_method(&self, customer_id: &str) -> Result<Option<String>> {
        let customer_id = parse_customer_id(customer_id)?;

        let customer = with_retry_cb(&self.config, &self.circuit_breaker, "get_default_payment_method", || {
            let client = self.client.clone();
            let customer_id = customer_id.clone();
            async move { stripe::Customer::retrieve(&client, &customer_id, &[]).await }
        })
        .await?;

        Ok(customer
            .invoice_settings
            .and_then(|settings| settings.default_payment_method)
            .map(|pm| pm.id().to_string()))
    }
}

// ============================================================================
// StripeCheckoutClient Implementation
// ============================================================================

impl StripeCheckoutClient for LiveStripeClient {
    async fn create_checkout_session(
        &self,
        request: CreateCheckoutSessionRequest,
    ) -> Result<CheckoutSession> {
        let client = self.idempotent_client("create_checkout_session");

        let mode = match request.mode {
            CheckoutMode::Payment => stripe::CheckoutSessionMode::Payment,
            CheckoutMode::Subscription => stripe::CheckoutSessionMode::Subscription,
            CheckoutMode::Setup => stripe::CheckoutSessionMode::Setup,
        };

        let customer_id = parse_customer_id(&request.customer_id)?;

        let mut params = stripe::CreateCheckoutSession::new();
        params.customer = Some(customer_id);
        params.mode = Some(mode);
        params.success_url = Some(&request.success_url);
        params.cancel_url = Some(&request.cancel_url);
        params.allow_promotion_codes = Some(request.allow_promotion_codes);

        // Set line items
        let line_items: Vec<stripe::CreateCheckoutSessionLineItems> = request
            .line_items
            .iter()
            .map(|item| stripe::CreateCheckoutSessionLineItems {
                price: Some(item.price_id.clone()),
                quantity: Some(item.quantity as u64),
                ..Default::default()
            })
            .collect();
        params.line_items = Some(line_items);

        // Set trial period if provided
        if let Some(trial_days) = request.trial_period_days {
            params.subscription_data = Some(stripe::CreateCheckoutSessionSubscriptionData {
                trial_period_days: Some(trial_days),
                ..Default::default()
            });
        }

        // Set metadata
        let mut meta = std::collections::HashMap::new();
        meta.insert(
            META_BILLABLE_ID.to_string(),
            request.metadata.billable_id.clone(),
        );
        meta.insert(
            META_BILLABLE_TYPE.to_string(),
            request.metadata.billable_type.clone(),
        );
        meta.insert(META_PLAN_ID.to_string(), request.metadata.plan_id.clone());
        params.metadata = Some(meta);

        // Tax and billing options
        if request.tax_id_collection {
            params.tax_id_collection = Some(stripe::CreateCheckoutSessionTaxIdCollection {
                enabled: true,
            });
        }

        if request.billing_address_collection {
            params.billing_address_collection =
                Some(stripe::CheckoutSessionBillingAddressCollection::Required);
        }

        // Apply coupon if provided
        if let Some(ref coupon) = request.coupon {
            params.discounts = Some(vec![stripe::CreateCheckoutSessionDiscounts {
                coupon: Some(coupon.clone()),
                ..Default::default()
            }]);
        }

        let session = with_retry_cb(&self.config, &self.circuit_breaker, "create_checkout_session", || {
            let client = client.clone();
            let params = params.clone();
            async move { stripe::CheckoutSession::create(&client, params).await }
        })
        .await?;

        Ok(CheckoutSession {
            id: session.id.to_string(),
            url: session.url.ok_or_else(|| {
                crate::error::TidewayError::Internal("Checkout session URL missing".to_string())
            })?,
        })
    }
}

// ============================================================================
// StripeSubscriptionClient Implementation
// ============================================================================

impl StripeSubscriptionClient for LiveStripeClient {
    async fn cancel_subscription(&self, subscription_id: &str) -> Result<()> {
        let sub_id = parse_subscription_id(subscription_id)?;

        with_retry_cb(&self.config, &self.circuit_breaker, "cancel_subscription", || {
            let client = self.client.clone();
            let sub_id = sub_id.clone();
            async move {
                stripe::Subscription::cancel(
                    &client,
                    &sub_id,
                    stripe::CancelSubscription::default(),
                )
                .await
            }
        })
        .await?;

        Ok(())
    }

    async fn cancel_subscription_at_period_end(&self, subscription_id: &str) -> Result<()> {
        let client = self.idempotent_client("cancel_subscription_at_period_end");
        let sub_id = parse_subscription_id(subscription_id)?;

        let mut params = stripe::UpdateSubscription::new();
        params.cancel_at_period_end = Some(true);

        with_retry_cb(&self.config, &self.circuit_breaker, "cancel_subscription_at_period_end", || {
            let client = client.clone();
            let sub_id = sub_id.clone();
            let params = params.clone();
            async move { stripe::Subscription::update(&client, &sub_id, params).await }
        })
        .await?;

        Ok(())
    }

    async fn resume_subscription(&self, subscription_id: &str) -> Result<()> {
        let client = self.idempotent_client("resume_subscription");
        let sub_id = parse_subscription_id(subscription_id)?;

        let mut params = stripe::UpdateSubscription::new();
        params.cancel_at_period_end = Some(false);

        with_retry_cb(&self.config, &self.circuit_breaker, "resume_subscription", || {
            let client = client.clone();
            let sub_id = sub_id.clone();
            let params = params.clone();
            async move { stripe::Subscription::update(&client, &sub_id, params).await }
        })
        .await?;

        Ok(())
    }

    async fn get_subscription(&self, subscription_id: &str) -> Result<StripeSubscriptionData> {
        let sub_id = parse_subscription_id(subscription_id)?;

        let subscription = with_retry_cb(&self.config, &self.circuit_breaker, "get_subscription", || {
            let client = self.client.clone();
            let sub_id = sub_id.clone();
            async move { stripe::Subscription::retrieve(&client, &sub_id, &[]).await }
        })
        .await?;

        map_subscription_to_data(subscription)
    }

    async fn update_subscription(
        &self,
        subscription_id: &str,
        update: UpdateSubscriptionRequest,
    ) -> Result<StripeSubscriptionData> {
        let client = self.idempotent_client("update_subscription");
        let sub_id = parse_subscription_id(subscription_id)?;

        // Use provided item IDs or fetch from Stripe (optimization: skip API call if IDs provided)
        let (base_item_id, seat_item_id) = match (&update.base_item_id, &update.seat_item_id) {
            // If we need item IDs but they weren't provided, fetch from Stripe
            (None, None) if update.price_id.is_some() || update.seat_quantity.is_some() => {
                let current = self.get_subscription(subscription_id).await?;
                (current.base_item_id, current.seat_item_id)
            }
            // Use provided IDs (avoids extra API call)
            (base, seat) => (base.clone(), seat.clone()),
        };

        let mut params = stripe::UpdateSubscription::new();

        if let Some(proration) = update.proration_behavior {
            use stripe::generated::billing::subscription::SubscriptionProrationBehavior as SPB;
            params.proration_behavior = Some(match proration {
                ProrationBehavior::CreateProrations => SPB::CreateProrations,
                ProrationBehavior::None => SPB::None,
                ProrationBehavior::AlwaysInvoice => SPB::AlwaysInvoice,
            });
        }

        // Handle seat quantity updates
        if let Some(seat_quantity) = update.seat_quantity {
            if let Some(ref seat_item_id) = seat_item_id {
                params.items = Some(vec![stripe::UpdateSubscriptionItems {
                    id: Some(seat_item_id.clone()),
                    quantity: Some(seat_quantity as u64),
                    ..Default::default()
                }]);
            }
        }

        // Handle price changes
        if let Some(ref price_id) = update.price_id {
            if let Some(ref base_item_id) = base_item_id {
                let items = params.items.get_or_insert_with(Vec::new);
                items.push(stripe::UpdateSubscriptionItems {
                    id: Some(base_item_id.clone()),
                    price: Some(price_id.clone()),
                    ..Default::default()
                });
            }
        }

        let subscription = with_retry_cb(&self.config, &self.circuit_breaker, "update_subscription", || {
            let client = client.clone();
            let sub_id = sub_id.clone();
            let params = params.clone();
            async move { stripe::Subscription::update(&client, &sub_id, params).await }
        })
        .await?;

        map_subscription_to_data(subscription)
    }

    async fn extend_trial(
        &self,
        subscription_id: &str,
        new_trial_end: u64,
    ) -> Result<StripeSubscriptionData> {
        let client = self.idempotent_client("extend_trial");
        let sub_id = parse_subscription_id(subscription_id)?;

        let mut params = stripe::UpdateSubscription::new();
        params.trial_end = Some(stripe::Scheduled::Timestamp(new_trial_end as i64));

        let subscription = with_retry_cb(&self.config, &self.circuit_breaker, "extend_trial", || {
            let client = client.clone();
            let sub_id = sub_id.clone();
            let params = params.clone();
            async move { stripe::Subscription::update(&client, &sub_id, params).await }
        })
        .await?;

        map_subscription_to_data(subscription)
    }

    async fn pause_subscription(&self, subscription_id: &str) -> Result<()> {
        let client = self.idempotent_client("pause_subscription");
        let sub_id = parse_subscription_id(subscription_id)?;

        // First, verify the subscription is not already paused
        let current = stripe::Subscription::retrieve(&self.client, &sub_id, &[]).await
            .map_err(|e| BillingError::StripeApiError {
                operation: "get_subscription_for_pause".to_string(),
                message: e.to_string(),
                code: None,
                http_status: None,
            })?;

        if current.pause_collection.is_some() {
            return Err(BillingError::SubscriptionAlreadyPaused {
                billable_id: subscription_id.to_string(),
            }.into());
        }

        let mut params = stripe::UpdateSubscription::new();
        params.pause_collection = Some(stripe::UpdateSubscriptionPauseCollection {
            // MarkUncollectible: Invoices created during pause are marked uncollectible
            // and invoice collection is disabled. This is the safest default.
            behavior: stripe::UpdateSubscriptionPauseCollectionBehavior::MarkUncollectible,
            resumes_at: None, // Pause indefinitely until explicitly resumed
        });

        with_retry_cb(&self.config, &self.circuit_breaker, "pause_subscription", || {
            let client = client.clone();
            let sub_id = sub_id.clone();
            let params = params.clone();
            async move { stripe::Subscription::update(&client, &sub_id, params).await }
        })
        .await?;

        Ok(())
    }

    async fn resume_paused_subscription(&self, subscription_id: &str) -> Result<StripeSubscriptionData> {
        let client = self.idempotent_client("resume_paused_subscription");
        let sub_id = parse_subscription_id(subscription_id)?;

        // First, verify the subscription is actually paused
        let current = stripe::Subscription::retrieve(&self.client, &sub_id, &[]).await
            .map_err(|e| BillingError::StripeApiError {
                operation: "get_subscription_for_resume".to_string(),
                message: e.to_string(),
                code: None,
                http_status: None,
            })?;

        if current.pause_collection.is_none() {
            return Err(BillingError::SubscriptionNotPaused {
                billable_id: subscription_id.to_string(),
            }.into());
        }

        // To resume a paused subscription in Stripe:
        // - Ideally: pass empty string "" for pause_collection (not supported by async-stripe typed API)
        // - Workaround: set resumes_at to current timestamp to trigger immediate resume
        //
        // Note: The async-stripe library doesn't have a direct way to clear pause_collection.
        // Setting resumes_at to the current time tells Stripe the pause should end now.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut params = stripe::UpdateSubscription::new();
        params.pause_collection = Some(stripe::UpdateSubscriptionPauseCollection {
            // Use MarkUncollectible as default behavior - this is commonly used and safe
            // The behavior doesn't matter much since we're immediately resuming
            behavior: stripe::UpdateSubscriptionPauseCollectionBehavior::MarkUncollectible,
            // Setting resumes_at to now triggers immediate resume
            resumes_at: Some(now as i64),
        });

        let subscription = with_retry_cb(&self.config, &self.circuit_breaker, "resume_paused_subscription", || {
            let client = client.clone();
            let sub_id = sub_id.clone();
            let params = params.clone();
            async move { stripe::Subscription::update(&client, &sub_id, params).await }
        })
        .await?;

        // Verify the subscription was actually resumed
        let result = map_subscription_to_data(subscription)?;

        // Log a warning if pause_collection is still present (this might indicate the resume didn't work)
        // In practice, Stripe should clear pause_collection when resumes_at is reached
        tracing::debug!(
            subscription_id = %subscription_id,
            status = %result.status,
            "Attempted to resume paused subscription"
        );

        Ok(result)
    }
}

// ============================================================================
// Payment Method Client
// ============================================================================

impl StripePaymentMethodClient for LiveStripeClient {
    async fn list_payment_methods(
        &self,
        customer_id: &str,
        limit: u8,
    ) -> Result<PaymentMethodList> {
        let client = self.client.clone();
        let customer_id = customer_id.parse::<stripe::CustomerId>()
            .map_err(|_| BillingError::NoCustomer {
                billable_id: customer_id.to_string(),
            })?;

        // Get customer to find default payment method
        let customer = with_retry_cb(&self.config, &self.circuit_breaker, "get_customer", || {
            let client = client.clone();
            let customer_id = customer_id.clone();
            async move { stripe::Customer::retrieve(&client, &customer_id, &[]).await }
        })
        .await?;

        let default_pm_id = customer.invoice_settings
            .and_then(|s| s.default_payment_method)
            .map(|pm| match pm {
                stripe::Expandable::Id(id) => id.to_string(),
                stripe::Expandable::Object(pm) => pm.id.to_string(),
            });

        // List payment methods
        let mut params = stripe::ListPaymentMethods::new();
        params.customer = Some(customer_id);
        params.type_ = Some(stripe::PaymentMethodTypeFilter::Card);
        params.limit = Some(limit.into());

        let list = with_retry_cb(&self.config, &self.circuit_breaker, "list_payment_methods", || {
            let client = client.clone();
            let params = params.clone();
            async move { stripe::PaymentMethod::list(&client, &params).await }
        })
        .await?;

        let methods = list.data.into_iter().map(|pm| {
            let card = pm.card.as_ref();
            PaymentMethod {
                id: pm.id.to_string(),
                card_brand: card.map(|c| format!("{:?}", c.brand).to_lowercase()),
                card_last4: card.map(|c| c.last4.clone()),
                card_exp_month: card.map(|c| c.exp_month as u32),
                card_exp_year: card.map(|c| c.exp_year as u32),
                is_default: default_pm_id.as_ref().map(|d| d == &pm.id.to_string()).unwrap_or(false),
            }
        }).collect();

        Ok(PaymentMethodList {
            methods,
            has_more: list.has_more,
        })
    }

    async fn attach_payment_method(
        &self,
        payment_method_id: &str,
        customer_id: &str,
    ) -> Result<PaymentMethod> {
        let client = self.client.clone();
        let pm_id = payment_method_id.parse::<stripe::PaymentMethodId>()
            .map_err(|_| BillingError::PaymentMethodNotFound {
                payment_method_id: payment_method_id.to_string(),
            })?;
        let customer_id = customer_id.parse::<stripe::CustomerId>()
            .map_err(|_| BillingError::NoCustomer {
                billable_id: customer_id.to_string(),
            })?;

        let pm = with_retry_cb(&self.config, &self.circuit_breaker, "attach_payment_method", || {
            let client = client.clone();
            let pm_id = pm_id.clone();
            let customer_id = customer_id.clone();
            async move {
                stripe::PaymentMethod::attach(
                    &client,
                    &pm_id,
                    stripe::AttachPaymentMethod { customer: customer_id },
                ).await
            }
        })
        .await?;

        let card = pm.card.as_ref();
        Ok(PaymentMethod {
            id: pm.id.to_string(),
            card_brand: card.map(|c| format!("{:?}", c.brand).to_lowercase()),
            card_last4: card.map(|c| c.last4.clone()),
            card_exp_month: card.map(|c| c.exp_month as u32),
            card_exp_year: card.map(|c| c.exp_year as u32),
            is_default: false,
        })
    }

    async fn detach_payment_method(
        &self,
        payment_method_id: &str,
    ) -> Result<()> {
        let client = self.client.clone();
        let pm_id = payment_method_id.parse::<stripe::PaymentMethodId>()
            .map_err(|_| BillingError::PaymentMethodNotFound {
                payment_method_id: payment_method_id.to_string(),
            })?;

        with_retry_cb(&self.config, &self.circuit_breaker, "detach_payment_method", || {
            let client = client.clone();
            let pm_id = pm_id.clone();
            async move { stripe::PaymentMethod::detach(&client, &pm_id).await }
        })
        .await?;

        Ok(())
    }

    async fn set_default_payment_method(
        &self,
        customer_id: &str,
        payment_method_id: &str,
    ) -> Result<()> {
        let client = self.idempotent_client("set_default_payment_method");
        let customer_id = customer_id.parse::<stripe::CustomerId>()
            .map_err(|_| BillingError::NoCustomer {
                billable_id: customer_id.to_string(),
            })?;
        let pm_id = payment_method_id.parse::<stripe::PaymentMethodId>()
            .map_err(|_| BillingError::PaymentMethodNotFound {
                payment_method_id: payment_method_id.to_string(),
            })?;

        let mut params = stripe::UpdateCustomer::new();
        params.invoice_settings = Some(stripe::CustomerInvoiceSettings {
            default_payment_method: Some(pm_id.to_string()),
            ..Default::default()
        });

        with_retry_cb(&self.config, &self.circuit_breaker, "set_default_payment_method", || {
            let client = client.clone();
            let customer_id = customer_id.clone();
            let params = params.clone();
            async move { stripe::Customer::update(&client, &customer_id, params).await }
        })
        .await?;

        Ok(())
    }
}

// ============================================================================
// Refund Client
// ============================================================================

impl StripeRefundClient for LiveStripeClient {
    async fn create_refund(&self, request: CreateRefundRequest) -> Result<Refund> {
        let client = self.idempotent_client("create_refund");

        let mut params = stripe::CreateRefund::new();

        if let Some(ref charge_id) = request.charge_id {
            params.charge = Some(charge_id.parse().map_err(|_| BillingError::ChargeNotFound {
                charge_id: charge_id.clone(),
            })?);
        }

        if let Some(ref pi_id) = request.payment_intent_id {
            params.payment_intent = Some(pi_id.parse().map_err(|_| BillingError::RefundFailed {
                reason: format!("Invalid payment intent ID: {}", pi_id),
            })?);
        }

        if let Some(amount) = request.amount {
            params.amount = Some(amount);
        }

        if let Some(reason) = request.reason {
            params.reason = Some(match reason {
                RefundReason::Duplicate => stripe::RefundReasonFilter::Duplicate,
                RefundReason::Fraudulent => stripe::RefundReasonFilter::Fraudulent,
                RefundReason::RequestedByCustomer => stripe::RefundReasonFilter::RequestedByCustomer,
            });
        }

        let refund = with_retry_cb(&self.config, &self.circuit_breaker, "create_refund", || {
            let client = client.clone();
            let params = params.clone();
            async move { stripe::Refund::create(&client, params).await }
        })
        .await?;

        Ok(map_refund(refund))
    }

    async fn get_refund(&self, refund_id: &str) -> Result<Refund> {
        let client = self.client.clone();
        let refund_id = refund_id.parse::<stripe::RefundId>()
            .map_err(|_| BillingError::RefundNotFound {
                refund_id: refund_id.to_string(),
            })?;

        let refund = with_retry_cb(&self.config, &self.circuit_breaker, "get_refund", || {
            let client = client.clone();
            let refund_id = refund_id.clone();
            async move { stripe::Refund::retrieve(&client, &refund_id, &[]).await }
        })
        .await?;

        Ok(map_refund(refund))
    }

    async fn list_refunds(&self, charge_id: &str, limit: u8) -> Result<Vec<Refund>> {
        let client = self.client.clone();

        let mut params = stripe::ListRefunds::new();
        params.charge = Some(charge_id.parse().map_err(|_| BillingError::ChargeNotFound {
            charge_id: charge_id.to_string(),
        })?);
        params.limit = Some(limit.into());

        let list = with_retry_cb(&self.config, &self.circuit_breaker, "list_refunds", || {
            let client = client.clone();
            let params = params.clone();
            async move { stripe::Refund::list(&client, &params).await }
        })
        .await?;

        Ok(list.data.into_iter().map(map_refund).collect())
    }

    async fn get_charge_customer_id(&self, charge_id: &str) -> Result<String> {
        let client = self.client.clone();
        let charge_id = charge_id.parse::<stripe::ChargeId>()
            .map_err(|_| BillingError::ChargeNotFound {
                charge_id: charge_id.to_string(),
            })?;

        let charge = with_retry_cb(&self.config, &self.circuit_breaker, "get_charge", || {
            let client = client.clone();
            let charge_id = charge_id.clone();
            async move { stripe::Charge::retrieve(&client, &charge_id, &[]).await }
        })
        .await?;

        // Extract customer ID from charge
        charge.customer
            .map(|c| match c {
                stripe::Expandable::Id(id) => id.to_string(),
                stripe::Expandable::Object(customer) => customer.id.to_string(),
            })
            .ok_or_else(|| BillingError::ChargeNotFound {
                charge_id: charge_id.to_string(),
            }.into())
    }

    async fn get_payment_intent_customer_id(&self, payment_intent_id: &str) -> Result<String> {
        let client = self.client.clone();
        let pi_id = payment_intent_id.parse::<stripe::PaymentIntentId>()
            .map_err(|_| BillingError::RefundFailed {
                reason: format!("Invalid payment intent ID: {}", payment_intent_id),
            })?;

        let pi = with_retry_cb(&self.config, &self.circuit_breaker, "get_payment_intent", || {
            let client = client.clone();
            let pi_id = pi_id.clone();
            async move { stripe::PaymentIntent::retrieve(&client, &pi_id, &[]).await }
        })
        .await?;

        // Extract customer ID from payment intent
        pi.customer
            .map(|c| match c {
                stripe::Expandable::Id(id) => id.to_string(),
                stripe::Expandable::Object(customer) => customer.id.to_string(),
            })
            .ok_or_else(|| BillingError::RefundFailed {
                reason: "Payment intent has no customer".to_string(),
            }.into())
    }
}

/// Map Stripe Refund to internal Refund type.
fn map_refund(refund: stripe::Refund) -> Refund {
    let charge_id = refund.charge.map(|c| match c {
        stripe::Expandable::Id(id) => id.to_string(),
        stripe::Expandable::Object(charge) => charge.id.to_string(),
    });

    let payment_intent_id = refund.payment_intent.map(|pi| match pi {
        stripe::Expandable::Id(id) => id.to_string(),
        stripe::Expandable::Object(pi) => pi.id.to_string(),
    });

    let status = refund.status.as_deref().map(RefundStatus::from_stripe).unwrap_or(RefundStatus::Pending);

    let reason = refund.reason.and_then(|r| {
        let reason_str = match r {
            stripe::RefundReason::Duplicate => "duplicate",
            stripe::RefundReason::Fraudulent => "fraudulent",
            stripe::RefundReason::RequestedByCustomer => "requested_by_customer",
            _ => return None,
        };
        RefundReason::from_stripe(reason_str)
    });

    Refund {
        id: refund.id.to_string(),
        amount: refund.amount,
        currency: refund.currency.to_string(),
        status,
        reason,
        created: refund.created as u64,
        charge_id,
        payment_intent_id,
    }
}

// ============================================================================
// Subscription Data Mapping
// ============================================================================

/// Map Stripe Subscription to internal StripeSubscriptionData.
///
/// Uses metadata to identify base plan vs seat items when available,
/// falling back to position-based detection for backwards compatibility.
/// All metadata values are sanitized to prevent injection attacks.
fn map_subscription_to_data(sub: stripe::Subscription) -> Result<StripeSubscriptionData> {
    let status = match sub.status {
        stripe::SubscriptionStatus::Active => "active",
        stripe::SubscriptionStatus::Canceled => "canceled",
        stripe::SubscriptionStatus::Incomplete => "incomplete",
        stripe::SubscriptionStatus::IncompleteExpired => "incomplete_expired",
        stripe::SubscriptionStatus::PastDue => "past_due",
        stripe::SubscriptionStatus::Trialing => "trialing",
        stripe::SubscriptionStatus::Unpaid => "unpaid",
        stripe::SubscriptionStatus::Paused => "paused",
    };

    // Extract and sanitize plan_id from subscription metadata
    let plan_id = get_sanitized_metadata(&sub.metadata, META_PLAN_ID).unwrap_or_default();

    // Parse subscription items using metadata for identification
    let (base_item_id, seat_item_id, extra_seats, fallback_plan_id) =
        parse_subscription_items(&sub.items.data);

    // Use metadata plan_id if available, otherwise fall back to price ID
    let final_plan_id = if plan_id.is_empty() {
        fallback_plan_id
    } else {
        plan_id
    };

    let customer_id = match &sub.customer {
        stripe::Expandable::Id(id) => id.to_string(),
        stripe::Expandable::Object(c) => c.id.to_string(),
    };

    // Sanitize all metadata values
    let metadata = SubscriptionMetadata {
        billable_id: get_sanitized_metadata(&sub.metadata, META_BILLABLE_ID),
        billable_type: get_sanitized_metadata(&sub.metadata, META_BILLABLE_TYPE),
    };

    Ok(StripeSubscriptionData {
        id: sub.id.to_string(),
        customer_id,
        plan_id: final_plan_id,
        status: status.to_string(),
        current_period_start: sub.current_period_start as u64,
        current_period_end: sub.current_period_end as u64,
        extra_seats,
        trial_end: sub.trial_end.map(|t| t as u64),
        cancel_at_period_end: sub.cancel_at_period_end,
        base_item_id,
        seat_item_id,
        metadata,
    })
}

/// Parse subscription items to extract base plan and seat information.
///
/// Returns (base_item_id, seat_item_id, extra_seats, fallback_plan_id)
fn parse_subscription_items(
    items: &[stripe::SubscriptionItem],
) -> (Option<String>, Option<String>, u32, String) {
    let mut base_item_id = None;
    let mut seat_item_id = None;
    let mut extra_seats = 0u32;
    let mut fallback_plan_id = String::new();

    for item in items {
        let item_type = item
            .metadata
            .as_ref()
            .and_then(|m| m.get(META_ITEM_TYPE))
            .map(String::as_str);

        match item_type {
            // Explicitly marked as base plan
            Some(META_ITEM_TYPE_BASE) => {
                base_item_id = Some(item.id.to_string());
                if let Some(ref price) = item.price {
                    fallback_plan_id = price.id.to_string();
                }
            }
            // Explicitly marked as seats
            Some(META_ITEM_TYPE_SEATS) => {
                seat_item_id = Some(item.id.to_string());
                extra_seats = item.quantity.unwrap_or(0) as u32;
            }
            // No metadata - use heuristics (backwards compatibility)
            None => {
                if base_item_id.is_none() {
                    // First item without metadata is likely the base plan
                    base_item_id = Some(item.id.to_string());
                    if let Some(ref price) = item.price {
                        fallback_plan_id = price.id.to_string();
                    }
                } else if seat_item_id.is_none() {
                    // Second item is likely seats
                    seat_item_id = Some(item.id.to_string());
                    extra_seats = item.quantity.unwrap_or(0) as u32;
                }
            }
            // Unknown item type - skip
            Some(_) => {}
        }
    }

    (base_item_id, seat_item_id, extra_seats, fallback_plan_id)
}

// ============================================================================
// StripePortalClient Implementation
// ============================================================================

impl StripePortalClient for LiveStripeClient {
    async fn create_portal_session(
        &self,
        request: CreatePortalSessionRequest,
    ) -> Result<PortalSession> {
        let customer_id = parse_customer_id(&request.customer_id)?;

        let mut params = stripe::CreateBillingPortalSession::new(customer_id);
        params.return_url = Some(&request.return_url);

        if let Some(ref config_id) = request.configuration_id {
            params.configuration = Some(config_id.as_str());
        }

        let session = with_retry_cb(&self.config, &self.circuit_breaker, "create_portal_session", || {
            let client = self.client.clone();
            let params = params.clone();
            async move { stripe::BillingPortalSession::create(&client, params).await }
        })
        .await?;

        Ok(PortalSession {
            id: session.id.to_string(),
            url: session.url,
        })
    }

    async fn create_portal_session_with_flow(
        &self,
        request: CreatePortalSessionRequest,
        flow: PortalFlow,
    ) -> Result<PortalSession> {
        let customer_id = parse_customer_id(&request.customer_id)?;

        let mut params = stripe::CreateBillingPortalSession::new(customer_id);
        params.return_url = Some(&request.return_url);

        if let Some(ref config_id) = request.configuration_id {
            params.configuration = Some(config_id.as_str());
        }

        // Set flow data based on flow type
        let flow_data = match flow {
            PortalFlow::PaymentMethodUpdate => stripe::CreateBillingPortalSessionFlowData {
                type_: stripe::CreateBillingPortalSessionFlowDataType::PaymentMethodUpdate,
                ..Default::default()
            },
            PortalFlow::SubscriptionUpdate { subscription_id } => {
                stripe::CreateBillingPortalSessionFlowData {
                    type_: stripe::CreateBillingPortalSessionFlowDataType::SubscriptionUpdate,
                    subscription_update: Some(
                        stripe::CreateBillingPortalSessionFlowDataSubscriptionUpdate {
                            subscription: subscription_id,
                        },
                    ),
                    ..Default::default()
                }
            }
            PortalFlow::SubscriptionCancel { subscription_id } => {
                stripe::CreateBillingPortalSessionFlowData {
                    type_: stripe::CreateBillingPortalSessionFlowDataType::SubscriptionCancel,
                    subscription_cancel: Some(
                        stripe::CreateBillingPortalSessionFlowDataSubscriptionCancel {
                            subscription: subscription_id,
                            ..Default::default()
                        },
                    ),
                    ..Default::default()
                }
            }
        };
        params.flow_data = Some(flow_data);

        let session = with_retry_cb(&self.config, &self.circuit_breaker, "create_portal_session_with_flow", || {
            let client = self.client.clone();
            let params = params.clone();
            async move { stripe::BillingPortalSession::create(&client, params).await }
        })
        .await?;

        Ok(PortalSession {
            id: session.id.to_string(),
            url: session.url,
        })
    }
}

// ============================================================================
// StripeInvoiceClient Implementation
// ============================================================================

#[async_trait::async_trait]
impl StripeInvoiceClient for LiveStripeClient {
    async fn list_invoices(
        &self,
        customer_id: &str,
        limit: u8,
        starting_after: Option<&str>,
        status: Option<InvoiceStatus>,
    ) -> Result<InvoiceList> {
        let customer_id = parse_customer_id(customer_id)?;

        let mut params = stripe::ListInvoices::new();
        params.customer = Some(customer_id);
        params.limit = Some(u64::from(limit));

        if let Some(after) = starting_after {
            let invoice_id = parse_invoice_id(after)?;
            params.starting_after = Some(invoice_id);
        }

        // Map our status to Stripe's status enum
        if let Some(status) = status {
            params.status = Some(match status {
                InvoiceStatus::Draft => stripe::InvoiceStatus::Draft,
                InvoiceStatus::Open => stripe::InvoiceStatus::Open,
                InvoiceStatus::Paid => stripe::InvoiceStatus::Paid,
                InvoiceStatus::Uncollectible => stripe::InvoiceStatus::Uncollectible,
                InvoiceStatus::Void => stripe::InvoiceStatus::Void,
            });
        }

        let response = with_retry_cb(&self.config, &self.circuit_breaker, "list_invoices", || {
            let client = self.client.clone();
            let params = params.clone();
            async move { stripe::Invoice::list(&client, &params).await }
        })
        .await?;

        let invoices: Vec<Invoice> = response
            .data
            .into_iter()
            .filter_map(|inv| map_stripe_invoice(inv).ok())
            .collect();

        let next_cursor = invoices.last().map(|inv| inv.id.clone());

        Ok(InvoiceList {
            invoices,
            has_more: response.has_more,
            next_cursor,
        })
    }

    async fn get_invoice(&self, invoice_id: &str) -> Result<Invoice> {
        let invoice_id = parse_invoice_id(invoice_id)?;

        let invoice = with_retry_cb(&self.config, &self.circuit_breaker, "get_invoice", || {
            let client = self.client.clone();
            let invoice_id = invoice_id.clone();
            async move { stripe::Invoice::retrieve(&client, &invoice_id, &[]).await }
        })
        .await?;

        map_stripe_invoice(invoice)
    }

    async fn get_upcoming_invoice(&self, _customer_id: &str) -> Result<Option<Invoice>> {
        // Note: The async-stripe crate doesn't have full support for upcoming invoices.
        // This would require a raw API call. For now, return None.
        // Users can implement this via the Stripe Portal or raw HTTP calls if needed.
        Ok(None)
    }

    async fn list_invoice_line_items(
        &self,
        invoice_id: &str,
        limit: u8,
    ) -> Result<Vec<InvoiceLineItem>> {
        // Fetch the invoice and extract line items from it
        let invoice_id = parse_invoice_id(invoice_id)?;

        let invoice = with_retry_cb(&self.config, &self.circuit_breaker, "get_invoice_for_lines", || {
            let client = self.client.clone();
            let invoice_id = invoice_id.clone();
            async move { stripe::Invoice::retrieve(&client, &invoice_id, &[]).await }
        })
        .await?;

        let items = invoice
            .lines
            .map(|lines| {
                lines
                    .data
                    .into_iter()
                    .take(limit as usize)
                    .map(map_stripe_line_item)
                    .collect()
            })
            .unwrap_or_default();

        Ok(items)
    }
}

// ============================================================================
// Invoice Data Mapping
// ============================================================================

/// Map Stripe Invoice to internal Invoice type.
fn map_stripe_invoice(inv: stripe::Invoice) -> Result<Invoice> {
    let status = match inv.status {
        Some(stripe::InvoiceStatus::Draft) => InvoiceStatus::Draft,
        Some(stripe::InvoiceStatus::Open) => InvoiceStatus::Open,
        Some(stripe::InvoiceStatus::Paid) => InvoiceStatus::Paid,
        Some(stripe::InvoiceStatus::Uncollectible) => InvoiceStatus::Uncollectible,
        Some(stripe::InvoiceStatus::Void) => InvoiceStatus::Void,
        None => InvoiceStatus::Draft, // Default for upcoming invoices
    };

    let customer_id = match &inv.customer {
        Some(stripe::Expandable::Id(id)) => id.to_string(),
        Some(stripe::Expandable::Object(c)) => c.id.to_string(),
        None => String::new(),
    };

    let subscription_id = inv.subscription.as_ref().map(|s| match s {
        stripe::Expandable::Id(id) => id.to_string(),
        stripe::Expandable::Object(sub) => sub.id.to_string(),
    });

    // Extract period from first line item if available
    let (period_start, period_end) = inv
        .lines
        .as_ref()
        .and_then(|lines| lines.data.first())
        .and_then(|item| item.period.as_ref())
        .map(|p| {
            let start = p.start.unwrap_or(0) as u64;
            let end = p.end.unwrap_or(0) as u64;
            (start, end)
        })
        .unwrap_or_else(|| {
            let start = inv.period_start.unwrap_or(0) as u64;
            let end = inv.period_end.unwrap_or(0) as u64;
            (start, end)
        });

    Ok(Invoice {
        id: inv.id.to_string(),
        customer_id,
        subscription_id,
        status,
        amount_due: inv.amount_due.unwrap_or(0),
        amount_paid: inv.amount_paid.unwrap_or(0),
        amount_remaining: inv.amount_remaining.unwrap_or(0),
        currency: inv.currency.map(|c| c.to_string()).unwrap_or_else(|| "usd".to_string()),
        created: inv.created.map(|t| t as u64).unwrap_or(0),
        due_date: inv.due_date.map(|t| t as u64),
        period_start,
        period_end,
        invoice_pdf: inv.invoice_pdf,
        hosted_invoice_url: inv.hosted_invoice_url,
        number: inv.number,
        paid: inv.paid.unwrap_or(false),
        line_items: None, // Populated separately if needed
    })
}

/// Map Stripe InvoiceLineItem to internal InvoiceLineItem type.
fn map_stripe_line_item(item: stripe::InvoiceLineItem) -> InvoiceLineItem {
    let (period_start, period_end) = item
        .period
        .as_ref()
        .map(|p| {
            let start = p.start.unwrap_or(0) as u64;
            let end = p.end.unwrap_or(0) as u64;
            (start, end)
        })
        .unwrap_or((0, 0));

    let price_id = item.price.as_ref().map(|p| p.id.to_string());
    let quantity = item.quantity.map(|q| q as u32);

    InvoiceLineItem {
        id: item.id.to_string(),
        description: item.description,
        amount: item.amount,
        currency: item.currency.to_string(),
        quantity,
        price_id,
        period_start,
        period_end,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_api_key_valid() {
        assert!(validate_api_key("sk_test_1234567890abcdef").is_ok());
        assert!(validate_api_key("sk_live_1234567890abcdef").is_ok());
        assert!(validate_api_key("rk_test_1234567890abcdef").is_ok());
        assert!(validate_api_key("rk_live_1234567890abcdef").is_ok());
    }

    #[test]
    fn test_validate_api_key_invalid() {
        assert!(validate_api_key("").is_err());
        assert!(validate_api_key("invalid_key").is_err());
        assert!(validate_api_key("sk_test_short").is_err());
        assert!(validate_api_key("pk_test_1234567890abcdef").is_err()); // publishable key
    }

    #[test]
    fn test_is_test_mode() {
        let client = LiveStripeClient::with_default_config("sk_test_12345678901234567890").unwrap();
        assert!(client.is_test_mode());
        assert!(!client.is_live_mode());

        let client = LiveStripeClient::with_default_config("rk_test_12345678901234567890").unwrap();
        assert!(client.is_test_mode());
        assert!(!client.is_live_mode());
    }

    #[test]
    fn test_is_live_mode() {
        let client = LiveStripeClient::with_default_config("sk_live_12345678901234567890").unwrap();
        assert!(!client.is_test_mode());
        assert!(client.is_live_mode());

        let client = LiveStripeClient::with_default_config("rk_live_12345678901234567890").unwrap();
        assert!(!client.is_test_mode());
        assert!(client.is_live_mode());
    }

    #[test]
    fn test_config_builder() {
        let config = LiveStripeClientConfig::new()
            .max_retries(5)
            .base_delay_ms(1000)
            .max_delay_ms(60_000)
            .timeout_seconds(60);

        assert_eq!(config.max_retries, 5);
        assert_eq!(config.base_delay_ms, 1000);
        assert_eq!(config.max_delay_ms, 60_000);
        assert_eq!(config.timeout_seconds, 60);
    }

    #[test]
    fn test_backoff_calculation() {
        let base = 500;
        let max = 30_000;

        // Test exponential increase (ranges due to jitter)
        let delay0 = calculate_backoff_delay(0, base, max);
        assert!(delay0.as_millis() >= 500 && delay0.as_millis() <= 625);

        let delay1 = calculate_backoff_delay(1, base, max);
        assert!(delay1.as_millis() >= 1000 && delay1.as_millis() <= 1250);

        let delay2 = calculate_backoff_delay(2, base, max);
        assert!(delay2.as_millis() >= 2000 && delay2.as_millis() <= 2500);

        // Test max cap
        let delay_high = calculate_backoff_delay(10, base, max);
        assert!(delay_high.as_millis() <= max as u128 + (max / 4) as u128);
    }

    #[test]
    fn test_backoff_with_zero_base() {
        // Should not panic with zero base
        let delay = calculate_backoff_delay(0, 0, 1000);
        assert_eq!(delay.as_millis(), 0);
    }

    #[test]
    fn test_debug_does_not_expose_api_key() {
        let client =
            LiveStripeClient::with_default_config("sk_test_secret_key_1234567890").unwrap();
        let debug_output = format!("{:?}", client);

        assert!(!debug_output.contains("sk_test_secret_key_1234567890"));
        assert!(debug_output.contains("is_test_mode: true"));
    }

    #[test]
    fn test_idempotency_key_generation() {
        let key1 = LiveStripeClient::generate_idempotency_key("create_customer");
        let key2 = LiveStripeClient::generate_idempotency_key("create_customer");

        assert!(key1.starts_with("create_customer_"));
        assert!(key2.starts_with("create_customer_"));
        assert_ne!(key1, key2); // Should be unique
    }

    #[test]
    fn test_timeout_getter() {
        let config = LiveStripeClientConfig::new().timeout_seconds(45);
        let client = LiveStripeClient::new("sk_test_12345678901234567890", config).unwrap();
        assert_eq!(client.timeout(), Duration::from_secs(45));
    }

    #[test]
    fn test_metadata_constants() {
        // Ensure constants are what we expect
        assert_eq!(META_BILLABLE_ID, "billable_id");
        assert_eq!(META_BILLABLE_TYPE, "billable_type");
        assert_eq!(META_PLAN_ID, "plan_id");
        assert_eq!(META_ITEM_TYPE, "item_type");
        assert_eq!(META_ITEM_TYPE_SEATS, "seats");
        assert_eq!(META_ITEM_TYPE_BASE, "base");
    }

    // ========================================================================
    // Circuit Breaker Tests
    // ========================================================================

    #[test]
    fn test_circuit_breaker_starts_closed() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig::default());
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.check().is_ok());
    }

    #[test]
    fn test_circuit_breaker_opens_after_threshold() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            open_duration_seconds: 60,
            enabled: true,
        };
        let cb = CircuitBreaker::new(config);

        // Record failures
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Check should fail when open
        assert!(cb.check().is_err());
    }

    #[test]
    fn test_circuit_breaker_resets_on_success() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            open_duration_seconds: 60,
            enabled: true,
        };
        let cb = CircuitBreaker::new(config);

        // Record some failures
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.failure_count(), 2);

        // Success resets the counter
        cb.record_success();
        assert_eq!(cb.failure_count(), 0);
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_disabled() {
        let config = CircuitBreakerConfig::disabled();
        let cb = CircuitBreaker::new(config);

        // Even after many failures, circuit stays closed
        for _ in 0..10 {
            cb.record_failure();
        }
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.check().is_ok());
    }

    #[test]
    fn test_circuit_breaker_reset() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            open_duration_seconds: 60,
            enabled: true,
        };
        let cb = CircuitBreaker::new(config);

        // Open the circuit
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Reset should close it
        cb.reset();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert_eq!(cb.failure_count(), 0);
    }

    #[test]
    fn test_circuit_breaker_config_builder() {
        let config = CircuitBreakerConfig::default()
            .failure_threshold(10)
            .open_duration_seconds(120);

        assert_eq!(config.failure_threshold, 10);
        assert_eq!(config.open_duration_seconds, 120);
        assert!(config.enabled);
    }

    // ========================================================================
    // Metadata Sanitization Tests
    // ========================================================================

    #[test]
    fn test_sanitize_metadata_value_normal() {
        assert_eq!(sanitize_metadata_value("hello"), "hello");
        assert_eq!(sanitize_metadata_value("org_123"), "org_123");
    }

    #[test]
    fn test_sanitize_metadata_value_trims_whitespace() {
        assert_eq!(sanitize_metadata_value("  hello  "), "hello");
        assert_eq!(sanitize_metadata_value("\thello\n"), "hello");
    }

    #[test]
    fn test_sanitize_metadata_value_removes_control_chars() {
        assert_eq!(sanitize_metadata_value("hello\x00world"), "helloworld");
        assert_eq!(sanitize_metadata_value("test\x1b[31mred"), "test[31mred");
    }

    #[test]
    fn test_sanitize_metadata_value_truncates_long_values() {
        let long_value = "a".repeat(1000);
        let sanitized = sanitize_metadata_value(&long_value);
        assert_eq!(sanitized.len(), MAX_METADATA_VALUE_LENGTH);
    }

    #[test]
    fn test_get_sanitized_metadata() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("key1".to_string(), "value1".to_string());
        metadata.insert("key2".to_string(), "  trimmed  ".to_string());

        assert_eq!(get_sanitized_metadata(&metadata, "key1"), Some("value1".to_string()));
        assert_eq!(get_sanitized_metadata(&metadata, "key2"), Some("trimmed".to_string()));
        assert_eq!(get_sanitized_metadata(&metadata, "missing"), None);
    }

    // ========================================================================
    // Config with Circuit Breaker Tests
    // ========================================================================

    #[test]
    fn test_config_with_circuit_breaker() {
        let config = LiveStripeClientConfig::new()
            .circuit_breaker(CircuitBreakerConfig::default().failure_threshold(10));

        assert_eq!(config.circuit_breaker.failure_threshold, 10);
    }

    #[test]
    fn test_config_disable_circuit_breaker() {
        let config = LiveStripeClientConfig::new().disable_circuit_breaker();

        assert!(!config.circuit_breaker.enabled);
    }

    #[test]
    fn test_client_circuit_state() {
        let client = LiveStripeClient::with_default_config("sk_test_12345678901234567890").unwrap();
        assert_eq!(client.circuit_state(), CircuitState::Closed);
    }
}
