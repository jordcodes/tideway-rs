//! Live Stripe client implementation.
//!
//! Production-ready Stripe client with retry logic, secure API key handling,
//! and proper error mapping.

use crate::error::Result;
use secrecy::{ExposeSecret, SecretString};
use std::time::Duration;

use super::checkout::{
    CheckoutMode, CheckoutSession, CreateCheckoutSessionRequest, StripeCheckoutClient,
};
use super::customer::{CreateCustomerRequest, StripeClient, UpdateCustomerRequest};
use super::error::BillingError;
use super::portal::{
    CreatePortalSessionRequest, PortalFlow, PortalSession, StripePortalClient,
};
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
}

impl Default for LiveStripeClientConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay_ms: 500,
            max_delay_ms: 30_000,
            timeout_seconds: 30,
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

// ============================================================================
// Live Stripe Client
// ============================================================================

/// Live Stripe client for production use.
///
/// Implements all Stripe client traits with:
/// - Secure API key handling using `SecretString`
/// - Retry logic with exponential backoff for transient failures
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
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Retry Logic
// ============================================================================

/// Execute an async operation with retry logic and timeout.
///
/// Retries on:
/// - HTTP 429 (Rate Limited)
/// - HTTP 5xx (Server Errors)
/// - Timeouts
async fn with_retry<T, F, Fut>(
    config: &LiveStripeClientConfig,
    operation: &str,
    operation_fn: F,
) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, stripe::StripeError>>,
{
    let timeout_duration = Duration::from_secs(config.timeout_seconds);
    let mut attempts = 0;

    loop {
        // Apply timeout to the operation
        let result = tokio::time::timeout(timeout_duration, operation_fn()).await;

        match result {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(e)) => {
                if !is_retryable_error(&e) || attempts >= config.max_retries {
                    return Err(map_stripe_error(e, operation));
                }

                log_retry(operation, attempts, &e, config);
                sleep_with_backoff(attempts, config).await;
                attempts += 1;
            }
            Err(_timeout) => {
                if attempts >= config.max_retries {
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

        let customer = with_retry(&self.config, "create_customer", || {
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

        with_retry(&self.config, "update_customer", || {
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

        with_retry(&self.config, "delete_customer", || {
            let client = self.client.clone();
            let customer_id = customer_id.clone();
            async move { stripe::Customer::delete(&client, &customer_id).await }
        })
        .await?;

        Ok(())
    }

    async fn get_default_payment_method(&self, customer_id: &str) -> Result<Option<String>> {
        let customer_id = parse_customer_id(customer_id)?;

        let customer = with_retry(&self.config, "get_default_payment_method", || {
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

        let session = with_retry(&self.config, "create_checkout_session", || {
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

        with_retry(&self.config, "cancel_subscription", || {
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

        with_retry(&self.config, "cancel_subscription_at_period_end", || {
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

        with_retry(&self.config, "resume_subscription", || {
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

        let subscription = with_retry(&self.config, "get_subscription", || {
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

        // First get the current subscription to find item IDs
        let current = self.get_subscription(subscription_id).await?;

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
            if let Some(ref seat_item_id) = current.seat_item_id {
                params.items = Some(vec![stripe::UpdateSubscriptionItems {
                    id: Some(seat_item_id.clone()),
                    quantity: Some(seat_quantity as u64),
                    ..Default::default()
                }]);
            }
        }

        // Handle price changes
        if let Some(ref price_id) = update.price_id {
            if let Some(ref base_item_id) = current.base_item_id {
                let items = params.items.get_or_insert_with(Vec::new);
                items.push(stripe::UpdateSubscriptionItems {
                    id: Some(base_item_id.clone()),
                    price: Some(price_id.clone()),
                    ..Default::default()
                });
            }
        }

        let subscription = with_retry(&self.config, "update_subscription", || {
            let client = client.clone();
            let sub_id = sub_id.clone();
            let params = params.clone();
            async move { stripe::Subscription::update(&client, &sub_id, params).await }
        })
        .await?;

        map_subscription_to_data(subscription)
    }
}

// ============================================================================
// Subscription Data Mapping
// ============================================================================

/// Map Stripe Subscription to internal StripeSubscriptionData.
///
/// Uses metadata to identify base plan vs seat items when available,
/// falling back to position-based detection for backwards compatibility.
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

    // Extract plan_id from subscription metadata
    let plan_id = sub
        .metadata
        .get(META_PLAN_ID)
        .cloned()
        .unwrap_or_default();

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

    let metadata = SubscriptionMetadata {
        billable_id: sub.metadata.get(META_BILLABLE_ID).cloned(),
        billable_type: sub.metadata.get(META_BILLABLE_TYPE).cloned(),
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

        let session = with_retry(&self.config, "create_portal_session", || {
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

        let session = with_retry(&self.config, "create_portal_session_with_flow", || {
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
}
