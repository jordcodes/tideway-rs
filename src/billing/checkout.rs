//! Stripe Checkout session management.
//!
//! Handles creating Stripe Checkout sessions for new subscriptions
//! and plan changes.

use crate::error::Result;
use super::customer::{CustomerManager, StripeClient};
use super::plans::Plans;
use super::storage::{BillableEntity, BillingStore};
use url::Url;

/// Checkout session management.
///
/// Creates Stripe Checkout sessions for subscription purchases.
pub struct CheckoutManager<S: BillingStore, C: StripeClient + StripeCheckoutClient> {
    customer_manager: CustomerManager<S, C>,
    client: C,
    plans: Plans,
    config: CheckoutConfig,
}

impl<S: BillingStore + Clone, C: StripeClient + StripeCheckoutClient + Clone> CheckoutManager<S, C> {
    /// Create a new checkout manager.
    #[must_use]
    pub fn new(store: S, client: C, plans: Plans, config: CheckoutConfig) -> Self {
        Self {
            customer_manager: CustomerManager::new(store, client.clone()),
            client,
            plans,
            config,
        }
    }

    /// Create a checkout session for a new subscription.
    ///
    /// Returns a checkout session with a URL to redirect the customer to.
    pub async fn create_checkout_session(
        &self,
        entity: &impl BillableEntity,
        request: CheckoutRequest,
    ) -> Result<CheckoutSession> {
        // Validate redirect URLs
        self.config.validate_redirect_url(&request.success_url)?;
        self.config.validate_redirect_url(&request.cancel_url)?;

        // Validate plan exists
        let plan = self.plans.get(&request.plan_id)
            .ok_or_else(|| crate::error::TidewayError::BadRequest(
                format!("Unknown plan: {}", request.plan_id)
            ))?;

        // Get or create customer
        let customer_id = self.customer_manager.get_or_create_customer(entity).await?;

        // Build line items
        let mut line_items = vec![
            CheckoutLineItem {
                price_id: plan.stripe_price_id.clone(),
                quantity: 1,
            }
        ];

        // Add extra seats if requested
        if let Some(extra_seats) = request.extra_seats {
            if extra_seats > 0 {
                let seat_price = plan.extra_seat_price_id.as_ref()
                    .ok_or_else(|| crate::error::TidewayError::BadRequest(
                        "Plan does not support extra seats".to_string()
                    ))?;
                line_items.push(CheckoutLineItem {
                    price_id: seat_price.clone(),
                    quantity: extra_seats,
                });
            }
        }

        // Determine trial days
        let trial_days = request.trial_days.or(plan.trial_days);

        // Create the Stripe checkout session
        let session = self.client.create_checkout_session(CreateCheckoutSessionRequest {
            customer_id,
            line_items,
            success_url: request.success_url,
            cancel_url: request.cancel_url,
            mode: CheckoutMode::Subscription,
            allow_promotion_codes: request.allow_promotion_codes.unwrap_or(self.config.allow_promotion_codes),
            trial_period_days: trial_days,
            metadata: CheckoutMetadata {
                billable_id: entity.billable_id().to_string(),
                billable_type: entity.billable_type().to_string(),
                plan_id: request.plan_id,
            },
            tax_id_collection: self.config.collect_tax_id,
            billing_address_collection: self.config.collect_billing_address,
        }).await?;

        Ok(session)
    }

    /// Create a checkout session for adding seats to an existing subscription.
    pub async fn create_seat_checkout_session(
        &self,
        entity: &impl BillableEntity,
        request: SeatCheckoutRequest,
    ) -> Result<CheckoutSession> {
        // Validate redirect URLs
        self.config.validate_redirect_url(&request.success_url)?;
        self.config.validate_redirect_url(&request.cancel_url)?;

        // Get existing subscription to validate plan
        let sub = self.customer_manager
            .get_customer_id(entity.billable_id())
            .await?
            .ok_or_else(|| crate::error::TidewayError::NotFound(
                "No customer found".to_string()
            ))?;

        let plan = self.plans.get(&request.plan_id)
            .ok_or_else(|| crate::error::TidewayError::BadRequest(
                format!("Unknown plan: {}", request.plan_id)
            ))?;

        let seat_price = plan.extra_seat_price_id.as_ref()
            .ok_or_else(|| crate::error::TidewayError::BadRequest(
                "Plan does not support extra seats".to_string()
            ))?;

        let session = self.client.create_checkout_session(CreateCheckoutSessionRequest {
            customer_id: sub,
            line_items: vec![
                CheckoutLineItem {
                    price_id: seat_price.clone(),
                    quantity: request.seats,
                }
            ],
            success_url: request.success_url,
            cancel_url: request.cancel_url,
            mode: CheckoutMode::Subscription,
            allow_promotion_codes: false,
            trial_period_days: None,
            metadata: CheckoutMetadata {
                billable_id: entity.billable_id().to_string(),
                billable_type: entity.billable_type().to_string(),
                plan_id: request.plan_id,
            },
            tax_id_collection: false,
            billing_address_collection: false,
        }).await?;

        Ok(session)
    }
}

/// Configuration for checkout sessions.
#[derive(Debug, Clone)]
pub struct CheckoutConfig {
    /// Allow promotion codes by default.
    pub allow_promotion_codes: bool,
    /// Collect tax ID from customers.
    pub collect_tax_id: bool,
    /// Collect billing address from customers.
    pub collect_billing_address: bool,
    /// Allowed domains for redirect URLs (empty = allow any HTTPS URL).
    /// This prevents open redirect vulnerabilities.
    pub allowed_redirect_domains: Vec<String>,
}

impl Default for CheckoutConfig {
    fn default() -> Self {
        Self {
            allow_promotion_codes: true,
            collect_tax_id: false,
            collect_billing_address: false,
            allowed_redirect_domains: Vec::new(),
        }
    }
}

impl CheckoutConfig {
    /// Create a new config with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable/disable promotion codes.
    #[must_use]
    pub fn allow_promotion_codes(mut self, allow: bool) -> Self {
        self.allow_promotion_codes = allow;
        self
    }

    /// Enable tax ID collection.
    #[must_use]
    pub fn collect_tax_id(mut self, collect: bool) -> Self {
        self.collect_tax_id = collect;
        self
    }

    /// Enable billing address collection.
    #[must_use]
    pub fn collect_billing_address(mut self, collect: bool) -> Self {
        self.collect_billing_address = collect;
        self
    }

    /// Set allowed redirect domains.
    ///
    /// Only URLs matching these domains will be accepted for success/cancel URLs.
    /// If empty, any HTTPS URL is allowed (not recommended for production).
    ///
    /// # Example
    /// ```ignore
    /// let config = CheckoutConfig::new()
    ///     .allowed_redirect_domains(["example.com", "app.example.com"]);
    /// ```
    #[must_use]
    pub fn allowed_redirect_domains<I, S>(mut self, domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_redirect_domains = domains.into_iter().map(Into::into).collect();
        self
    }

    /// Add a single allowed redirect domain.
    #[must_use]
    pub fn add_allowed_domain(mut self, domain: impl Into<String>) -> Self {
        self.allowed_redirect_domains.push(domain.into());
        self
    }

    /// Validate a redirect URL against the allowed domains.
    ///
    /// Returns an error if:
    /// - The URL is not valid
    /// - The URL is not HTTPS
    /// - The URL's domain is not in the allowed list (if list is non-empty)
    pub fn validate_redirect_url(&self, url: &str) -> Result<()> {
        let parsed = Url::parse(url).map_err(|e| {
            crate::error::TidewayError::BadRequest(format!("Invalid redirect URL: {}", e))
        })?;

        // Must be HTTPS
        if parsed.scheme() != "https" {
            return Err(crate::error::TidewayError::BadRequest(
                "Redirect URL must use HTTPS".to_string()
            ));
        }

        // Check domain if allowed list is configured
        if !self.allowed_redirect_domains.is_empty() {
            let host = parsed.host_str().ok_or_else(|| {
                crate::error::TidewayError::BadRequest("Redirect URL must have a host".to_string())
            })?;

            let domain_allowed = self.allowed_redirect_domains.iter().any(|allowed| {
                // Exact match or subdomain match
                host == allowed || host.ends_with(&format!(".{}", allowed))
            });

            if !domain_allowed {
                return Err(crate::error::TidewayError::BadRequest(
                    format!("Redirect URL domain '{}' is not allowed", host)
                ));
            }
        }

        Ok(())
    }
}

/// Request to create a checkout session.
#[derive(Debug, Clone)]
pub struct CheckoutRequest {
    /// The plan to subscribe to.
    pub plan_id: String,
    /// URL to redirect to on success.
    pub success_url: String,
    /// URL to redirect to on cancel.
    pub cancel_url: String,
    /// Number of extra seats to purchase.
    pub extra_seats: Option<u32>,
    /// Override trial days (uses plan default if not set).
    pub trial_days: Option<u32>,
    /// Allow promotion codes.
    pub allow_promotion_codes: Option<bool>,
}

impl CheckoutRequest {
    /// Create a new checkout request.
    #[must_use]
    pub fn new(plan_id: impl Into<String>, success_url: impl Into<String>, cancel_url: impl Into<String>) -> Self {
        Self {
            plan_id: plan_id.into(),
            success_url: success_url.into(),
            cancel_url: cancel_url.into(),
            extra_seats: None,
            trial_days: None,
            allow_promotion_codes: None,
        }
    }

    /// Add extra seats to the checkout.
    #[must_use]
    pub fn with_extra_seats(mut self, seats: u32) -> Self {
        self.extra_seats = Some(seats);
        self
    }

    /// Set custom trial days.
    #[must_use]
    pub fn with_trial_days(mut self, days: u32) -> Self {
        self.trial_days = Some(days);
        self
    }

    /// Allow or disallow promotion codes.
    #[must_use]
    pub fn with_promotion_codes(mut self, allow: bool) -> Self {
        self.allow_promotion_codes = Some(allow);
        self
    }
}

/// Request to create a seat checkout session.
#[derive(Debug, Clone)]
pub struct SeatCheckoutRequest {
    /// The plan the subscription is on.
    pub plan_id: String,
    /// Number of seats to add.
    pub seats: u32,
    /// URL to redirect to on success.
    pub success_url: String,
    /// URL to redirect to on cancel.
    pub cancel_url: String,
}

/// Checkout session response.
#[derive(Debug, Clone)]
pub struct CheckoutSession {
    /// Stripe checkout session ID.
    pub id: String,
    /// URL to redirect the customer to.
    pub url: String,
}

/// Line item for checkout.
#[derive(Debug, Clone)]
pub struct CheckoutLineItem {
    /// Stripe price ID.
    pub price_id: String,
    /// Quantity.
    pub quantity: u32,
}

/// Checkout mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckoutMode {
    /// One-time payment.
    Payment,
    /// Subscription.
    Subscription,
    /// Setup (collect payment method).
    Setup,
}

impl CheckoutMode {
    /// Convert to Stripe API string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Payment => "payment",
            Self::Subscription => "subscription",
            Self::Setup => "setup",
        }
    }
}

/// Metadata for checkout sessions.
#[derive(Debug, Clone)]
pub struct CheckoutMetadata {
    /// The billable entity ID.
    pub billable_id: String,
    /// The billable entity type.
    pub billable_type: String,
    /// The plan being purchased.
    pub plan_id: String,
}

/// Request to create a Stripe checkout session.
#[derive(Debug, Clone)]
pub struct CreateCheckoutSessionRequest {
    /// Stripe customer ID.
    pub customer_id: String,
    /// Line items.
    pub line_items: Vec<CheckoutLineItem>,
    /// Success URL.
    pub success_url: String,
    /// Cancel URL.
    pub cancel_url: String,
    /// Checkout mode.
    pub mode: CheckoutMode,
    /// Allow promotion codes.
    pub allow_promotion_codes: bool,
    /// Trial period in days.
    pub trial_period_days: Option<u32>,
    /// Session metadata.
    pub metadata: CheckoutMetadata,
    /// Collect tax ID.
    pub tax_id_collection: bool,
    /// Collect billing address.
    pub billing_address_collection: bool,
}

/// Trait for Stripe checkout operations.
#[allow(async_fn_in_trait)]
pub trait StripeCheckoutClient: Send + Sync {
    /// Create a Stripe checkout session.
    async fn create_checkout_session(&self, request: CreateCheckoutSessionRequest) -> Result<CheckoutSession>;
}

/// Mock Stripe checkout client for testing.
#[cfg(any(test, feature = "test-billing"))]
pub mod test {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Mock checkout client.
    #[derive(Default)]
    pub struct MockStripeCheckoutClient {
        session_counter: AtomicU64,
    }

    impl MockStripeCheckoutClient {
        /// Create a new mock client.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl StripeCheckoutClient for MockStripeCheckoutClient {
        async fn create_checkout_session(&self, _request: CreateCheckoutSessionRequest) -> Result<CheckoutSession> {
            let id = format!("cs_test_{}", self.session_counter.fetch_add(1, Ordering::SeqCst));
            Ok(CheckoutSession {
                id: id.clone(),
                url: format!("https://checkout.stripe.com/c/pay/{}", id),
            })
        }
    }

    /// Combined mock client for testing that implements all Stripe traits.
    #[derive(Default)]
    pub struct MockFullStripeClient {
        pub customer: super::super::customer::test::MockStripeClient,
        pub checkout: MockStripeCheckoutClient,
    }

    impl MockFullStripeClient {
        /// Create a new combined mock client.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl super::super::customer::StripeClient for MockFullStripeClient {
        async fn create_customer(&self, request: super::super::customer::CreateCustomerRequest) -> Result<String> {
            self.customer.create_customer(request).await
        }

        async fn update_customer(&self, customer_id: &str, request: super::super::customer::UpdateCustomerRequest) -> Result<()> {
            self.customer.update_customer(customer_id, request).await
        }

        async fn delete_customer(&self, customer_id: &str) -> Result<()> {
            self.customer.delete_customer(customer_id).await
        }

        async fn get_default_payment_method(&self, customer_id: &str) -> Result<Option<String>> {
            self.customer.get_default_payment_method(customer_id).await
        }
    }

    impl StripeCheckoutClient for MockFullStripeClient {
        async fn create_checkout_session(&self, request: CreateCheckoutSessionRequest) -> Result<CheckoutSession> {
            self.checkout.create_checkout_session(request).await
        }
    }

    impl Clone for MockFullStripeClient {
        fn clone(&self) -> Self {
            // For testing purposes, create a new instance
            // The counters won't be shared but that's fine for tests
            Self::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test::MockFullStripeClient;
    use crate::billing::storage::test::InMemoryBillingStore;
    use crate::billing::storage::BillableEntity;

    struct TestEntity {
        id: String,
        email: String,
    }

    impl BillableEntity for TestEntity {
        fn billable_id(&self) -> &str {
            &self.id
        }

        fn billable_type(&self) -> &str {
            "org"
        }

        fn email(&self) -> &str {
            &self.email
        }

        fn name(&self) -> Option<&str> {
            None
        }
    }

    fn create_test_plans() -> Plans {
        Plans::builder()
            .plan("starter")
                .stripe_price("price_starter")
                .extra_seat_price("price_seat")
                .included_seats(3)
                .trial_days(14)
                .done()
            .plan("pro")
                .stripe_price("price_pro")
                .included_seats(5)
                .done()
            .build()
    }

    #[tokio::test]
    async fn test_create_checkout_session() {
        let store = InMemoryBillingStore::new();
        let client = MockFullStripeClient::new();
        let plans = create_test_plans();
        let config = CheckoutConfig::default();

        let manager = CheckoutManager::new(store, client, plans, config);

        let entity = TestEntity {
            id: "org_123".to_string(),
            email: "test@example.com".to_string(),
        };

        let request = CheckoutRequest::new(
            "starter",
            "https://example.com/success",
            "https://example.com/cancel",
        );

        let session = manager.create_checkout_session(&entity, request).await.unwrap();
        assert!(session.id.starts_with("cs_test_"));
        assert!(session.url.contains("checkout.stripe.com"));
    }

    #[tokio::test]
    async fn test_create_checkout_session_with_extra_seats() {
        let store = InMemoryBillingStore::new();
        let client = MockFullStripeClient::new();
        let plans = create_test_plans();
        let config = CheckoutConfig::default();

        let manager = CheckoutManager::new(store, client, plans, config);

        let entity = TestEntity {
            id: "org_456".to_string(),
            email: "test@example.com".to_string(),
        };

        let request = CheckoutRequest::new(
            "starter",
            "https://example.com/success",
            "https://example.com/cancel",
        ).with_extra_seats(5);

        let session = manager.create_checkout_session(&entity, request).await.unwrap();
        assert!(session.id.starts_with("cs_test_"));
    }

    #[tokio::test]
    async fn test_create_checkout_session_invalid_plan() {
        let store = InMemoryBillingStore::new();
        let client = MockFullStripeClient::new();
        let plans = create_test_plans();
        let config = CheckoutConfig::default();

        let manager = CheckoutManager::new(store, client, plans, config);

        let entity = TestEntity {
            id: "org_789".to_string(),
            email: "test@example.com".to_string(),
        };

        let request = CheckoutRequest::new(
            "nonexistent",
            "https://example.com/success",
            "https://example.com/cancel",
        );

        let result = manager.create_checkout_session(&entity, request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_checkout_session_no_seat_support() {
        let store = InMemoryBillingStore::new();
        let client = MockFullStripeClient::new();
        let plans = create_test_plans();
        let config = CheckoutConfig::default();

        let manager = CheckoutManager::new(store, client, plans, config);

        let entity = TestEntity {
            id: "org_abc".to_string(),
            email: "test@example.com".to_string(),
        };

        // Pro plan doesn't have extra seat price configured
        let request = CheckoutRequest::new(
            "pro",
            "https://example.com/success",
            "https://example.com/cancel",
        ).with_extra_seats(5);

        let result = manager.create_checkout_session(&entity, request).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_url_validation_https_required() {
        let config = CheckoutConfig::new();

        // HTTPS should pass
        assert!(config.validate_redirect_url("https://example.com/success").is_ok());

        // HTTP should fail
        let result = config.validate_redirect_url("http://example.com/success");
        assert!(result.is_err());
    }

    #[test]
    fn test_url_validation_invalid_url() {
        let config = CheckoutConfig::new();

        let result = config.validate_redirect_url("not-a-url");
        assert!(result.is_err());

        let result = config.validate_redirect_url("");
        assert!(result.is_err());
    }

    #[test]
    fn test_url_validation_allowed_domains() {
        let config = CheckoutConfig::new()
            .allowed_redirect_domains(["example.com", "app.mysite.com"]);

        // Exact match should pass
        assert!(config.validate_redirect_url("https://example.com/success").is_ok());
        assert!(config.validate_redirect_url("https://app.mysite.com/cancel").is_ok());

        // Subdomain of allowed domain should pass
        assert!(config.validate_redirect_url("https://app.example.com/success").is_ok());
        assert!(config.validate_redirect_url("https://staging.app.mysite.com/success").is_ok());

        // Different domain should fail
        let result = config.validate_redirect_url("https://evil.com/redirect");
        assert!(result.is_err());

        // Similar but not matching domain should fail
        let result = config.validate_redirect_url("https://notexample.com/success");
        assert!(result.is_err());
    }

    #[test]
    fn test_url_validation_empty_allowed_list() {
        let config = CheckoutConfig::new();

        // Any HTTPS URL should pass when no allowed list is configured
        assert!(config.validate_redirect_url("https://example.com/success").is_ok());
        assert!(config.validate_redirect_url("https://any-domain.com/path").is_ok());
    }

    #[tokio::test]
    async fn test_checkout_rejects_invalid_url() {
        let store = InMemoryBillingStore::new();
        let client = MockFullStripeClient::new();
        let plans = create_test_plans();
        let config = CheckoutConfig::new()
            .allowed_redirect_domains(["example.com"]);

        let manager = CheckoutManager::new(store, client, plans, config);

        let entity = TestEntity {
            id: "org_url_test".to_string(),
            email: "test@example.com".to_string(),
        };

        // Valid domain should succeed
        let request = CheckoutRequest::new(
            "starter",
            "https://example.com/success",
            "https://example.com/cancel",
        );
        assert!(manager.create_checkout_session(&entity, request).await.is_ok());

        // Invalid domain should fail
        let request = CheckoutRequest::new(
            "starter",
            "https://evil.com/success",
            "https://example.com/cancel",
        );
        assert!(manager.create_checkout_session(&entity, request).await.is_err());
    }
}
