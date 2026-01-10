//! Stripe Customer Portal session management.
//!
//! Handles creating Stripe Customer Portal sessions for subscription management.

use crate::error::Result;
use super::error::BillingError;
use super::storage::BillingStore;
use url::Url;

/// Customer Portal session management.
///
/// Creates Stripe Customer Portal sessions for subscription self-service.
pub struct PortalManager<S: BillingStore, C: StripePortalClient> {
    store: S,
    client: C,
    config: PortalConfig,
}

impl<S: BillingStore, C: StripePortalClient> PortalManager<S, C> {
    /// Create a new portal manager.
    #[must_use]
    pub fn new(store: S, client: C, config: PortalConfig) -> Self {
        Self { store, client, config }
    }

    /// Create a customer portal session.
    ///
    /// Returns a portal session with a URL to redirect the customer to.
    /// The portal allows customers to manage their subscription, payment methods,
    /// and billing information.
    pub async fn create_portal_session(
        &self,
        billable_id: &str,
        return_url: &str,
    ) -> Result<PortalSession> {
        // Validate return URL
        self.config.validate_return_url(return_url)?;

        // Get customer ID
        let customer_id = self.store.get_stripe_customer_id(billable_id).await?
            .ok_or_else(|| crate::error::TidewayError::NotFound(
                "No Stripe customer found".to_string()
            ))?;

        // Create portal session
        let session = self.client.create_portal_session(CreatePortalSessionRequest {
            customer_id,
            return_url: return_url.to_string(),
            configuration_id: self.config.configuration_id.clone(),
        }).await?;

        Ok(session)
    }

    /// Create a portal session with a specific flow.
    ///
    /// Flows allow you to direct the customer to a specific page in the portal.
    pub async fn create_portal_session_with_flow(
        &self,
        billable_id: &str,
        return_url: &str,
        flow: PortalFlow,
    ) -> Result<PortalSession> {
        // Validate return URL
        self.config.validate_return_url(return_url)?;

        let customer_id = self.store.get_stripe_customer_id(billable_id).await?
            .ok_or_else(|| crate::error::TidewayError::NotFound(
                "No Stripe customer found".to_string()
            ))?;

        let session = self.client.create_portal_session_with_flow(CreatePortalSessionRequest {
            customer_id,
            return_url: return_url.to_string(),
            configuration_id: self.config.configuration_id.clone(),
        }, flow).await?;

        Ok(session)
    }
}

/// Configuration for the customer portal.
#[derive(Debug, Clone, Default)]
pub struct PortalConfig {
    /// Stripe portal configuration ID (optional).
    /// If not set, uses the default configuration.
    pub configuration_id: Option<String>,
    /// Allowed domains for return URLs.
    /// If empty, any HTTPS URL is allowed.
    pub allowed_return_domains: Vec<String>,
    /// Allow HTTP for localhost URLs (development only).
    /// This should NEVER be enabled in production.
    pub allow_localhost_http: bool,
}

impl PortalConfig {
    /// Create a new portal config.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the Stripe portal configuration ID.
    #[must_use]
    pub fn configuration_id(mut self, id: impl Into<String>) -> Self {
        self.configuration_id = Some(id.into());
        self
    }

    /// Set allowed domains for return URLs.
    ///
    /// Subdomains are automatically allowed (e.g., "example.com" allows "app.example.com").
    /// If not set, any HTTPS URL is allowed.
    #[must_use]
    pub fn allowed_return_domains<I, S>(mut self, domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_return_domains = domains.into_iter().map(Into::into).collect();
        self
    }

    /// Allow HTTP for localhost URLs (development only).
    ///
    /// # Warning
    /// This should NEVER be enabled in production. It allows insecure HTTP
    /// connections for localhost, 127.0.0.1, and [::1] addresses only.
    #[must_use]
    pub fn allow_localhost_http(mut self, allow: bool) -> Self {
        self.allow_localhost_http = allow;
        self
    }

    /// Check if a host is a localhost address.
    fn is_localhost(host: &str) -> bool {
        matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
    }

    /// Validate a return URL.
    ///
    /// Checks that the URL is valid HTTPS and the domain is allowed.
    pub fn validate_return_url(&self, url: &str) -> Result<()> {
        let parsed = Url::parse(url).map_err(|e| {
            BillingError::InvalidRedirectUrl {
                url: url.to_string(),
                reason: format!("invalid URL: {}", e),
            }
        })?;

        // Check scheme - must be HTTPS, unless localhost HTTP is allowed
        let is_https = parsed.scheme() == "https";
        let is_localhost_http = self.allow_localhost_http
            && parsed.scheme() == "http"
            && parsed.host_str().map(Self::is_localhost).unwrap_or(false);

        if !is_https && !is_localhost_http {
            return Err(BillingError::InvalidRedirectUrl {
                url: url.to_string(),
                reason: "return URL must use HTTPS".to_string(),
            }.into());
        }

        // Check domain if allowed list is configured
        if !self.allowed_return_domains.is_empty() {
            let host = parsed.host_str().ok_or_else(|| {
                BillingError::InvalidRedirectUrl {
                    url: url.to_string(),
                    reason: "return URL must have a host".to_string(),
                }
            })?;

            let domain_allowed = self.allowed_return_domains.iter().any(|allowed| {
                // Exact match or subdomain match
                host == allowed || host.ends_with(&format!(".{}", allowed))
            });

            if !domain_allowed {
                return Err(BillingError::RedirectDomainNotAllowed {
                    domain: host.to_string(),
                }.into());
            }
        }

        Ok(())
    }
}

/// Portal session response.
#[derive(Debug, Clone)]
#[must_use]
pub struct PortalSession {
    /// Stripe portal session ID.
    pub id: String,
    /// URL to redirect the customer to.
    pub url: String,
}

/// Request to create a portal session.
#[derive(Debug, Clone)]
pub struct CreatePortalSessionRequest {
    /// Stripe customer ID.
    pub customer_id: String,
    /// URL to return to after portal.
    pub return_url: String,
    /// Portal configuration ID.
    pub configuration_id: Option<String>,
}

/// Portal flow types for directing customers to specific pages.
#[derive(Debug, Clone)]
pub enum PortalFlow {
    /// Update payment method.
    PaymentMethodUpdate,
    /// Update subscription (change plan).
    SubscriptionUpdate {
        /// The subscription ID to update.
        subscription_id: String,
    },
    /// Cancel subscription.
    SubscriptionCancel {
        /// The subscription ID to cancel.
        subscription_id: String,
    },
}

impl PortalFlow {
    /// Get the flow type string for Stripe API.
    #[must_use]
    pub fn flow_type(&self) -> &'static str {
        match self {
            Self::PaymentMethodUpdate => "payment_method_update",
            Self::SubscriptionUpdate { .. } => "subscription_update",
            Self::SubscriptionCancel { .. } => "subscription_cancel",
        }
    }
}

/// Trait for Stripe customer portal operations.
#[allow(async_fn_in_trait)]
pub trait StripePortalClient: Send + Sync {
    /// Create a customer portal session.
    async fn create_portal_session(&self, request: CreatePortalSessionRequest) -> Result<PortalSession>;

    /// Create a customer portal session with a specific flow.
    async fn create_portal_session_with_flow(
        &self,
        request: CreatePortalSessionRequest,
        flow: PortalFlow,
    ) -> Result<PortalSession>;
}

/// Mock Stripe portal client for testing.
#[cfg(any(test, feature = "test-billing"))]
pub mod test {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Mock portal client.
    #[derive(Default)]
    pub struct MockStripePortalClient {
        session_counter: AtomicU64,
    }

    impl MockStripePortalClient {
        /// Create a new mock client.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl StripePortalClient for MockStripePortalClient {
        async fn create_portal_session(&self, _request: CreatePortalSessionRequest) -> Result<PortalSession> {
            let id = format!("bps_test_{}", self.session_counter.fetch_add(1, Ordering::SeqCst));
            Ok(PortalSession {
                id: id.clone(),
                url: format!("https://billing.stripe.com/p/session/{}", id),
            })
        }

        async fn create_portal_session_with_flow(
            &self,
            _request: CreatePortalSessionRequest,
            _flow: PortalFlow,
        ) -> Result<PortalSession> {
            let id = format!("bps_test_{}", self.session_counter.fetch_add(1, Ordering::SeqCst));
            Ok(PortalSession {
                id: id.clone(),
                url: format!("https://billing.stripe.com/p/session/{}", id),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test::MockStripePortalClient;
    use crate::billing::storage::test::InMemoryBillingStore;

    #[tokio::test]
    async fn test_create_portal_session() {
        let store = InMemoryBillingStore::new();
        // Link a customer first
        store.set_stripe_customer_id("org_123", "org", "cus_123").await.unwrap();

        let client = MockStripePortalClient::new();
        let config = PortalConfig::new();

        let manager = PortalManager::new(store, client, config);

        let session = manager.create_portal_session(
            "org_123",
            "https://example.com/billing",
        ).await.unwrap();

        assert!(session.id.starts_with("bps_test_"));
        assert!(session.url.contains("billing.stripe.com"));
    }

    #[tokio::test]
    async fn test_create_portal_session_no_customer() {
        let store = InMemoryBillingStore::new();
        let client = MockStripePortalClient::new();
        let config = PortalConfig::new();

        let manager = PortalManager::new(store, client, config);

        let result = manager.create_portal_session(
            "nonexistent",
            "https://example.com/billing",
        ).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_portal_session_with_flow() {
        let store = InMemoryBillingStore::new();
        store.set_stripe_customer_id("org_456", "org", "cus_456").await.unwrap();

        let client = MockStripePortalClient::new();
        let config = PortalConfig::new();

        let manager = PortalManager::new(store, client, config);

        let session = manager.create_portal_session_with_flow(
            "org_456",
            "https://example.com/billing",
            PortalFlow::PaymentMethodUpdate,
        ).await.unwrap();

        assert!(session.id.starts_with("bps_test_"));
    }

    #[tokio::test]
    async fn test_portal_flow_types() {
        assert_eq!(PortalFlow::PaymentMethodUpdate.flow_type(), "payment_method_update");
        assert_eq!(PortalFlow::SubscriptionUpdate { subscription_id: "sub_123".to_string() }.flow_type(), "subscription_update");
        assert_eq!(PortalFlow::SubscriptionCancel { subscription_id: "sub_123".to_string() }.flow_type(), "subscription_cancel");
    }

    #[test]
    fn test_portal_url_validation_https_required() {
        let config = PortalConfig::new();

        // HTTPS should pass
        assert!(config.validate_return_url("https://example.com/billing").is_ok());

        // HTTP should fail
        let result = config.validate_return_url("http://example.com/billing");
        assert!(result.is_err());
    }

    #[test]
    fn test_portal_url_validation_invalid_url() {
        let config = PortalConfig::new();

        assert!(config.validate_return_url("not-a-url").is_err());
        assert!(config.validate_return_url("").is_err());
    }

    #[test]
    fn test_portal_url_validation_allowed_domains() {
        let config = PortalConfig::new()
            .allowed_return_domains(["example.com", "myapp.io"]);

        // Exact match should pass
        assert!(config.validate_return_url("https://example.com/billing").is_ok());
        assert!(config.validate_return_url("https://myapp.io/settings").is_ok());

        // Subdomain should pass
        assert!(config.validate_return_url("https://app.example.com/billing").is_ok());

        // Different domain should fail
        assert!(config.validate_return_url("https://evil.com/billing").is_err());
    }

    #[tokio::test]
    async fn test_portal_rejects_invalid_url() {
        let store = InMemoryBillingStore::new();
        store.set_stripe_customer_id("org_url", "org", "cus_url").await.unwrap();

        let client = MockStripePortalClient::new();
        let config = PortalConfig::new()
            .allowed_return_domains(["example.com"]);

        let manager = PortalManager::new(store, client, config);

        // Valid domain should succeed
        let result = manager.create_portal_session("org_url", "https://example.com/billing").await;
        assert!(result.is_ok());

        // Invalid domain should fail
        let result = manager.create_portal_session("org_url", "https://evil.com/billing").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_portal_url_validation_localhost_http() {
        // Without flag, HTTP localhost should fail
        let config = PortalConfig::new();
        assert!(config.validate_return_url("http://localhost:5173/billing").is_err());
        assert!(config.validate_return_url("http://127.0.0.1:3000/billing").is_err());

        // With flag enabled, HTTP localhost should pass
        let config = PortalConfig::new().allow_localhost_http(true);
        assert!(config.validate_return_url("http://localhost:5173/billing").is_ok());
        assert!(config.validate_return_url("http://127.0.0.1:3000/billing").is_ok());
        assert!(config.validate_return_url("http://[::1]:8080/billing").is_ok());

        // HTTP on non-localhost should still fail
        assert!(config.validate_return_url("http://example.com/billing").is_err());

        // HTTPS should always work
        assert!(config.validate_return_url("https://example.com/billing").is_ok());
    }
}
