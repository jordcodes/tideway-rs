//! Stripe Customer Portal session management.
//!
//! Handles creating Stripe Customer Portal sessions for subscription management.

use crate::error::Result;
use super::storage::BillingStore;

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
}
