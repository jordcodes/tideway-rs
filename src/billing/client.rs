//! Consolidated Stripe client types.
//!
//! This module provides convenience types for working with all Stripe operations.
//! Individual traits remain separate for flexibility, but this module provides
//! unified types for when you need multiple capabilities.

use crate::error::Result;

use super::customer::{CreateCustomerRequest, StripeClient, UpdateCustomerRequest};
use super::checkout::{CheckoutSession, CreateCheckoutSessionRequest, StripeCheckoutClient};
use super::subscription::{StripeSubscriptionClient, StripeSubscriptionData, UpdateSubscriptionRequest};
use super::portal::{CreatePortalSessionRequest, PortalFlow, PortalSession, StripePortalClient};

/// A type that implements all Stripe client traits.
///
/// Use this trait bound when you need a client that can perform all Stripe operations.
/// Individual managers use specific traits to maintain flexibility, but this is useful
/// for creating unified implementations or for integration testing.
///
/// # Example
///
/// ```rust,ignore
/// fn create_billing_system<C: FullStripeClient>(client: C) {
///     // Can use client for any Stripe operation
/// }
/// ```
pub trait FullStripeClient: StripeClient + StripeCheckoutClient + StripeSubscriptionClient + StripePortalClient {}

/// Blanket implementation for any type that implements all traits.
impl<T> FullStripeClient for T
where
    T: StripeClient + StripeCheckoutClient + StripeSubscriptionClient + StripePortalClient,
{}

/// Mock Stripe client for testing that implements all client traits.
#[cfg(any(test, feature = "test-billing"))]
pub mod test {
    use super::*;
    use super::super::subscription::SubscriptionMetadata;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A comprehensive mock Stripe client that implements all client traits.
    ///
    /// Use this for integration tests where you need full billing functionality.
    /// For unit tests, prefer the individual mock clients for better isolation.
    #[derive(Default)]
    pub struct ComprehensiveMockStripeClient {
        customer_counter: AtomicU64,
        session_counter: AtomicU64,
        portal_counter: AtomicU64,
    }

    impl ComprehensiveMockStripeClient {
        /// Create a new comprehensive mock client.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl StripeClient for ComprehensiveMockStripeClient {
        async fn create_customer(&self, _request: CreateCustomerRequest) -> Result<String> {
            let id = format!("cus_mock_{}", self.customer_counter.fetch_add(1, Ordering::SeqCst));
            Ok(id)
        }

        async fn update_customer(&self, _customer_id: &str, _request: UpdateCustomerRequest) -> Result<()> {
            Ok(())
        }

        async fn delete_customer(&self, _customer_id: &str) -> Result<()> {
            Ok(())
        }

        async fn get_default_payment_method(&self, _customer_id: &str) -> Result<Option<String>> {
            Ok(Some("pm_mock_default".to_string()))
        }
    }

    impl StripeCheckoutClient for ComprehensiveMockStripeClient {
        async fn create_checkout_session(&self, _request: CreateCheckoutSessionRequest) -> Result<CheckoutSession> {
            let id = format!("cs_mock_{}", self.session_counter.fetch_add(1, Ordering::SeqCst));
            Ok(CheckoutSession {
                id: id.clone(),
                url: format!("https://checkout.stripe.com/c/pay/{}", id),
            })
        }
    }

    impl StripeSubscriptionClient for ComprehensiveMockStripeClient {
        async fn cancel_subscription(&self, _subscription_id: &str) -> Result<()> {
            Ok(())
        }

        async fn cancel_subscription_at_period_end(&self, _subscription_id: &str) -> Result<()> {
            Ok(())
        }

        async fn resume_subscription(&self, _subscription_id: &str) -> Result<()> {
            Ok(())
        }

        async fn get_subscription(&self, subscription_id: &str) -> Result<StripeSubscriptionData> {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            Ok(StripeSubscriptionData {
                id: subscription_id.to_string(),
                customer_id: "cus_mock_0".to_string(),
                plan_id: "starter".to_string(),
                status: "active".to_string(),
                current_period_start: now,
                current_period_end: now + 30 * 24 * 60 * 60,
                extra_seats: 0,
                trial_end: None,
                cancel_at_period_end: false,
                base_item_id: Some("si_base_mock".to_string()),
                seat_item_id: None,
                metadata: SubscriptionMetadata {
                    billable_id: None,
                    billable_type: None,
                },
            })
        }

        async fn update_subscription(
            &self,
            subscription_id: &str,
            _request: UpdateSubscriptionRequest,
        ) -> Result<StripeSubscriptionData> {
            // Return updated subscription data
            self.get_subscription(subscription_id).await
        }
    }

    impl StripePortalClient for ComprehensiveMockStripeClient {
        async fn create_portal_session(&self, _request: CreatePortalSessionRequest) -> Result<PortalSession> {
            let id = format!("bps_mock_{}", self.portal_counter.fetch_add(1, Ordering::SeqCst));
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
            let id = format!("bps_mock_{}", self.portal_counter.fetch_add(1, Ordering::SeqCst));
            Ok(PortalSession {
                id: id.clone(),
                url: format!("https://billing.stripe.com/p/session/{}", id),
            })
        }
    }

    // Implement Clone manually since AtomicU64 doesn't implement Clone
    impl Clone for ComprehensiveMockStripeClient {
        fn clone(&self) -> Self {
            // Create a fresh instance - counters won't be shared but that's fine for tests
            Self::new()
        }
    }

    // Re-export with shorter alias for convenience
    pub use ComprehensiveMockStripeClient as FullMockStripeClient;
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test::ComprehensiveMockStripeClient;
    use super::super::checkout::{CheckoutMetadata, CheckoutMode};

    #[tokio::test]
    async fn test_mock_client_implements_all_traits() {
        let client = ComprehensiveMockStripeClient::new();

        // Test StripeClient
        let customer_id = client.create_customer(CreateCustomerRequest {
            email: "test@example.com".to_string(),
            name: None,
            metadata: None,
        }).await.unwrap();
        assert!(customer_id.starts_with("cus_mock_"));

        // Test StripeCheckoutClient
        let session = client.create_checkout_session(CreateCheckoutSessionRequest {
            customer_id: customer_id.clone(),
            line_items: vec![],
            success_url: "https://example.com/success".to_string(),
            cancel_url: "https://example.com/cancel".to_string(),
            mode: CheckoutMode::Subscription,
            allow_promotion_codes: false,
            trial_period_days: None,
            metadata: CheckoutMetadata {
                billable_id: "org_test".to_string(),
                billable_type: "org".to_string(),
                plan_id: "starter".to_string(),
            },
            tax_id_collection: false,
            billing_address_collection: false,
        }).await.unwrap();
        assert!(session.id.starts_with("cs_mock_"));

        // Test StripeSubscriptionClient
        let sub = client.get_subscription("sub_123").await.unwrap();
        assert_eq!(sub.id, "sub_123");

        // Test StripePortalClient
        let portal = client.create_portal_session(CreatePortalSessionRequest {
            customer_id,
            return_url: "https://example.com/billing".to_string(),
            configuration_id: None,
        }).await.unwrap();
        assert!(portal.id.starts_with("bps_mock_"));
    }

    #[test]
    fn test_full_stripe_client_trait() {
        fn accepts_full_client<C: FullStripeClient>(_client: C) {}

        let client = ComprehensiveMockStripeClient::new();
        accepts_full_client(client);
    }
}
