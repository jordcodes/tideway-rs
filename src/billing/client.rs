//! Consolidated Stripe client types.
//!
//! This module provides convenience types for working with all Stripe operations.
//! Individual traits remain separate for flexibility, but this module provides
//! unified types for when you need multiple capabilities.

use super::checkout::StripeCheckoutClient;
use super::customer::StripeClient;
use super::invoice::StripeInvoiceClient;
use super::payment::StripePaymentMethodClient;
use super::portal::StripePortalClient;
use super::subscription::StripeSubscriptionClient;

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
pub trait FullStripeClient: StripeClient + StripeCheckoutClient + StripeSubscriptionClient + StripePortalClient + StripeInvoiceClient + StripePaymentMethodClient {}

/// Blanket implementation for any type that implements all traits.
impl<T> FullStripeClient for T
where
    T: StripeClient + StripeCheckoutClient + StripeSubscriptionClient + StripePortalClient + StripeInvoiceClient + StripePaymentMethodClient,
{}

/// Mock Stripe client for testing that implements all client traits.
#[cfg(any(test, feature = "test-billing"))]
pub mod test {
    use super::*;
    use super::super::checkout::{CheckoutSession, CreateCheckoutSessionRequest};
    use super::super::customer::{CreateCustomerRequest, UpdateCustomerRequest};
    use super::super::invoice::{Invoice, InvoiceLineItem, InvoiceList, InvoiceStatus};
    use super::super::payment::{PaymentMethod, PaymentMethodList};
    use super::super::portal::{CreatePortalSessionRequest, PortalFlow, PortalSession};
    use super::super::subscription::{StripeSubscriptionData, SubscriptionMetadata, UpdateSubscriptionRequest};
    use crate::error::Result;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::RwLock;
    use std::collections::HashMap;

    /// A comprehensive mock Stripe client that implements all client traits.
    ///
    /// Use this for integration tests where you need full billing functionality.
    /// For unit tests, prefer the individual mock clients for better isolation.
    pub struct ComprehensiveMockStripeClient {
        customer_counter: AtomicU64,
        session_counter: AtomicU64,
        portal_counter: AtomicU64,
        payment_methods: std::sync::Arc<RwLock<HashMap<String, Vec<PaymentMethod>>>>,
        default_payment_methods: std::sync::Arc<RwLock<HashMap<String, String>>>,
        /// Default currency for mock invoices and refunds (e.g., "gbp", "usd").
        pub default_currency: String,
    }

    impl Default for ComprehensiveMockStripeClient {
        fn default() -> Self {
            Self {
                customer_counter: AtomicU64::new(0),
                session_counter: AtomicU64::new(0),
                portal_counter: AtomicU64::new(0),
                payment_methods: std::sync::Arc::new(RwLock::new(HashMap::new())),
                default_payment_methods: std::sync::Arc::new(RwLock::new(HashMap::new())),
                default_currency: "gbp".to_string(),
            }
        }
    }

    impl ComprehensiveMockStripeClient {
        /// Create a new comprehensive mock client with GBP as the default currency.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Create a new comprehensive mock client with a specific default currency.
        #[must_use]
        pub fn with_currency(currency: impl Into<String>) -> Self {
            Self {
                default_currency: currency.into().to_lowercase(),
                ..Self::default()
            }
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

        async fn extend_trial(
            &self,
            subscription_id: &str,
            new_trial_end: u64,
        ) -> Result<StripeSubscriptionData> {
            let mut data = self.get_subscription(subscription_id).await?;
            data.trial_end = Some(new_trial_end);
            data.status = "trialing".to_string();
            Ok(data)
        }

        async fn pause_subscription(&self, _subscription_id: &str) -> Result<()> {
            Ok(())
        }

        async fn resume_paused_subscription(&self, subscription_id: &str) -> Result<StripeSubscriptionData> {
            let mut data = self.get_subscription(subscription_id).await?;
            data.status = "active".to_string();
            Ok(data)
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

    #[async_trait::async_trait]
    impl StripeInvoiceClient for ComprehensiveMockStripeClient {
        async fn list_invoices(
            &self,
            _customer_id: &str,
            _limit: u8,
            _starting_after: Option<&str>,
            _status: Option<InvoiceStatus>,
        ) -> Result<InvoiceList> {
            Ok(InvoiceList {
                invoices: vec![],
                has_more: false,
                next_cursor: None,
            })
        }

        async fn get_invoice(&self, invoice_id: &str) -> Result<Invoice> {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            Ok(Invoice {
                id: invoice_id.to_string(),
                customer_id: "cus_mock_0".to_string(),
                subscription_id: Some("sub_mock".to_string()),
                status: InvoiceStatus::Paid,
                amount_due: 2999,
                amount_paid: 2999,
                amount_remaining: 0,
                currency: self.default_currency.clone(),
                created: now,
                due_date: Some(now + 30 * 24 * 60 * 60),
                period_start: now,
                period_end: now + 30 * 24 * 60 * 60,
                invoice_pdf: Some(format!("https://pay.stripe.com/invoice/{}/pdf", invoice_id)),
                hosted_invoice_url: Some(format!("https://invoice.stripe.com/{}", invoice_id)),
                number: Some(format!("INV-{}", invoice_id)),
                paid: true,
                line_items: None,
            })
        }

        async fn get_upcoming_invoice(&self, _customer_id: &str) -> Result<Option<Invoice>> {
            Ok(None)
        }

        async fn list_invoice_line_items(
            &self,
            invoice_id: &str,
            _limit: u8,
        ) -> Result<Vec<InvoiceLineItem>> {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            Ok(vec![
                InvoiceLineItem {
                    id: format!("il_{}_1", invoice_id),
                    description: Some("Pro Plan".to_string()),
                    amount: 2999,
                    currency: self.default_currency.clone(),
                    quantity: Some(1),
                    price_id: Some("price_pro".to_string()),
                    period_start: now,
                    period_end: now + 30 * 24 * 60 * 60,
                },
            ])
        }
    }

    impl StripePaymentMethodClient for ComprehensiveMockStripeClient {
        async fn list_payment_methods(
            &self,
            customer_id: &str,
            _limit: u8,
        ) -> Result<PaymentMethodList> {
            let methods = self.payment_methods.read().unwrap();
            let defaults = self.default_payment_methods.read().unwrap();
            let default_id = defaults.get(customer_id);

            let customer_methods = methods.get(customer_id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|mut m| {
                    m.is_default = default_id.map(|d| d == &m.id).unwrap_or(false);
                    m
                })
                .collect();

            Ok(PaymentMethodList {
                methods: customer_methods,
                has_more: false,
            })
        }

        async fn attach_payment_method(
            &self,
            payment_method_id: &str,
            customer_id: &str,
        ) -> Result<PaymentMethod> {
            let method = PaymentMethod {
                id: payment_method_id.to_string(),
                card_brand: Some("visa".to_string()),
                card_last4: Some("4242".to_string()),
                card_exp_month: Some(12),
                card_exp_year: Some(2099),
                is_default: false,
            };

            let mut methods = self.payment_methods.write().unwrap();
            methods.entry(customer_id.to_string())
                .or_default()
                .push(method.clone());

            Ok(method)
        }

        async fn detach_payment_method(
            &self,
            payment_method_id: &str,
        ) -> Result<()> {
            let mut methods = self.payment_methods.write().unwrap();
            for customer_methods in methods.values_mut() {
                customer_methods.retain(|m| m.id != payment_method_id);
            }
            Ok(())
        }

        async fn set_default_payment_method(
            &self,
            customer_id: &str,
            payment_method_id: &str,
        ) -> Result<()> {
            let mut defaults = self.default_payment_methods.write().unwrap();
            defaults.insert(customer_id.to_string(), payment_method_id.to_string());
            Ok(())
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
    use super::super::checkout::{CheckoutMetadata, CheckoutMode, CreateCheckoutSessionRequest};
    use super::super::customer::CreateCustomerRequest;
    use super::super::portal::CreatePortalSessionRequest;

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
            coupon: None,
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
