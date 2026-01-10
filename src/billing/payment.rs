//! Payment method management for Stripe billing.
//!
//! Handles listing, attaching, detaching, and setting default payment methods
//! for customers.

use crate::error::Result;
use super::storage::BillingStore;

/// A payment method attached to a customer.
#[derive(Debug, Clone)]
pub struct PaymentMethod {
    /// Stripe payment method ID.
    pub id: String,
    /// Card brand (visa, mastercard, amex, etc.).
    pub card_brand: Option<String>,
    /// Last 4 digits of the card.
    pub card_last4: Option<String>,
    /// Card expiration month (1-12).
    pub card_exp_month: Option<u32>,
    /// Card expiration year (e.g., 2025).
    pub card_exp_year: Option<u32>,
    /// Whether this is the default payment method.
    pub is_default: bool,
}

/// List of payment methods with pagination.
#[derive(Debug, Clone)]
pub struct PaymentMethodList {
    /// The payment methods.
    pub methods: Vec<PaymentMethod>,
    /// Whether there are more payment methods available.
    pub has_more: bool,
}

/// Trait for Stripe payment method operations.
#[allow(async_fn_in_trait)]
pub trait StripePaymentMethodClient: Send + Sync {
    /// List payment methods for a customer.
    async fn list_payment_methods(
        &self,
        customer_id: &str,
        limit: u8,
    ) -> Result<PaymentMethodList>;

    /// Attach a payment method to a customer.
    async fn attach_payment_method(
        &self,
        payment_method_id: &str,
        customer_id: &str,
    ) -> Result<PaymentMethod>;

    /// Detach a payment method from a customer.
    async fn detach_payment_method(
        &self,
        payment_method_id: &str,
    ) -> Result<()>;

    /// Set the default payment method for a customer.
    async fn set_default_payment_method(
        &self,
        customer_id: &str,
        payment_method_id: &str,
    ) -> Result<()>;
}

/// Default limit for listing payment methods.
const DEFAULT_PAYMENT_METHOD_LIMIT: u8 = 100;

/// Payment method management operations.
///
/// Handles listing, setting default, and removing payment methods.
pub struct PaymentMethodManager<S: BillingStore, C: StripePaymentMethodClient> {
    store: S,
    client: C,
    /// Maximum number of payment methods to return in list operations.
    list_limit: u8,
}

impl<S: BillingStore, C: StripePaymentMethodClient> PaymentMethodManager<S, C> {
    /// Create a new payment method manager with default settings.
    #[must_use]
    pub fn new(store: S, client: C) -> Self {
        Self {
            store,
            client,
            list_limit: DEFAULT_PAYMENT_METHOD_LIMIT,
        }
    }

    /// Create a new payment method manager with a custom list limit.
    ///
    /// # Arguments
    ///
    /// * `store` - The billing store
    /// * `client` - The Stripe payment method client
    /// * `list_limit` - Maximum number of payment methods to return (1-100)
    #[must_use]
    pub fn with_limit(store: S, client: C, list_limit: u8) -> Self {
        Self {
            store,
            client,
            list_limit: list_limit.clamp(1, 100),
        }
    }

    /// List payment methods for a billable entity.
    ///
    /// Returns payment methods attached to the customer, up to the configured limit.
    pub async fn list_payment_methods(
        &self,
        billable_id: &str,
    ) -> Result<PaymentMethodList> {
        let sub = self.store.get_subscription(billable_id).await?
            .ok_or_else(|| super::error::BillingError::NoSubscription {
                billable_id: billable_id.to_string(),
            })?;

        self.client.list_payment_methods(&sub.stripe_customer_id, self.list_limit).await
    }

    /// List payment methods with a specific limit.
    ///
    /// Use this for pagination or when you need a different limit than the default.
    pub async fn list_payment_methods_with_limit(
        &self,
        billable_id: &str,
        limit: u8,
    ) -> Result<PaymentMethodList> {
        let sub = self.store.get_subscription(billable_id).await?
            .ok_or_else(|| super::error::BillingError::NoSubscription {
                billable_id: billable_id.to_string(),
            })?;

        self.client.list_payment_methods(&sub.stripe_customer_id, limit.clamp(1, 100)).await
    }

    /// Set the default payment method for a billable entity.
    ///
    /// The payment method must already be attached to the customer.
    ///
    /// # Security
    ///
    /// This method verifies that the payment method belongs to the customer
    /// before setting it as default, preventing unauthorized modifications.
    pub async fn set_default(
        &self,
        billable_id: &str,
        payment_method_id: &str,
    ) -> Result<()> {
        let sub = self.store.get_subscription(billable_id).await?
            .ok_or_else(|| super::error::BillingError::NoSubscription {
                billable_id: billable_id.to_string(),
            })?;

        // Verify the payment method belongs to this customer
        let methods = self.client.list_payment_methods(&sub.stripe_customer_id, self.list_limit).await?;
        if !methods.methods.iter().any(|m| m.id == payment_method_id) {
            return Err(super::error::BillingError::PaymentMethodNotFound {
                payment_method_id: payment_method_id.to_string(),
            }.into());
        }

        self.client.set_default_payment_method(&sub.stripe_customer_id, payment_method_id).await
    }

    /// Remove a payment method from a billable entity.
    ///
    /// Detaches the payment method from the customer.
    ///
    /// # Security
    ///
    /// This method verifies that the payment method belongs to the customer
    /// before detaching, preventing unauthorized removal of other customers'
    /// payment methods.
    pub async fn remove(
        &self,
        billable_id: &str,
        payment_method_id: &str,
    ) -> Result<()> {
        let sub = self.store.get_subscription(billable_id).await?
            .ok_or_else(|| super::error::BillingError::NoSubscription {
                billable_id: billable_id.to_string(),
            })?;

        // Verify the payment method belongs to this customer before detaching
        let methods = self.client.list_payment_methods(&sub.stripe_customer_id, self.list_limit).await?;
        if !methods.methods.iter().any(|m| m.id == payment_method_id) {
            return Err(super::error::BillingError::PaymentMethodNotFound {
                payment_method_id: payment_method_id.to_string(),
            }.into());
        }

        self.client.detach_payment_method(payment_method_id).await
    }

    /// Attach a new payment method to a billable entity.
    ///
    /// The payment method ID should be obtained from Stripe.js or Elements.
    pub async fn attach(
        &self,
        billable_id: &str,
        payment_method_id: &str,
    ) -> Result<PaymentMethod> {
        let sub = self.store.get_subscription(billable_id).await?
            .ok_or_else(|| super::error::BillingError::NoSubscription {
                billable_id: billable_id.to_string(),
            })?;

        self.client.attach_payment_method(payment_method_id, &sub.stripe_customer_id).await
    }

    /// Get the default payment method for a billable entity.
    ///
    /// Returns the payment method marked as default, if any.
    pub async fn get_default(
        &self,
        billable_id: &str,
    ) -> Result<Option<PaymentMethod>> {
        let methods = self.list_payment_methods(billable_id).await?;
        Ok(methods.methods.into_iter().find(|m| m.is_default))
    }
}

/// Mock Stripe payment method client for testing.
#[cfg(any(test, feature = "test-billing"))]
pub mod test {
    use super::*;
    use std::sync::RwLock;
    use std::collections::HashMap;

    /// Mock Stripe payment method client.
    #[derive(Default)]
    pub struct MockStripePaymentMethodClient {
        payment_methods: std::sync::Arc<RwLock<HashMap<String, Vec<PaymentMethod>>>>,
        default_methods: std::sync::Arc<RwLock<HashMap<String, String>>>,
    }

    impl MockStripePaymentMethodClient {
        /// Create a new mock client.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Add a payment method for testing.
        pub fn add_payment_method(&self, customer_id: &str, method: PaymentMethod) {
            let mut methods = self.payment_methods.write().unwrap();
            methods.entry(customer_id.to_string())
                .or_default()
                .push(method);
        }
    }

    impl StripePaymentMethodClient for MockStripePaymentMethodClient {
        async fn list_payment_methods(
            &self,
            customer_id: &str,
            _limit: u8,
        ) -> Result<PaymentMethodList> {
            let methods = self.payment_methods.read().unwrap();
            let defaults = self.default_methods.read().unwrap();
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
            let mut defaults = self.default_methods.write().unwrap();
            defaults.insert(customer_id.to_string(), payment_method_id.to_string());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test::MockStripePaymentMethodClient;
    use crate::billing::storage::test::InMemoryBillingStore;
    use crate::billing::storage::{StoredSubscription, SubscriptionStatus};

    fn create_test_subscription(_billable_id: &str) -> StoredSubscription {
        StoredSubscription {
            stripe_subscription_id: "sub_123".to_string(),
            stripe_customer_id: "cus_123".to_string(),
            plan_id: "starter".to_string(),
            status: SubscriptionStatus::Active,
            current_period_start: 1700000000,
            current_period_end: 1702592000,
            extra_seats: 0,
            trial_end: None,
            cancel_at_period_end: false,
            base_item_id: None,
            seat_item_id: None,
            updated_at: 1700000000,
        }
    }

    #[tokio::test]
    async fn test_list_payment_methods() {
        let store = InMemoryBillingStore::new();
        let client = MockStripePaymentMethodClient::new();

        // Add subscription
        store.save_subscription("org_123", &create_test_subscription("org_123")).await.unwrap();

        // Add payment methods
        client.add_payment_method("cus_123", PaymentMethod {
            id: "pm_1".to_string(),
            card_brand: Some("visa".to_string()),
            card_last4: Some("4242".to_string()),
            card_exp_month: Some(12),
            card_exp_year: Some(2099),
            is_default: false,
        });
        client.add_payment_method("cus_123", PaymentMethod {
            id: "pm_2".to_string(),
            card_brand: Some("mastercard".to_string()),
            card_last4: Some("5555".to_string()),
            card_exp_month: Some(6),
            card_exp_year: Some(2026),
            is_default: false,
        });

        let manager = PaymentMethodManager::new(store, client);
        let methods = manager.list_payment_methods("org_123").await.unwrap();

        assert_eq!(methods.methods.len(), 2);
        assert!(!methods.has_more);
    }

    #[tokio::test]
    async fn test_set_default_payment_method() {
        let store = InMemoryBillingStore::new();
        let client = MockStripePaymentMethodClient::new();

        store.save_subscription("org_123", &create_test_subscription("org_123")).await.unwrap();

        client.add_payment_method("cus_123", PaymentMethod {
            id: "pm_1".to_string(),
            card_brand: Some("visa".to_string()),
            card_last4: Some("4242".to_string()),
            card_exp_month: Some(12),
            card_exp_year: Some(2099),
            is_default: false,
        });

        let manager = PaymentMethodManager::new(store, client);

        // Set default
        manager.set_default("org_123", "pm_1").await.unwrap();

        // Get default
        let default = manager.get_default("org_123").await.unwrap();
        assert!(default.is_some());
        assert_eq!(default.unwrap().id, "pm_1");
    }

    #[tokio::test]
    async fn test_attach_payment_method() {
        let store = InMemoryBillingStore::new();
        let client = MockStripePaymentMethodClient::new();

        store.save_subscription("org_123", &create_test_subscription("org_123")).await.unwrap();

        let manager = PaymentMethodManager::new(store, client);

        // Attach new payment method
        let method = manager.attach("org_123", "pm_new").await.unwrap();
        assert_eq!(method.id, "pm_new");
        assert_eq!(method.card_brand, Some("visa".to_string()));

        // Should now appear in list
        let methods = manager.list_payment_methods("org_123").await.unwrap();
        assert_eq!(methods.methods.len(), 1);
    }

    #[tokio::test]
    async fn test_remove_payment_method() {
        let store = InMemoryBillingStore::new();
        let client = MockStripePaymentMethodClient::new();

        store.save_subscription("org_123", &create_test_subscription("org_123")).await.unwrap();

        client.add_payment_method("cus_123", PaymentMethod {
            id: "pm_1".to_string(),
            card_brand: Some("visa".to_string()),
            card_last4: Some("4242".to_string()),
            card_exp_month: Some(12),
            card_exp_year: Some(2099),
            is_default: false,
        });

        let manager = PaymentMethodManager::new(store, client);

        // Verify it exists
        let methods = manager.list_payment_methods("org_123").await.unwrap();
        assert_eq!(methods.methods.len(), 1);

        // Remove
        manager.remove("org_123", "pm_1").await.unwrap();

        // Should be gone
        let methods = manager.list_payment_methods("org_123").await.unwrap();
        assert_eq!(methods.methods.len(), 0);
    }

    #[tokio::test]
    async fn test_no_subscription_error() {
        let store = InMemoryBillingStore::new();
        let client = MockStripePaymentMethodClient::new();

        let manager = PaymentMethodManager::new(store, client);

        // Should fail without subscription
        let result = manager.list_payment_methods("nonexistent").await;
        assert!(result.is_err());
    }
}
