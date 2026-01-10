//! Customer management for Stripe billing.
//!
//! Handles creating and linking Stripe customers to billable entities.

use crate::error::Result;
use super::storage::{BillableEntity, BillingStore};

/// Customer management operations.
///
/// Handles creating Stripe customers and linking them to billable entities.
pub struct CustomerManager<S: BillingStore, C: StripeClient> {
    store: S,
    client: C,
}

impl<S: BillingStore, C: StripeClient> CustomerManager<S, C> {
    /// Create a new customer manager.
    #[must_use]
    pub fn new(store: S, client: C) -> Self {
        Self { store, client }
    }

    /// Get the Stripe customer ID for a billable entity, creating one if needed.
    ///
    /// This is the primary method for getting a customer ID. It will:
    /// 1. Check if the entity already has a linked Stripe customer
    /// 2. If not, create a new Stripe customer
    /// 3. Link the new customer to the entity
    pub async fn get_or_create_customer(
        &self,
        entity: &impl BillableEntity,
    ) -> Result<String> {
        // Check if already linked
        if let Some(customer_id) = self.store.get_stripe_customer_id(entity.billable_id()).await? {
            return Ok(customer_id);
        }

        // Create new customer in Stripe
        let customer_id = self.client.create_customer(CreateCustomerRequest {
            email: entity.email().to_string(),
            name: entity.name().map(String::from),
            metadata: Some(CustomerMetadata {
                billable_id: entity.billable_id().to_string(),
                billable_type: entity.billable_type().to_string(),
            }),
        }).await?;

        // Link to entity
        self.store.set_stripe_customer_id(
            entity.billable_id(),
            entity.billable_type(),
            &customer_id,
        ).await?;

        Ok(customer_id)
    }

    /// Get the Stripe customer ID for an entity (without creating).
    pub async fn get_customer_id(&self, billable_id: &str) -> Result<Option<String>> {
        self.store.get_stripe_customer_id(billable_id).await
    }

    /// Link an existing Stripe customer to a billable entity.
    ///
    /// Use this when you already have a Stripe customer (e.g., migrating from another system).
    pub async fn link_customer(
        &self,
        entity: &impl BillableEntity,
        stripe_customer_id: &str,
    ) -> Result<()> {
        self.store.set_stripe_customer_id(
            entity.billable_id(),
            entity.billable_type(),
            stripe_customer_id,
        ).await
    }

    /// Update customer details in Stripe.
    pub async fn update_customer(
        &self,
        billable_id: &str,
        update: UpdateCustomerRequest,
    ) -> Result<()> {
        let customer_id = self.store.get_stripe_customer_id(billable_id).await?
            .ok_or_else(|| crate::error::TidewayError::NotFound(
                "No Stripe customer linked".to_string()
            ))?;

        self.client.update_customer(&customer_id, update).await
    }

    /// Delete a customer from Stripe (and unlink).
    ///
    /// This permanently deletes the Stripe customer. Use with caution.
    pub async fn delete_customer(&self, billable_id: &str) -> Result<()> {
        if let Some(customer_id) = self.store.get_stripe_customer_id(billable_id).await? {
            self.client.delete_customer(&customer_id).await?;
        }
        // Note: We don't remove the store record as deletion is handled by the store impl
        Ok(())
    }
}

/// Request to create a Stripe customer.
#[derive(Debug, Clone)]
pub struct CreateCustomerRequest {
    /// Customer email address.
    pub email: String,
    /// Customer name.
    pub name: Option<String>,
    /// Metadata to attach to the customer.
    pub metadata: Option<CustomerMetadata>,
}

/// Metadata attached to Stripe customers.
#[derive(Debug, Clone)]
pub struct CustomerMetadata {
    /// The billable entity ID (user_id or org_id).
    pub billable_id: String,
    /// The type of billable entity ("user" or "org").
    pub billable_type: String,
}

/// Request to update a Stripe customer.
#[derive(Debug, Clone, Default)]
pub struct UpdateCustomerRequest {
    /// New email address.
    pub email: Option<String>,
    /// New name.
    pub name: Option<String>,
}

/// Trait for Stripe API operations.
///
/// This abstraction allows testing without real Stripe calls and supports
/// different Stripe client implementations.
#[allow(async_fn_in_trait)]
pub trait StripeClient: Send + Sync {
    /// Create a new customer in Stripe.
    async fn create_customer(&self, request: CreateCustomerRequest) -> Result<String>;

    /// Update an existing customer in Stripe.
    async fn update_customer(&self, customer_id: &str, request: UpdateCustomerRequest) -> Result<()>;

    /// Delete a customer from Stripe.
    async fn delete_customer(&self, customer_id: &str) -> Result<()>;

    /// Get a customer's default payment method.
    async fn get_default_payment_method(&self, customer_id: &str) -> Result<Option<String>>;
}

/// Mock Stripe client for testing.
#[cfg(any(test, feature = "test-billing"))]
pub mod test {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::RwLock;
    use std::collections::HashMap;

    /// Mock Stripe client for testing.
    #[derive(Default)]
    pub struct MockStripeClient {
        customer_counter: AtomicU64,
        customers: RwLock<HashMap<String, MockCustomer>>,
    }

    #[derive(Clone)]
    struct MockCustomer {
        email: String,
        name: Option<String>,
        metadata: Option<CustomerMetadata>,
    }

    impl MockStripeClient {
        /// Create a new mock client.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Get all created customers (for test assertions).
        pub fn get_customers(&self) -> Vec<(String, String)> {
            self.customers
                .read()
                .unwrap()
                .iter()
                .map(|(id, c)| (id.clone(), c.email.clone()))
                .collect()
        }
    }

    impl StripeClient for MockStripeClient {
        async fn create_customer(&self, request: CreateCustomerRequest) -> Result<String> {
            let id = format!("cus_test_{}", self.customer_counter.fetch_add(1, Ordering::SeqCst));
            self.customers.write().unwrap().insert(
                id.clone(),
                MockCustomer {
                    email: request.email,
                    name: request.name,
                    metadata: request.metadata,
                },
            );
            Ok(id)
        }

        async fn update_customer(&self, customer_id: &str, request: UpdateCustomerRequest) -> Result<()> {
            let mut customers = self.customers.write().unwrap();
            if let Some(customer) = customers.get_mut(customer_id) {
                if let Some(email) = request.email {
                    customer.email = email;
                }
                if let Some(name) = request.name {
                    customer.name = Some(name);
                }
                Ok(())
            } else {
                Err(crate::error::TidewayError::NotFound(
                    format!("Customer not found: {}", customer_id)
                ))
            }
        }

        async fn delete_customer(&self, customer_id: &str) -> Result<()> {
            self.customers.write().unwrap().remove(customer_id);
            Ok(())
        }

        async fn get_default_payment_method(&self, _customer_id: &str) -> Result<Option<String>> {
            // Mock returns no payment method by default
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test::MockStripeClient;
    use crate::billing::storage::test::InMemoryBillingStore;

    struct TestEntity {
        id: String,
        email: String,
        name: String,
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
            Some(&self.name)
        }
    }

    #[tokio::test]
    async fn test_get_or_create_customer_creates_new() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeClient::new();
        let manager = CustomerManager::new(store, client);

        let entity = TestEntity {
            id: "org_123".to_string(),
            email: "test@example.com".to_string(),
            name: "Test Org".to_string(),
        };

        let customer_id = manager.get_or_create_customer(&entity).await.unwrap();
        assert!(customer_id.starts_with("cus_test_"));
    }

    #[tokio::test]
    async fn test_get_or_create_customer_returns_existing() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeClient::new();
        let manager = CustomerManager::new(store, client);

        let entity = TestEntity {
            id: "org_123".to_string(),
            email: "test@example.com".to_string(),
            name: "Test Org".to_string(),
        };

        // First call creates
        let id1 = manager.get_or_create_customer(&entity).await.unwrap();
        // Second call returns same
        let id2 = manager.get_or_create_customer(&entity).await.unwrap();

        assert_eq!(id1, id2);
    }

    #[tokio::test]
    async fn test_link_customer() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeClient::new();
        let manager = CustomerManager::new(store, client);

        let entity = TestEntity {
            id: "org_456".to_string(),
            email: "existing@example.com".to_string(),
            name: "Existing Org".to_string(),
        };

        // Link existing customer
        manager.link_customer(&entity, "cus_existing_123").await.unwrap();

        // Verify it's linked
        let customer_id = manager.get_customer_id("org_456").await.unwrap();
        assert_eq!(customer_id, Some("cus_existing_123".to_string()));
    }

    #[tokio::test]
    async fn test_update_customer() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeClient::new();
        let manager = CustomerManager::new(store, client);

        let entity = TestEntity {
            id: "org_789".to_string(),
            email: "old@example.com".to_string(),
            name: "Old Name".to_string(),
        };

        // Create customer first
        manager.get_or_create_customer(&entity).await.unwrap();

        // Update it
        manager.update_customer("org_789", UpdateCustomerRequest {
            email: Some("new@example.com".to_string()),
            name: Some("New Name".to_string()),
        }).await.unwrap();
    }

    #[tokio::test]
    async fn test_update_customer_not_found() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeClient::new();
        let manager = CustomerManager::new(store, client);

        let result = manager.update_customer("nonexistent", UpdateCustomerRequest::default()).await;
        assert!(result.is_err());
    }
}
