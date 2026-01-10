//! Refund management for Stripe billing.
//!
//! Handles creating, retrieving, and listing refunds for charges and payment intents.
//!
//! # Security
//!
//! This module provides two managers:
//! - `RefundManager` - Low-level refund operations without authorization checks.
//!   Use this only for admin operations or when authorization is handled externally.
//! - `SecureRefundManager` - Verifies charge ownership before processing refunds.
//!   **Use this for customer-facing operations.**

use crate::error::Result;
use super::storage::BillingStore;

/// A Stripe refund.
#[derive(Debug, Clone)]
pub struct Refund {
    /// Stripe refund ID.
    pub id: String,
    /// Amount refunded in cents.
    pub amount: i64,
    /// Currency (e.g., "usd").
    pub currency: String,
    /// Refund status.
    pub status: RefundStatus,
    /// Reason for the refund.
    pub reason: Option<RefundReason>,
    /// Unix timestamp of when the refund was created.
    pub created: u64,
    /// The charge ID this refund is for.
    pub charge_id: Option<String>,
    /// The payment intent ID this refund is for.
    pub payment_intent_id: Option<String>,
}

/// Status of a refund.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefundStatus {
    /// Refund is pending.
    Pending,
    /// Refund succeeded.
    Succeeded,
    /// Refund failed.
    Failed,
    /// Refund was canceled.
    Canceled,
}

impl RefundStatus {
    /// Convert from Stripe status string.
    #[must_use]
    pub fn from_stripe(status: &str) -> Self {
        match status {
            "pending" => Self::Pending,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "canceled" => Self::Canceled,
            _ => Self::Pending,
        }
    }

    /// Convert to string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Canceled => "canceled",
        }
    }
}

/// Reason for a refund.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefundReason {
    /// Duplicate charge.
    Duplicate,
    /// Fraudulent charge.
    Fraudulent,
    /// Requested by customer.
    RequestedByCustomer,
}

impl RefundReason {
    /// Convert to Stripe reason string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Duplicate => "duplicate",
            Self::Fraudulent => "fraudulent",
            Self::RequestedByCustomer => "requested_by_customer",
        }
    }

    /// Convert from Stripe reason string.
    #[must_use]
    pub fn from_stripe(reason: &str) -> Option<Self> {
        match reason {
            "duplicate" => Some(Self::Duplicate),
            "fraudulent" => Some(Self::Fraudulent),
            "requested_by_customer" => Some(Self::RequestedByCustomer),
            _ => None,
        }
    }
}

/// Request to create a refund.
#[derive(Debug, Clone, Default)]
pub struct CreateRefundRequest {
    /// The charge ID to refund.
    pub charge_id: Option<String>,
    /// The payment intent ID to refund.
    pub payment_intent_id: Option<String>,
    /// Amount to refund in cents. If None, refunds the full amount.
    pub amount: Option<i64>,
    /// Reason for the refund.
    pub reason: Option<RefundReason>,
}

impl CreateRefundRequest {
    /// Create a new refund request for a charge.
    #[must_use]
    pub fn for_charge(charge_id: impl Into<String>) -> Self {
        Self {
            charge_id: Some(charge_id.into()),
            ..Default::default()
        }
    }

    /// Create a new refund request for a payment intent.
    #[must_use]
    pub fn for_payment_intent(payment_intent_id: impl Into<String>) -> Self {
        Self {
            payment_intent_id: Some(payment_intent_id.into()),
            ..Default::default()
        }
    }

    /// Set the refund amount (partial refund).
    #[must_use]
    pub fn with_amount(mut self, amount: i64) -> Self {
        self.amount = Some(amount);
        self
    }

    /// Set the refund reason.
    #[must_use]
    pub fn with_reason(mut self, reason: RefundReason) -> Self {
        self.reason = Some(reason);
        self
    }
}

/// Trait for Stripe refund operations.
#[allow(async_fn_in_trait)]
pub trait StripeRefundClient: Send + Sync {
    /// Create a new refund.
    async fn create_refund(&self, request: CreateRefundRequest) -> Result<Refund>;

    /// Get a refund by ID.
    async fn get_refund(&self, refund_id: &str) -> Result<Refund>;

    /// List refunds for a charge.
    async fn list_refunds(&self, charge_id: &str, limit: u8) -> Result<Vec<Refund>>;

    /// Get the customer ID associated with a charge.
    ///
    /// Used for authorization checks to verify charge ownership.
    async fn get_charge_customer_id(&self, charge_id: &str) -> Result<String>;

    /// Get the customer ID associated with a payment intent.
    ///
    /// Used for authorization checks to verify payment intent ownership.
    async fn get_payment_intent_customer_id(&self, payment_intent_id: &str) -> Result<String>;
}

/// Low-level refund management operations.
///
/// Provides a low-level interface for refunding charges and payment intents.
///
/// # Security Warning
///
/// This manager does **not** verify that the charge belongs to the caller.
/// Use [`SecureRefundManager`] for customer-facing operations, or ensure
/// authorization is handled at a higher layer (e.g., admin-only endpoints).
pub struct RefundManager<C: StripeRefundClient> {
    client: C,
}

impl<C: StripeRefundClient> RefundManager<C> {
    /// Create a new refund manager.
    ///
    /// # Security
    ///
    /// This manager does not perform authorization checks.
    /// For customer-facing operations, use [`SecureRefundManager`] instead.
    #[must_use]
    pub fn new(client: C) -> Self {
        Self { client }
    }

    /// Refund a charge.
    ///
    /// # Security Warning
    ///
    /// This method does not verify charge ownership. Ensure the caller
    /// is authorized before invoking this method.
    ///
    /// # Arguments
    ///
    /// * `charge_id` - The Stripe charge ID
    /// * `amount` - Amount to refund in cents. If None, refunds the full charge.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Full refund
    /// let refund = manager.refund_charge("ch_xxx", None).await?;
    ///
    /// // Partial refund ($5.00)
    /// let refund = manager.refund_charge("ch_xxx", Some(500)).await?;
    /// ```
    pub async fn refund_charge(
        &self,
        charge_id: &str,
        amount: Option<i64>,
    ) -> Result<Refund> {
        let mut request = CreateRefundRequest::for_charge(charge_id);
        if let Some(amt) = amount {
            request = request.with_amount(amt);
        }
        self.client.create_refund(request).await
    }

    /// Refund a payment intent.
    ///
    /// # Security Warning
    ///
    /// This method does not verify payment intent ownership. Ensure the caller
    /// is authorized before invoking this method.
    ///
    /// # Arguments
    ///
    /// * `payment_intent_id` - The Stripe payment intent ID
    /// * `amount` - Amount to refund in cents. If None, refunds the full payment.
    pub async fn refund_payment_intent(
        &self,
        payment_intent_id: &str,
        amount: Option<i64>,
    ) -> Result<Refund> {
        let mut request = CreateRefundRequest::for_payment_intent(payment_intent_id);
        if let Some(amt) = amount {
            request = request.with_amount(amt);
        }
        self.client.create_refund(request).await
    }

    /// Refund with a specific reason.
    ///
    /// Useful for fraud-related refunds or duplicate charges.
    ///
    /// # Security Warning
    ///
    /// This method does not verify charge ownership.
    pub async fn refund_with_reason(
        &self,
        charge_id: &str,
        amount: Option<i64>,
        reason: RefundReason,
    ) -> Result<Refund> {
        let mut request = CreateRefundRequest::for_charge(charge_id)
            .with_reason(reason);
        if let Some(amt) = amount {
            request = request.with_amount(amt);
        }
        self.client.create_refund(request).await
    }

    /// Get a refund by ID.
    pub async fn get_refund(&self, refund_id: &str) -> Result<Refund> {
        self.client.get_refund(refund_id).await
    }

    /// List refunds for a charge.
    pub async fn list_refunds_for_charge(&self, charge_id: &str, limit: u8) -> Result<Vec<Refund>> {
        self.client.list_refunds(charge_id, limit).await
    }
}

/// Secure refund manager with authorization checks.
///
/// Verifies that charges and payment intents belong to the billable entity
/// before processing refunds. **Use this for all customer-facing operations.**
///
/// # Example
///
/// ```ignore
/// let manager = SecureRefundManager::new(store, client);
///
/// // This will verify the charge belongs to org_123 before refunding
/// let refund = manager.refund_charge("org_123", "ch_xxx", None).await?;
/// ```
pub struct SecureRefundManager<S: BillingStore, C: StripeRefundClient> {
    store: S,
    client: C,
}

impl<S: BillingStore, C: StripeRefundClient> SecureRefundManager<S, C> {
    /// Create a new secure refund manager.
    #[must_use]
    pub fn new(store: S, client: C) -> Self {
        Self { store, client }
    }

    /// Verify that a charge belongs to the given billable entity.
    async fn verify_charge_ownership(&self, billable_id: &str, charge_id: &str) -> Result<()> {
        let sub = self.store.get_subscription(billable_id).await?
            .ok_or_else(|| super::error::BillingError::NoSubscription {
                billable_id: billable_id.to_string(),
            })?;

        let charge_customer_id = self.client.get_charge_customer_id(charge_id).await?;

        if charge_customer_id != sub.stripe_customer_id {
            return Err(super::error::BillingError::ChargeNotFound {
                charge_id: charge_id.to_string(),
            }.into());
        }

        Ok(())
    }

    /// Verify that a payment intent belongs to the given billable entity.
    async fn verify_payment_intent_ownership(&self, billable_id: &str, payment_intent_id: &str) -> Result<()> {
        let sub = self.store.get_subscription(billable_id).await?
            .ok_or_else(|| super::error::BillingError::NoSubscription {
                billable_id: billable_id.to_string(),
            })?;

        let pi_customer_id = self.client.get_payment_intent_customer_id(payment_intent_id).await?;

        if pi_customer_id != sub.stripe_customer_id {
            return Err(super::error::BillingError::RefundFailed {
                reason: "Payment intent does not belong to this customer".to_string(),
            }.into());
        }

        Ok(())
    }

    /// Refund a charge with ownership verification.
    ///
    /// Verifies that the charge belongs to the billable entity before processing.
    ///
    /// # Arguments
    ///
    /// * `billable_id` - The billable entity ID (used to verify ownership)
    /// * `charge_id` - The Stripe charge ID
    /// * `amount` - Amount to refund in cents. If None, refunds the full charge.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Full refund - verifies charge belongs to org_123
    /// let refund = manager.refund_charge("org_123", "ch_xxx", None).await?;
    ///
    /// // Partial refund ($5.00)
    /// let refund = manager.refund_charge("org_123", "ch_xxx", Some(500)).await?;
    /// ```
    pub async fn refund_charge(
        &self,
        billable_id: &str,
        charge_id: &str,
        amount: Option<i64>,
    ) -> Result<Refund> {
        // Verify the charge belongs to this customer
        self.verify_charge_ownership(billable_id, charge_id).await?;

        let mut request = CreateRefundRequest::for_charge(charge_id);
        if let Some(amt) = amount {
            request = request.with_amount(amt);
        }
        self.client.create_refund(request).await
    }

    /// Refund a payment intent with ownership verification.
    ///
    /// Verifies that the payment intent belongs to the billable entity before processing.
    ///
    /// # Arguments
    ///
    /// * `billable_id` - The billable entity ID (used to verify ownership)
    /// * `payment_intent_id` - The Stripe payment intent ID
    /// * `amount` - Amount to refund in cents. If None, refunds the full payment.
    pub async fn refund_payment_intent(
        &self,
        billable_id: &str,
        payment_intent_id: &str,
        amount: Option<i64>,
    ) -> Result<Refund> {
        // Verify the payment intent belongs to this customer
        self.verify_payment_intent_ownership(billable_id, payment_intent_id).await?;

        let mut request = CreateRefundRequest::for_payment_intent(payment_intent_id);
        if let Some(amt) = amount {
            request = request.with_amount(amt);
        }
        self.client.create_refund(request).await
    }

    /// Refund a charge with a specific reason and ownership verification.
    ///
    /// # Arguments
    ///
    /// * `billable_id` - The billable entity ID (used to verify ownership)
    /// * `charge_id` - The Stripe charge ID
    /// * `amount` - Amount to refund in cents. If None, refunds the full charge.
    /// * `reason` - The reason for the refund
    pub async fn refund_with_reason(
        &self,
        billable_id: &str,
        charge_id: &str,
        amount: Option<i64>,
        reason: RefundReason,
    ) -> Result<Refund> {
        // Verify the charge belongs to this customer
        self.verify_charge_ownership(billable_id, charge_id).await?;

        let mut request = CreateRefundRequest::for_charge(charge_id)
            .with_reason(reason);
        if let Some(amt) = amount {
            request = request.with_amount(amt);
        }
        self.client.create_refund(request).await
    }

    /// Get a refund by ID.
    pub async fn get_refund(&self, refund_id: &str) -> Result<Refund> {
        self.client.get_refund(refund_id).await
    }

    /// List refunds for a charge with ownership verification.
    ///
    /// # Arguments
    ///
    /// * `billable_id` - The billable entity ID (used to verify ownership)
    /// * `charge_id` - The Stripe charge ID
    /// * `limit` - Maximum number of refunds to return
    pub async fn list_refunds_for_charge(
        &self,
        billable_id: &str,
        charge_id: &str,
        limit: u8,
    ) -> Result<Vec<Refund>> {
        // Verify the charge belongs to this customer
        self.verify_charge_ownership(billable_id, charge_id).await?;

        self.client.list_refunds(charge_id, limit).await
    }
}

/// Mock Stripe refund client for testing.
#[cfg(any(test, feature = "test-billing"))]
pub mod test {
    use super::*;
    use std::sync::RwLock;
    use std::collections::HashMap;

    /// Mock Stripe refund client.
    #[derive(Default)]
    pub struct MockStripeRefundClient {
        refunds: std::sync::Arc<RwLock<HashMap<String, Refund>>>,
        charge_refunds: std::sync::Arc<RwLock<HashMap<String, Vec<String>>>>,
        charge_customers: std::sync::Arc<RwLock<HashMap<String, String>>>,
        payment_intent_customers: std::sync::Arc<RwLock<HashMap<String, String>>>,
        refund_counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    impl MockStripeRefundClient {
        /// Create a new mock client.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Register a charge with its customer ID for ownership verification.
        pub fn add_charge(&self, charge_id: &str, customer_id: &str) {
            self.charge_customers
                .write()
                .unwrap()
                .insert(charge_id.to_string(), customer_id.to_string());
        }

        /// Register a payment intent with its customer ID for ownership verification.
        pub fn add_payment_intent(&self, payment_intent_id: &str, customer_id: &str) {
            self.payment_intent_customers
                .write()
                .unwrap()
                .insert(payment_intent_id.to_string(), customer_id.to_string());
        }
    }

    impl StripeRefundClient for MockStripeRefundClient {
        async fn create_refund(&self, request: CreateRefundRequest) -> Result<Refund> {
            let id = format!(
                "re_mock_{}",
                self.refund_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            );

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let refund = Refund {
                id: id.clone(),
                amount: request.amount.unwrap_or(1000), // Default to $10
                currency: "usd".to_string(),
                status: RefundStatus::Succeeded,
                reason: request.reason,
                created: now,
                charge_id: request.charge_id.clone(),
                payment_intent_id: request.payment_intent_id,
            };

            // Store the refund
            self.refunds.write().unwrap().insert(id.clone(), refund.clone());

            // Track charge -> refunds mapping
            if let Some(charge_id) = &request.charge_id {
                self.charge_refunds
                    .write()
                    .unwrap()
                    .entry(charge_id.clone())
                    .or_default()
                    .push(id);
            }

            Ok(refund)
        }

        async fn get_refund(&self, refund_id: &str) -> Result<Refund> {
            self.refunds
                .read()
                .unwrap()
                .get(refund_id)
                .cloned()
                .ok_or_else(|| super::super::error::BillingError::RefundNotFound {
                    refund_id: refund_id.to_string(),
                }.into())
        }

        async fn list_refunds(&self, charge_id: &str, limit: u8) -> Result<Vec<Refund>> {
            let charge_refunds = self.charge_refunds.read().unwrap();
            let refunds = self.refunds.read().unwrap();

            let refund_ids = charge_refunds.get(charge_id).cloned().unwrap_or_default();
            let result: Vec<Refund> = refund_ids
                .into_iter()
                .take(limit as usize)
                .filter_map(|id| refunds.get(&id).cloned())
                .collect();

            Ok(result)
        }

        async fn get_charge_customer_id(&self, charge_id: &str) -> Result<String> {
            self.charge_customers
                .read()
                .unwrap()
                .get(charge_id)
                .cloned()
                .ok_or_else(|| super::super::error::BillingError::ChargeNotFound {
                    charge_id: charge_id.to_string(),
                }.into())
        }

        async fn get_payment_intent_customer_id(&self, payment_intent_id: &str) -> Result<String> {
            self.payment_intent_customers
                .read()
                .unwrap()
                .get(payment_intent_id)
                .cloned()
                .ok_or_else(|| super::super::error::BillingError::RefundFailed {
                    reason: format!("Payment intent not found: {}", payment_intent_id),
                }.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test::MockStripeRefundClient;

    #[tokio::test]
    async fn test_refund_charge() {
        let client = MockStripeRefundClient::new();
        let manager = RefundManager::new(client);

        let refund = manager.refund_charge("ch_123", None).await.unwrap();
        assert!(refund.id.starts_with("re_mock_"));
        assert_eq!(refund.status, RefundStatus::Succeeded);
        assert_eq!(refund.charge_id, Some("ch_123".to_string()));
    }

    #[tokio::test]
    async fn test_refund_partial() {
        let client = MockStripeRefundClient::new();
        let manager = RefundManager::new(client);

        let refund = manager.refund_charge("ch_123", Some(500)).await.unwrap();
        assert_eq!(refund.amount, 500);
    }

    #[tokio::test]
    async fn test_refund_payment_intent() {
        let client = MockStripeRefundClient::new();
        let manager = RefundManager::new(client);

        let refund = manager.refund_payment_intent("pi_123", None).await.unwrap();
        assert_eq!(refund.payment_intent_id, Some("pi_123".to_string()));
    }

    #[tokio::test]
    async fn test_refund_with_reason() {
        let client = MockStripeRefundClient::new();
        let manager = RefundManager::new(client);

        let refund = manager
            .refund_with_reason("ch_123", None, RefundReason::Duplicate)
            .await
            .unwrap();
        assert_eq!(refund.reason, Some(RefundReason::Duplicate));
    }

    #[tokio::test]
    async fn test_get_refund() {
        let client = MockStripeRefundClient::new();
        let manager = RefundManager::new(client);

        // Create a refund first
        let created = manager.refund_charge("ch_123", None).await.unwrap();

        // Retrieve it
        let retrieved = manager.get_refund(&created.id).await.unwrap();
        assert_eq!(created.id, retrieved.id);
    }

    #[tokio::test]
    async fn test_list_refunds_for_charge() {
        let client = MockStripeRefundClient::new();
        let manager = RefundManager::new(client);

        // Create multiple refunds
        manager.refund_charge("ch_123", Some(100)).await.unwrap();
        manager.refund_charge("ch_123", Some(200)).await.unwrap();
        manager.refund_charge("ch_456", Some(300)).await.unwrap(); // Different charge

        // List refunds for ch_123
        let refunds = manager.list_refunds_for_charge("ch_123", 10).await.unwrap();
        assert_eq!(refunds.len(), 2);
    }

    #[test]
    fn test_refund_status() {
        assert_eq!(RefundStatus::from_stripe("pending"), RefundStatus::Pending);
        assert_eq!(RefundStatus::from_stripe("succeeded"), RefundStatus::Succeeded);
        assert_eq!(RefundStatus::from_stripe("failed"), RefundStatus::Failed);
        assert_eq!(RefundStatus::from_stripe("canceled"), RefundStatus::Canceled);
        assert_eq!(RefundStatus::from_stripe("unknown"), RefundStatus::Pending);
    }

    #[test]
    fn test_refund_reason() {
        assert_eq!(RefundReason::Duplicate.as_str(), "duplicate");
        assert_eq!(RefundReason::Fraudulent.as_str(), "fraudulent");
        assert_eq!(RefundReason::RequestedByCustomer.as_str(), "requested_by_customer");

        assert_eq!(RefundReason::from_stripe("duplicate"), Some(RefundReason::Duplicate));
        assert_eq!(RefundReason::from_stripe("unknown"), None);
    }

    #[test]
    fn test_create_refund_request_builder() {
        let request = CreateRefundRequest::for_charge("ch_123")
            .with_amount(500)
            .with_reason(RefundReason::RequestedByCustomer);

        assert_eq!(request.charge_id, Some("ch_123".to_string()));
        assert_eq!(request.amount, Some(500));
        assert_eq!(request.reason, Some(RefundReason::RequestedByCustomer));
    }

    // ========================================================================
    // SecureRefundManager Tests
    // ========================================================================

    use crate::billing::storage::test::InMemoryBillingStore;
    use crate::billing::storage::{StoredSubscription, SubscriptionStatus};

    fn create_test_subscription() -> StoredSubscription {
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
    async fn test_secure_refund_charge_with_valid_ownership() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeRefundClient::new();

        // Set up subscription
        store.save_subscription("org_123", &create_test_subscription()).await.unwrap();

        // Register charge with correct customer
        client.add_charge("ch_test", "cus_123");

        let manager = SecureRefundManager::new(store, client);

        // Should succeed - charge belongs to customer
        let refund = manager.refund_charge("org_123", "ch_test", None).await.unwrap();
        assert!(refund.id.starts_with("re_mock_"));
    }

    #[tokio::test]
    async fn test_secure_refund_charge_with_invalid_ownership() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeRefundClient::new();

        // Set up subscription
        store.save_subscription("org_123", &create_test_subscription()).await.unwrap();

        // Register charge with DIFFERENT customer
        client.add_charge("ch_other", "cus_other");

        let manager = SecureRefundManager::new(store, client);

        // Should fail - charge belongs to different customer
        let result = manager.refund_charge("org_123", "ch_other", None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_secure_refund_charge_no_subscription() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeRefundClient::new();

        // No subscription set up

        let manager = SecureRefundManager::new(store, client);

        // Should fail - no subscription
        let result = manager.refund_charge("nonexistent", "ch_test", None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_secure_refund_payment_intent_with_valid_ownership() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeRefundClient::new();

        store.save_subscription("org_123", &create_test_subscription()).await.unwrap();
        client.add_payment_intent("pi_test", "cus_123");

        let manager = SecureRefundManager::new(store, client);

        let refund = manager.refund_payment_intent("org_123", "pi_test", None).await.unwrap();
        assert!(refund.id.starts_with("re_mock_"));
    }

    #[tokio::test]
    async fn test_secure_refund_payment_intent_with_invalid_ownership() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeRefundClient::new();

        store.save_subscription("org_123", &create_test_subscription()).await.unwrap();
        client.add_payment_intent("pi_other", "cus_other");

        let manager = SecureRefundManager::new(store, client);

        let result = manager.refund_payment_intent("org_123", "pi_other", None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_secure_list_refunds_with_ownership() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeRefundClient::new();

        store.save_subscription("org_123", &create_test_subscription()).await.unwrap();
        client.add_charge("ch_test", "cus_123");

        let manager = SecureRefundManager::new(store, client);

        // Create a refund first
        manager.refund_charge("org_123", "ch_test", Some(100)).await.unwrap();

        // List should work
        let refunds = manager.list_refunds_for_charge("org_123", "ch_test", 10).await.unwrap();
        assert_eq!(refunds.len(), 1);
    }
}
