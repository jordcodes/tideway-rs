//! Storage traits for billing data.
//!
//! Implement these traits to persist billing state to your database.

use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Trait for storing billing data.
///
/// Implement this trait to persist billing state to your database.
/// An in-memory implementation is provided for testing.
#[async_trait]
pub trait BillingStore: Send + Sync {
    // Customer management

    /// Get the Stripe customer ID for a billable entity.
    async fn get_stripe_customer_id(&self, billable_id: &str) -> Result<Option<String>>;

    /// Link a billable entity to a Stripe customer.
    async fn set_stripe_customer_id(
        &self,
        billable_id: &str,
        billable_type: &str,
        customer_id: &str,
    ) -> Result<()>;

    // Subscription tracking

    /// Get the cached subscription for a billable entity.
    async fn get_subscription(&self, billable_id: &str) -> Result<Option<StoredSubscription>>;

    /// Save/update the cached subscription.
    async fn save_subscription(
        &self,
        billable_id: &str,
        subscription: &StoredSubscription,
    ) -> Result<()>;

    /// Save subscription only if it hasn't been modified since `expected_version`.
    ///
    /// This is used for optimistic locking to prevent race conditions.
    /// Returns `Ok(true)` if the save succeeded, `Ok(false)` if the version didn't match.
    ///
    /// The default implementation always succeeds (no locking) for backwards compatibility.
    async fn compare_and_save_subscription(
        &self,
        billable_id: &str,
        subscription: &StoredSubscription,
        expected_version: u64,
    ) -> Result<bool> {
        // Default implementation: check version and save
        // Implementers should override with atomic compare-and-swap
        if let Some(current) = self.get_subscription(billable_id).await? {
            if current.updated_at != expected_version {
                return Ok(false);
            }
        }
        self.save_subscription(billable_id, subscription).await?;
        Ok(true)
    }

    /// Delete the subscription record.
    async fn delete_subscription(&self, billable_id: &str) -> Result<()>;

    /// Get subscription by Stripe subscription ID.
    async fn get_subscription_by_stripe_id(
        &self,
        stripe_subscription_id: &str,
    ) -> Result<Option<(String, StoredSubscription)>>;

    // Webhook idempotency

    /// Check if a webhook event has already been processed.
    async fn is_event_processed(&self, event_id: &str) -> Result<bool>;

    /// Mark a webhook event as processed.
    async fn mark_event_processed(&self, event_id: &str) -> Result<()>;

    // Optional: cleanup old events

    /// Clean up old processed events (default: no-op).
    async fn cleanup_old_events(&self, _older_than_days: u32) -> Result<usize> {
        Ok(0)
    }
}

/// Cached subscription state.
///
/// This is synced from Stripe via webhooks to avoid API calls on every request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredSubscription {
    /// Stripe subscription ID.
    pub stripe_subscription_id: String,
    /// Stripe customer ID.
    pub stripe_customer_id: String,
    /// Plan ID (your internal plan identifier).
    pub plan_id: String,
    /// Subscription status.
    pub status: SubscriptionStatus,
    /// Current billing period start (Unix timestamp).
    pub current_period_start: u64,
    /// Current billing period end (Unix timestamp).
    pub current_period_end: u64,
    /// Number of extra seats purchased.
    pub extra_seats: u32,
    /// Trial end timestamp (if in trial).
    pub trial_end: Option<u64>,
    /// Whether subscription will cancel at period end.
    pub cancel_at_period_end: bool,
    /// Stripe subscription item ID for the base plan.
    pub base_item_id: Option<String>,
    /// Stripe subscription item ID for extra seats.
    pub seat_item_id: Option<String>,
    /// Last updated timestamp.
    pub updated_at: u64,
}

impl StoredSubscription {
    /// Check if the subscription is active (including trialing).
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(
            self.status,
            SubscriptionStatus::Active | SubscriptionStatus::Trialing
        )
    }

    /// Check if the subscription is in trial.
    #[must_use]
    pub fn is_trialing(&self) -> bool {
        self.status == SubscriptionStatus::Trialing
    }

    /// Check if payment has failed.
    #[must_use]
    pub fn is_past_due(&self) -> bool {
        self.status == SubscriptionStatus::PastDue
    }

    /// Check if the subscription is canceled.
    #[must_use]
    pub fn is_canceled(&self) -> bool {
        self.status == SubscriptionStatus::Canceled
    }

    /// Check if the subscription will cancel at period end.
    #[must_use]
    pub fn will_cancel(&self) -> bool {
        self.cancel_at_period_end
    }

    /// Get remaining trial days (if in trial).
    #[must_use]
    pub fn trial_days_remaining(&self) -> Option<u32> {
        self.trial_end.and_then(|end| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            if end > now {
                Some(((end - now) / 86400) as u32)
            } else {
                None
            }
        })
    }
}

/// Subscription status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    /// Subscription is active and paid.
    Active,
    /// Subscription is in trial period.
    Trialing,
    /// Payment failed, subscription still active but past due.
    PastDue,
    /// Subscription has been canceled.
    Canceled,
    /// Subscription is incomplete (awaiting payment).
    Incomplete,
    /// Subscription expired after incomplete payment.
    IncompleteExpired,
    /// Subscription is paused.
    Paused,
    /// Subscription is unpaid.
    Unpaid,
}

impl SubscriptionStatus {
    /// Parse from Stripe subscription status string.
    #[must_use]
    pub fn from_stripe(status: &str) -> Self {
        match status {
            "active" => Self::Active,
            "trialing" => Self::Trialing,
            "past_due" => Self::PastDue,
            "canceled" => Self::Canceled,
            "incomplete" => Self::Incomplete,
            "incomplete_expired" => Self::IncompleteExpired,
            "paused" => Self::Paused,
            "unpaid" => Self::Unpaid,
            _ => Self::Canceled, // Default to canceled for unknown statuses
        }
    }

    /// Convert to string for Stripe.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Trialing => "trialing",
            Self::PastDue => "past_due",
            Self::Canceled => "canceled",
            Self::Incomplete => "incomplete",
            Self::IncompleteExpired => "incomplete_expired",
            Self::Paused => "paused",
            Self::Unpaid => "unpaid",
        }
    }
}

impl std::fmt::Display for SubscriptionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Information about a billable entity.
///
/// Implement this trait for your User or Organization types.
pub trait BillableEntity: Send + Sync {
    /// Get the unique ID of this billable entity.
    fn billable_id(&self) -> &str;

    /// Get the type of billable entity ("user" or "org").
    fn billable_type(&self) -> &str;

    /// Get the email for this entity (for Stripe customer creation).
    fn email(&self) -> &str;

    /// Get the display name for this entity.
    fn name(&self) -> Option<&str>;
}

/// In-memory billing store for testing.
#[cfg(any(test, feature = "test-billing"))]
pub mod test {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};

    /// In-memory billing store for testing.
    ///
    /// Wraps data in Arc for cheap cloning.
    #[derive(Default, Clone)]
    pub struct InMemoryBillingStore {
        inner: Arc<InMemoryBillingStoreInner>,
    }

    #[derive(Default)]
    struct InMemoryBillingStoreInner {
        customers: RwLock<HashMap<String, CustomerRecord>>,
        subscriptions: RwLock<HashMap<String, StoredSubscription>>,
        processed_events: RwLock<HashMap<String, u64>>,
    }

    #[derive(Clone)]
    struct CustomerRecord {
        #[allow(dead_code)]
        billable_type: String,
        stripe_customer_id: String,
    }

    impl InMemoryBillingStore {
        /// Create a new in-memory store.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Get all subscriptions (for testing).
        pub fn get_all_subscriptions(&self) -> HashMap<String, StoredSubscription> {
            self.inner.subscriptions.read().unwrap().clone()
        }

        /// Get all processed events (for testing).
        pub fn get_processed_events(&self) -> Vec<String> {
            self.inner.processed_events
                .read()
                .unwrap()
                .keys()
                .cloned()
                .collect()
        }
    }

    #[async_trait]
    impl BillingStore for InMemoryBillingStore {
        async fn get_stripe_customer_id(&self, billable_id: &str) -> Result<Option<String>> {
            Ok(self
                .inner
                .customers
                .read()
                .unwrap()
                .get(billable_id)
                .map(|r| r.stripe_customer_id.clone()))
        }

        async fn set_stripe_customer_id(
            &self,
            billable_id: &str,
            billable_type: &str,
            customer_id: &str,
        ) -> Result<()> {
            self.inner.customers.write().unwrap().insert(
                billable_id.to_string(),
                CustomerRecord {
                    billable_type: billable_type.to_string(),
                    stripe_customer_id: customer_id.to_string(),
                },
            );
            Ok(())
        }

        async fn get_subscription(&self, billable_id: &str) -> Result<Option<StoredSubscription>> {
            Ok(self
                .inner
                .subscriptions
                .read()
                .unwrap()
                .get(billable_id)
                .cloned())
        }

        async fn save_subscription(
            &self,
            billable_id: &str,
            subscription: &StoredSubscription,
        ) -> Result<()> {
            self.inner
                .subscriptions
                .write()
                .unwrap()
                .insert(billable_id.to_string(), subscription.clone());
            Ok(())
        }

        async fn compare_and_save_subscription(
            &self,
            billable_id: &str,
            subscription: &StoredSubscription,
            expected_version: u64,
        ) -> Result<bool> {
            let mut subs = self.inner.subscriptions.write().unwrap();

            // Check if current version matches expected
            if let Some(current) = subs.get(billable_id) {
                if current.updated_at != expected_version {
                    return Ok(false);
                }
            }

            // Version matches (or no existing record), save the new subscription
            subs.insert(billable_id.to_string(), subscription.clone());
            Ok(true)
        }

        async fn delete_subscription(&self, billable_id: &str) -> Result<()> {
            self.inner.subscriptions.write().unwrap().remove(billable_id);
            Ok(())
        }

        async fn get_subscription_by_stripe_id(
            &self,
            stripe_subscription_id: &str,
        ) -> Result<Option<(String, StoredSubscription)>> {
            let subs = self.inner.subscriptions.read().unwrap();
            for (billable_id, sub) in subs.iter() {
                if sub.stripe_subscription_id == stripe_subscription_id {
                    return Ok(Some((billable_id.clone(), sub.clone())));
                }
            }
            Ok(None)
        }

        async fn is_event_processed(&self, event_id: &str) -> Result<bool> {
            Ok(self
                .inner
                .processed_events
                .read()
                .unwrap()
                .contains_key(event_id))
        }

        async fn mark_event_processed(&self, event_id: &str) -> Result<()> {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            self.inner
                .processed_events
                .write()
                .unwrap()
                .insert(event_id.to_string(), now);
            Ok(())
        }

        async fn cleanup_old_events(&self, older_than_days: u32) -> Result<usize> {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let cutoff = now - (older_than_days as u64 * 86400);
            let mut events = self.inner.processed_events.write().unwrap();
            let initial_len = events.len();
            events.retain(|_, &mut timestamp| timestamp >= cutoff);
            Ok(initial_len - events.len())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscription_status_from_stripe() {
        assert_eq!(
            SubscriptionStatus::from_stripe("active"),
            SubscriptionStatus::Active
        );
        assert_eq!(
            SubscriptionStatus::from_stripe("trialing"),
            SubscriptionStatus::Trialing
        );
        assert_eq!(
            SubscriptionStatus::from_stripe("past_due"),
            SubscriptionStatus::PastDue
        );
        assert_eq!(
            SubscriptionStatus::from_stripe("canceled"),
            SubscriptionStatus::Canceled
        );
        assert_eq!(
            SubscriptionStatus::from_stripe("unknown"),
            SubscriptionStatus::Canceled
        );
    }

    #[test]
    fn test_subscription_is_active() {
        let sub = StoredSubscription {
            stripe_subscription_id: "sub_123".to_string(),
            stripe_customer_id: "cus_123".to_string(),
            plan_id: "starter".to_string(),
            status: SubscriptionStatus::Active,
            current_period_start: 0,
            current_period_end: 0,
            extra_seats: 0,
            trial_end: None,
            cancel_at_period_end: false,
            base_item_id: None,
            seat_item_id: None,
            updated_at: 0,
        };

        assert!(sub.is_active());
        assert!(!sub.is_trialing());
        assert!(!sub.is_past_due());
    }

    #[test]
    fn test_subscription_trialing() {
        let sub = StoredSubscription {
            stripe_subscription_id: "sub_123".to_string(),
            stripe_customer_id: "cus_123".to_string(),
            plan_id: "starter".to_string(),
            status: SubscriptionStatus::Trialing,
            current_period_start: 0,
            current_period_end: 0,
            extra_seats: 0,
            trial_end: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 86400 * 7,
            ), // 7 days
            cancel_at_period_end: false,
            base_item_id: None,
            seat_item_id: None,
            updated_at: 0,
        };

        assert!(sub.is_active());
        assert!(sub.is_trialing());
        assert!(sub.trial_days_remaining().unwrap() >= 6);
    }

    #[tokio::test]
    async fn test_in_memory_store() {
        use test::InMemoryBillingStore;

        let store = InMemoryBillingStore::new();

        // Test customer
        assert!(store
            .get_stripe_customer_id("org_123")
            .await
            .unwrap()
            .is_none());

        store
            .set_stripe_customer_id("org_123", "org", "cus_abc")
            .await
            .unwrap();

        assert_eq!(
            store
                .get_stripe_customer_id("org_123")
                .await
                .unwrap()
                .unwrap(),
            "cus_abc"
        );

        // Test subscription
        let sub = StoredSubscription {
            stripe_subscription_id: "sub_123".to_string(),
            stripe_customer_id: "cus_abc".to_string(),
            plan_id: "starter".to_string(),
            status: SubscriptionStatus::Active,
            current_period_start: 0,
            current_period_end: 0,
            extra_seats: 2,
            trial_end: None,
            cancel_at_period_end: false,
            base_item_id: None,
            seat_item_id: None,
            updated_at: 0,
        };

        store.save_subscription("org_123", &sub).await.unwrap();

        let loaded = store.get_subscription("org_123").await.unwrap().unwrap();
        assert_eq!(loaded.plan_id, "starter");
        assert_eq!(loaded.extra_seats, 2);

        // Test event idempotency
        assert!(!store.is_event_processed("evt_123").await.unwrap());
        store.mark_event_processed("evt_123").await.unwrap();
        assert!(store.is_event_processed("evt_123").await.unwrap());
    }
}
