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
    /// # Important: Production Implementations MUST Override This
    ///
    /// The default implementation has a **time-of-check to time-of-use (TOCTOU) race condition**
    /// and is only suitable for single-threaded development/testing scenarios.
    ///
    /// Production implementations MUST override this method with an atomic compare-and-swap
    /// operation. Examples:
    ///
    /// - **PostgreSQL**: Use `UPDATE ... WHERE updated_at = $expected_version`
    /// - **Redis**: Use `WATCH`/`MULTI`/`EXEC` transactions
    /// - **DynamoDB**: Use conditional writes with `ConditionExpression`
    ///
    /// # Example (PostgreSQL)
    ///
    /// ```sql
    /// UPDATE subscriptions
    /// SET ..., updated_at = NOW()
    /// WHERE billable_id = $1 AND updated_at = $2
    /// RETURNING billable_id
    /// ```
    ///
    /// If the query returns a row, the update succeeded. If not, version mismatch.
    async fn compare_and_save_subscription(
        &self,
        billable_id: &str,
        subscription: &StoredSubscription,
        expected_version: u64,
    ) -> Result<bool> {
        // WARNING: This default implementation is NOT atomic and has a TOCTOU race condition.
        // It exists only for backwards compatibility and simple development scenarios.
        // Production code MUST override this method with an atomic implementation.
        #[cfg(debug_assertions)]
        {
            static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                tracing::warn!(
                    target: "tideway::billing",
                    "Using default non-atomic compare_and_save_subscription implementation. \
                     This is NOT safe for production use with concurrent requests. \
                     Override this method with an atomic compare-and-swap operation."
                );
            }
        }

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

// =============================================================================
// Plan Storage
// =============================================================================

/// A plan stored in the database.
///
/// This represents a subscription plan that can be managed through the admin UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredPlan {
    /// Unique plan identifier (e.g., "starter", "pro", "enterprise").
    pub id: String,
    /// Display name shown to users.
    pub name: String,
    /// Description of the plan.
    pub description: Option<String>,
    /// Stripe Price ID for the subscription.
    pub stripe_price_id: String,
    /// Stripe Price ID for additional seats (optional).
    pub stripe_seat_price_id: Option<String>,
    /// Price in cents (for display purposes).
    pub price_cents: i64,
    /// Currency code (e.g., "usd", "gbp", "eur").
    pub currency: String,
    /// Billing interval.
    pub interval: PlanInterval,
    /// Number of seats included in the base price.
    pub included_seats: u32,
    /// Features available on this plan (JSON object).
    pub features: serde_json::Value,
    /// Resource limits for this plan (JSON object).
    pub limits: serde_json::Value,
    /// Trial period in days (None = no trial).
    pub trial_days: Option<u32>,
    /// Whether the plan is active and available for purchase.
    pub is_active: bool,
    /// Sort order for display.
    pub sort_order: i32,
    /// Created timestamp.
    pub created_at: u64,
    /// Updated timestamp.
    pub updated_at: u64,
}

impl StoredPlan {
    /// Create a new StoredPlan with minimal required fields.
    #[must_use]
    pub fn new(id: impl Into<String>, stripe_price_id: impl Into<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            id: id.into(),
            name: String::new(),
            description: None,
            stripe_price_id: stripe_price_id.into(),
            stripe_seat_price_id: None,
            price_cents: 0,
            currency: "usd".to_string(),
            interval: PlanInterval::Monthly,
            included_seats: 1,
            features: serde_json::json!({}),
            limits: serde_json::json!({}),
            trial_days: None,
            is_active: true,
            sort_order: 0,
            created_at: now,
            updated_at: now,
        }
    }

    /// Check if this plan has a specific feature.
    #[must_use]
    pub fn has_feature(&self, feature: &str) -> bool {
        self.features
            .get(feature)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    /// Get a feature limit value.
    #[must_use]
    pub fn get_limit(&self, limit: &str) -> Option<i64> {
        self.limits.get(limit).and_then(|v| v.as_i64())
    }

    /// Check if a resource usage is within limits.
    #[must_use]
    pub fn check_limit(&self, resource: &str, current: i64) -> bool {
        match self.get_limit(resource) {
            None => true, // No limit = unlimited
            Some(max) => current < max,
        }
    }

    /// Get the price formatted for display (e.g., "$9.99").
    #[must_use]
    pub fn formatted_price(&self) -> String {
        let symbol = match self.currency.as_str() {
            "usd" => "$",
            "gbp" => "£",
            "eur" => "€",
            _ => &self.currency,
        };
        let dollars = self.price_cents as f64 / 100.0;
        format!("{}{:.2}", symbol, dollars)
    }
}

/// Billing interval for a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanInterval {
    /// Billed monthly.
    Monthly,
    /// Billed yearly.
    Yearly,
    /// One-time payment (lifetime).
    OneTime,
}

impl PlanInterval {
    /// Convert from string.
    #[must_use]
    pub fn from_str(s: &str) -> Self {
        match s {
            "monthly" | "month" => Self::Monthly,
            "yearly" | "year" | "annual" => Self::Yearly,
            "one_time" | "onetime" | "lifetime" => Self::OneTime,
            _ => Self::Monthly,
        }
    }

    /// Convert to string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Monthly => "monthly",
            Self::Yearly => "yearly",
            Self::OneTime => "one_time",
        }
    }
}

impl std::fmt::Display for PlanInterval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Trait for storing plan data.
///
/// Implement this trait to persist plans to your database.
#[async_trait]
pub trait PlanStore: Send + Sync {
    /// Get all active plans, ordered by sort_order.
    async fn list_plans(&self) -> Result<Vec<StoredPlan>>;

    /// Get all plans (including inactive), ordered by sort_order.
    async fn list_all_plans(&self) -> Result<Vec<StoredPlan>>;

    /// Get a plan by ID.
    async fn get_plan(&self, plan_id: &str) -> Result<Option<StoredPlan>>;

    /// Get a plan by Stripe price ID.
    async fn get_plan_by_stripe_price(&self, stripe_price_id: &str) -> Result<Option<StoredPlan>>;

    /// Create a new plan.
    async fn create_plan(&self, plan: &StoredPlan) -> Result<()>;

    /// Update an existing plan.
    async fn update_plan(&self, plan: &StoredPlan) -> Result<()>;

    /// Delete a plan by ID.
    async fn delete_plan(&self, plan_id: &str) -> Result<()>;

    /// Activate or deactivate a plan.
    async fn set_plan_active(&self, plan_id: &str, is_active: bool) -> Result<()>;
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
        plans: RwLock<HashMap<String, StoredPlan>>,
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

        /// Get all plans (for testing).
        pub fn get_all_plans(&self) -> HashMap<String, StoredPlan> {
            self.inner.plans.read().unwrap().clone()
        }

        /// Seed plans for testing.
        pub fn seed_plans(&self, plans: Vec<StoredPlan>) {
            let mut store = self.inner.plans.write().unwrap();
            for plan in plans {
                store.insert(plan.id.clone(), plan);
            }
        }
    }

    #[async_trait]
    impl PlanStore for InMemoryBillingStore {
        async fn list_plans(&self) -> Result<Vec<StoredPlan>> {
            let plans = self.inner.plans.read().unwrap();
            let mut active: Vec<StoredPlan> = plans
                .values()
                .filter(|p| p.is_active)
                .cloned()
                .collect();
            active.sort_by_key(|p| p.sort_order);
            Ok(active)
        }

        async fn list_all_plans(&self) -> Result<Vec<StoredPlan>> {
            let plans = self.inner.plans.read().unwrap();
            let mut all: Vec<StoredPlan> = plans.values().cloned().collect();
            all.sort_by_key(|p| p.sort_order);
            Ok(all)
        }

        async fn get_plan(&self, plan_id: &str) -> Result<Option<StoredPlan>> {
            Ok(self.inner.plans.read().unwrap().get(plan_id).cloned())
        }

        async fn get_plan_by_stripe_price(&self, stripe_price_id: &str) -> Result<Option<StoredPlan>> {
            let plans = self.inner.plans.read().unwrap();
            Ok(plans.values().find(|p| p.stripe_price_id == stripe_price_id).cloned())
        }

        async fn create_plan(&self, plan: &StoredPlan) -> Result<()> {
            self.inner.plans.write().unwrap().insert(plan.id.clone(), plan.clone());
            Ok(())
        }

        async fn update_plan(&self, plan: &StoredPlan) -> Result<()> {
            let mut plans = self.inner.plans.write().unwrap();
            if plans.contains_key(&plan.id) {
                plans.insert(plan.id.clone(), plan.clone());
            }
            Ok(())
        }

        async fn delete_plan(&self, plan_id: &str) -> Result<()> {
            self.inner.plans.write().unwrap().remove(plan_id);
            Ok(())
        }

        async fn set_plan_active(&self, plan_id: &str, is_active: bool) -> Result<()> {
            let mut plans = self.inner.plans.write().unwrap();
            if let Some(plan) = plans.get_mut(plan_id) {
                plan.is_active = is_active;
            }
            Ok(())
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

    fn create_test_plan(id: &str, price_cents: i64, is_active: bool, sort_order: i32) -> StoredPlan {
        StoredPlan {
            id: id.to_string(),
            name: format!("{} Plan", id),
            description: Some(format!("Description for {}", id)),
            stripe_price_id: format!("price_{}", id),
            stripe_seat_price_id: None,
            price_cents,
            currency: "usd".to_string(),
            interval: PlanInterval::Monthly,
            included_seats: 1,
            features: serde_json::json!({"basic": true}),
            limits: serde_json::json!({"projects": 10}),
            trial_days: Some(14),
            is_active,
            sort_order,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[tokio::test]
    async fn test_in_memory_plan_store() {
        use test::InMemoryBillingStore;

        let store = InMemoryBillingStore::new();

        // Initially empty
        assert!(store.list_plans().await.unwrap().is_empty());
        assert!(store.list_all_plans().await.unwrap().is_empty());

        // Create plans
        let starter = create_test_plan("starter", 999, true, 1);
        let pro = create_test_plan("pro", 2999, true, 2);
        let inactive = create_test_plan("legacy", 499, false, 0);

        store.create_plan(&starter).await.unwrap();
        store.create_plan(&pro).await.unwrap();
        store.create_plan(&inactive).await.unwrap();

        // List active plans (should be sorted by sort_order)
        let active = store.list_plans().await.unwrap();
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].id, "starter");
        assert_eq!(active[1].id, "pro");

        // List all plans
        let all = store.list_all_plans().await.unwrap();
        assert_eq!(all.len(), 3);

        // Get by ID
        let plan = store.get_plan("starter").await.unwrap().unwrap();
        assert_eq!(plan.price_cents, 999);

        // Get by Stripe price
        let plan = store.get_plan_by_stripe_price("price_pro").await.unwrap().unwrap();
        assert_eq!(plan.id, "pro");

        // Update plan
        let mut updated = starter.clone();
        updated.price_cents = 1499;
        store.update_plan(&updated).await.unwrap();
        let plan = store.get_plan("starter").await.unwrap().unwrap();
        assert_eq!(plan.price_cents, 1499);

        // Set active status
        store.set_plan_active("starter", false).await.unwrap();
        let active = store.list_plans().await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, "pro");

        // Delete plan
        store.delete_plan("pro").await.unwrap();
        assert!(store.get_plan("pro").await.unwrap().is_none());
    }

    #[test]
    fn test_stored_plan_helpers() {
        let plan = StoredPlan {
            id: "test".to_string(),
            name: "Test".to_string(),
            description: None,
            stripe_price_id: "price_test".to_string(),
            stripe_seat_price_id: None,
            price_cents: 1999,
            currency: "usd".to_string(),
            interval: PlanInterval::Monthly,
            included_seats: 5,
            features: serde_json::json!({"api_access": true, "support": false}),
            limits: serde_json::json!({"projects": 50, "storage_mb": 1000}),
            trial_days: Some(14),
            is_active: true,
            sort_order: 0,
            created_at: 0,
            updated_at: 0,
        };

        // Test has_feature
        assert!(plan.has_feature("api_access"));
        assert!(!plan.has_feature("support"));
        assert!(!plan.has_feature("nonexistent"));

        // Test get_limit
        assert_eq!(plan.get_limit("projects"), Some(50));
        assert_eq!(plan.get_limit("storage_mb"), Some(1000));
        assert_eq!(plan.get_limit("nonexistent"), None);

        // Test check_limit
        assert!(plan.check_limit("projects", 49)); // under limit
        assert!(!plan.check_limit("projects", 50)); // at limit (not under)
        assert!(plan.check_limit("nonexistent", 9999)); // no limit = unlimited

        // Test formatted_price
        assert_eq!(plan.formatted_price(), "$19.99");
    }

    #[test]
    fn test_plan_interval() {
        assert_eq!(PlanInterval::from_str("monthly"), PlanInterval::Monthly);
        assert_eq!(PlanInterval::from_str("month"), PlanInterval::Monthly);
        assert_eq!(PlanInterval::from_str("yearly"), PlanInterval::Yearly);
        assert_eq!(PlanInterval::from_str("year"), PlanInterval::Yearly);
        assert_eq!(PlanInterval::from_str("annual"), PlanInterval::Yearly);
        assert_eq!(PlanInterval::from_str("one_time"), PlanInterval::OneTime);
        assert_eq!(PlanInterval::from_str("lifetime"), PlanInterval::OneTime);
        assert_eq!(PlanInterval::from_str("unknown"), PlanInterval::Monthly); // default

        assert_eq!(PlanInterval::Monthly.as_str(), "monthly");
        assert_eq!(PlanInterval::Yearly.as_str(), "yearly");
        assert_eq!(PlanInterval::OneTime.as_str(), "one_time");
    }
}
