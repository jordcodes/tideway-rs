//! Seat management for subscriptions.
//!
//! Handles adding and removing seats from subscriptions with prorated billing.
//!
//! Seat changes send an absolute quantity to Stripe, so concurrent changes to the same
//! subscription must be serialized or one of them is silently lost. Two layers handle this:
//!
//! - Within a `SeatManager`, changes for the same billable entity hold a per-entity async lock
//!   from the initial read until the local save.
//! - Across processes, each change first reserves the new seat count in the local store with
//!   `compare_and_save_subscription`. Only the caller that wins the reservation calls Stripe;
//!   the others re-read and recompute from the reserved count. A failed Stripe call releases
//!   the reservation.

use super::plans::{PlanConfig, Plans};
use super::storage::{BillingStore, StoredSubscription};
use super::subscription::{ProrationBehavior, StripeSubscriptionClient, UpdateSubscriptionRequest};
use super::validation::validate_billable_id;
use crate::error::{Result, TidewayError};
use std::collections::HashMap;
use std::sync::{Arc, Weak};

/// How many times a seat change re-reads and retries after losing a reservation race.
const MAX_RESERVATION_ATTEMPTS: usize = 5;

/// Get current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn next_subscription_version_at(current_version: u64, wall_clock: u64) -> u64 {
    wall_clock.max(current_version.saturating_add(1))
}

fn next_subscription_version(current_version: u64) -> u64 {
    next_subscription_version_at(current_version, current_timestamp())
}

/// Per-billable-entity async locks that serialize seat changes within one `SeatManager`.
#[derive(Default)]
struct SeatLocks {
    locks: std::sync::Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>,
}

impl SeatLocks {
    fn lock_for(&self, billable_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self
            .locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(lock) = locks.get(billable_id).and_then(Weak::upgrade) {
            return lock;
        }
        // Only entities with an in-flight change keep their lock alive.
        locks.retain(|_, lock| lock.strong_count() > 0);
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(billable_id.to_string(), Arc::downgrade(&lock));
        lock
    }
}

/// Requested seat change, resolved against the current subscription state.
#[derive(Clone, Copy)]
enum SeatChange {
    Add(u32),
    Remove(u32),
    Set(u32),
}

impl SeatChange {
    /// Validate the change and compute the new extra-seat count.
    fn new_extra_seats(self, sub: &StoredSubscription, plan: &PlanConfig) -> Result<u32> {
        let new_count = match self {
            Self::Add(count) => {
                ensure_extra_seats_supported(plan)?;
                sub.extra_seats.checked_add(count).ok_or_else(|| {
                    TidewayError::BadRequest(format!(
                        "Cannot add {} seats to {} extra seats: seat count is too large",
                        count, sub.extra_seats
                    ))
                })?
            }
            Self::Remove(count) => {
                if count > sub.extra_seats {
                    return Err(TidewayError::BadRequest(format!(
                        "Cannot remove {} seats, only {} extra seats on subscription",
                        count, sub.extra_seats
                    )));
                }
                sub.extra_seats - count
            }
            Self::Set(count) => {
                ensure_extra_seats_supported(plan)?;
                count
            }
        };

        if plan.included_seats.checked_add(new_count).is_none() {
            return Err(TidewayError::BadRequest(format!(
                "Seat count {} is too large for a plan with {} included seats",
                new_count, plan.included_seats
            )));
        }

        Ok(new_count)
    }
}

fn ensure_extra_seats_supported(plan: &PlanConfig) -> Result<()> {
    if plan.extra_seat_price_id.is_none() {
        return Err(TidewayError::BadRequest(
            "Plan does not support extra seats".to_string(),
        ));
    }
    Ok(())
}

fn seat_change_result(plan: &PlanConfig, previous_seats: u32, new_seats: u32) -> SeatChangeResult {
    SeatChangeResult {
        previous_seats,
        new_seats,
        total_seats: plan.included_seats.saturating_add(new_seats),
    }
}

/// Seat management operations.
///
/// Handles adding/removing seats with Stripe proration. Concurrent changes for the same
/// billable entity are serialized (see the module docs).
pub struct SeatManager<S: BillingStore, C: StripeSubscriptionClient> {
    store: S,
    client: C,
    plans: Plans,
    locks: SeatLocks,
}

impl<S: BillingStore, C: StripeSubscriptionClient> SeatManager<S, C> {
    /// Create a new seat manager.
    #[must_use]
    pub fn new(store: S, client: C, plans: Plans) -> Self {
        Self {
            store,
            client,
            plans,
            locks: SeatLocks::default(),
        }
    }

    async fn load_subscription(
        &self,
        billable_id: &str,
    ) -> Result<(StoredSubscription, &PlanConfig)> {
        let sub = self
            .store
            .get_subscription(billable_id)
            .await?
            .ok_or_else(|| TidewayError::NotFound("No subscription found".to_string()))?;

        let plan = self
            .plans
            .get(&sub.plan_id)
            .ok_or_else(|| TidewayError::NotFound("Plan not found".to_string()))?;

        Ok((sub, plan))
    }

    /// Apply a seat change: reserve it locally, update Stripe, then confirm locally.
    async fn change_seats(
        &self,
        billable_id: &str,
        change: SeatChange,
    ) -> Result<SeatChangeResult> {
        let lock = self.locks.lock_for(billable_id);
        let _guard = lock.lock().await;

        for _ in 0..MAX_RESERVATION_ATTEMPTS {
            let (sub, plan) = self.load_subscription(billable_id).await?;
            let new_count = change.new_extra_seats(&sub, plan)?;

            if new_count == sub.extra_seats {
                return Ok(seat_change_result(plan, sub.extra_seats, new_count));
            }

            // Reserve the new count before calling Stripe so any concurrent change that read
            // the same snapshot fails its reservation and recomputes from this one.
            let mut reserved = sub.clone();
            reserved.extra_seats = new_count;
            reserved.updated_at = next_subscription_version(sub.updated_at);
            if !self
                .store
                .compare_and_save_subscription(billable_id, &reserved, sub.updated_at)
                .await?
            {
                tracing::debug!(
                    billable_id = %billable_id,
                    "Seat reservation lost to a concurrent change; retrying"
                );
                continue;
            }

            let updated = match self
                .client
                .update_subscription(
                    &sub.stripe_subscription_id,
                    UpdateSubscriptionRequest {
                        seat_price_id: plan.extra_seat_price_id.clone(),
                        seat_quantity: Some(new_count),
                        proration_behavior: Some(ProrationBehavior::CreateProrations),
                        ..Default::default()
                    },
                )
                .await
            {
                Ok(updated) => updated,
                Err(err) => {
                    self.release_reservation(billable_id, &sub, &reserved).await;
                    return Err(err);
                }
            };

            // Save locally - this handles reconciliation if version conflict occurs
            return self
                .save_seat_update_after_stripe(
                    billable_id,
                    &sub,
                    plan,
                    updated.extra_seats,
                    reserved.updated_at,
                )
                .await;
        }

        Err(TidewayError::Conflict(
            "Seats on this subscription are being changed concurrently. Please retry.".to_string(),
        ))
    }

    /// Restore the pre-reservation seat count after a failed Stripe update.
    async fn release_reservation(
        &self,
        billable_id: &str,
        original: &StoredSubscription,
        reserved: &StoredSubscription,
    ) {
        let mut restored = original.clone();
        restored.updated_at = next_subscription_version(reserved.updated_at);

        match self
            .store
            .compare_and_save_subscription(billable_id, &restored, reserved.updated_at)
            .await
        {
            Ok(true) => {}
            Ok(false) => tracing::warn!(
                billable_id = %billable_id,
                "Seat reservation was superseded before it could be released"
            ),
            Err(err) => tracing::error!(
                billable_id = %billable_id,
                error = %err,
                "Failed to release seat reservation after Stripe error. \
                 A webhook should reconcile this, or manual intervention may be needed."
            ),
        }
    }

    /// Save seat update to local store after successful Stripe update.
    ///
    /// Handles version conflict reconciliation. Returns Ok if saved successfully
    /// or if state is already consistent. Returns Err if reconciliation fails.
    async fn save_seat_update_after_stripe(
        &self,
        billable_id: &str,
        sub: &StoredSubscription,
        plan: &PlanConfig,
        updated_extra_seats: u32,
        reserved_version: u64,
    ) -> Result<SeatChangeResult> {
        let mut updated_sub = sub.clone();
        updated_sub.extra_seats = updated_extra_seats;
        updated_sub.updated_at = next_subscription_version(reserved_version);

        let saved = self
            .store
            .compare_and_save_subscription(billable_id, &updated_sub, reserved_version)
            .await?;

        if saved {
            return Ok(seat_change_result(
                plan,
                sub.extra_seats,
                updated_extra_seats,
            ));
        }

        // Version conflict after Stripe success - try to reconcile
        // Re-read to check if another process (e.g., webhook) already updated the state
        if let Some(current) = self.store.get_subscription(billable_id).await?
            && current.extra_seats == updated_extra_seats
        {
            // State is already consistent (likely updated by webhook)
            tracing::debug!(
                billable_id = %billable_id,
                "Local state already matches Stripe after version conflict"
            );
            return Ok(seat_change_result(
                plan,
                sub.extra_seats,
                current.extra_seats,
            ));
        }

        // Local state differs from Stripe - this shouldn't happen normally.
        // Log and fail rather than risk inconsistent state.
        tracing::error!(
            billable_id = %billable_id,
            stripe_subscription_id = %sub.stripe_subscription_id,
            expected_seats = updated_extra_seats,
            "Stripe update succeeded but local save failed - state may be inconsistent. \
             A webhook should reconcile this, or manual intervention may be needed."
        );

        Err(TidewayError::Internal(
            "Seat update succeeded in Stripe but local state update failed. \
             Please retry or contact support if the issue persists."
                .to_string(),
        ))
    }

    /// Get seat information for a subscription.
    pub async fn get_seat_info(&self, billable_id: &str) -> Result<SeatInfo> {
        validate_billable_id(billable_id)?;

        let (sub, plan) = self.load_subscription(billable_id).await?;

        Ok(SeatInfo {
            included_seats: plan.included_seats,
            extra_seats: sub.extra_seats,
            total_seats: plan.included_seats.saturating_add(sub.extra_seats),
            can_add_seats: plan.extra_seat_price_id.is_some(),
        })
    }

    /// Check if there is a seat available.
    ///
    /// Returns true if `current_member_count < total_seats`.
    pub async fn has_seat_available(
        &self,
        billable_id: &str,
        current_member_count: u32,
    ) -> Result<bool> {
        // Note: get_seat_info already validates billable_id
        let seat_info = self.get_seat_info(billable_id).await?;
        Ok(current_member_count < seat_info.total_seats)
    }

    /// Add seats to a subscription.
    ///
    /// This will update the subscription in Stripe and prorate the charge.
    /// Concurrent seat changes for the same billable entity are serialized.
    pub async fn add_seats(&self, billable_id: &str, count: u32) -> Result<SeatChangeResult> {
        validate_billable_id(billable_id)?;

        if count == 0 {
            return Err(TidewayError::BadRequest(
                "Must add at least 1 seat".to_string(),
            ));
        }

        self.change_seats(billable_id, SeatChange::Add(count)).await
    }

    /// Remove seats from a subscription.
    ///
    /// Cannot reduce below 0 extra seats. This will credit the account via proration.
    /// Concurrent seat changes for the same billable entity are serialized.
    pub async fn remove_seats(&self, billable_id: &str, count: u32) -> Result<SeatChangeResult> {
        validate_billable_id(billable_id)?;

        if count == 0 {
            return Err(TidewayError::BadRequest(
                "Must remove at least 1 seat".to_string(),
            ));
        }

        self.change_seats(billable_id, SeatChange::Remove(count))
            .await
    }

    /// Set seats to a specific count.
    ///
    /// More convenient than add/remove for absolute seat management.
    /// Concurrent seat changes for the same billable entity are serialized.
    pub async fn set_seats(&self, billable_id: &str, count: u32) -> Result<SeatChangeResult> {
        validate_billable_id(billable_id)?;

        self.change_seats(billable_id, SeatChange::Set(count)).await
    }
}

/// Information about seats on a subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct SeatInfo {
    /// Seats included in the base plan.
    pub included_seats: u32,
    /// Extra seats purchased.
    pub extra_seats: u32,
    /// Total seats available.
    pub total_seats: u32,
    /// Whether more seats can be added.
    pub can_add_seats: bool,
}

/// Result of a seat change operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct SeatChangeResult {
    /// Previous number of extra seats.
    pub previous_seats: u32,
    /// New number of extra seats.
    pub new_seats: u32,
    /// Total seats now available.
    pub total_seats: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::storage::test::InMemoryBillingStore;
    use crate::billing::storage::{BillingStore, StoredSubscription, SubscriptionStatus};
    use crate::billing::subscription::StripeSubscriptionData;
    use crate::billing::subscription::SubscriptionMetadata;
    use crate::billing::subscription::test::MockStripeSubscriptionClient;

    fn create_test_plans() -> Plans {
        Plans::builder()
            .plan("starter")
            .stripe_price("price_starter")
            .extra_seat_price("price_seat")
            .included_seats(3)
            .done()
            .unwrap()
            .plan("basic")
            .stripe_price("price_basic")
            .included_seats(1)
            .done()
            .unwrap()
            .build()
            .unwrap()
    }

    fn create_test_subscription(
        billable_id: &str,
        plan_id: &str,
        extra_seats: u32,
    ) -> StoredSubscription {
        StoredSubscription {
            stripe_subscription_id: format!("sub_{}", billable_id),
            stripe_customer_id: format!("cus_{}", billable_id),
            plan_id: plan_id.to_string(),
            status: SubscriptionStatus::Active,
            current_period_start: 1700000000,
            current_period_end: 1702592000,
            extra_seats,
            trial_end: None,
            cancel_at_period_end: false,
            base_item_id: Some("si_base".to_string()),
            seat_item_id: Some("si_seat".to_string()),
            updated_at: 1700000000,
        }
    }

    #[tokio::test]
    async fn test_get_seat_info() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        // Add subscription
        let sub = create_test_subscription("org_123", "starter", 2);
        store.save_subscription("org_123", &sub).await.unwrap();

        let manager = SeatManager::new(store, client, plans);

        let info = manager.get_seat_info("org_123").await.unwrap();
        assert_eq!(info.included_seats, 3);
        assert_eq!(info.extra_seats, 2);
        assert_eq!(info.total_seats, 5);
        assert!(info.can_add_seats);
    }

    #[tokio::test]
    async fn test_get_seat_info_no_extra_seats_support() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        // Add subscription on basic plan (no extra seats)
        let sub = create_test_subscription("org_456", "basic", 0);
        store.save_subscription("org_456", &sub).await.unwrap();

        let manager = SeatManager::new(store, client, plans);

        let info = manager.get_seat_info("org_456").await.unwrap();
        assert_eq!(info.included_seats, 1);
        assert_eq!(info.extra_seats, 0);
        assert_eq!(info.total_seats, 1);
        assert!(!info.can_add_seats);
    }

    #[tokio::test]
    async fn test_has_seat_available() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        let sub = create_test_subscription("org_789", "starter", 2);
        store.save_subscription("org_789", &sub).await.unwrap();

        let manager = SeatManager::new(store, client, plans);

        // Total seats = 5 (3 included + 2 extra)
        assert!(manager.has_seat_available("org_789", 4).await.unwrap());
        assert!(!manager.has_seat_available("org_789", 5).await.unwrap());
        assert!(!manager.has_seat_available("org_789", 6).await.unwrap());
    }

    #[tokio::test]
    async fn test_add_seats() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        let sub = create_test_subscription("org_add", "starter", 2);
        store.save_subscription("org_add", &sub).await.unwrap();

        // Set up mock client to return updated subscription
        client.add_subscription(StripeSubscriptionData {
            id: "sub_org_add".to_string(),
            customer_id: "cus_org_add".to_string(),
            plan_id: "starter".to_string(),
            status: "active".to_string(),
            current_period_start: 1700000000,
            current_period_end: 1702592000,
            extra_seats: 5, // Will be updated by mock
            trial_end: None,
            cancel_at_period_end: false,
            base_item_id: Some("si_base".to_string()),
            seat_item_id: Some("si_seat".to_string()),
            metadata: SubscriptionMetadata::default(),
        });

        let manager = SeatManager::new(store.clone(), client, plans);

        let result = manager.add_seats("org_add", 3).await.unwrap();
        assert_eq!(result.previous_seats, 2);
        assert_eq!(result.new_seats, 5);
        assert_eq!(result.total_seats, 8); // 3 included + 5 extra
    }

    #[tokio::test]
    async fn test_add_seats_zero() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        let sub = create_test_subscription("org_zero", "starter", 2);
        store.save_subscription("org_zero", &sub).await.unwrap();

        let manager = SeatManager::new(store, client, plans);

        let result = manager.add_seats("org_zero", 0).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_add_seats_no_support() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        let sub = create_test_subscription("org_basic", "basic", 0);
        store.save_subscription("org_basic", &sub).await.unwrap();

        let manager = SeatManager::new(store, client, plans);

        let result = manager.add_seats("org_basic", 1).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_remove_seats() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        let sub = create_test_subscription("org_remove", "starter", 5);
        store.save_subscription("org_remove", &sub).await.unwrap();

        client.add_subscription(StripeSubscriptionData {
            id: "sub_org_remove".to_string(),
            customer_id: "cus_org_remove".to_string(),
            plan_id: "starter".to_string(),
            status: "active".to_string(),
            current_period_start: 1700000000,
            current_period_end: 1702592000,
            extra_seats: 2, // Will be updated
            trial_end: None,
            cancel_at_period_end: false,
            base_item_id: Some("si_base".to_string()),
            seat_item_id: Some("si_seat".to_string()),
            metadata: SubscriptionMetadata::default(),
        });

        let manager = SeatManager::new(store, client, plans);

        let result = manager.remove_seats("org_remove", 3).await.unwrap();
        assert_eq!(result.previous_seats, 5);
        assert_eq!(result.new_seats, 2);
        assert_eq!(result.total_seats, 5); // 3 included + 2 extra
    }

    #[tokio::test]
    async fn test_remove_seats_too_many() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        let sub = create_test_subscription("org_too_many", "starter", 2);
        store.save_subscription("org_too_many", &sub).await.unwrap();

        let manager = SeatManager::new(store, client, plans);

        let result = manager.remove_seats("org_too_many", 5).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_set_seats() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        let sub = create_test_subscription("org_set", "starter", 2);
        store.save_subscription("org_set", &sub).await.unwrap();

        client.add_subscription(StripeSubscriptionData {
            id: "sub_org_set".to_string(),
            customer_id: "cus_org_set".to_string(),
            plan_id: "starter".to_string(),
            status: "active".to_string(),
            current_period_start: 1700000000,
            current_period_end: 1702592000,
            extra_seats: 10,
            trial_end: None,
            cancel_at_period_end: false,
            base_item_id: Some("si_base".to_string()),
            seat_item_id: Some("si_seat".to_string()),
            metadata: SubscriptionMetadata::default(),
        });

        let manager = SeatManager::new(store, client, plans);

        let result = manager.set_seats("org_set", 10).await.unwrap();
        assert_eq!(result.previous_seats, 2);
        assert_eq!(result.new_seats, 10);
        assert_eq!(result.total_seats, 13);
    }

    #[tokio::test]
    async fn test_set_first_extra_seat_includes_seat_price() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        let mut sub = create_test_subscription("org_first_seat", "starter", 0);
        sub.seat_item_id = None;
        store
            .save_subscription("org_first_seat", &sub)
            .await
            .unwrap();

        client.add_subscription(StripeSubscriptionData {
            id: "sub_org_first_seat".to_string(),
            customer_id: "cus_org_first_seat".to_string(),
            plan_id: "starter".to_string(),
            status: "active".to_string(),
            current_period_start: 1700000000,
            current_period_end: 1702592000,
            extra_seats: 0,
            trial_end: None,
            cancel_at_period_end: false,
            base_item_id: Some("si_base".to_string()),
            seat_item_id: None,
            metadata: SubscriptionMetadata::default(),
        });

        let manager = SeatManager::new(store, client.clone(), plans);
        let _result = manager.set_seats("org_first_seat", 1).await.unwrap();

        let update = client.last_update().expect("seat update request");
        assert_eq!(update.seat_quantity, Some(1));
        assert_eq!(update.seat_price_id.as_deref(), Some("price_seat"));
    }

    #[tokio::test]
    async fn test_set_seats_no_change() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        let sub = create_test_subscription("org_same", "starter", 5);
        store.save_subscription("org_same", &sub).await.unwrap();

        let manager = SeatManager::new(store, client, plans);

        // Setting to same value should return immediately without calling Stripe
        let result = manager.set_seats("org_same", 5).await.unwrap();
        assert_eq!(result.previous_seats, 5);
        assert_eq!(result.new_seats, 5);
        assert_eq!(result.total_seats, 8);
    }

    #[tokio::test]
    async fn test_compare_and_save_subscription() {
        let store = InMemoryBillingStore::new();

        let sub = create_test_subscription("org_cas", "starter", 2);
        store.save_subscription("org_cas", &sub).await.unwrap();

        // Modify with correct version should succeed
        let mut updated = sub.clone();
        updated.extra_seats = 5;
        updated.updated_at = 1700000001;

        let result = store
            .compare_and_save_subscription("org_cas", &updated, sub.updated_at)
            .await
            .unwrap();
        assert!(result);

        // Verify the update was saved
        let loaded = store.get_subscription("org_cas").await.unwrap().unwrap();
        assert_eq!(loaded.extra_seats, 5);

        // Modify with wrong version should fail
        let mut another = loaded.clone();
        another.extra_seats = 10;

        let result = store
            .compare_and_save_subscription("org_cas", &another, sub.updated_at)
            .await
            .unwrap();
        assert!(!result);

        // Verify the update was not saved
        let loaded = store.get_subscription("org_cas").await.unwrap().unwrap();
        assert_eq!(loaded.extra_seats, 5); // Still 5, not 10
    }

    /// Store wrapper that holds the first two subscription reads until both have arrived (or a
    /// short timeout passes), forcing concurrent seat changes to start from the same snapshot.
    #[derive(Clone)]
    struct RendezvousStore {
        inner: InMemoryBillingStore,
        arrivals: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl RendezvousStore {
        fn new(inner: InMemoryBillingStore) -> Self {
            Self {
                inner,
                arrivals: Default::default(),
            }
        }
    }

    #[async_trait::async_trait]
    impl BillingStore for RendezvousStore {
        async fn get_stripe_customer_id(&self, billable_id: &str) -> Result<Option<String>> {
            self.inner.get_stripe_customer_id(billable_id).await
        }

        async fn set_stripe_customer_id(
            &self,
            billable_id: &str,
            billable_type: &str,
            customer_id: &str,
        ) -> Result<()> {
            self.inner
                .set_stripe_customer_id(billable_id, billable_type, customer_id)
                .await
        }

        async fn get_subscription(&self, billable_id: &str) -> Result<Option<StoredSubscription>> {
            use std::sync::atomic::Ordering;
            let snapshot = self.inner.get_subscription(billable_id).await?;
            if self.arrivals.fetch_add(1, Ordering::SeqCst) < 2 {
                for _ in 0..20 {
                    if self.arrivals.load(Ordering::SeqCst) >= 2 {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
            Ok(snapshot)
        }

        async fn save_subscription(
            &self,
            billable_id: &str,
            subscription: &StoredSubscription,
        ) -> Result<()> {
            self.inner
                .save_subscription(billable_id, subscription)
                .await
        }

        async fn compare_and_save_subscription(
            &self,
            billable_id: &str,
            subscription: &StoredSubscription,
            expected_version: u64,
        ) -> Result<bool> {
            self.inner
                .compare_and_save_subscription(billable_id, subscription, expected_version)
                .await
        }

        async fn delete_subscription(&self, billable_id: &str) -> Result<()> {
            self.inner.delete_subscription(billable_id).await
        }

        async fn get_subscription_by_stripe_id(
            &self,
            stripe_subscription_id: &str,
        ) -> Result<Option<(String, StoredSubscription)>> {
            self.inner
                .get_subscription_by_stripe_id(stripe_subscription_id)
                .await
        }

        async fn is_event_processed(&self, event_id: &str) -> Result<bool> {
            self.inner.is_event_processed(event_id).await
        }

        async fn mark_event_processed(&self, event_id: &str) -> Result<()> {
            self.inner.mark_event_processed(event_id).await
        }

        async fn count_subscriptions_by_plan(&self, plan_id: &str) -> Result<u32> {
            self.inner.count_subscriptions_by_plan(plan_id).await
        }
    }

    fn stripe_subscription(billable_id: &str, extra_seats: u32) -> StripeSubscriptionData {
        StripeSubscriptionData {
            id: format!("sub_{}", billable_id),
            customer_id: format!("cus_{}", billable_id),
            plan_id: "starter".to_string(),
            status: "active".to_string(),
            current_period_start: 1700000000,
            current_period_end: 1702592000,
            extra_seats,
            trial_end: None,
            cancel_at_period_end: false,
            base_item_id: Some("si_base".to_string()),
            seat_item_id: Some("si_seat".to_string()),
            metadata: SubscriptionMetadata::default(),
        }
    }

    async fn assert_seats(
        store: &InMemoryBillingStore,
        client: &MockStripeSubscriptionClient,
        billable_id: &str,
        expected: u32,
    ) {
        let local = store.get_subscription(billable_id).await.unwrap().unwrap();
        assert_eq!(local.extra_seats, expected, "local extra seats");
        let stripe = client
            .get_subscription(&format!("sub_{}", billable_id))
            .await
            .unwrap();
        assert_eq!(stripe.extra_seats, expected, "Stripe extra seats");
    }

    /// Two concurrent single-seat adds from 2 extra seats must apply one after the other.
    fn assert_serialized(first: SeatChangeResult, second: SeatChangeResult) {
        let mut transitions = [
            (first.previous_seats, first.new_seats),
            (second.previous_seats, second.new_seats),
        ];
        transitions.sort_unstable();
        assert_eq!(transitions, [(2, 3), (3, 4)]);
    }

    #[tokio::test]
    async fn concurrent_add_seats_on_one_manager_do_not_lose_updates() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let sub = create_test_subscription("org_race", "starter", 2);
        store.save_subscription("org_race", &sub).await.unwrap();
        client.add_subscription(stripe_subscription("org_race", 2));

        let manager = SeatManager::new(
            RendezvousStore::new(store.clone()),
            client.clone(),
            create_test_plans(),
        );

        let (first, second) = tokio::join!(
            manager.add_seats("org_race", 1),
            manager.add_seats("org_race", 1)
        );
        assert_serialized(first.unwrap(), second.unwrap());

        assert_seats(&store, &client, "org_race", 4).await;
    }

    #[tokio::test]
    async fn concurrent_add_seats_across_managers_do_not_lose_updates() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let sub = create_test_subscription("org_race_multi", "starter", 2);
        store
            .save_subscription("org_race_multi", &sub)
            .await
            .unwrap();
        client.add_subscription(stripe_subscription("org_race_multi", 2));

        // Separate managers model separate processes: no shared in-process lock.
        let shared_store = RendezvousStore::new(store.clone());
        let first_manager =
            SeatManager::new(shared_store.clone(), client.clone(), create_test_plans());
        let second_manager = SeatManager::new(shared_store, client.clone(), create_test_plans());

        let (first, second) = tokio::join!(
            first_manager.add_seats("org_race_multi", 1),
            second_manager.add_seats("org_race_multi", 1)
        );
        assert_serialized(first.unwrap(), second.unwrap());

        assert_seats(&store, &client, "org_race_multi", 4).await;
    }

    #[tokio::test]
    async fn add_seats_rejects_extra_seat_overflow_before_calling_stripe() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let sub = create_test_subscription("org_overflow", "starter", u32::MAX - 1);
        store.save_subscription("org_overflow", &sub).await.unwrap();
        client.add_subscription(stripe_subscription("org_overflow", u32::MAX - 1));

        let manager = SeatManager::new(store.clone(), client.clone(), create_test_plans());

        let err = manager.add_seats("org_overflow", 5).await.unwrap_err();
        assert!(matches!(err, crate::error::TidewayError::BadRequest(_)));
        assert!(client.last_update().is_none());
        let local = store
            .get_subscription("org_overflow")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(local.extra_seats, u32::MAX - 1);
    }

    #[tokio::test]
    async fn set_seats_rejects_total_seat_overflow_before_calling_stripe() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let sub = create_test_subscription("org_total_overflow", "starter", 2);
        store
            .save_subscription("org_total_overflow", &sub)
            .await
            .unwrap();
        client.add_subscription(stripe_subscription("org_total_overflow", 2));

        let manager = SeatManager::new(store.clone(), client.clone(), create_test_plans());

        // 3 included + u32::MAX extra overflows the total.
        let err = manager
            .set_seats("org_total_overflow", u32::MAX)
            .await
            .unwrap_err();
        assert!(matches!(err, crate::error::TidewayError::BadRequest(_)));
        assert!(client.last_update().is_none());
    }

    #[tokio::test]
    async fn get_seat_info_saturates_total_for_out_of_range_stored_seats() {
        let store = InMemoryBillingStore::new();
        let sub = create_test_subscription("org_huge", "starter", u32::MAX);
        store.save_subscription("org_huge", &sub).await.unwrap();

        let manager = SeatManager::new(
            store,
            MockStripeSubscriptionClient::new(),
            create_test_plans(),
        );

        let info = manager.get_seat_info("org_huge").await.unwrap();
        assert_eq!(info.total_seats, u32::MAX);
    }

    #[tokio::test]
    async fn failed_stripe_update_restores_local_seats() {
        let store = InMemoryBillingStore::new();
        // No Stripe subscription registered, so the update fails.
        let client = MockStripeSubscriptionClient::new();
        let sub = create_test_subscription("org_stripe_fail", "starter", 2);
        store
            .save_subscription("org_stripe_fail", &sub)
            .await
            .unwrap();

        let manager = SeatManager::new(store.clone(), client, create_test_plans());

        assert!(manager.add_seats("org_stripe_fail", 3).await.is_err());

        let local = store
            .get_subscription("org_stripe_fail")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(local.extra_seats, 2);

        // A later change still works from the restored state.
        assert!(manager.remove_seats("org_stripe_fail", 1).await.is_err());
        let local = store
            .get_subscription("org_stripe_fail")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(local.extra_seats, 2);
    }

    #[test]
    fn subscription_version_advances_when_updates_share_a_clock_tick() {
        assert_eq!(
            next_subscription_version_at(1_700_000_000, 1_700_000_000),
            1_700_000_001
        );
    }
}
