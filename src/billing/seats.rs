//! Seat management for subscriptions.
//!
//! Handles adding and removing seats from subscriptions with prorated billing.

use crate::error::Result;
use super::plans::Plans;
use super::storage::BillingStore;
use super::subscription::{StripeSubscriptionClient, UpdateSubscriptionRequest, ProrationBehavior};
use super::validation::validate_billable_id;

/// Maximum number of retries for optimistic locking conflicts.
const MAX_RETRIES: u32 = 3;

/// Get current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Seat management operations.
///
/// Handles adding/removing seats with Stripe proration.
pub struct SeatManager<S: BillingStore, C: StripeSubscriptionClient> {
    store: S,
    client: C,
    plans: Plans,
}

impl<S: BillingStore, C: StripeSubscriptionClient> SeatManager<S, C> {
    /// Create a new seat manager.
    #[must_use]
    pub fn new(store: S, client: C, plans: Plans) -> Self {
        Self { store, client, plans }
    }

    /// Get seat information for a subscription.
    pub async fn get_seat_info(&self, billable_id: &str) -> Result<SeatInfo> {
        validate_billable_id(billable_id)?;

        let sub = self.store.get_subscription(billable_id).await?
            .ok_or_else(|| crate::error::TidewayError::NotFound(
                "No subscription found".to_string()
            ))?;

        let plan = self.plans.get(&sub.plan_id)
            .ok_or_else(|| crate::error::TidewayError::NotFound(
                "Plan not found".to_string()
            ))?;

        Ok(SeatInfo {
            included_seats: plan.included_seats,
            extra_seats: sub.extra_seats,
            total_seats: plan.included_seats + sub.extra_seats,
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
    /// Uses optimistic locking to prevent race conditions with concurrent requests.
    pub async fn add_seats(
        &self,
        billable_id: &str,
        count: u32,
    ) -> Result<SeatChangeResult> {
        validate_billable_id(billable_id)?;

        if count == 0 {
            return Err(crate::error::TidewayError::BadRequest(
                "Must add at least 1 seat".to_string()
            ));
        }

        for _attempt in 0..MAX_RETRIES {
            let sub = self.store.get_subscription(billable_id).await?
                .ok_or_else(|| crate::error::TidewayError::NotFound(
                    "No subscription found".to_string()
                ))?;

            let plan = self.plans.get(&sub.plan_id)
                .ok_or_else(|| crate::error::TidewayError::NotFound(
                    "Plan not found".to_string()
                ))?;

            if plan.extra_seat_price_id.is_none() {
                return Err(crate::error::TidewayError::BadRequest(
                    "Plan does not support extra seats".to_string()
                ));
            }

            let original_version = sub.updated_at;
            let new_seat_count = sub.extra_seats + count;

            // Update in Stripe
            let updated = self.client.update_subscription(
                &sub.stripe_subscription_id,
                UpdateSubscriptionRequest {
                    seat_quantity: Some(new_seat_count),
                    proration_behavior: Some(ProrationBehavior::CreateProrations),
                    ..Default::default()
                },
            ).await?;

            // IMPORTANT: Stripe update succeeded. We must now save locally.
            // If local save fails, we MUST NOT retry the Stripe call.
            let mut updated_sub = sub.clone();
            updated_sub.extra_seats = updated.extra_seats;
            updated_sub.updated_at = current_timestamp();

            let saved = self.store.compare_and_save_subscription(
                billable_id,
                &updated_sub,
                original_version,
            ).await?;

            if saved {
                return Ok(SeatChangeResult {
                    previous_seats: sub.extra_seats,
                    new_seats: updated.extra_seats,
                    total_seats: plan.included_seats + updated.extra_seats,
                });
            }

            // Version conflict after Stripe success - try to reconcile
            // Re-read to check if another process (e.g., webhook) already updated the state
            if let Some(current) = self.store.get_subscription(billable_id).await? {
                if current.extra_seats == updated.extra_seats {
                    // State is already consistent (likely updated by webhook)
                    tracing::debug!(
                        billable_id = %billable_id,
                        "Local state already matches Stripe after version conflict"
                    );
                    return Ok(SeatChangeResult {
                        previous_seats: sub.extra_seats,
                        new_seats: current.extra_seats,
                        total_seats: plan.included_seats + current.extra_seats,
                    });
                }
            }

            // If this is not the last attempt and local state differs from what we
            // sent to Stripe, we have a problem. Another concurrent request may have
            // changed the seats. Log this and fail rather than risk double-charging.
            tracing::error!(
                billable_id = %billable_id,
                stripe_subscription_id = %sub.stripe_subscription_id,
                expected_seats = new_seat_count,
                "Stripe update succeeded but local save failed - state may be inconsistent. \
                 A webhook should reconcile this, or manual intervention may be needed."
            );

            // Don't retry - we already charged the customer in Stripe
            return Err(crate::error::TidewayError::Internal(
                "Seat update succeeded in Stripe but local state update failed. \
                 Please retry or contact support if the issue persists.".to_string()
            ));
        }

        Err(crate::error::TidewayError::Internal(
            "Failed to update seats after multiple retries due to concurrent modifications".to_string()
        ))
    }

    /// Remove seats from a subscription.
    ///
    /// Cannot reduce below 0 extra seats. This will credit the account via proration.
    /// Uses optimistic locking to prevent race conditions with concurrent requests.
    pub async fn remove_seats(
        &self,
        billable_id: &str,
        count: u32,
    ) -> Result<SeatChangeResult> {
        validate_billable_id(billable_id)?;

        if count == 0 {
            return Err(crate::error::TidewayError::BadRequest(
                "Must remove at least 1 seat".to_string()
            ));
        }

        for _attempt in 0..MAX_RETRIES {
            let sub = self.store.get_subscription(billable_id).await?
                .ok_or_else(|| crate::error::TidewayError::NotFound(
                    "No subscription found".to_string()
                ))?;

            let plan = self.plans.get(&sub.plan_id)
                .ok_or_else(|| crate::error::TidewayError::NotFound(
                    "Plan not found".to_string()
                ))?;

            if count > sub.extra_seats {
                return Err(crate::error::TidewayError::BadRequest(
                    format!("Cannot remove {} seats, only {} extra seats on subscription", count, sub.extra_seats)
                ));
            }

            let original_version = sub.updated_at;
            let new_seat_count = sub.extra_seats - count;

            // Update in Stripe
            let updated = self.client.update_subscription(
                &sub.stripe_subscription_id,
                UpdateSubscriptionRequest {
                    seat_quantity: Some(new_seat_count),
                    proration_behavior: Some(ProrationBehavior::CreateProrations),
                    ..Default::default()
                },
            ).await?;

            // IMPORTANT: Stripe update succeeded. We must now save locally.
            // If local save fails, we MUST NOT retry the Stripe call.
            let mut updated_sub = sub.clone();
            updated_sub.extra_seats = updated.extra_seats;
            updated_sub.updated_at = current_timestamp();

            let saved = self.store.compare_and_save_subscription(
                billable_id,
                &updated_sub,
                original_version,
            ).await?;

            if saved {
                return Ok(SeatChangeResult {
                    previous_seats: sub.extra_seats,
                    new_seats: updated.extra_seats,
                    total_seats: plan.included_seats + updated.extra_seats,
                });
            }

            // Version conflict after Stripe success - try to reconcile
            if let Some(current) = self.store.get_subscription(billable_id).await? {
                if current.extra_seats == updated.extra_seats {
                    tracing::debug!(
                        billable_id = %billable_id,
                        "Local state already matches Stripe after version conflict"
                    );
                    return Ok(SeatChangeResult {
                        previous_seats: sub.extra_seats,
                        new_seats: current.extra_seats,
                        total_seats: plan.included_seats + current.extra_seats,
                    });
                }
            }

            tracing::error!(
                billable_id = %billable_id,
                stripe_subscription_id = %sub.stripe_subscription_id,
                expected_seats = new_seat_count,
                "Stripe update succeeded but local save failed - state may be inconsistent."
            );

            return Err(crate::error::TidewayError::Internal(
                "Seat update succeeded in Stripe but local state update failed. \
                 Please retry or contact support if the issue persists.".to_string()
            ));
        }

        Err(crate::error::TidewayError::Internal(
            "Failed to update seats after multiple retries due to concurrent modifications".to_string()
        ))
    }

    /// Set seats to a specific count.
    ///
    /// More convenient than add/remove for absolute seat management.
    /// Uses optimistic locking to prevent race conditions with concurrent requests.
    pub async fn set_seats(
        &self,
        billable_id: &str,
        count: u32,
    ) -> Result<SeatChangeResult> {
        validate_billable_id(billable_id)?;

        for _attempt in 0..MAX_RETRIES {
            let sub = self.store.get_subscription(billable_id).await?
                .ok_or_else(|| crate::error::TidewayError::NotFound(
                    "No subscription found".to_string()
                ))?;

            let plan = self.plans.get(&sub.plan_id)
                .ok_or_else(|| crate::error::TidewayError::NotFound(
                    "Plan not found".to_string()
                ))?;

            if plan.extra_seat_price_id.is_none() {
                return Err(crate::error::TidewayError::BadRequest(
                    "Plan does not support extra seats".to_string()
                ));
            }

            if count == sub.extra_seats {
                return Ok(SeatChangeResult {
                    previous_seats: sub.extra_seats,
                    new_seats: count,
                    total_seats: plan.included_seats + count,
                });
            }

            let original_version = sub.updated_at;

            // Update in Stripe
            let updated = self.client.update_subscription(
                &sub.stripe_subscription_id,
                UpdateSubscriptionRequest {
                    seat_quantity: Some(count),
                    proration_behavior: Some(ProrationBehavior::CreateProrations),
                    ..Default::default()
                },
            ).await?;

            // IMPORTANT: Stripe update succeeded. We must now save locally.
            // If local save fails, we MUST NOT retry the Stripe call.
            let mut updated_sub = sub.clone();
            updated_sub.extra_seats = updated.extra_seats;
            updated_sub.updated_at = current_timestamp();

            let saved = self.store.compare_and_save_subscription(
                billable_id,
                &updated_sub,
                original_version,
            ).await?;

            if saved {
                return Ok(SeatChangeResult {
                    previous_seats: sub.extra_seats,
                    new_seats: updated.extra_seats,
                    total_seats: plan.included_seats + updated.extra_seats,
                });
            }

            // Version conflict after Stripe success - try to reconcile
            if let Some(current) = self.store.get_subscription(billable_id).await? {
                if current.extra_seats == updated.extra_seats {
                    tracing::debug!(
                        billable_id = %billable_id,
                        "Local state already matches Stripe after version conflict"
                    );
                    return Ok(SeatChangeResult {
                        previous_seats: sub.extra_seats,
                        new_seats: current.extra_seats,
                        total_seats: plan.included_seats + current.extra_seats,
                    });
                }
            }

            tracing::error!(
                billable_id = %billable_id,
                stripe_subscription_id = %sub.stripe_subscription_id,
                expected_seats = count,
                "Stripe update succeeded but local save failed - state may be inconsistent."
            );

            return Err(crate::error::TidewayError::Internal(
                "Seat update succeeded in Stripe but local state update failed. \
                 Please retry or contact support if the issue persists.".to_string()
            ));
        }

        Err(crate::error::TidewayError::Internal(
            "Failed to update seats after multiple retries due to concurrent modifications".to_string()
        ))
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
    use crate::billing::subscription::test::MockStripeSubscriptionClient;
    use crate::billing::subscription::StripeSubscriptionData;
    use crate::billing::subscription::SubscriptionMetadata;

    fn create_test_plans() -> Plans {
        Plans::builder()
            .plan("starter")
                .stripe_price("price_starter")
                .extra_seat_price("price_seat")
                .included_seats(3)
                .done()
            .plan("basic")
                .stripe_price("price_basic")
                .included_seats(1)
                .done()
            .build()
    }

    fn create_test_subscription(billable_id: &str, plan_id: &str, extra_seats: u32) -> StoredSubscription {
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

        let result = store.compare_and_save_subscription("org_cas", &updated, sub.updated_at).await.unwrap();
        assert!(result);

        // Verify the update was saved
        let loaded = store.get_subscription("org_cas").await.unwrap().unwrap();
        assert_eq!(loaded.extra_seats, 5);

        // Modify with wrong version should fail
        let mut another = loaded.clone();
        another.extra_seats = 10;

        let result = store.compare_and_save_subscription("org_cas", &another, sub.updated_at).await.unwrap();
        assert!(!result);

        // Verify the update was not saved
        let loaded = store.get_subscription("org_cas").await.unwrap().unwrap();
        assert_eq!(loaded.extra_seats, 5); // Still 5, not 10
    }
}
