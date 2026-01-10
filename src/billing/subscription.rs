//! Subscription management for Stripe billing.
//!
//! Handles subscription lifecycle including creation, updates, cancellation,
//! and syncing state from Stripe webhooks.

use crate::error::Result;
use super::plans::Plans;
use super::storage::{BillingStore, StoredSubscription, SubscriptionStatus};

/// Subscription management operations.
///
/// Handles creating, updating, and canceling subscriptions.
pub struct SubscriptionManager<S: BillingStore, C: StripeSubscriptionClient> {
    store: S,
    client: C,
    plans: Plans,
}

impl<S: BillingStore, C: StripeSubscriptionClient> SubscriptionManager<S, C> {
    /// Create a new subscription manager.
    #[must_use]
    pub fn new(store: S, client: C, plans: Plans) -> Self {
        Self { store, client, plans }
    }

    /// Get the current subscription for a billable entity.
    pub async fn get_subscription(&self, billable_id: &str) -> Result<Option<Subscription>> {
        let stored = self.store.get_subscription(billable_id).await?;

        match stored {
            Some(sub) => {
                let plan = self.plans.get(&sub.plan_id).cloned();
                Ok(Some(Subscription::from_stored(sub, plan)))
            }
            None => Ok(None),
        }
    }

    /// Check if a billable entity has an active subscription.
    pub async fn has_active_subscription(&self, billable_id: &str) -> Result<bool> {
        match self.store.get_subscription(billable_id).await? {
            Some(sub) => Ok(sub.is_active()),
            None => Ok(false),
        }
    }

    /// Cancel a subscription.
    ///
    /// By default, the subscription will cancel at the end of the current billing period.
    /// Set `immediate` to true to cancel immediately (no refund).
    pub async fn cancel_subscription(
        &self,
        billable_id: &str,
        immediate: bool,
    ) -> Result<()> {
        let sub = self.store.get_subscription(billable_id).await?
            .ok_or_else(|| crate::error::TidewayError::NotFound(
                "No active subscription".to_string()
            ))?;

        if immediate {
            self.client.cancel_subscription(&sub.stripe_subscription_id).await?;
        } else {
            self.client.cancel_subscription_at_period_end(&sub.stripe_subscription_id).await?;
        }

        // Update local state (webhook will also update, but this is immediate feedback)
        let mut updated = sub.clone();
        if immediate {
            updated.status = SubscriptionStatus::Canceled;
        } else {
            updated.cancel_at_period_end = true;
        }
        self.store.save_subscription(billable_id, &updated).await?;

        Ok(())
    }

    /// Resume a subscription that was set to cancel at period end.
    pub async fn resume_subscription(&self, billable_id: &str) -> Result<()> {
        let sub = self.store.get_subscription(billable_id).await?
            .ok_or_else(|| crate::error::TidewayError::NotFound(
                "No subscription found".to_string()
            ))?;

        if !sub.cancel_at_period_end {
            return Err(crate::error::TidewayError::BadRequest(
                "Subscription is not scheduled for cancellation".to_string()
            ));
        }

        self.client.resume_subscription(&sub.stripe_subscription_id).await?;

        // Update local state
        let mut updated = sub;
        updated.cancel_at_period_end = false;
        self.store.save_subscription(billable_id, &updated).await?;

        Ok(())
    }

    /// Extend the trial period for a subscription.
    ///
    /// The subscription must currently be in a trialing state.
    ///
    /// # Arguments
    ///
    /// * `billable_id` - The billable entity ID
    /// * `additional_days` - Number of days to add to the current trial period
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `additional_days` is 0 (use at least 1 day)
    /// - The subscription is not found
    /// - The subscription is not in trialing state
    pub async fn extend_trial(
        &self,
        billable_id: &str,
        additional_days: u32,
    ) -> Result<Subscription> {
        // Validate additional_days is at least 1
        if additional_days == 0 {
            return Err(crate::error::TidewayError::BadRequest(
                "Trial extension must be at least 1 day".to_string()
            ));
        }

        let sub = self.store.get_subscription(billable_id).await?
            .ok_or_else(|| super::error::BillingError::NoSubscription {
                billable_id: billable_id.to_string(),
            })?;

        if sub.status != SubscriptionStatus::Trialing {
            return Err(super::error::BillingError::SubscriptionNotTrialing {
                billable_id: billable_id.to_string(),
            }.into());
        }

        // Calculate new trial end
        let current_trial_end = sub.trial_end.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });
        let additional_seconds = u64::from(additional_days) * 86400;
        let new_trial_end = current_trial_end.saturating_add(additional_seconds);

        // Update in Stripe
        let stripe_data = self.client.extend_trial(&sub.stripe_subscription_id, new_trial_end).await?;

        // Update local state
        self.sync_from_stripe(stripe_data).await?;

        // Return updated subscription
        self.get_subscription(billable_id).await?
            .ok_or_else(|| crate::error::TidewayError::Internal(
                "Subscription disappeared after extension".to_string()
            ))
    }

    /// Check if a subscription is paused.
    pub async fn is_paused(&self, billable_id: &str) -> Result<bool> {
        match self.store.get_subscription(billable_id).await? {
            Some(sub) => Ok(sub.status == SubscriptionStatus::Paused),
            None => Ok(false),
        }
    }

    /// Pause a subscription.
    ///
    /// Paused subscriptions stop billing but maintain the subscription relationship.
    /// The customer's access may be limited depending on your application logic.
    ///
    /// # Errors
    ///
    /// Returns an error if the subscription is not found, not active, or already paused.
    pub async fn pause_subscription(&self, billable_id: &str) -> Result<()> {
        let sub = self.store.get_subscription(billable_id).await?
            .ok_or_else(|| super::error::BillingError::NoSubscription {
                billable_id: billable_id.to_string(),
            })?;

        if sub.status == SubscriptionStatus::Paused {
            return Err(super::error::BillingError::SubscriptionAlreadyPaused {
                billable_id: billable_id.to_string(),
            }.into());
        }

        if !sub.is_active() {
            return Err(super::error::BillingError::SubscriptionInactive {
                billable_id: billable_id.to_string(),
            }.into());
        }

        self.client.pause_subscription(&sub.stripe_subscription_id).await?;

        // Update local state
        let mut updated = sub;
        updated.status = SubscriptionStatus::Paused;
        self.store.save_subscription(billable_id, &updated).await?;

        Ok(())
    }

    /// Resume a paused subscription.
    ///
    /// Reactivates billing for a paused subscription. The subscription will
    /// return to active status and billing will resume.
    ///
    /// # Errors
    ///
    /// Returns an error if the subscription is not found or not in paused state.
    pub async fn resume_paused_subscription(&self, billable_id: &str) -> Result<Subscription> {
        let sub = self.store.get_subscription(billable_id).await?
            .ok_or_else(|| super::error::BillingError::NoSubscription {
                billable_id: billable_id.to_string(),
            })?;

        if sub.status != SubscriptionStatus::Paused {
            return Err(super::error::BillingError::SubscriptionNotPaused {
                billable_id: billable_id.to_string(),
            }.into());
        }

        // Resume in Stripe
        let stripe_data = self.client.resume_paused_subscription(&sub.stripe_subscription_id).await?;

        // Update local state
        self.sync_from_stripe(stripe_data).await?;

        // Return updated subscription
        self.get_subscription(billable_id).await?
            .ok_or_else(|| crate::error::TidewayError::Internal(
                "Subscription disappeared after resuming".to_string()
            ))
    }

    /// Update subscription from a Stripe webhook event.
    ///
    /// This is called by the webhook handler to sync subscription state.
    pub async fn sync_from_stripe(
        &self,
        stripe_subscription: StripeSubscriptionData,
    ) -> Result<()> {
        // Find the billable entity for this subscription
        let billable_id = match self.store
            .get_subscription_by_stripe_id(&stripe_subscription.id)
            .await?
        {
            Some((id, _)) => id,
            None => {
                // New subscription - extract billable_id from metadata
                stripe_subscription.metadata.billable_id.clone()
                    .ok_or_else(|| crate::error::TidewayError::BadRequest(
                        "Subscription missing billable_id metadata".to_string()
                    ))?
            }
        };

        // Map to stored subscription
        let stored = StoredSubscription {
            stripe_subscription_id: stripe_subscription.id,
            stripe_customer_id: stripe_subscription.customer_id,
            plan_id: stripe_subscription.plan_id,
            status: SubscriptionStatus::from_stripe(&stripe_subscription.status),
            current_period_start: stripe_subscription.current_period_start,
            current_period_end: stripe_subscription.current_period_end,
            extra_seats: stripe_subscription.extra_seats,
            trial_end: stripe_subscription.trial_end,
            cancel_at_period_end: stripe_subscription.cancel_at_period_end,
            base_item_id: stripe_subscription.base_item_id,
            seat_item_id: stripe_subscription.seat_item_id,
            updated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };

        self.store.save_subscription(&billable_id, &stored).await?;
        Ok(())
    }

    /// Delete subscription record (called when subscription is deleted in Stripe).
    pub async fn delete_subscription(&self, stripe_subscription_id: &str) -> Result<()> {
        if let Some((billable_id, _)) = self.store
            .get_subscription_by_stripe_id(stripe_subscription_id)
            .await?
        {
            self.store.delete_subscription(&billable_id).await?;
        }
        Ok(())
    }

    /// Get the plan configuration for a subscription.
    pub async fn get_plan(&self, billable_id: &str) -> Result<Option<super::plans::PlanConfig>> {
        let sub = self.store.get_subscription(billable_id).await?;
        match sub {
            Some(s) => Ok(self.plans.get(&s.plan_id).cloned()),
            None => Ok(None),
        }
    }

    /// Refresh subscription state from Stripe.
    ///
    /// Fetches the current subscription state from Stripe and updates local storage.
    /// Use this when you need guaranteed fresh data (e.g., before critical operations).
    ///
    /// Returns the refreshed subscription, or None if no subscription exists locally.
    pub async fn refresh_from_stripe(&self, billable_id: &str) -> Result<Option<Subscription>> {
        let stored = match self.store.get_subscription(billable_id).await? {
            Some(sub) => sub,
            None => return Ok(None),
        };

        // Fetch fresh data from Stripe
        let stripe_data = self.client.get_subscription(&stored.stripe_subscription_id).await?;

        // Update local state
        self.sync_from_stripe(stripe_data).await?;

        // Return the updated subscription
        self.get_subscription(billable_id).await
    }

    /// Reconcile local subscription state with Stripe.
    ///
    /// Compares local state with Stripe and returns information about any differences.
    /// Optionally updates local state to match Stripe.
    ///
    /// This is useful for:
    /// - Periodic health checks to detect missed webhooks
    /// - Debugging subscription state issues
    /// - Recovering from webhook delivery failures
    pub async fn reconcile(
        &self,
        billable_id: &str,
        update_local: bool,
    ) -> Result<ReconcileResult> {
        let stored = match self.store.get_subscription(billable_id).await? {
            Some(sub) => sub,
            None => return Ok(ReconcileResult::NoLocalSubscription),
        };

        // Fetch current state from Stripe
        let stripe_data = match self.client.get_subscription(&stored.stripe_subscription_id).await {
            Ok(data) => data,
            Err(_) => return Ok(ReconcileResult::NotFoundInStripe),
        };

        // Compare key fields
        let status_matches = stored.status == SubscriptionStatus::from_stripe(&stripe_data.status);
        let seats_match = stored.extra_seats == stripe_data.extra_seats;
        let plan_matches = stored.plan_id == stripe_data.plan_id;
        let period_matches = stored.current_period_end == stripe_data.current_period_end;
        let cancel_matches = stored.cancel_at_period_end == stripe_data.cancel_at_period_end;

        if status_matches && seats_match && plan_matches && period_matches && cancel_matches {
            return Ok(ReconcileResult::InSync);
        }

        // Build list of differences
        let mut differences = Vec::new();

        if !status_matches {
            differences.push(ReconcileDifference::Status {
                local: stored.status.as_str().to_string(),
                remote: stripe_data.status.clone(),
            });
        }

        if !seats_match {
            differences.push(ReconcileDifference::Seats {
                local: stored.extra_seats,
                remote: stripe_data.extra_seats,
            });
        }

        if !plan_matches {
            differences.push(ReconcileDifference::Plan {
                local: stored.plan_id.clone(),
                remote: stripe_data.plan_id.clone(),
            });
        }

        if !period_matches {
            differences.push(ReconcileDifference::PeriodEnd {
                local: stored.current_period_end,
                remote: stripe_data.current_period_end,
            });
        }

        if !cancel_matches {
            differences.push(ReconcileDifference::CancelAtPeriodEnd {
                local: stored.cancel_at_period_end,
                remote: stripe_data.cancel_at_period_end,
            });
        }

        // Update local state if requested
        if update_local {
            self.sync_from_stripe(stripe_data).await?;
        }

        Ok(ReconcileResult::Diverged {
            differences,
            updated_local: update_local,
        })
    }
}

/// Result of a reconciliation check.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum ReconcileResult {
    /// No local subscription found for this billable ID.
    NoLocalSubscription,
    /// Subscription not found in Stripe (may have been deleted).
    NotFoundInStripe,
    /// Local and Stripe state are in sync.
    InSync,
    /// Local and Stripe state have diverged.
    Diverged {
        /// List of differences found.
        differences: Vec<ReconcileDifference>,
        /// Whether local state was updated.
        updated_local: bool,
    },
}

/// A specific difference between local and Stripe state.
#[derive(Debug, Clone, PartialEq)]
pub enum ReconcileDifference {
    /// Subscription status differs.
    Status { local: String, remote: String },
    /// Extra seat count differs.
    Seats { local: u32, remote: u32 },
    /// Plan ID differs.
    Plan { local: String, remote: String },
    /// Current period end differs.
    PeriodEnd { local: u64, remote: u64 },
    /// Cancel at period end flag differs.
    CancelAtPeriodEnd { local: bool, remote: bool },
}

/// Rich subscription object with plan details.
#[derive(Debug, Clone)]
#[must_use]
pub struct Subscription {
    /// Stripe subscription ID.
    pub id: String,
    /// Stripe customer ID.
    pub customer_id: String,
    /// Plan ID.
    pub plan_id: String,
    /// Subscription status.
    pub status: SubscriptionStatus,
    /// Current billing period start (Unix timestamp).
    pub current_period_start: u64,
    /// Current billing period end (Unix timestamp).
    pub current_period_end: u64,
    /// Number of extra seats purchased.
    pub extra_seats: u32,
    /// Trial end timestamp.
    pub trial_end: Option<u64>,
    /// Whether subscription cancels at period end.
    pub cancel_at_period_end: bool,
    /// Plan configuration (if plan is known).
    pub plan: Option<super::plans::PlanConfig>,
}

impl Subscription {
    /// Create from stored subscription with optional plan.
    #[must_use]
    pub fn from_stored(stored: StoredSubscription, plan: Option<super::plans::PlanConfig>) -> Self {
        Self {
            id: stored.stripe_subscription_id,
            customer_id: stored.stripe_customer_id,
            plan_id: stored.plan_id,
            status: stored.status,
            current_period_start: stored.current_period_start,
            current_period_end: stored.current_period_end,
            extra_seats: stored.extra_seats,
            trial_end: stored.trial_end,
            cancel_at_period_end: stored.cancel_at_period_end,
            plan,
        }
    }

    /// Check if subscription is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(
            self.status,
            SubscriptionStatus::Active | SubscriptionStatus::Trialing
        )
    }

    /// Check if subscription is in trial.
    #[must_use]
    pub fn is_trialing(&self) -> bool {
        self.status == SubscriptionStatus::Trialing
    }

    /// Get total seats available (included + extra).
    #[must_use]
    pub fn total_seats(&self) -> u32 {
        let included = self.plan.as_ref().map(|p| p.included_seats).unwrap_or(0);
        included + self.extra_seats
    }

    /// Check if a feature is available.
    #[must_use]
    pub fn has_feature(&self, feature: &str) -> bool {
        self.plan.as_ref().map(|p| p.has_feature(feature)).unwrap_or(false)
    }

    /// Get days remaining in trial.
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

    /// Get days until subscription renews.
    #[must_use]
    pub fn days_until_renewal(&self) -> u32 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if self.current_period_end > now {
            ((self.current_period_end - now) / 86400) as u32
        } else {
            0
        }
    }
}

/// Stripe subscription data (from webhook or API).
#[derive(Debug, Clone)]
pub struct StripeSubscriptionData {
    /// Stripe subscription ID.
    pub id: String,
    /// Stripe customer ID.
    pub customer_id: String,
    /// Plan ID (from metadata or price lookup).
    pub plan_id: String,
    /// Subscription status string.
    pub status: String,
    /// Current period start (Unix timestamp).
    pub current_period_start: u64,
    /// Current period end (Unix timestamp).
    pub current_period_end: u64,
    /// Number of extra seats.
    pub extra_seats: u32,
    /// Trial end timestamp.
    pub trial_end: Option<u64>,
    /// Whether subscription cancels at period end.
    pub cancel_at_period_end: bool,
    /// Base plan subscription item ID.
    pub base_item_id: Option<String>,
    /// Extra seats subscription item ID.
    pub seat_item_id: Option<String>,
    /// Subscription metadata.
    pub metadata: SubscriptionMetadata,
}

/// Metadata attached to Stripe subscriptions.
#[derive(Debug, Clone, Default)]
pub struct SubscriptionMetadata {
    /// The billable entity ID.
    pub billable_id: Option<String>,
    /// The billable entity type.
    pub billable_type: Option<String>,
}

/// Trait for Stripe subscription operations.
#[allow(async_fn_in_trait)]
pub trait StripeSubscriptionClient: Send + Sync {
    /// Cancel a subscription immediately.
    async fn cancel_subscription(&self, subscription_id: &str) -> Result<()>;

    /// Schedule subscription to cancel at period end.
    async fn cancel_subscription_at_period_end(&self, subscription_id: &str) -> Result<()>;

    /// Resume a subscription scheduled for cancellation.
    async fn resume_subscription(&self, subscription_id: &str) -> Result<()>;

    /// Get subscription details from Stripe.
    async fn get_subscription(&self, subscription_id: &str) -> Result<StripeSubscriptionData>;

    /// Update subscription (for plan changes, seat updates).
    async fn update_subscription(
        &self,
        subscription_id: &str,
        update: UpdateSubscriptionRequest,
    ) -> Result<StripeSubscriptionData>;

    /// Extend trial period for a subscription.
    ///
    /// Sets a new trial end timestamp. The subscription must be in trialing state.
    async fn extend_trial(
        &self,
        subscription_id: &str,
        new_trial_end: u64,
    ) -> Result<StripeSubscriptionData>;

    /// Pause a subscription.
    ///
    /// Paused subscriptions stop billing but maintain the subscription relationship.
    async fn pause_subscription(&self, subscription_id: &str) -> Result<()>;

    /// Resume a paused subscription.
    ///
    /// Reactivates billing for a paused subscription.
    async fn resume_paused_subscription(&self, subscription_id: &str) -> Result<StripeSubscriptionData>;
}

/// Request to update a subscription.
#[derive(Debug, Clone, Default)]
pub struct UpdateSubscriptionRequest {
    /// New plan price ID.
    pub price_id: Option<String>,
    /// New seat count (for seat item).
    pub seat_quantity: Option<u32>,
    /// Proration behavior.
    pub proration_behavior: Option<ProrationBehavior>,
    /// Base plan subscription item ID (to avoid extra API call).
    /// If not provided, will be fetched from Stripe.
    pub base_item_id: Option<String>,
    /// Seat subscription item ID (to avoid extra API call).
    /// If not provided, will be fetched from Stripe.
    pub seat_item_id: Option<String>,
}

impl UpdateSubscriptionRequest {
    /// Create a new update request.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the new price ID.
    #[must_use]
    pub fn price_id(mut self, price_id: impl Into<String>) -> Self {
        self.price_id = Some(price_id.into());
        self
    }

    /// Set the new seat quantity.
    #[must_use]
    pub fn seat_quantity(mut self, quantity: u32) -> Self {
        self.seat_quantity = Some(quantity);
        self
    }

    /// Set the proration behavior.
    #[must_use]
    pub fn proration_behavior(mut self, behavior: ProrationBehavior) -> Self {
        self.proration_behavior = Some(behavior);
        self
    }

    /// Set the base item ID (avoids fetching from Stripe).
    #[must_use]
    pub fn base_item_id(mut self, id: impl Into<String>) -> Self {
        self.base_item_id = Some(id.into());
        self
    }

    /// Set the seat item ID (avoids fetching from Stripe).
    #[must_use]
    pub fn seat_item_id(mut self, id: impl Into<String>) -> Self {
        self.seat_item_id = Some(id.into());
        self
    }
}

/// How to handle proration on plan changes.
#[derive(Debug, Clone, Copy, Default)]
pub enum ProrationBehavior {
    /// Create prorations for any changes (default).
    #[default]
    CreateProrations,
    /// Don't create prorations.
    None,
    /// Always invoice immediately.
    AlwaysInvoice,
}

impl ProrationBehavior {
    /// Convert to Stripe API string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CreateProrations => "create_prorations",
            Self::None => "none",
            Self::AlwaysInvoice => "always_invoice",
        }
    }
}

/// Mock Stripe subscription client for testing.
#[cfg(any(test, feature = "test-billing"))]
pub mod test {
    use super::*;
    use std::sync::RwLock;
    use std::collections::HashMap;

    /// Mock Stripe subscription client.
    #[derive(Default, Clone)]
    pub struct MockStripeSubscriptionClient {
        subscriptions: std::sync::Arc<RwLock<HashMap<String, MockSubscription>>>,
    }

    #[derive(Clone)]
    struct MockSubscription {
        data: StripeSubscriptionData,
    }

    impl MockStripeSubscriptionClient {
        /// Create a new mock client.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Add a subscription for testing.
        pub fn add_subscription(&self, data: StripeSubscriptionData) {
            self.subscriptions.write().unwrap().insert(
                data.id.clone(),
                MockSubscription { data },
            );
        }
    }

    impl StripeSubscriptionClient for MockStripeSubscriptionClient {
        async fn cancel_subscription(&self, subscription_id: &str) -> Result<()> {
            let mut subs = self.subscriptions.write().unwrap();
            if let Some(sub) = subs.get_mut(subscription_id) {
                sub.data.status = "canceled".to_string();
                Ok(())
            } else {
                Err(crate::error::TidewayError::NotFound(
                    format!("Subscription not found: {}", subscription_id)
                ))
            }
        }

        async fn cancel_subscription_at_period_end(&self, subscription_id: &str) -> Result<()> {
            let mut subs = self.subscriptions.write().unwrap();
            if let Some(sub) = subs.get_mut(subscription_id) {
                sub.data.cancel_at_period_end = true;
                Ok(())
            } else {
                Err(crate::error::TidewayError::NotFound(
                    format!("Subscription not found: {}", subscription_id)
                ))
            }
        }

        async fn resume_subscription(&self, subscription_id: &str) -> Result<()> {
            let mut subs = self.subscriptions.write().unwrap();
            if let Some(sub) = subs.get_mut(subscription_id) {
                sub.data.cancel_at_period_end = false;
                Ok(())
            } else {
                Err(crate::error::TidewayError::NotFound(
                    format!("Subscription not found: {}", subscription_id)
                ))
            }
        }

        async fn get_subscription(&self, subscription_id: &str) -> Result<StripeSubscriptionData> {
            let subs = self.subscriptions.read().unwrap();
            subs.get(subscription_id)
                .map(|s| s.data.clone())
                .ok_or_else(|| crate::error::TidewayError::NotFound(
                    format!("Subscription not found: {}", subscription_id)
                ))
        }

        async fn update_subscription(
            &self,
            subscription_id: &str,
            update: UpdateSubscriptionRequest,
        ) -> Result<StripeSubscriptionData> {
            let mut subs = self.subscriptions.write().unwrap();
            if let Some(sub) = subs.get_mut(subscription_id) {
                if let Some(seat_qty) = update.seat_quantity {
                    sub.data.extra_seats = seat_qty;
                }
                Ok(sub.data.clone())
            } else {
                Err(crate::error::TidewayError::NotFound(
                    format!("Subscription not found: {}", subscription_id)
                ))
            }
        }

        async fn extend_trial(
            &self,
            subscription_id: &str,
            new_trial_end: u64,
        ) -> Result<StripeSubscriptionData> {
            let mut subs = self.subscriptions.write().unwrap();
            if let Some(sub) = subs.get_mut(subscription_id) {
                sub.data.trial_end = Some(new_trial_end);
                Ok(sub.data.clone())
            } else {
                Err(crate::error::TidewayError::NotFound(
                    format!("Subscription not found: {}", subscription_id)
                ))
            }
        }

        async fn pause_subscription(&self, subscription_id: &str) -> Result<()> {
            let mut subs = self.subscriptions.write().unwrap();
            if let Some(sub) = subs.get_mut(subscription_id) {
                sub.data.status = "paused".to_string();
                Ok(())
            } else {
                Err(crate::error::TidewayError::NotFound(
                    format!("Subscription not found: {}", subscription_id)
                ))
            }
        }

        async fn resume_paused_subscription(&self, subscription_id: &str) -> Result<StripeSubscriptionData> {
            let mut subs = self.subscriptions.write().unwrap();
            if let Some(sub) = subs.get_mut(subscription_id) {
                sub.data.status = "active".to_string();
                Ok(sub.data.clone())
            } else {
                Err(crate::error::TidewayError::NotFound(
                    format!("Subscription not found: {}", subscription_id)
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test::MockStripeSubscriptionClient;
    use crate::billing::storage::test::InMemoryBillingStore;
    use crate::billing::plans::Plans;

    fn create_test_plans() -> Plans {
        Plans::builder()
            .plan("starter")
                .stripe_price("price_starter")
                .included_seats(3)
                .features(["reports"])
                .done()
            .plan("pro")
                .stripe_price("price_pro")
                .included_seats(5)
                .features(["reports", "api"])
                .done()
            .build()
    }

    fn create_test_subscription_data(billable_id: &str) -> StripeSubscriptionData {
        StripeSubscriptionData {
            id: "sub_123".to_string(),
            customer_id: "cus_123".to_string(),
            plan_id: "starter".to_string(),
            status: "active".to_string(),
            current_period_start: 1700000000,
            current_period_end: 1702592000,
            extra_seats: 2,
            trial_end: None,
            cancel_at_period_end: false,
            base_item_id: Some("si_base".to_string()),
            seat_item_id: Some("si_seat".to_string()),
            metadata: SubscriptionMetadata {
                billable_id: Some(billable_id.to_string()),
                billable_type: Some("org".to_string()),
            },
        }
    }

    #[tokio::test]
    async fn test_sync_from_stripe() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();
        let manager = SubscriptionManager::new(store, client, plans);

        let stripe_data = create_test_subscription_data("org_123");
        manager.sync_from_stripe(stripe_data).await.unwrap();

        let sub = manager.get_subscription("org_123").await.unwrap().unwrap();
        assert_eq!(sub.plan_id, "starter");
        assert_eq!(sub.extra_seats, 2);
        assert!(sub.is_active());
    }

    #[tokio::test]
    async fn test_get_subscription_with_plan() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();
        let manager = SubscriptionManager::new(store, client, plans);

        // Sync a subscription
        let stripe_data = create_test_subscription_data("org_123");
        manager.sync_from_stripe(stripe_data).await.unwrap();

        let sub = manager.get_subscription("org_123").await.unwrap().unwrap();
        assert!(sub.plan.is_some());
        assert_eq!(sub.total_seats(), 5); // 3 included + 2 extra
        assert!(sub.has_feature("reports"));
        assert!(!sub.has_feature("api"));
    }

    #[tokio::test]
    async fn test_cancel_subscription() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        // Add subscription to mock client
        let stripe_data = create_test_subscription_data("org_123");
        client.add_subscription(stripe_data.clone());

        let manager = SubscriptionManager::new(store, client, plans);

        // Sync first
        manager.sync_from_stripe(stripe_data).await.unwrap();

        // Cancel at period end
        manager.cancel_subscription("org_123", false).await.unwrap();

        let sub = manager.get_subscription("org_123").await.unwrap().unwrap();
        assert!(sub.cancel_at_period_end);
        assert!(sub.is_active()); // Still active until period end
    }

    #[tokio::test]
    async fn test_cancel_subscription_immediate() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        let stripe_data = create_test_subscription_data("org_123");
        client.add_subscription(stripe_data.clone());

        let manager = SubscriptionManager::new(store, client, plans);
        manager.sync_from_stripe(stripe_data).await.unwrap();

        // Immediate cancel
        manager.cancel_subscription("org_123", true).await.unwrap();

        let sub = manager.get_subscription("org_123").await.unwrap().unwrap();
        assert_eq!(sub.status, SubscriptionStatus::Canceled);
    }

    #[tokio::test]
    async fn test_resume_subscription() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        let stripe_data = create_test_subscription_data("org_123");
        client.add_subscription(stripe_data.clone());

        let manager = SubscriptionManager::new(store, client, plans);
        manager.sync_from_stripe(stripe_data).await.unwrap();

        // Cancel at period end
        manager.cancel_subscription("org_123", false).await.unwrap();

        // Resume
        manager.resume_subscription("org_123").await.unwrap();

        let sub = manager.get_subscription("org_123").await.unwrap().unwrap();
        assert!(!sub.cancel_at_period_end);
    }

    #[tokio::test]
    async fn test_has_active_subscription() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();
        let manager = SubscriptionManager::new(store, client, plans);

        // No subscription yet
        assert!(!manager.has_active_subscription("org_123").await.unwrap());

        // Add one
        let stripe_data = create_test_subscription_data("org_123");
        manager.sync_from_stripe(stripe_data).await.unwrap();

        assert!(manager.has_active_subscription("org_123").await.unwrap());
    }

    #[tokio::test]
    async fn test_delete_subscription() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();
        let manager = SubscriptionManager::new(store, client, plans);

        // Sync a subscription
        let stripe_data = create_test_subscription_data("org_123");
        manager.sync_from_stripe(stripe_data).await.unwrap();

        // Delete it
        manager.delete_subscription("sub_123").await.unwrap();

        // Should be gone
        assert!(manager.get_subscription("org_123").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_refresh_from_stripe() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        // Set up initial local state
        let stripe_data = create_test_subscription_data("org_123");
        client.add_subscription(stripe_data.clone());

        let manager = SubscriptionManager::new(store, client.clone(), plans);
        manager.sync_from_stripe(stripe_data).await.unwrap();

        // Modify the Stripe state (simulating an external change)
        let mut updated_stripe = create_test_subscription_data("org_123");
        updated_stripe.extra_seats = 10;
        updated_stripe.status = "past_due".to_string();
        client.add_subscription(updated_stripe);

        // Refresh from Stripe
        let sub = manager.refresh_from_stripe("org_123").await.unwrap().unwrap();

        // Should reflect Stripe's current state
        assert_eq!(sub.extra_seats, 10);
        assert_eq!(sub.status, SubscriptionStatus::PastDue);
    }

    #[tokio::test]
    async fn test_reconcile_in_sync() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        let stripe_data = create_test_subscription_data("org_123");
        client.add_subscription(stripe_data.clone());

        let manager = SubscriptionManager::new(store, client, plans);
        manager.sync_from_stripe(stripe_data).await.unwrap();

        // Local and Stripe should be in sync
        let result = manager.reconcile("org_123", false).await.unwrap();
        assert_eq!(result, ReconcileResult::InSync);
    }

    #[tokio::test]
    async fn test_reconcile_diverged() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        // Set up initial state
        let stripe_data = create_test_subscription_data("org_123");
        client.add_subscription(stripe_data.clone());

        let manager = SubscriptionManager::new(store, client.clone(), plans);
        manager.sync_from_stripe(stripe_data).await.unwrap();

        // Modify Stripe state to create divergence
        let mut updated_stripe = create_test_subscription_data("org_123");
        updated_stripe.extra_seats = 5; // Changed from 2 to 5
        updated_stripe.cancel_at_period_end = true; // Changed from false to true
        client.add_subscription(updated_stripe);

        // Check for divergence without updating
        let result = manager.reconcile("org_123", false).await.unwrap();

        match result {
            ReconcileResult::Diverged { differences, updated_local } => {
                assert!(!updated_local);
                assert!(differences.iter().any(|d| matches!(d, ReconcileDifference::Seats { local: 2, remote: 5 })));
                assert!(differences.iter().any(|d| matches!(d, ReconcileDifference::CancelAtPeriodEnd { local: false, remote: true })));
            }
            _ => panic!("Expected Diverged result"),
        }

        // Local state should still be old
        let sub = manager.get_subscription("org_123").await.unwrap().unwrap();
        assert_eq!(sub.extra_seats, 2);
    }

    #[tokio::test]
    async fn test_reconcile_with_update() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        let stripe_data = create_test_subscription_data("org_123");
        client.add_subscription(stripe_data.clone());

        let manager = SubscriptionManager::new(store, client.clone(), plans);
        manager.sync_from_stripe(stripe_data).await.unwrap();

        // Modify Stripe state
        let mut updated_stripe = create_test_subscription_data("org_123");
        updated_stripe.extra_seats = 8;
        client.add_subscription(updated_stripe);

        // Reconcile WITH update
        let result = manager.reconcile("org_123", true).await.unwrap();

        match result {
            ReconcileResult::Diverged { updated_local, .. } => {
                assert!(updated_local);
            }
            _ => panic!("Expected Diverged result"),
        }

        // Local state should now match Stripe
        let sub = manager.get_subscription("org_123").await.unwrap().unwrap();
        assert_eq!(sub.extra_seats, 8);
    }

    #[tokio::test]
    async fn test_reconcile_no_local_subscription() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();
        let manager = SubscriptionManager::new(store, client, plans);

        let result = manager.reconcile("nonexistent", false).await.unwrap();
        assert_eq!(result, ReconcileResult::NoLocalSubscription);
    }

    #[tokio::test]
    async fn test_reconcile_not_found_in_stripe() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        // Sync a subscription but don't add it to mock client
        let stripe_data = create_test_subscription_data("org_123");

        let manager = SubscriptionManager::new(store, client, plans);
        manager.sync_from_stripe(stripe_data).await.unwrap();

        // Reconcile - should find local but not in Stripe
        let result = manager.reconcile("org_123", false).await.unwrap();
        assert_eq!(result, ReconcileResult::NotFoundInStripe);
    }

    // ========================================================================
    // Trial Extension Tests
    // ========================================================================

    #[tokio::test]
    async fn test_extend_trial() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        // Create a trialing subscription
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut stripe_data = create_test_subscription_data("org_123");
        stripe_data.status = "trialing".to_string();
        stripe_data.trial_end = Some(now + 7 * 86400); // 7 days from now
        client.add_subscription(stripe_data.clone());

        let manager = SubscriptionManager::new(store, client, plans);
        manager.sync_from_stripe(stripe_data).await.unwrap();

        // Extend trial by 14 days
        let sub = manager.extend_trial("org_123", 14).await.unwrap();

        // Trial should be extended
        assert!(sub.trial_end.is_some());
        let new_trial_end = sub.trial_end.unwrap();
        // Should be approximately 21 days from now (7 + 14)
        assert!(new_trial_end > now + 20 * 86400);
    }

    #[tokio::test]
    async fn test_extend_trial_not_trialing() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        // Create an active (not trialing) subscription
        let stripe_data = create_test_subscription_data("org_123");
        client.add_subscription(stripe_data.clone());

        let manager = SubscriptionManager::new(store, client, plans);
        manager.sync_from_stripe(stripe_data).await.unwrap();

        // Try to extend trial - should fail
        let result = manager.extend_trial("org_123", 14).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_extend_trial_zero_days() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        let manager = SubscriptionManager::new(store, client, plans);

        // Try to extend trial with 0 days - should fail immediately
        let result = manager.extend_trial("org_123", 0).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("at least 1 day"));
    }

    // ========================================================================
    // Pause/Resume Tests
    // ========================================================================

    #[tokio::test]
    async fn test_pause_subscription() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        let stripe_data = create_test_subscription_data("org_123");
        client.add_subscription(stripe_data.clone());

        let manager = SubscriptionManager::new(store, client, plans);
        manager.sync_from_stripe(stripe_data).await.unwrap();

        // Pause subscription
        manager.pause_subscription("org_123").await.unwrap();

        // Check it's paused
        assert!(manager.is_paused("org_123").await.unwrap());
    }

    #[tokio::test]
    async fn test_pause_already_paused() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        // Create a paused subscription
        let mut stripe_data = create_test_subscription_data("org_123");
        stripe_data.status = "paused".to_string();
        client.add_subscription(stripe_data.clone());

        let manager = SubscriptionManager::new(store, client, plans);
        manager.sync_from_stripe(stripe_data).await.unwrap();

        // Try to pause again - should fail
        let result = manager.pause_subscription("org_123").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resume_paused_subscription() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        // Create a paused subscription
        let mut stripe_data = create_test_subscription_data("org_123");
        stripe_data.status = "paused".to_string();
        client.add_subscription(stripe_data.clone());

        let manager = SubscriptionManager::new(store, client, plans);
        manager.sync_from_stripe(stripe_data).await.unwrap();

        // Resume
        let sub = manager.resume_paused_subscription("org_123").await.unwrap();
        assert!(sub.is_active());
        assert!(!manager.is_paused("org_123").await.unwrap());
    }

    #[tokio::test]
    async fn test_resume_not_paused() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();

        // Create an active subscription
        let stripe_data = create_test_subscription_data("org_123");
        client.add_subscription(stripe_data.clone());

        let manager = SubscriptionManager::new(store, client, plans);
        manager.sync_from_stripe(stripe_data).await.unwrap();

        // Try to resume - should fail
        let result = manager.resume_paused_subscription("org_123").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_is_paused_no_subscription() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeSubscriptionClient::new();
        let plans = create_test_plans();
        let manager = SubscriptionManager::new(store, client, plans);

        // No subscription - should return false
        assert!(!manager.is_paused("nonexistent").await.unwrap());
    }
}
