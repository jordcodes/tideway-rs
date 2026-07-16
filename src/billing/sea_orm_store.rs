//! SeaORM-backed billing storage.
//!
//! Provides production-ready database persistence for billing data using SeaORM.
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::billing::SeaOrmBillingStore;
//! use sea_orm::DatabaseConnection;
//!
//! let billing_store = SeaOrmBillingStore::new(db.clone());
//!
//! // Use with billing managers
//! let customer_manager = CustomerManager::new(billing_store.clone(), stripe_client);
//! ```

use async_trait::async_trait;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect, Set, TransactionTrait, TryInsertResult, entity::prelude::*, sea_query::OnConflict,
};

use super::storage::{
    BillingStore, PlanInterval, PlanStore, StoredPlan, StoredSubscription, SubscriptionStatus,
};
use crate::TidewayError;
use crate::error::Result;
use crate::webhooks::{ClaimOutcome, DEFAULT_CLAIM_TTL, EventClaim};
use std::time::Duration;

// =============================================================================
// SeaORM Entities
// =============================================================================

mod entity {
    use sea_orm::entity::prelude::*;

    // -------------------------------------------------------------------------
    // Billing Customer Entity
    // -------------------------------------------------------------------------
    pub mod billing_customer {
        use super::*;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
        #[sea_orm(table_name = "billing_customers")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub billable_id: String,
            pub billable_type: String,
            pub stripe_customer_id: String,
            pub created_at: DateTimeWithTimeZone,
            pub updated_at: DateTimeWithTimeZone,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}

        impl ActiveModelBehavior for ActiveModel {}
    }

    // -------------------------------------------------------------------------
    // Billing Subscription Entity
    // -------------------------------------------------------------------------
    pub mod billing_subscription {
        use super::*;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
        #[sea_orm(table_name = "billing_subscriptions")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub billable_id: String,
            #[sea_orm(unique)]
            pub stripe_subscription_id: String,
            pub stripe_customer_id: String,
            pub plan_id: String,
            pub status: String,
            pub current_period_start: i64,
            pub current_period_end: i64,
            pub extra_seats: i32,
            pub trial_end: Option<i64>,
            pub cancel_at_period_end: bool,
            pub base_item_id: Option<String>,
            pub seat_item_id: Option<String>,
            /// Unix timestamp used for optimistic locking in compare_and_save_subscription.
            pub updated_at: i64,
            pub created_at: DateTimeWithTimeZone,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}

        impl ActiveModelBehavior for ActiveModel {}
    }

    // -------------------------------------------------------------------------
    // Billing Plan Entity
    // -------------------------------------------------------------------------
    pub mod billing_plan {
        use super::*;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
        #[sea_orm(table_name = "billing_plans")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub id: String,
            pub name: String,
            pub description: Option<String>,
            pub stripe_price_id: String,
            pub stripe_seat_price_id: Option<String>,
            pub price_cents: i64,
            pub currency: String,
            pub interval: String,
            pub included_seats: i32,
            #[sea_orm(column_type = "JsonBinary")]
            pub features: serde_json::Value,
            #[sea_orm(column_type = "JsonBinary")]
            pub limits: serde_json::Value,
            pub trial_days: Option<i32>,
            pub is_active: bool,
            pub sort_order: i32,
            pub created_at: DateTimeWithTimeZone,
            pub updated_at: DateTimeWithTimeZone,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}

        impl ActiveModelBehavior for ActiveModel {}
    }

    // -------------------------------------------------------------------------
    // Billing Processed Event Entity
    // -------------------------------------------------------------------------
    pub mod billing_processed_event {
        use super::*;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
        #[sea_orm(table_name = "billing_processed_events")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub event_id: String,
            pub status: String,
            pub claim_token: Option<String>,
            pub claimed_at: Option<DateTimeWithTimeZone>,
            pub processed_at: DateTimeWithTimeZone,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}

        impl ActiveModelBehavior for ActiveModel {}
    }
}

use entity::{billing_customer, billing_plan, billing_processed_event, billing_subscription};

// =============================================================================
// Helper Functions
// =============================================================================

// Safe integer conversions to prevent overflow

/// Convert i64 to u64 safely (negative values become 0).
#[inline]
fn i64_to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

/// Convert u64 to i64 safely (values > i64::MAX become i64::MAX).
#[inline]
fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Convert i32 to u32 safely (negative values become 0).
#[inline]
fn i32_to_u32(value: i32) -> u32 {
    u32::try_from(value).unwrap_or(0)
}

/// Convert u32 to i32 safely (values > i32::MAX become i32::MAX).
#[inline]
fn u32_to_i32(value: u32) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

/// Convert u64 to usize safely (values > usize::MAX become usize::MAX).
#[inline]
fn u64_to_usize(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// Convert a database model to a StoredSubscription.
fn model_to_stored_subscription(model: billing_subscription::Model) -> StoredSubscription {
    StoredSubscription {
        stripe_subscription_id: model.stripe_subscription_id,
        stripe_customer_id: model.stripe_customer_id,
        plan_id: model.plan_id,
        status: SubscriptionStatus::from_stripe(&model.status),
        current_period_start: i64_to_u64(model.current_period_start),
        current_period_end: i64_to_u64(model.current_period_end),
        extra_seats: i32_to_u32(model.extra_seats),
        trial_end: model.trial_end.map(i64_to_u64),
        cancel_at_period_end: model.cancel_at_period_end,
        base_item_id: model.base_item_id,
        seat_item_id: model.seat_item_id,
        updated_at: i64_to_u64(model.updated_at),
    }
}

/// Create an ActiveModel from a StoredSubscription for inserts.
fn subscription_to_active_model(
    billable_id: &str,
    subscription: &StoredSubscription,
    created_at: DateTimeWithTimeZone,
) -> billing_subscription::ActiveModel {
    billing_subscription::ActiveModel {
        billable_id: Set(billable_id.to_string()),
        stripe_subscription_id: Set(subscription.stripe_subscription_id.clone()),
        stripe_customer_id: Set(subscription.stripe_customer_id.clone()),
        plan_id: Set(subscription.plan_id.clone()),
        status: Set(subscription.status.as_str().to_string()),
        current_period_start: Set(u64_to_i64(subscription.current_period_start)),
        current_period_end: Set(u64_to_i64(subscription.current_period_end)),
        extra_seats: Set(u32_to_i32(subscription.extra_seats)),
        trial_end: Set(subscription.trial_end.map(u64_to_i64)),
        cancel_at_period_end: Set(subscription.cancel_at_period_end),
        base_item_id: Set(subscription.base_item_id.clone()),
        seat_item_id: Set(subscription.seat_item_id.clone()),
        updated_at: Set(u64_to_i64(subscription.updated_at)),
        created_at: Set(created_at),
    }
}

/// Convert a database model to a StoredPlan.
fn model_to_stored_plan(model: billing_plan::Model) -> StoredPlan {
    StoredPlan {
        id: model.id,
        name: model.name,
        description: model.description,
        stripe_price_id: model.stripe_price_id,
        stripe_seat_price_id: model.stripe_seat_price_id,
        price_cents: model.price_cents,
        currency: model.currency,
        interval: PlanInterval::from_str(&model.interval),
        included_seats: i32_to_u32(model.included_seats),
        features: model.features,
        limits: model.limits,
        trial_days: model.trial_days.map(i32_to_u32),
        is_active: model.is_active,
        sort_order: model.sort_order,
        created_at: model.created_at.timestamp() as u64,
        updated_at: model.updated_at.timestamp() as u64,
    }
}

/// Create an ActiveModel from a StoredPlan for inserts.
fn plan_to_active_model(plan: &StoredPlan) -> billing_plan::ActiveModel {
    let now = chrono::Utc::now().fixed_offset();
    billing_plan::ActiveModel {
        id: Set(plan.id.clone()),
        name: Set(plan.name.clone()),
        description: Set(plan.description.clone()),
        stripe_price_id: Set(plan.stripe_price_id.clone()),
        stripe_seat_price_id: Set(plan.stripe_seat_price_id.clone()),
        price_cents: Set(plan.price_cents),
        currency: Set(plan.currency.clone()),
        interval: Set(plan.interval.as_str().to_string()),
        included_seats: Set(u32_to_i32(plan.included_seats)),
        features: Set(plan.features.clone()),
        limits: Set(plan.limits.clone()),
        trial_days: Set(plan.trial_days.map(u32_to_i32)),
        is_active: Set(plan.is_active),
        sort_order: Set(plan.sort_order),
        created_at: Set(now),
        updated_at: Set(now),
    }
}

/// Build a conditional UPDATE query for a subscription with version check.
fn build_subscription_update(
    billable_id: &str,
    subscription: &StoredSubscription,
    expected_version: u64,
) -> sea_orm::UpdateMany<billing_subscription::Entity> {
    let new_version = subscription
        .updated_at
        .max(expected_version.saturating_add(1));

    billing_subscription::Entity::update_many()
        .col_expr(
            billing_subscription::Column::StripeSubscriptionId,
            Expr::value(&subscription.stripe_subscription_id),
        )
        .col_expr(
            billing_subscription::Column::StripeCustomerId,
            Expr::value(&subscription.stripe_customer_id),
        )
        .col_expr(
            billing_subscription::Column::PlanId,
            Expr::value(&subscription.plan_id),
        )
        .col_expr(
            billing_subscription::Column::Status,
            Expr::value(subscription.status.as_str()),
        )
        .col_expr(
            billing_subscription::Column::CurrentPeriodStart,
            Expr::value(u64_to_i64(subscription.current_period_start)),
        )
        .col_expr(
            billing_subscription::Column::CurrentPeriodEnd,
            Expr::value(u64_to_i64(subscription.current_period_end)),
        )
        .col_expr(
            billing_subscription::Column::ExtraSeats,
            Expr::value(u32_to_i32(subscription.extra_seats)),
        )
        .col_expr(
            billing_subscription::Column::TrialEnd,
            Expr::value(subscription.trial_end.map(u64_to_i64)),
        )
        .col_expr(
            billing_subscription::Column::CancelAtPeriodEnd,
            Expr::value(subscription.cancel_at_period_end),
        )
        .col_expr(
            billing_subscription::Column::BaseItemId,
            Expr::value(subscription.base_item_id.clone()),
        )
        .col_expr(
            billing_subscription::Column::SeatItemId,
            Expr::value(subscription.seat_item_id.clone()),
        )
        .col_expr(
            billing_subscription::Column::UpdatedAt,
            Expr::value(u64_to_i64(new_version)),
        )
        .filter(billing_subscription::Column::BillableId.eq(billable_id))
        .filter(billing_subscription::Column::UpdatedAt.eq(u64_to_i64(expected_version)))
}

// =============================================================================
// SeaOrmBillingStore
// =============================================================================

/// SeaORM-backed billing store implementing the BillingStore trait.
///
/// Provides production-ready database persistence for billing data with
/// support for optimistic locking via `compare_and_save_subscription`.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::billing::SeaOrmBillingStore;
/// use sea_orm::DatabaseConnection;
///
/// // Create from existing database connection
/// let billing_store = SeaOrmBillingStore::new(db.clone());
///
/// // Use with billing managers
/// let customer_manager = CustomerManager::new(billing_store.clone(), stripe_client);
/// ```
#[derive(Clone, Debug)]
pub struct SeaOrmBillingStore {
    db: DatabaseConnection,
    claim_ttl: Duration,
}

impl SeaOrmBillingStore {
    /// Create a new SeaORM billing store.
    ///
    /// # Arguments
    ///
    /// * `db` - A SeaORM database connection
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            db,
            claim_ttl: DEFAULT_CLAIM_TTL,
        }
    }

    /// Configure abandoned-claim recovery. Keep this longer than normal handler execution.
    #[must_use]
    pub fn with_event_claim_ttl(mut self, claim_ttl: Duration) -> Self {
        self.claim_ttl = claim_ttl;
        self
    }

    /// Get a reference to the underlying database connection.
    #[must_use]
    pub fn connection(&self) -> &DatabaseConnection {
        &self.db
    }
}

#[async_trait]
impl BillingStore for SeaOrmBillingStore {
    // -------------------------------------------------------------------------
    // Customer Management
    // -------------------------------------------------------------------------

    async fn get_stripe_customer_id(&self, billable_id: &str) -> Result<Option<String>> {
        tracing::debug!(billable_id = %billable_id, "fetching stripe customer id");

        let customer = billing_customer::Entity::find_by_id(billable_id)
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(customer.map(|c| c.stripe_customer_id))
    }

    async fn set_stripe_customer_id(
        &self,
        billable_id: &str,
        billable_type: &str,
        customer_id: &str,
    ) -> Result<()> {
        tracing::debug!(
            billable_id = %billable_id,
            billable_type = %billable_type,
            customer_id = %customer_id,
            "setting stripe customer id"
        );

        let now = chrono::Utc::now().fixed_offset();

        // Use upsert (INSERT ... ON CONFLICT UPDATE) for atomic operation
        let customer = billing_customer::ActiveModel {
            billable_id: Set(billable_id.to_string()),
            billable_type: Set(billable_type.to_string()),
            stripe_customer_id: Set(customer_id.to_string()),
            created_at: Set(now),
            updated_at: Set(now),
        };

        billing_customer::Entity::insert(customer)
            .on_conflict(
                OnConflict::column(billing_customer::Column::BillableId)
                    .update_columns([
                        billing_customer::Column::StripeCustomerId,
                        billing_customer::Column::UpdatedAt,
                    ])
                    .to_owned(),
            )
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Subscription Tracking
    // -------------------------------------------------------------------------

    async fn get_subscription(&self, billable_id: &str) -> Result<Option<StoredSubscription>> {
        tracing::debug!(billable_id = %billable_id, "fetching subscription");

        let subscription = billing_subscription::Entity::find_by_id(billable_id)
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(subscription.map(model_to_stored_subscription))
    }

    async fn save_subscription(
        &self,
        billable_id: &str,
        subscription: &StoredSubscription,
    ) -> Result<()> {
        tracing::debug!(
            billable_id = %billable_id,
            stripe_subscription_id = %subscription.stripe_subscription_id,
            status = %subscription.status,
            "saving subscription"
        );

        let now = chrono::Utc::now().fixed_offset();
        let active_model = subscription_to_active_model(billable_id, subscription, now);

        // Use upsert for atomic operation - update all fields on conflict
        billing_subscription::Entity::insert(active_model)
            .on_conflict(
                OnConflict::column(billing_subscription::Column::BillableId)
                    .update_columns([
                        billing_subscription::Column::StripeSubscriptionId,
                        billing_subscription::Column::StripeCustomerId,
                        billing_subscription::Column::PlanId,
                        billing_subscription::Column::Status,
                        billing_subscription::Column::CurrentPeriodStart,
                        billing_subscription::Column::CurrentPeriodEnd,
                        billing_subscription::Column::ExtraSeats,
                        billing_subscription::Column::TrialEnd,
                        billing_subscription::Column::CancelAtPeriodEnd,
                        billing_subscription::Column::BaseItemId,
                        billing_subscription::Column::SeatItemId,
                        billing_subscription::Column::UpdatedAt,
                    ])
                    .to_owned(),
            )
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    async fn compare_and_save_subscription(
        &self,
        billable_id: &str,
        subscription: &StoredSubscription,
        expected_version: u64,
    ) -> Result<bool> {
        tracing::debug!(
            billable_id = %billable_id,
            expected_version = expected_version,
            new_version = subscription.updated_at,
            "compare and save subscription"
        );

        // Use a transaction to ensure atomicity
        let txn = self
            .db
            .begin()
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        // Try conditional UPDATE for existing records (version must match)
        let update_result = build_subscription_update(billable_id, subscription, expected_version)
            .exec(&txn)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        if update_result.rows_affected > 0 {
            txn.commit()
                .await
                .map_err(|e| TidewayError::Database(e.to_string()))?;
            tracing::debug!(billable_id = %billable_id, "subscription updated successfully");
            return Ok(true);
        }

        // UPDATE affected 0 rows - check why
        let exists = billing_subscription::Entity::find_by_id(billable_id)
            .one(&txn)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        if exists.is_some() {
            // Record exists but version didn't match - concurrent modification
            txn.rollback()
                .await
                .map_err(|e| TidewayError::Database(e.to_string()))?;
            tracing::debug!(
                billable_id = %billable_id,
                expected_version = expected_version,
                "version mismatch - concurrent modification detected"
            );
            return Ok(false);
        }

        // Record doesn't exist - insert if expected_version is 0
        if expected_version == 0 {
            let now = chrono::Utc::now().fixed_offset();
            subscription_to_active_model(billable_id, subscription, now)
                .insert(&txn)
                .await
                .map_err(|e| TidewayError::Database(e.to_string()))?;

            txn.commit()
                .await
                .map_err(|e| TidewayError::Database(e.to_string()))?;
            tracing::debug!(billable_id = %billable_id, "subscription inserted successfully");
            return Ok(true);
        }

        // Record doesn't exist but expected_version > 0 - version mismatch
        txn.rollback()
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;
        tracing::debug!(
            billable_id = %billable_id,
            expected_version = expected_version,
            "subscription not found but expected_version > 0"
        );
        Ok(false)
    }

    async fn delete_subscription(&self, billable_id: &str) -> Result<()> {
        tracing::debug!(billable_id = %billable_id, "deleting subscription");

        billing_subscription::Entity::delete_by_id(billable_id)
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    async fn get_subscription_by_stripe_id(
        &self,
        stripe_subscription_id: &str,
    ) -> Result<Option<(String, StoredSubscription)>> {
        tracing::debug!(
            stripe_subscription_id = %stripe_subscription_id,
            "fetching subscription by stripe id"
        );

        let subscription = billing_subscription::Entity::find()
            .filter(billing_subscription::Column::StripeSubscriptionId.eq(stripe_subscription_id))
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(subscription.map(|s| {
            let billable_id = s.billable_id.clone();
            (billable_id, model_to_stored_subscription(s))
        }))
    }

    // -------------------------------------------------------------------------
    // Webhook Idempotency
    // -------------------------------------------------------------------------

    async fn is_event_processed(&self, event_id: &str) -> Result<bool> {
        tracing::debug!(event_id = %event_id, "checking if event is processed");

        let event = billing_processed_event::Entity::find_by_id(event_id)
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(event.is_some_and(|event| event.status == "processed"))
    }

    async fn acquire_event_claim(&self, event_id: &str) -> Result<ClaimOutcome> {
        use sea_orm::sea_query::Expr;

        let claim = EventClaim::new(event_id);
        let now = chrono::Utc::now().fixed_offset();
        let event = billing_processed_event::ActiveModel {
            event_id: Set(event_id.to_string()),
            status: Set("processing".to_string()),
            claim_token: Set(Some(claim.token().to_string())),
            claimed_at: Set(Some(now)),
            processed_at: Set(now),
        };

        let inserted = billing_processed_event::Entity::insert(event)
            .on_conflict(
                OnConflict::column(billing_processed_event::Column::EventId)
                    .do_nothing()
                    .to_owned(),
            )
            .do_nothing()
            .exec(&self.db)
            .await;

        match inserted {
            Ok(TryInsertResult::Inserted(_)) => return Ok(ClaimOutcome::Acquired(claim)),
            Ok(TryInsertResult::Conflicted) | Err(sea_orm::DbErr::RecordNotInserted) => {}
            Ok(TryInsertResult::Empty) => {
                return Err(TidewayError::internal(
                    "Billing webhook event claim produced an empty insert",
                ));
            }
            Err(error) => return Err(TidewayError::Database(error.to_string())),
        }

        let ttl = chrono::Duration::from_std(self.claim_ttl)
            .map_err(|_| TidewayError::internal("Billing webhook claim TTL is too large"))?;
        let reclaimed = billing_processed_event::Entity::update_many()
            .col_expr(
                billing_processed_event::Column::ClaimToken,
                Expr::value(Some(claim.token().to_string())),
            )
            .col_expr(
                billing_processed_event::Column::ClaimedAt,
                Expr::value(Some(now)),
            )
            .filter(billing_processed_event::Column::EventId.eq(event_id))
            .filter(billing_processed_event::Column::Status.eq("processing"))
            .filter(billing_processed_event::Column::ClaimedAt.lte(now - ttl))
            .exec(&self.db)
            .await
            .map_err(|error| TidewayError::Database(error.to_string()))?;

        if reclaimed.rows_affected == 1 {
            return Ok(ClaimOutcome::Acquired(claim));
        }

        let current = billing_processed_event::Entity::find_by_id(event_id)
            .one(&self.db)
            .await
            .map_err(|error| TidewayError::Database(error.to_string()))?
            .ok_or_else(|| TidewayError::internal("Billing webhook claim disappeared"))?;
        if current.status == "processed" {
            return Ok(ClaimOutcome::AlreadyProcessed);
        }
        let age = current
            .claimed_at
            .and_then(|claimed_at| (now - claimed_at).to_std().ok())
            .unwrap_or_default();
        Ok(ClaimOutcome::InProgress {
            retry_after: self.claim_ttl.saturating_sub(age),
        })
    }

    async fn complete_event_claim(&self, claim: &EventClaim) -> Result<()> {
        use sea_orm::sea_query::Expr;

        let result = billing_processed_event::Entity::update_many()
            .col_expr(
                billing_processed_event::Column::Status,
                Expr::value("processed"),
            )
            .col_expr(
                billing_processed_event::Column::ClaimToken,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                billing_processed_event::Column::ProcessedAt,
                Expr::value(chrono::Utc::now().fixed_offset()),
            )
            .filter(billing_processed_event::Column::EventId.eq(claim.event_id()))
            .filter(billing_processed_event::Column::Status.eq("processing"))
            .filter(billing_processed_event::Column::ClaimToken.eq(claim.token()))
            .exec(&self.db)
            .await
            .map_err(|error| TidewayError::Database(error.to_string()))?;

        if result.rows_affected != 1 {
            return Err(TidewayError::internal(
                "Billing webhook event claim is no longer owned by this worker",
            ));
        }
        Ok(())
    }

    async fn release_owned_event_claim(&self, claim: &EventClaim) -> Result<()> {
        billing_processed_event::Entity::delete_many()
            .filter(billing_processed_event::Column::EventId.eq(claim.event_id()))
            .filter(billing_processed_event::Column::Status.eq("processing"))
            .filter(billing_processed_event::Column::ClaimToken.eq(claim.token()))
            .exec(&self.db)
            .await
            .map_err(|error| TidewayError::Database(error.to_string()))?;
        Ok(())
    }

    async fn claim_event(&self, event_id: &str) -> Result<bool> {
        Ok(matches!(
            self.acquire_event_claim(event_id).await?,
            ClaimOutcome::Acquired(_)
        ))
    }

    async fn mark_event_processed(&self, event_id: &str) -> Result<()> {
        use sea_orm::sea_query::Expr;

        tracing::debug!(event_id = %event_id, "marking event as processed");

        let now = chrono::Utc::now().fixed_offset();

        let updated = billing_processed_event::Entity::update_many()
            .col_expr(
                billing_processed_event::Column::Status,
                Expr::value("processed"),
            )
            .col_expr(
                billing_processed_event::Column::ClaimToken,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                billing_processed_event::Column::ProcessedAt,
                Expr::value(now),
            )
            .filter(billing_processed_event::Column::EventId.eq(event_id))
            .filter(billing_processed_event::Column::Status.eq("processing"))
            .exec(&self.db)
            .await
            .map_err(|error| TidewayError::Database(error.to_string()))?;
        if updated.rows_affected == 1 {
            return Ok(());
        }

        let event = billing_processed_event::ActiveModel {
            event_id: Set(event_id.to_string()),
            status: Set("processed".to_string()),
            claim_token: Set(None),
            claimed_at: Set(None),
            processed_at: Set(now),
        };

        // Use INSERT ... ON CONFLICT DO NOTHING for idempotent insert
        // This is atomic and doesn't rely on error string matching
        billing_processed_event::Entity::insert(event)
            .on_conflict(
                OnConflict::column(billing_processed_event::Column::EventId)
                    .do_nothing()
                    .to_owned(),
            )
            .do_nothing()
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    async fn release_event_claim(&self, event_id: &str) -> Result<()> {
        tracing::debug!(event_id = %event_id, "releasing event processing claim");

        billing_processed_event::Entity::delete_many()
            .filter(billing_processed_event::Column::EventId.eq(event_id))
            .filter(billing_processed_event::Column::Status.eq("processing"))
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    async fn cleanup_old_events(&self, older_than_days: u32) -> Result<usize> {
        self.cleanup_old_events_batched(older_than_days, None).await
    }

    async fn count_subscriptions_by_plan(&self, plan_id: &str) -> Result<u32> {
        tracing::debug!(plan_id = %plan_id, "counting active subscriptions for plan");

        let count = billing_subscription::Entity::find()
            .filter(billing_subscription::Column::PlanId.eq(plan_id))
            .filter(billing_subscription::Column::Status.is_in(["active", "trialing"]))
            .count(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(count as u32)
    }
}

// =============================================================================
// PlanStore Implementation
// =============================================================================

#[async_trait]
impl PlanStore for SeaOrmBillingStore {
    async fn list_plans(&self) -> Result<Vec<StoredPlan>> {
        tracing::debug!("listing active plans");

        let plans = billing_plan::Entity::find()
            .filter(billing_plan::Column::IsActive.eq(true))
            .order_by_asc(billing_plan::Column::SortOrder)
            .all(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(plans.into_iter().map(model_to_stored_plan).collect())
    }

    async fn list_all_plans(&self) -> Result<Vec<StoredPlan>> {
        tracing::debug!("listing all plans");

        let plans = billing_plan::Entity::find()
            .order_by_asc(billing_plan::Column::SortOrder)
            .all(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(plans.into_iter().map(model_to_stored_plan).collect())
    }

    async fn get_plan(&self, plan_id: &str) -> Result<Option<StoredPlan>> {
        tracing::debug!(plan_id = %plan_id, "fetching plan");

        let plan = billing_plan::Entity::find_by_id(plan_id)
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(plan.map(model_to_stored_plan))
    }

    async fn get_plan_by_stripe_price(&self, stripe_price_id: &str) -> Result<Option<StoredPlan>> {
        tracing::debug!(stripe_price_id = %stripe_price_id, "fetching plan by stripe price");

        let plan = billing_plan::Entity::find()
            .filter(billing_plan::Column::StripePriceId.eq(stripe_price_id))
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(plan.map(model_to_stored_plan))
    }

    async fn create_plan(&self, plan: &StoredPlan) -> Result<()> {
        tracing::debug!(plan_id = %plan.id, "creating plan");

        let active_model = plan_to_active_model(plan);

        billing_plan::Entity::insert(active_model)
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    async fn update_plan(&self, plan: &StoredPlan) -> Result<()> {
        tracing::debug!(plan_id = %plan.id, "updating plan");

        let now = chrono::Utc::now().fixed_offset();

        billing_plan::Entity::update_many()
            .col_expr(billing_plan::Column::Name, Expr::value(&plan.name))
            .col_expr(
                billing_plan::Column::Description,
                Expr::value(plan.description.clone()),
            )
            .col_expr(
                billing_plan::Column::StripePriceId,
                Expr::value(&plan.stripe_price_id),
            )
            .col_expr(
                billing_plan::Column::StripeSeatPriceId,
                Expr::value(plan.stripe_seat_price_id.clone()),
            )
            .col_expr(
                billing_plan::Column::PriceCents,
                Expr::value(plan.price_cents),
            )
            .col_expr(billing_plan::Column::Currency, Expr::value(&plan.currency))
            .col_expr(
                billing_plan::Column::Interval,
                Expr::value(plan.interval.as_str()),
            )
            .col_expr(
                billing_plan::Column::IncludedSeats,
                Expr::value(u32_to_i32(plan.included_seats)),
            )
            .col_expr(
                billing_plan::Column::Features,
                Expr::value(plan.features.clone()),
            )
            .col_expr(
                billing_plan::Column::Limits,
                Expr::value(plan.limits.clone()),
            )
            .col_expr(
                billing_plan::Column::TrialDays,
                Expr::value(plan.trial_days.map(u32_to_i32)),
            )
            .col_expr(billing_plan::Column::IsActive, Expr::value(plan.is_active))
            .col_expr(
                billing_plan::Column::SortOrder,
                Expr::value(plan.sort_order),
            )
            .col_expr(billing_plan::Column::UpdatedAt, Expr::value(now))
            .filter(billing_plan::Column::Id.eq(&plan.id))
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    async fn delete_plan(&self, plan_id: &str) -> Result<()> {
        tracing::debug!(plan_id = %plan_id, "deleting plan");

        billing_plan::Entity::delete_by_id(plan_id)
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    async fn set_plan_active(&self, plan_id: &str, is_active: bool) -> Result<()> {
        tracing::debug!(plan_id = %plan_id, is_active = is_active, "setting plan active status");

        let now = chrono::Utc::now().fixed_offset();

        billing_plan::Entity::update_many()
            .col_expr(billing_plan::Column::IsActive, Expr::value(is_active))
            .col_expr(billing_plan::Column::UpdatedAt, Expr::value(now))
            .filter(billing_plan::Column::Id.eq(plan_id))
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }
}

// =============================================================================
// Additional Methods (not part of BillingStore trait)
// =============================================================================

impl SeaOrmBillingStore {
    /// Delete old processed events in batches to avoid locking the table.
    ///
    /// This is useful for high-volume production systems where the
    /// `billing_processed_events` table may contain millions of rows.
    ///
    /// # Arguments
    ///
    /// * `older_than_days` - Delete events older than this many days
    /// * `batch_size` - Optional batch size (default: 1000, None for unbatched)
    ///
    /// # Returns
    ///
    /// Total number of deleted events across all batches.
    pub async fn cleanup_old_events_batched(
        &self,
        older_than_days: u32,
        batch_size: Option<u32>,
    ) -> Result<usize> {
        tracing::debug!(
            older_than_days = older_than_days,
            batch_size = ?batch_size,
            "cleaning up old events"
        );

        let cutoff = chrono::Utc::now() - chrono::Duration::days(i64::from(older_than_days));
        let cutoff_tz = cutoff.fixed_offset();

        let batch_size = match batch_size {
            Some(0) => return Ok(0), // No-op if batch size is 0
            Some(size) => size,
            None => {
                // Unbatched: delete all at once
                let result = billing_processed_event::Entity::delete_many()
                    .filter(billing_processed_event::Column::Status.eq("processed"))
                    .filter(billing_processed_event::Column::ProcessedAt.lt(cutoff_tz))
                    .exec(&self.db)
                    .await
                    .map_err(|e| TidewayError::Database(e.to_string()))?;

                let deleted = u64_to_usize(result.rows_affected);
                tracing::info!(deleted = deleted, "cleaned up old billing events");
                return Ok(deleted);
            }
        };

        // Batched deletion
        let mut total_deleted: usize = 0;
        loop {
            // Find batch of event IDs to delete
            let events_to_delete: Vec<String> = billing_processed_event::Entity::find()
                .filter(billing_processed_event::Column::Status.eq("processed"))
                .filter(billing_processed_event::Column::ProcessedAt.lt(cutoff_tz))
                .limit(u64::from(batch_size))
                .all(&self.db)
                .await
                .map_err(|e| TidewayError::Database(e.to_string()))?
                .into_iter()
                .map(|e| e.event_id)
                .collect();

            if events_to_delete.is_empty() {
                break;
            }

            let batch_count = events_to_delete.len();

            // Delete this batch
            billing_processed_event::Entity::delete_many()
                .filter(billing_processed_event::Column::Status.eq("processed"))
                .filter(billing_processed_event::Column::EventId.is_in(events_to_delete))
                .exec(&self.db)
                .await
                .map_err(|e| TidewayError::Database(e.to_string()))?;

            total_deleted = total_deleted.saturating_add(batch_count);

            tracing::debug!(
                batch_deleted = batch_count,
                total_deleted = total_deleted,
                "deleted batch of old billing events"
            );

            // If we got fewer than batch_size, we're done
            if batch_count < batch_size as usize {
                break;
            }
        }

        tracing::info!(deleted = total_deleted, "cleaned up old billing events");
        Ok(total_deleted)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ConnectionTrait, Database, Statement};

    async fn setup_billing_events_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("sqlite in-memory db should connect");

        db.execute(Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            "CREATE TABLE billing_processed_events (
                event_id TEXT PRIMARY KEY NOT NULL,
                status TEXT NOT NULL DEFAULT 'processed',
                claim_token TEXT NULL,
                claimed_at TEXT NULL,
                processed_at TEXT NOT NULL
            )"
            .to_string(),
        ))
        .await
        .expect("should create billing_processed_events table");

        db
    }

    async fn setup_billing_subscriptions_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("sqlite in-memory db should connect");

        db.execute(Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            "CREATE TABLE billing_subscriptions (
                billable_id TEXT PRIMARY KEY NOT NULL,
                stripe_subscription_id TEXT UNIQUE NOT NULL,
                stripe_customer_id TEXT NOT NULL,
                plan_id TEXT NOT NULL,
                status TEXT NOT NULL,
                current_period_start INTEGER NOT NULL,
                current_period_end INTEGER NOT NULL,
                extra_seats INTEGER NOT NULL,
                trial_end INTEGER,
                cancel_at_period_end INTEGER NOT NULL,
                base_item_id TEXT,
                seat_item_id TEXT,
                updated_at INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )"
            .to_string(),
        ))
        .await
        .expect("should create billing_subscriptions table");

        db
    }

    #[tokio::test]
    async fn claim_event_allows_exactly_one_concurrent_winner() {
        let store = SeaOrmBillingStore::new(setup_billing_events_db().await);

        let (first, second) = tokio::join!(
            store.acquire_event_claim("evt_concurrent"),
            store.acquire_event_claim("evt_concurrent")
        );

        let outcomes = [
            first.expect("first claim should not fail"),
            second.expect("second claim should not fail"),
        ];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ClaimOutcome::Acquired(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ClaimOutcome::InProgress { .. }))
                .count(),
            1
        );
        assert!(!store.is_event_processed("evt_concurrent").await.unwrap());

        let claim = outcomes
            .into_iter()
            .find_map(|outcome| match outcome {
                ClaimOutcome::Acquired(claim) => Some(claim),
                _ => None,
            })
            .unwrap();
        store.complete_event_claim(&claim).await.unwrap();
        assert!(store.is_event_processed("evt_concurrent").await.unwrap());
        assert!(matches!(
            store.acquire_event_claim("evt_concurrent").await.unwrap(),
            ClaimOutcome::AlreadyProcessed
        ));
    }

    #[tokio::test]
    async fn stale_claim_is_recovered_once_and_old_owner_cannot_mutate_it() {
        use sea_orm::sea_query::Expr;

        let store = SeaOrmBillingStore::new(setup_billing_events_db().await);
        let old_claim = match store.acquire_event_claim("evt_stale").await.unwrap() {
            ClaimOutcome::Acquired(claim) => claim,
            outcome => panic!("unexpected claim outcome: {outcome:?}"),
        };
        let stale_at = chrono::Utc::now().fixed_offset() - chrono::Duration::minutes(10);
        billing_processed_event::Entity::update_many()
            .col_expr(
                billing_processed_event::Column::ClaimedAt,
                Expr::value(Some(stale_at)),
            )
            .filter(billing_processed_event::Column::EventId.eq("evt_stale"))
            .exec(store.connection())
            .await
            .unwrap();

        let (first, second) = tokio::join!(
            store.acquire_event_claim("evt_stale"),
            store.acquire_event_claim("evt_stale")
        );
        let outcomes = [first.unwrap(), second.unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ClaimOutcome::Acquired(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ClaimOutcome::InProgress { .. }))
                .count(),
            1
        );
        let current_claim = outcomes
            .into_iter()
            .find_map(|outcome| match outcome {
                ClaimOutcome::Acquired(claim) => Some(claim),
                _ => None,
            })
            .unwrap();

        store.release_owned_event_claim(&old_claim).await.unwrap();
        assert!(store.complete_event_claim(&old_claim).await.is_err());
        store.complete_event_claim(&current_claim).await.unwrap();
        store
            .release_owned_event_claim(&current_claim)
            .await
            .unwrap();
        assert!(store.is_event_processed("evt_stale").await.unwrap());
    }

    #[tokio::test]
    async fn compare_and_save_allows_exactly_one_concurrent_winner() {
        let store = SeaOrmBillingStore::new(setup_billing_subscriptions_db().await);
        let initial = StoredSubscription {
            stripe_subscription_id: "sub_concurrent".to_string(),
            stripe_customer_id: "cus_concurrent".to_string(),
            plan_id: "starter".to_string(),
            status: SubscriptionStatus::Active,
            current_period_start: 1_700_000_000,
            current_period_end: 1_702_592_000,
            extra_seats: 1,
            trial_end: None,
            cancel_at_period_end: false,
            base_item_id: Some("si_base".to_string()),
            seat_item_id: Some("si_seat".to_string()),
            updated_at: 100,
        };
        store
            .save_subscription("org_concurrent", &initial)
            .await
            .expect("save initial subscription");

        let mut first_update = initial.clone();
        first_update.extra_seats = 2;
        first_update.updated_at = 100;
        let mut second_update = initial.clone();
        second_update.extra_seats = 3;
        second_update.updated_at = 100;

        let (first, second) = tokio::join!(
            store.compare_and_save_subscription("org_concurrent", &first_update, 100),
            store.compare_and_save_subscription("org_concurrent", &second_update, 100),
        );
        let winners = [
            first.expect("first update should not fail"),
            second.expect("second update should not fail"),
        ];

        assert_eq!(winners.into_iter().filter(|saved| *saved).count(), 1);
        let saved = store
            .get_subscription("org_concurrent")
            .await
            .expect("load subscription")
            .expect("subscription should exist");
        assert!(matches!(saved.extra_seats, 2 | 3));
        assert_eq!(saved.updated_at, 101);
    }

    #[test]
    fn test_model_to_stored_subscription() {
        let model = billing_subscription::Model {
            billable_id: "org_123".to_string(),
            stripe_subscription_id: "sub_abc".to_string(),
            stripe_customer_id: "cus_xyz".to_string(),
            plan_id: "starter".to_string(),
            status: "active".to_string(),
            current_period_start: 1700000000,
            current_period_end: 1702592000,
            extra_seats: 2,
            trial_end: Some(1700500000),
            cancel_at_period_end: false,
            base_item_id: Some("si_base".to_string()),
            seat_item_id: Some("si_seat".to_string()),
            updated_at: 1700000000,
            created_at: chrono::Utc::now().fixed_offset(),
        };

        let stored = model_to_stored_subscription(model);

        assert_eq!(stored.stripe_subscription_id, "sub_abc");
        assert_eq!(stored.stripe_customer_id, "cus_xyz");
        assert_eq!(stored.plan_id, "starter");
        assert_eq!(stored.status, SubscriptionStatus::Active);
        assert_eq!(stored.current_period_start, 1700000000);
        assert_eq!(stored.current_period_end, 1702592000);
        assert_eq!(stored.extra_seats, 2);
        assert_eq!(stored.trial_end, Some(1700500000));
        assert!(!stored.cancel_at_period_end);
        assert_eq!(stored.base_item_id, Some("si_base".to_string()));
        assert_eq!(stored.seat_item_id, Some("si_seat".to_string()));
        assert_eq!(stored.updated_at, 1700000000);
    }

    #[test]
    fn test_subscription_to_active_model() {
        let subscription = StoredSubscription {
            stripe_subscription_id: "sub_abc".to_string(),
            stripe_customer_id: "cus_xyz".to_string(),
            plan_id: "starter".to_string(),
            status: SubscriptionStatus::Active,
            current_period_start: 1700000000,
            current_period_end: 1702592000,
            extra_seats: 2,
            trial_end: Some(1700500000),
            cancel_at_period_end: false,
            base_item_id: Some("si_base".to_string()),
            seat_item_id: Some("si_seat".to_string()),
            updated_at: 1700000000,
        };

        let now = chrono::Utc::now().fixed_offset();
        let active = subscription_to_active_model("org_123", &subscription, now);

        // Verify the active model was created (can't easily check Set values)
        assert!(matches!(active.billable_id, Set(_)));
        assert!(matches!(active.stripe_subscription_id, Set(_)));
    }

    #[test]
    fn test_subscription_status_conversion() {
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
    }

    #[test]
    fn test_safe_integer_conversions() {
        // i64 to u64: negative becomes 0
        assert_eq!(i64_to_u64(100), 100);
        assert_eq!(i64_to_u64(0), 0);
        assert_eq!(i64_to_u64(-1), 0);
        assert_eq!(i64_to_u64(i64::MIN), 0);
        assert_eq!(i64_to_u64(i64::MAX), i64::MAX as u64);

        // u64 to i64: values > i64::MAX become i64::MAX
        assert_eq!(u64_to_i64(100), 100);
        assert_eq!(u64_to_i64(0), 0);
        assert_eq!(u64_to_i64(i64::MAX as u64), i64::MAX);
        assert_eq!(u64_to_i64(u64::MAX), i64::MAX);

        // i32 to u32: negative becomes 0
        assert_eq!(i32_to_u32(100), 100);
        assert_eq!(i32_to_u32(0), 0);
        assert_eq!(i32_to_u32(-1), 0);
        assert_eq!(i32_to_u32(i32::MIN), 0);

        // u32 to i32: values > i32::MAX become i32::MAX
        assert_eq!(u32_to_i32(100), 100);
        assert_eq!(u32_to_i32(0), 0);
        assert_eq!(u32_to_i32(i32::MAX as u32), i32::MAX);
        assert_eq!(u32_to_i32(u32::MAX), i32::MAX);

        // u64 to usize: values > usize::MAX become usize::MAX
        assert_eq!(u64_to_usize(100), 100);
        assert_eq!(u64_to_usize(0), 0);
        assert_eq!(u64_to_usize(usize::MAX as u64), usize::MAX);
        // Saturation always yields a valid usize upper bound.
        assert_eq!(u64_to_usize(u64::MAX), usize::MAX);
    }
}
