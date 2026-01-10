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
    entity::prelude::*, sea_query::OnConflict, ActiveModelTrait, ColumnTrait, DatabaseConnection,
    EntityTrait, QueryFilter, Set, TransactionTrait,
};

use super::storage::{BillingStore, StoredSubscription, SubscriptionStatus};
use crate::error::Result;
use crate::TidewayError;

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
    // Billing Processed Event Entity
    // -------------------------------------------------------------------------
    pub mod billing_processed_event {
        use super::*;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
        #[sea_orm(table_name = "billing_processed_events")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub event_id: String,
            pub processed_at: DateTimeWithTimeZone,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}

        impl ActiveModelBehavior for ActiveModel {}
    }
}

use entity::{billing_customer, billing_processed_event, billing_subscription};

// =============================================================================
// Helper Functions
// =============================================================================

/// Convert a database model to a StoredSubscription.
fn model_to_stored_subscription(model: billing_subscription::Model) -> StoredSubscription {
    StoredSubscription {
        stripe_subscription_id: model.stripe_subscription_id,
        stripe_customer_id: model.stripe_customer_id,
        plan_id: model.plan_id,
        status: SubscriptionStatus::from_stripe(&model.status),
        current_period_start: model.current_period_start as u64,
        current_period_end: model.current_period_end as u64,
        extra_seats: model.extra_seats as u32,
        trial_end: model.trial_end.map(|t| t as u64),
        cancel_at_period_end: model.cancel_at_period_end,
        base_item_id: model.base_item_id,
        seat_item_id: model.seat_item_id,
        updated_at: model.updated_at as u64,
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
        current_period_start: Set(subscription.current_period_start as i64),
        current_period_end: Set(subscription.current_period_end as i64),
        extra_seats: Set(subscription.extra_seats as i32),
        trial_end: Set(subscription.trial_end.map(|t| t as i64)),
        cancel_at_period_end: Set(subscription.cancel_at_period_end),
        base_item_id: Set(subscription.base_item_id.clone()),
        seat_item_id: Set(subscription.seat_item_id.clone()),
        updated_at: Set(subscription.updated_at as i64),
        created_at: Set(created_at),
    }
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
}

impl SeaOrmBillingStore {
    /// Create a new SeaORM billing store.
    ///
    /// # Arguments
    ///
    /// * `db` - A SeaORM database connection
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
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

        // First, try conditional UPDATE for existing records
        let update_result = billing_subscription::Entity::update_many()
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
                Expr::value(subscription.current_period_start as i64),
            )
            .col_expr(
                billing_subscription::Column::CurrentPeriodEnd,
                Expr::value(subscription.current_period_end as i64),
            )
            .col_expr(
                billing_subscription::Column::ExtraSeats,
                Expr::value(subscription.extra_seats as i32),
            )
            .col_expr(
                billing_subscription::Column::TrialEnd,
                Expr::value(subscription.trial_end.map(|t| t as i64)),
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
                Expr::value(subscription.updated_at as i64),
            )
            .filter(billing_subscription::Column::BillableId.eq(billable_id))
            .filter(billing_subscription::Column::UpdatedAt.eq(expected_version as i64))
            .exec(&txn)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        if update_result.rows_affected > 0 {
            // Update succeeded - version matched
            txn.commit()
                .await
                .map_err(|e| TidewayError::Database(e.to_string()))?;
            tracing::debug!(billable_id = %billable_id, "subscription updated successfully");
            return Ok(true);
        }

        // UPDATE affected 0 rows - either record doesn't exist or version mismatch
        // Check if record exists
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

        // Record doesn't exist and expected_version is 0 - insert new record
        if expected_version == 0 {
            let now = chrono::Utc::now().fixed_offset();
            let active_model = subscription_to_active_model(billable_id, subscription, now);

            active_model
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

        Ok(event.is_some())
    }

    async fn mark_event_processed(&self, event_id: &str) -> Result<()> {
        tracing::debug!(event_id = %event_id, "marking event as processed");

        let now = chrono::Utc::now().fixed_offset();

        let event = billing_processed_event::ActiveModel {
            event_id: Set(event_id.to_string()),
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

    async fn cleanup_old_events(&self, older_than_days: u32) -> Result<usize> {
        tracing::debug!(older_than_days = older_than_days, "cleaning up old events");

        let cutoff = chrono::Utc::now() - chrono::Duration::days(older_than_days as i64);
        let cutoff_tz = cutoff.fixed_offset();

        let result = billing_processed_event::Entity::delete_many()
            .filter(billing_processed_event::Column::ProcessedAt.lt(cutoff_tz))
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        tracing::info!(deleted = result.rows_affected, "cleaned up old billing events");
        Ok(result.rows_affected as usize)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
}
