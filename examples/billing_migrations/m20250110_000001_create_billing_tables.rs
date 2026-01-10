//! Billing tables migration.
//!
//! Creates the tables needed for the tideway billing module:
//! - billing_customers: Links billable entities to Stripe customers
//! - billing_subscriptions: Cached subscription state from Stripe
//! - billing_processed_events: Webhook event idempotency tracking
//!
//! # Usage
//!
//! Copy this file to your migrations directory and add it to your migrator:
//!
//! ```rust,ignore
//! use sea_orm_migration::prelude::*;
//!
//! pub struct Migrator;
//!
//! #[async_trait::async_trait]
//! impl MigratorTrait for Migrator {
//!     fn migrations() -> Vec<Box<dyn MigrationTrait>> {
//!         vec![
//!             // Your other migrations...
//!             Box::new(m20250110_000001_create_billing_tables::Migration),
//!         ]
//!     }
//! }
//! ```

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Valid subscription status values (matches Stripe's subscription statuses).
const VALID_STATUSES: &[&str] = &[
    "active",
    "trialing",
    "past_due",
    "canceled",
    "incomplete",
    "incomplete_expired",
    "paused",
    "unpaid",
];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create billing_customers table
        manager
            .create_table(
                Table::create()
                    .table(BillingCustomers::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(BillingCustomers::BillableId)
                            .string_len(255)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(BillingCustomers::BillableType)
                            .string_len(50)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BillingCustomers::StripeCustomerId)
                            .string_len(255)
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(BillingCustomers::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(BillingCustomers::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        // Note: stripe_customer_id already has an index from unique_key()

        // Create billing_subscriptions table
        manager
            .create_table(
                Table::create()
                    .table(BillingSubscriptions::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(BillingSubscriptions::BillableId)
                            .string_len(255)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(BillingSubscriptions::StripeSubscriptionId)
                            .string_len(255)
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(BillingSubscriptions::StripeCustomerId)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BillingSubscriptions::PlanId)
                            .string_len(100)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BillingSubscriptions::Status)
                            .string_len(50)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BillingSubscriptions::CurrentPeriodStart)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BillingSubscriptions::CurrentPeriodEnd)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BillingSubscriptions::ExtraSeats)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(BillingSubscriptions::TrialEnd)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(BillingSubscriptions::CancelAtPeriodEnd)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(BillingSubscriptions::BaseItemId)
                            .string_len(255)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(BillingSubscriptions::SeatItemId)
                            .string_len(255)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(BillingSubscriptions::UpdatedAt)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BillingSubscriptions::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        // Note: stripe_subscription_id already has an index from unique_key()

        // Add CHECK constraint for status column (PostgreSQL/SQLite)
        // This ensures only valid Stripe subscription statuses can be stored
        let status_values = VALID_STATUSES
            .iter()
            .map(|s| format!("'{}'", s))
            .collect::<Vec<_>>()
            .join(", ");

        let check_constraint_sql = format!(
            "ALTER TABLE billing_subscriptions ADD CONSTRAINT chk_billing_subscriptions_status CHECK (status IN ({}))",
            status_values
        );

        // Execute raw SQL for CHECK constraint (may fail on some DBs, that's ok)
        let _ = manager
            .get_connection()
            .execute_unprepared(&check_constraint_sql)
            .await;

        // Create billing_processed_events table
        manager
            .create_table(
                Table::create()
                    .table(BillingProcessedEvents::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(BillingProcessedEvents::EventId)
                            .string_len(255)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(BillingProcessedEvents::ProcessedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        // Create index on processed_at for cleanup queries
        manager
            .create_index(
                Index::create()
                    .name("idx_billing_processed_events_processed_at")
                    .table(BillingProcessedEvents::Table)
                    .col(BillingProcessedEvents::ProcessedAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop tables in reverse order (constraints are dropped with tables)
        manager
            .drop_table(Table::drop().table(BillingProcessedEvents::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(BillingSubscriptions::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(BillingCustomers::Table).to_owned())
            .await?;

        Ok(())
    }
}

// =============================================================================
// Table Definitions
// =============================================================================

#[derive(DeriveIden)]
enum BillingCustomers {
    Table,
    BillableId,
    BillableType,
    StripeCustomerId,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum BillingSubscriptions {
    Table,
    BillableId,
    StripeSubscriptionId,
    StripeCustomerId,
    PlanId,
    Status,
    CurrentPeriodStart,
    CurrentPeriodEnd,
    ExtraSeats,
    TrialEnd,
    CancelAtPeriodEnd,
    BaseItemId,
    SeatItemId,
    UpdatedAt,
    CreatedAt,
}

#[derive(DeriveIden)]
enum BillingProcessedEvents {
    Table,
    EventId,
    ProcessedAt,
}
