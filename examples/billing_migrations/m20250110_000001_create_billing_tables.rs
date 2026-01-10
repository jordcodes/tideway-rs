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

use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create billing_customers table
        manager
            .create_table(
                Table::create()
                    .table(BillingCustomers::Table)
                    .if_not_exists()
                    .col(string(BillingCustomers::BillableId).primary_key())
                    .col(string(BillingCustomers::BillableType).not_null())
                    .col(string(BillingCustomers::StripeCustomerId).not_null().unique_key())
                    .col(
                        timestamp_with_time_zone(BillingCustomers::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp_with_time_zone(BillingCustomers::UpdatedAt)
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
                    .col(string(BillingSubscriptions::BillableId).primary_key())
                    .col(
                        string(BillingSubscriptions::StripeSubscriptionId)
                            .not_null()
                            .unique_key(),
                    )
                    .col(string(BillingSubscriptions::StripeCustomerId).not_null())
                    .col(string(BillingSubscriptions::PlanId).not_null())
                    .col(string(BillingSubscriptions::Status).not_null())
                    .col(big_integer(BillingSubscriptions::CurrentPeriodStart).not_null())
                    .col(big_integer(BillingSubscriptions::CurrentPeriodEnd).not_null())
                    .col(
                        integer(BillingSubscriptions::ExtraSeats)
                            .not_null()
                            .default(0),
                    )
                    .col(big_integer_null(BillingSubscriptions::TrialEnd))
                    .col(
                        boolean(BillingSubscriptions::CancelAtPeriodEnd)
                            .not_null()
                            .default(false),
                    )
                    .col(string_null(BillingSubscriptions::BaseItemId))
                    .col(string_null(BillingSubscriptions::SeatItemId))
                    .col(big_integer(BillingSubscriptions::UpdatedAt).not_null())
                    .col(
                        timestamp_with_time_zone(BillingSubscriptions::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        // Note: stripe_subscription_id already has an index from unique_key()

        // Create billing_processed_events table
        manager
            .create_table(
                Table::create()
                    .table(BillingProcessedEvents::Table)
                    .if_not_exists()
                    .col(string(BillingProcessedEvents::EventId).primary_key())
                    .col(
                        timestamp_with_time_zone(BillingProcessedEvents::ProcessedAt)
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
        // Drop tables in reverse order
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
