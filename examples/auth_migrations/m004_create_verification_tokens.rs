//! Example migration: Create verification tokens table for email verification and password reset.
//!
//! Copy and adapt this migration to your project.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(VerificationTokens::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(VerificationTokens::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(VerificationTokens::UserId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(VerificationTokens::TokenHash)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(VerificationTokens::TokenType)
                            .string_len(32)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(VerificationTokens::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(VerificationTokens::UsedAt).timestamp_with_time_zone().null())
                    .col(
                        ColumnDef::new(VerificationTokens::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_verification_tokens_user")
                            .from(VerificationTokens::Table, VerificationTokens::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Create index on token_hash for fast lookups
        manager
            .create_index(
                Index::create()
                    .name("idx_verification_tokens_hash")
                    .table(VerificationTokens::Table)
                    .col(VerificationTokens::TokenHash)
                    .to_owned(),
            )
            .await?;

        // Create index on user_id for cleanup
        manager
            .create_index(
                Index::create()
                    .name("idx_verification_tokens_user_id")
                    .table(VerificationTokens::Table)
                    .col(VerificationTokens::UserId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(VerificationTokens::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum VerificationTokens {
    Table,
    Id,
    UserId,
    TokenHash,
    TokenType,  // "email_verification" or "password_reset"
    ExpiresAt,
    UsedAt,
    CreatedAt,
}

// Reference to Users table from m001
#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}
