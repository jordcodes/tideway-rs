//! Example migration: Create refresh token families table for token rotation.
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
                    .table(RefreshTokenFamilies::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RefreshTokenFamilies::Family)
                            .string_len(32)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(RefreshTokenFamilies::UserId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RefreshTokenFamilies::Generation)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(RefreshTokenFamilies::Revoked)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(RefreshTokenFamilies::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_refresh_tokens_user")
                            .from(RefreshTokenFamilies::Table, RefreshTokenFamilies::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Create index on user_id for fast lookups when revoking all user tokens
        manager
            .create_index(
                Index::create()
                    .name("idx_refresh_token_families_user_id")
                    .table(RefreshTokenFamilies::Table)
                    .col(RefreshTokenFamilies::UserId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(RefreshTokenFamilies::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum RefreshTokenFamilies {
    Table,
    Family,
    UserId,
    Generation,
    Revoked,
    CreatedAt,
}

// Reference to Users table from m001
#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}
