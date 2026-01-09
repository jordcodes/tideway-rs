//! Example migration: Create MFA table for TOTP and backup codes.
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
                    .table(UserMfa::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserMfa::UserId)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(UserMfa::TotpSecret)
                            .string_len(255)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserMfa::TotpEnabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(UserMfa::BackupCodes)
                            .json()
                            .null(),
                    )
                    .col(ColumnDef::new(UserMfa::EnabledAt).timestamp_with_time_zone().null())
                    .col(
                        ColumnDef::new(UserMfa::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(UserMfa::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_user_mfa_user")
                            .from(UserMfa::Table, UserMfa::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserMfa::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum UserMfa {
    Table,
    UserId,
    TotpSecret,
    TotpEnabled,
    BackupCodes,
    EnabledAt,
    CreatedAt,
    UpdatedAt,
}

// Reference to Users table from m001
#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}
