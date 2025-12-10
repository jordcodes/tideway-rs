use crate::error::{Result, TidewayError};
use sea_orm_migration::MigratorTrait;

/// Run pending migrations
///
/// # Example
///
/// ```rust,ignore
/// use sea_orm_migration::MigratorTrait;
/// use tideway::database::run_migrations;
///
/// // Define your migrator
/// pub struct Migrator;
///
/// #[async_trait::async_trait]
/// impl MigratorTrait for Migrator {
///     fn migrations() -> Vec<Box<dyn MigrationTrait>> {
///         vec![
///             Box::new(m20250101_create_users::Migration),
///             Box::new(m20250102_create_organizations::Migration),
///         ]
///     }
/// }
///
/// // Run migrations
/// run_migrations::<Migrator>(&db).await?;
/// ```
pub async fn run_migrations<M: MigratorTrait>(db: &sea_orm::DatabaseConnection) -> Result<()> {
    M::up(db, None)
        .await
        .map_err(|e| TidewayError::internal(format!("Migration failed: {}", e)))?;

    tracing::info!("Database migrations completed successfully");
    Ok(())
}

/// Check migration status
pub async fn migration_status<M: MigratorTrait>(db: &sea_orm::DatabaseConnection) -> Result<()> {
    M::status(db)
        .await
        .map_err(|e| TidewayError::internal(format!("Failed to check migration status: {}", e)))
}

/// Rollback the last migration
pub async fn rollback_migration<M: MigratorTrait>(
    db: &sea_orm::DatabaseConnection,
    steps: Option<u32>,
) -> Result<()> {
    M::down(db, steps)
        .await
        .map_err(|e| TidewayError::internal(format!("Rollback failed: {}", e)))?;

    tracing::info!("Rolled back {} migration(s)", steps.unwrap_or(1));
    Ok(())
}

/// Reset the database (down all migrations then up)
pub async fn reset_database<M: MigratorTrait>(db: &sea_orm::DatabaseConnection) -> Result<()> {
    M::fresh(db)
        .await
        .map_err(|e| TidewayError::internal(format!("Database reset failed: {}", e)))?;

    tracing::info!("Database reset completed");
    Ok(())
}
