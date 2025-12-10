use super::config::DatabaseConfig;
use crate::error::{Result, TidewayError};
use sea_orm::{ConnectOptions, Database, DatabaseConnection as SeaOrmConnection};
use std::time::Duration;

/// Wrapper around SeaORM database connection
#[derive(Clone)]
pub struct DatabaseConnection {
    pub conn: SeaOrmConnection,
}

impl DatabaseConnection {
    /// Create a new database connection from config
    pub async fn connect(config: &DatabaseConfig) -> Result<Self> {
        let mut opt = ConnectOptions::new(&config.url);
        opt.max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .connect_timeout(Duration::from_secs(config.connect_timeout))
            .idle_timeout(Duration::from_secs(config.idle_timeout))
            .sqlx_logging(true);

        let conn = Database::connect(opt)
            .await
            .map_err(|e| TidewayError::internal(format!("Failed to connect to database: {}", e)))?;

        tracing::info!(
            "Database connected with {} max connections",
            config.max_connections
        );

        Ok(Self { conn })
    }

    /// Ping the database to check connection health
    pub async fn ping(&self) -> Result<()> {
        self.conn
            .ping()
            .await
            .map_err(|e| TidewayError::internal(format!("Database ping failed: {}", e)))
    }

    /// Close the database connection
    pub async fn close(self) -> Result<()> {
        self.conn
            .close()
            .await
            .map_err(|e| TidewayError::internal(format!("Failed to close database: {}", e)))
    }

    /// Get the inner SeaORM connection
    pub fn as_ref(&self) -> &SeaOrmConnection {
        &self.conn
    }
}

impl std::ops::Deref for DatabaseConnection {
    type Target = SeaOrmConnection;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}
