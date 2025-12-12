use crate::database::config::redact_database_url;
use crate::error::{Result, TidewayError};
use crate::traits::database::{DatabaseConnection, DatabasePool};
use async_trait::async_trait;
use sea_orm::{ConnectOptions, Database, DatabaseConnection as SeaOrmConnection};
use std::sync::Arc;
use std::time::Duration;

/// Wrapper around SeaORM connection to implement DatabaseConnection trait
pub struct SeaOrmConnectionWrapper {
    pub conn: SeaOrmConnection,
}

impl DatabaseConnection for SeaOrmConnectionWrapper {
    fn is_valid(&self) -> bool {
        // SeaORM connections are always valid (they're connection pools)
        true
    }
}

impl std::ops::Deref for SeaOrmConnectionWrapper {
    type Target = SeaOrmConnection;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

/// SeaORM database pool implementation
///
/// # Security Note
///
/// The stored URL is automatically redacted (password replaced with `[REDACTED]`)
/// to prevent accidental credential leakage in logs or error messages.
pub struct SeaOrmPool {
    conn: Arc<SeaOrmConnection>,
    /// Redacted URL (safe for logging)
    redacted_url: String,
}

impl SeaOrmPool {
    /// Create a new SeaORM pool from a connection
    ///
    /// The URL is automatically redacted for safety.
    pub fn new(conn: SeaOrmConnection, url: String) -> Self {
        Self {
            conn: Arc::new(conn),
            redacted_url: redact_database_url(&url),
        }
    }

    /// Create a new SeaORM pool from config
    pub async fn from_config(config: &crate::database::DatabaseConfig) -> Result<Self> {
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

        Ok(Self::new(conn, config.url.clone()))
    }

    /// Get the inner SeaORM connection
    pub fn inner(&self) -> &SeaOrmConnection {
        &self.conn
    }
}

#[async_trait]
impl DatabasePool for SeaOrmPool {
    async fn connection(&self) -> Result<Box<dyn DatabaseConnection>> {
        // SeaORM's DatabaseConnection is already a pool/connection manager
        // We wrap the Arc reference so it can be used
        // Note: In practice, SeaORM connections are Clone (they're connection pools)
        Ok(Box::new(SeaOrmConnectionWrapper {
            conn: (*self.conn).clone(),
        }))
    }

    fn is_healthy(&self) -> bool {
        // Check health by trying to ping (synchronously we can't, so assume healthy)
        // In practice, you might want to spawn a task to check periodically
        true
    }

    async fn close(self: Box<Self>) -> Result<()> {
        // Convert Arc back to owned connection for closing
        // This is tricky with Arc - we'd need to ensure we're the only owner
        // For now, we'll just drop it (the pool will close when all references are dropped)
        drop(self);
        Ok(())
    }

    fn connection_url(&self) -> Option<&str> {
        Some(&self.redacted_url)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
