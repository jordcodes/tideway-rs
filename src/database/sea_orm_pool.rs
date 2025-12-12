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
    /// Cached health status (updated by ping operations)
    /// This avoids blocking the sync is_healthy() trait method
    health_status: Arc<std::sync::atomic::AtomicBool>,
}

impl SeaOrmPool {
    /// Create a new SeaORM pool from a connection
    ///
    /// The URL is automatically redacted for safety.
    pub fn new(conn: SeaOrmConnection, url: String) -> Self {
        Self {
            conn: Arc::new(conn),
            redacted_url: redact_database_url(&url),
            health_status: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }

    /// Create a new SeaORM pool from config
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `max_connections` is 0 or greater than 1000
    /// - `min_connections` is greater than `max_connections`
    /// - `connect_timeout` is 0 or greater than 300 seconds
    /// - Database connection fails
    pub async fn from_config(config: &crate::database::DatabaseConfig) -> Result<Self> {
        // Validate configuration to prevent resource exhaustion
        if config.max_connections == 0 {
            return Err(TidewayError::bad_request("max_connections must be greater than 0"));
        }
        if config.max_connections > 1000 {
            return Err(TidewayError::bad_request("max_connections cannot exceed 1000"));
        }
        if config.min_connections > config.max_connections {
            return Err(TidewayError::bad_request(
                "min_connections cannot be greater than max_connections"
            ));
        }
        if config.connect_timeout == 0 {
            return Err(TidewayError::bad_request("connect_timeout must be greater than 0"));
        }
        if config.connect_timeout > 300 {
            return Err(TidewayError::bad_request("connect_timeout cannot exceed 300 seconds"));
        }

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

    /// Ping the database and update health status
    ///
    /// Call this periodically (e.g., every 30 seconds) to keep health status current.
    /// The synchronous `is_healthy()` method returns the cached status from the last ping.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Background health check task
    /// tokio::spawn(async move {
    ///     let mut interval = tokio::time::interval(Duration::from_secs(30));
    ///     loop {
    ///         interval.tick().await;
    ///         pool.ping().await;
    ///     }
    /// });
    /// ```
    pub async fn ping(&self) -> bool {
        match self.conn.ping().await {
            Ok(()) => {
                self.health_status.store(true, std::sync::atomic::Ordering::Release);
                true
            }
            Err(e) => {
                tracing::warn!("Database ping failed: {}", e);
                self.health_status.store(false, std::sync::atomic::Ordering::Release);
                false
            }
        }
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
        // Return cached health status from last ping() call
        // Call ping() periodically via a background task for accurate status
        self.health_status.load(std::sync::atomic::Ordering::Acquire)
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
