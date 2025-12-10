//! Database connection pool trait
//!
//! This trait abstracts database connection pooling, allowing users to
//! swap between SeaORM, SQLx, Diesel, or custom implementations.

use crate::error::Result;
use async_trait::async_trait;
use std::any::Any;

/// A connection handle from a database pool
///
/// This is intentionally opaque - each implementation provides
/// its own connection type (e.g., `DatabaseConnection` for SeaORM)
pub trait DatabaseConnection: Send + Sync {
    /// Check if the connection is still valid
    fn is_valid(&self) -> bool;
}

/// Database connection pool trait
///
/// Implementations should manage connection pooling internally
/// and provide connections on demand.
#[async_trait]
#[allow(async_fn_in_trait)] // async_trait macro handles Send/Sync bounds
pub trait DatabasePool: Send + Sync {
    /// Get a connection from the pool
    ///
    /// Returns a boxed connection trait object. Users can downcast
    /// to the concrete type if needed, or use helper methods.
    async fn connection(&self) -> Result<Box<dyn DatabaseConnection>>;

    /// Check if the pool is healthy and can provide connections
    fn is_healthy(&self) -> bool;

    /// Close the pool and all connections
    ///
    /// This consumes the pool, so it should be called when shutting down.
    async fn close(self: Box<Self>) -> Result<()>;

    /// Get connection URL (for debugging/monitoring)
    fn connection_url(&self) -> Option<&str>;

    /// Get a reference to this pool as `Any` for downcasting
    fn as_any(&self) -> &dyn Any;
}
