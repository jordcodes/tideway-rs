//! SQLx database pool implementation
//!
//! Provides an alternative to SeaORM using SQLx directly.

#[cfg(feature = "database-sqlx")]
use crate::error::{Result, TidewayError};
#[cfg(feature = "database-sqlx")]
use crate::traits::database::{DatabaseConnection, DatabasePool};
#[cfg(feature = "database-sqlx")]
use async_trait::async_trait;
// SQLx types will be used when implementation is complete

/// SQLx connection wrapper (placeholder)
///
/// TODO: Implement when database-sqlx feature is added
#[cfg(feature = "database-sqlx")]
#[deprecated(
    note = "The database-sqlx backend is currently a placeholder and not yet implemented. Use the SeaORM backend in this release."
)]
pub struct SqlxConnectionWrapper {
    // Will hold SQLx connection
}

#[cfg(feature = "database-sqlx")]
#[allow(deprecated)]
impl DatabaseConnection for SqlxConnectionWrapper {
    fn is_valid(&self) -> bool {
        false
    }
}

/// SQLx database pool (placeholder)
///
/// TODO: Implement when database-sqlx feature is added
#[cfg(feature = "database-sqlx")]
#[deprecated(
    note = "The database-sqlx backend is currently a placeholder and not yet implemented. Use the SeaORM backend in this release."
)]
pub struct SqlxPool {
    // Placeholder
}

#[cfg(feature = "database-sqlx")]
#[allow(deprecated)]
impl SqlxPool {
    pub async fn new(_url: &str) -> Result<Self> {
        Err(TidewayError::internal(
            "database-sqlx backend is currently a placeholder and not yet implemented. Use feature `database` (SeaORM) for production support.",
        ))
    }
}

#[cfg(feature = "database-sqlx")]
#[async_trait]
#[allow(deprecated)]
impl DatabasePool for SqlxPool {
    async fn connection(&self) -> Result<Box<dyn DatabaseConnection>> {
        Err(TidewayError::internal(
            "database-sqlx backend is currently a placeholder and not yet implemented.",
        ))
    }

    fn is_healthy(&self) -> bool {
        false
    }

    async fn close(self: Box<Self>) -> Result<()> {
        Ok(())
    }

    fn connection_url(&self) -> Option<&str> {
        None
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
