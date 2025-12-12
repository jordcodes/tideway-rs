//! Database connection pooling and management.
//!
//! Provides abstractions for database connections with support for
//! SeaORM (default) and SQLx backends.

#[cfg(feature = "database")]
pub mod config;
#[cfg(feature = "database")]
pub mod connection;
#[cfg(feature = "database")]
pub mod migration;
#[cfg(feature = "database")]
pub mod sea_orm_pool;
#[cfg(feature = "database-sqlx")]
pub mod sqlx_pool;

#[cfg(feature = "database")]
pub use config::{DatabaseConfig, redact_database_url};
#[cfg(feature = "database")]
pub use connection::DatabaseConnection;
#[cfg(feature = "database")]
pub use sea_orm_pool::SeaOrmPool;
#[cfg(feature = "database")]
pub use sea_orm;
