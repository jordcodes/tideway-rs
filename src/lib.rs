//! Tideway - A batteries-included Rust web framework
//!
//! Tideway is built on top of Axum and Tokio, providing opinionated defaults
//! for building SaaS applications quickly while maintaining performance and flexibility.
//!
//! # Features
//!
//! - **HTTP**: Axum-based routing with sensible defaults
//! - **Authentication**: JWT-based auth with pluggable providers
//! - **Database**: SeaORM integration with migrations
//! - **Health Checks**: Built-in health check system
//! - **OpenAPI**: Automatic API documentation with utoipa
//! - **Webhooks**: Webhook handling with verification and idempotency
//! - **Testing**: Alba-style HTTP testing utilities
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use tideway::{App, ConfigBuilder, init_tracing};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Initialize logging
//!     init_tracing();
//!
//!     // Create and configure app
//!     let config = ConfigBuilder::new()
//!         .from_env()
//!         .build()
//!         .unwrap();
//!
//!     let app = App::with_config(config);
//!
//!     // Start server
//!     app.serve().await.unwrap();
//! }
//! ```

#![allow(async_fn_in_trait)] // async_trait macro handles Send/Sync bounds properly

mod app;
pub mod auth;
#[cfg(feature = "billing")]
pub mod billing;
#[cfg(feature = "organizations")]
pub mod organizations;
#[cfg(feature = "cache")]
pub mod cache;
pub mod compression;
mod config;
mod core;
pub mod cors;
#[cfg(feature = "database")]
pub mod database;
mod error;
pub mod health;
mod http;
#[cfg(feature = "metrics")]
pub mod metrics;
mod middleware;
#[cfg(feature = "openapi")]
pub mod openapi;
pub mod ratelimit;
pub mod request_logging;
pub mod security;
#[cfg(feature = "sessions")]
pub mod session;
#[cfg(feature = "jobs")]
pub mod jobs;
#[cfg(feature = "email")]
pub mod email;
pub mod testing;
pub mod timeout;
#[cfg(any(feature = "database", feature = "cache", feature = "sessions", feature = "jobs", feature = "email"))]
pub mod traits;
pub use testing::{TestFactory, TestUser, fake};
pub mod dev;
mod utils;
#[cfg(feature = "validation")]
pub mod validation;
pub mod webhooks;
#[cfg(feature = "websocket")]
pub mod websocket;

// Re-exports for public API
pub use app::{AppContext, AppContextBuilder};
pub use compression::{CompressionConfig, CompressionConfigBuilder};
pub use config::{Config, ConfigBuilder, LoggingConfig, ServerConfig};
pub use core::{App, AppBuilder};
pub use cors::{CorsConfig, CorsConfigBuilder};
pub use dev::{DevConfig, DevConfigBuilder};
pub use error::{ErrorContext, ErrorInfo, ErrorResponse, ErrorWithContext, Result, TidewayError};
pub use health::{ComponentHealth, HealthCheck, HealthChecker, HealthStatus};
pub use http::{
    ApiResponse, CreatedResponse, FileConfig, Form, JsonResponse, Multipart, NoContentResponse,
    PaginatedData, PaginationMeta, PaginationQuery, PathParams, Query, RouteModule,
};
#[cfg(feature = "metrics")]
pub use metrics::{MetricsConfig, MetricsConfigBuilder, MetricsCollector};
pub use ratelimit::{RateLimitConfig, RateLimitConfigBuilder};
pub use request_logging::{RequestLoggingConfig, RequestLoggingConfigBuilder};
pub use security::{SecurityConfig, SecurityConfigBuilder};
pub use timeout::{TimeoutConfig, TimeoutConfigBuilder};
#[cfg(feature = "cache")]
pub use traits::cache::{Cache, CacheExt};
#[cfg(feature = "database")]
pub use traits::database::{DatabaseConnection, DatabasePool};
#[cfg(feature = "database")]
pub use database::SeaOrmPool;
#[cfg(feature = "sessions")]
pub use traits::session::{SessionData, SessionStore};
#[cfg(feature = "jobs")]
pub use traits::job::{Job, JobData, JobQueue};
#[cfg(feature = "jobs")]
pub use jobs::{JobBackend, JobRegistry, JobWorker, WorkerPool, InMemoryJobQueue};
#[cfg(all(feature = "jobs", feature = "jobs-redis"))]
pub use jobs::RedisJobQueue;
#[cfg(feature = "email")]
pub use traits::mailer::{Email, Mailer};
#[cfg(feature = "email")]
pub use email::{ConsoleMailer, SmtpMailer, SmtpConfig};
#[cfg(feature = "validation")]
pub use validation::{
    ValidatedForm, ValidatedJson, ValidatedQuery, validate_form, validate_json, validator,
};
#[cfg(feature = "websocket")]
pub use websocket::{Connection, ConnectionManager, ConnectionMetrics, Message, Room, WebSocketHandler, ws};

// Macro re-exports
#[cfg(feature = "macros")]
pub use tideway_macros::api;

use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize tracing/logging with sensible defaults
///
/// This should be called early in your application, typically in main()
/// before creating the App. Safe to call multiple times - subsequent calls
/// are ignored if tracing is already initialized.
///
/// # Environment Variables
///
/// - `RUST_LOG`: Set log level (e.g., "info", "debug", "tideway=debug")
/// - `TIDEWAY_LOG_JSON`: Set to "true" for JSON formatted logs
///
/// # Example
///
/// ```rust,ignore
/// use tideway::init_tracing;
///
/// #[tokio::main]
/// async fn main() {
///     init_tracing();
///     // ... rest of your app
/// }
/// ```
pub fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let json_logs = std::env::var("TIDEWAY_LOG_JSON")
        .map(|v| v.parse::<bool>().unwrap_or(false))
        .unwrap_or(false);

    let result = if json_logs {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().json())
            .try_init()
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .try_init()
    };

    // Silently ignore if already initialized (e.g., in tests or called twice)
    if let Err(e) = result {
        // Only log if it's not the "already initialized" error
        if !e.to_string().contains("already") {
            eprintln!("Warning: Failed to initialize tracing: {}", e);
        }
    }
}

/// Initialize tracing with a custom configuration
///
/// Safe to call multiple times - subsequent calls are ignored if tracing
/// is already initialized.
pub fn init_tracing_with_config(config: &Config) {
    let env_filter = EnvFilter::new(&config.logging.level);

    let result = if config.logging.json {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().json())
            .try_init()
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .try_init()
    };

    // Silently ignore if already initialized
    if let Err(e) = result {
        if !e.to_string().contains("already") {
            eprintln!("Warning: Failed to initialize tracing: {}", e);
        }
    }
}
