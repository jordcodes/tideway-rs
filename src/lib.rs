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
#[cfg(feature = "auth")]
pub mod auth;
#[cfg(all(not(feature = "auth"), feature = "feature-gate-errors"))]
pub mod auth {
    compile_error!("Enable the `auth` feature to use tideway::auth");
}
#[cfg(all(not(feature = "auth"), feature = "feature-gate-warnings"))]
#[deprecated(note = "Enable the `auth` feature to use tideway::auth")]
pub mod auth {}
#[cfg(feature = "billing")]
pub mod billing;
#[cfg(all(not(feature = "billing"), feature = "feature-gate-errors"))]
pub mod billing {
    compile_error!("Enable the `billing` feature to use tideway::billing");
}
#[cfg(all(not(feature = "billing"), feature = "feature-gate-warnings"))]
#[deprecated(note = "Enable the `billing` feature to use tideway::billing")]
pub mod billing {}
#[cfg(feature = "organizations")]
pub mod organizations;
#[cfg(all(not(feature = "organizations"), feature = "feature-gate-errors"))]
pub mod organizations {
    compile_error!("Enable the `organizations` feature to use tideway::organizations");
}
#[cfg(all(not(feature = "organizations"), feature = "feature-gate-warnings"))]
#[deprecated(note = "Enable the `organizations` feature to use tideway::organizations")]
pub mod organizations {}
#[cfg(feature = "admin")]
pub mod admin;
#[cfg(all(not(feature = "admin"), feature = "feature-gate-errors"))]
pub mod admin {
    compile_error!("Enable the `admin` feature to use tideway::admin");
}
#[cfg(all(not(feature = "admin"), feature = "feature-gate-warnings"))]
#[deprecated(note = "Enable the `admin` feature to use tideway::admin")]
pub mod admin {}
#[cfg(feature = "cache")]
pub mod cache;
#[cfg(all(not(feature = "cache"), feature = "feature-gate-errors"))]
pub mod cache {
    compile_error!("Enable the `cache` feature to use tideway::cache");
}
#[cfg(all(not(feature = "cache"), feature = "feature-gate-warnings"))]
#[deprecated(note = "Enable the `cache` feature to use tideway::cache")]
pub mod cache {}
pub mod compression;
mod config;
mod core;
pub mod cors;
#[cfg(feature = "database")]
pub mod database;
#[cfg(all(not(feature = "database"), feature = "feature-gate-errors"))]
pub mod database {
    compile_error!("Enable the `database` feature to use tideway::database");
}
#[cfg(all(not(feature = "database"), feature = "feature-gate-warnings"))]
#[deprecated(note = "Enable the `database` feature to use tideway::database")]
pub mod database {}
mod error;
pub mod health;
mod http;
#[cfg(feature = "metrics")]
pub mod metrics;
#[cfg(all(not(feature = "metrics"), feature = "feature-gate-errors"))]
pub mod metrics {
    compile_error!("Enable the `metrics` feature to use tideway::metrics");
}
#[cfg(all(not(feature = "metrics"), feature = "feature-gate-warnings"))]
#[deprecated(note = "Enable the `metrics` feature to use tideway::metrics")]
pub mod metrics {}
mod middleware;
#[cfg(feature = "openapi")]
pub mod openapi;
#[cfg(all(not(feature = "openapi"), feature = "feature-gate-errors"))]
pub mod openapi {
    compile_error!("Enable the `openapi` feature to use tideway::openapi");
}
#[cfg(all(not(feature = "openapi"), feature = "feature-gate-warnings"))]
#[deprecated(note = "Enable the `openapi` feature to use tideway::openapi")]
pub mod openapi {}
pub mod ratelimit;
pub mod request_logging;
pub mod security;
#[cfg(feature = "sessions")]
pub mod session;
#[cfg(all(not(feature = "sessions"), feature = "feature-gate-errors"))]
pub mod session {
    compile_error!("Enable the `sessions` feature to use tideway::session");
}
#[cfg(all(not(feature = "sessions"), feature = "feature-gate-warnings"))]
#[deprecated(note = "Enable the `sessions` feature to use tideway::session")]
pub mod session {}
#[cfg(feature = "jobs")]
pub mod jobs;
#[cfg(all(not(feature = "jobs"), feature = "feature-gate-errors"))]
pub mod jobs {
    compile_error!("Enable the `jobs` feature to use tideway::jobs");
}
#[cfg(all(not(feature = "jobs"), feature = "feature-gate-warnings"))]
#[deprecated(note = "Enable the `jobs` feature to use tideway::jobs")]
pub mod jobs {}
#[cfg(feature = "email")]
pub mod email;
#[cfg(all(not(feature = "email"), feature = "feature-gate-errors"))]
pub mod email {
    compile_error!("Enable the `email` feature to use tideway::email");
}
#[cfg(all(not(feature = "email"), feature = "feature-gate-warnings"))]
#[deprecated(note = "Enable the `email` feature to use tideway::email")]
pub mod email {}
pub mod testing;
pub mod timeout;
#[cfg(any(feature = "database", feature = "cache", feature = "sessions", feature = "jobs", feature = "email"))]
pub mod traits;
pub use testing::{TestFactory, TestUser, fake};
pub mod dev;
mod utils;
#[cfg(feature = "validation")]
pub mod validation;
#[cfg(all(not(feature = "validation"), feature = "feature-gate-errors"))]
pub mod validation {
    compile_error!("Enable the `validation` feature to use tideway::validation");
}
#[cfg(all(not(feature = "validation"), feature = "feature-gate-warnings"))]
#[deprecated(note = "Enable the `validation` feature to use tideway::validation")]
pub mod validation {}
pub mod webhooks;
#[cfg(feature = "websocket")]
pub mod websocket;
#[cfg(all(not(feature = "websocket"), feature = "feature-gate-errors"))]
pub mod websocket {
    compile_error!("Enable the `websocket` feature to use tideway::websocket");
}
#[cfg(all(not(feature = "websocket"), feature = "feature-gate-warnings"))]
#[deprecated(note = "Enable the `websocket` feature to use tideway::websocket")]
pub mod websocket {}

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
    ApiResponse, CreatedResponse, FileConfig, Form, JsonResponse, MessageResponse, Multipart,
    NoContentResponse, PaginatedData, PaginationMeta, PaginationQuery, PathParams, Query,
    RouteModule,
};
#[cfg(feature = "metrics")]
pub use metrics::{MetricsConfig, MetricsConfigBuilder, MetricsCollector};
pub use ratelimit::{RateLimitConfig, RateLimitConfigBuilder};
pub use request_logging::{RequestLoggingConfig, RequestLoggingConfigBuilder};
pub use security::{SecurityConfig, SecurityConfigBuilder};
pub use timeout::{TimeoutConfig, TimeoutConfigBuilder};
#[cfg(feature = "cache")]
pub use traits::cache::{Cache, CacheExt};

/// Register multiple modules with a Tideway `App`.
///
/// # Example
/// ```ignore
/// let app = tideway::register_modules!(
///     App::new(),
///     UsersModule,
///     AdminModule,
///     BillingModule,
/// );
///
/// let app = tideway::register_modules!(
///     App::new(),
///     UsersModule,
///     AdminModule;
///     optional: billing_module, local_auth_module
/// );
/// ```
#[macro_export]
macro_rules! register_modules {
    ($app:expr, $($module:expr),+ ; optional: $($optional:expr),+ $(,)?) => {{
        let mut app = $app;
        $(app = app.register_module($module);)+
        $(app = app.register_optional_module($optional);)+
        app
    }};
    ($app:expr, $($module:expr),+ $(,)?) => {{
        let mut app = $app;
        $(app = app.register_module($module);)+
        app
    }};
    ($app:expr; optional: $($optional:expr),+ $(,)?) => {{
        let mut app = $app;
        $(app = app.register_optional_module($optional);)+
        app
    }};
}

/// Register optional modules with a Tideway `App`.
///
/// # Example
/// ```ignore
/// let app = tideway::register_optional_modules!(
///     App::new(),
///     optional_module,
///     another_optional,
/// );
/// ```
#[macro_export]
macro_rules! register_optional_modules {
    ($app:expr, $($optional:expr),+ $(,)?) => {{
        let mut app = $app;
        $(app = app.register_optional_module($optional);)+
        app
    }};
}

/// Define a `RouteModule` with a compact route list.
///
/// # Example
/// ```ignore
/// tideway::module!(
///     UsersModule,
///     prefix = "/api",
///     routes = [
///         (get, "/users", list_users),
///         (post, "/users", create_user),
///     ]
/// );
/// ```
#[macro_export]
macro_rules! module {
    ($(#[$attr:meta])*, $name:ident, prefix = $prefix:expr, routes = [ $(($method:ident, $path:expr, $handler:expr)),+ $(,)? ]) => {
        $(#[$attr])*
        pub struct $name;

        impl $crate::RouteModule for $name {
            fn routes(&self) -> axum::Router<$crate::AppContext> {
                let mut router = axum::Router::new();
                $(
                    router = router.route($path, axum::routing::$method($handler));
                )+
                router
            }

            fn prefix(&self) -> Option<&str> {
                Some($prefix)
            }
        }
    };
    ($name:ident, prefix = $prefix:expr, routes = [ $(($method:ident, $path:expr, $handler:expr)),+ $(,)? ]) => {
        pub struct $name;

        impl $crate::RouteModule for $name {
            fn routes(&self) -> axum::Router<$crate::AppContext> {
                let mut router = axum::Router::new();
                $(
                    router = router.route($path, axum::routing::$method($handler));
                )+
                router
            }

            fn prefix(&self) -> Option<&str> {
                Some($prefix)
            }
        }
    };
    ($(#[$attr:meta])*, $name:ident, routes = [ $(($method:ident, $path:expr, $handler:expr)),+ $(,)? ]) => {
        $(#[$attr])*
        pub struct $name;

        impl $crate::RouteModule for $name {
            fn routes(&self) -> axum::Router<$crate::AppContext> {
                let mut router = axum::Router::new();
                $(
                    router = router.route($path, axum::routing::$method($handler));
                )+
                router
            }
        }
    };
    ($name:ident, routes = [ $(($method:ident, $path:expr, $handler:expr)),+ $(,)? ]) => {
        pub struct $name;

        impl $crate::RouteModule for $name {
            fn routes(&self) -> axum::Router<$crate::AppContext> {
                let mut router = axum::Router::new();
                $(
                    router = router.route($path, axum::routing::$method($handler));
                )+
                router
            }
        }
    };
}
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
