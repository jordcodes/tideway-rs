//! Request and response logging middleware.
//!
//! Provides structured logging for HTTP requests and responses,
//! useful for debugging and monitoring.

mod config;
mod middleware;

pub use config::{RequestLoggingConfig, RequestLoggingConfigBuilder};
pub use middleware::build_request_logging_layer;

