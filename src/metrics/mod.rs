//! Prometheus metrics collection and exposition.
//!
//! This module provides middleware for collecting HTTP request metrics
//! and a handler for exposing them in Prometheus format.

#[cfg(feature = "metrics")]
mod config;
#[cfg(feature = "metrics")]
mod middleware;
#[cfg(feature = "metrics")]
mod collector;
#[cfg(feature = "metrics")]
mod handler;

#[cfg(feature = "metrics")]
pub use config::{MetricsConfig, MetricsConfigBuilder};
#[cfg(feature = "metrics")]
pub use middleware::build_metrics_layer;
#[cfg(feature = "metrics")]
pub use handler::metrics_handler;
#[cfg(feature = "metrics")]
pub use collector::MetricsCollector;
