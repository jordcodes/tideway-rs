//! Request timeout middleware.
//!
//! Automatically cancels requests that exceed a configured duration
//! and returns a 408 Request Timeout response.

mod config;
mod layer;

pub use config::{TimeoutConfig, TimeoutConfigBuilder};
pub use layer::build_timeout_layer;

