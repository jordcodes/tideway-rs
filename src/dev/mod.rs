//! Development mode utilities for Tideway applications
//!
//! This module provides development-specific middleware and helpers for debugging
//! and enhanced error reporting. These features should be disabled in production.

mod config;
mod error_middleware;
mod request_dumper;

pub use config::{DevConfig, DevConfigBuilder};
pub use error_middleware::build_dev_error_layer;
pub use request_dumper::build_request_dumper_layer;
