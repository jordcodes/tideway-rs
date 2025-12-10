//! Security headers middleware.
//!
//! Adds security headers like HSTS, CSP, X-Frame-Options, and others
//! to HTTP responses for improved security.

mod config;
mod headers;

pub use config::{SecurityConfig, SecurityConfigBuilder};
pub use headers::build_security_headers_layer;

