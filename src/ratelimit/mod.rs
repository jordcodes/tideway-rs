//! Rate limiting middleware.
//!
//! Provides per-IP and global rate limiting to protect against
//! abuse and ensure fair resource usage.

mod client_ip;
mod config;
mod layer;

pub use client_ip::{ClientIpResolver, TrustedProxyParseError};
pub use config::{RateLimitConfig, RateLimitConfigBuilder};
pub use layer::build_rate_limit_layer;
