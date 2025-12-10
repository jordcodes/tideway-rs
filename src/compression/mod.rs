//! Response compression middleware.
//!
//! Automatically compresses HTTP responses using gzip or brotli
//! to reduce bandwidth usage.

mod config;
mod layer;

pub use config::{CompressionConfig, CompressionConfigBuilder};
pub use layer::build_compression_layer;

