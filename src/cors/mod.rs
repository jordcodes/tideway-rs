//! Cross-Origin Resource Sharing (CORS) middleware.
//!
//! Configures CORS headers to allow controlled cross-origin access
//! to your API from web browsers.

mod config;
mod layer;

pub use config::{CorsConfig, CorsConfigBuilder};
pub use layer::build_cors_layer;
