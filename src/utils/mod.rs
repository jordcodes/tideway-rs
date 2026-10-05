//! Utility functions and helpers.
//!
//! Common utilities for environment variable handling and other helpers.

pub mod ensure;
pub mod env;

pub use env::{get_env_with_prefix, is_production_like_environment};
