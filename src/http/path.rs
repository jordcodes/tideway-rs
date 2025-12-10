//! Path parameter extractors and helpers
//!
//! This module provides utilities for extracting and validating path parameters.

use axum::extract::Path as AxumPath;
use serde::Deserialize;
use uuid::Uuid;

/// Path parameter extractor
///
/// This is a thin wrapper around Axum's `Path` extractor.
pub type PathParams<T> = AxumPath<T>;

/// Helper methods for common path parameter operations
#[allow(dead_code)] // Public API - methods may be used by consumers
pub trait PathExt {
    /// Extract a numeric ID from path parameters
    fn id(&self) -> Result<i64, String>;

    /// Extract a UUID from path parameters
    fn uuid(&self) -> Result<Uuid, String>;
}

impl<T: PathParamsExtract> PathExt for AxumPath<T> {
    fn id(&self) -> Result<i64, String> {
        // This is a placeholder - users should use PathParams directly
        // or implement their own struct with Deserialize
        Err("Use PathParams<i64> or a custom struct with Deserialize".to_string())
    }

    fn uuid(&self) -> Result<Uuid, String> {
        Err("Use PathParams<Uuid> or a custom struct with Deserialize".to_string())
    }
}

/// Trait for types that can be extracted from path parameters
pub trait PathParamsExtract: for<'de> Deserialize<'de> {}

impl<T: for<'de> Deserialize<'de>> PathParamsExtract for T {}

/// Helper for extracting a single ID from path
///
/// # Example
///
/// ```rust,no_run
/// use tideway::http::path::extract_id;
/// use axum::extract::Path;
///
/// async fn handler(Path(id): Path<i64>) -> String {
///     format!("User ID: {}", id)
/// }
/// ```
#[allow(dead_code)] // Public API function
pub fn extract_id(path: &str) -> Result<i64, String> {
    path.parse::<i64>()
        .map_err(|_| format!("Invalid ID: {}", path))
}

/// Helper for extracting a UUID from path
///
/// # Example
///
/// ```rust,no_run
/// use tideway::http::path::extract_uuid;
/// use axum::extract::Path;
/// use uuid::Uuid;
///
/// async fn handler(Path(id): Path<Uuid>) -> String {
///     format!("User UUID: {}", id)
/// }
/// ```
#[allow(dead_code)] // Public API function
pub fn extract_uuid(path: &str) -> Result<Uuid, String> {
    Uuid::parse_str(path)
        .map_err(|_| format!("Invalid UUID: {}", path))
}
