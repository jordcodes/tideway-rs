//! Query parameter extractors and helpers
//!
//! This module provides utilities for extracting and validating query parameters
//! from HTTP requests.

use axum::extract::Query as AxumQuery;
use serde::{Deserialize, Serialize};

/// Query parameter extractor with validation support
///
/// This is a thin wrapper around Axum's `Query` extractor, provided for consistency
/// with other Tideway extractors. For validation, use `ValidatedQuery` instead.
pub type Query<T> = AxumQuery<T>;

/// Pagination query parameters
///
/// Common pagination pattern used in REST APIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationQuery {
    /// Page number (1-indexed)
    #[serde(default = "default_page")]
    pub page: u32,

    /// Number of items per page
    #[serde(default = "default_per_page")]
    pub per_page: u32,

    /// Sort field (optional)
    #[serde(default)]
    pub sort: Option<String>,

    /// Sort order: "asc" or "desc"
    #[serde(default = "default_order")]
    pub order: String,
}

fn default_page() -> u32 {
    1
}

fn default_per_page() -> u32 {
    20
}

fn default_order() -> String {
    "asc".to_string()
}

impl Default for PaginationQuery {
    fn default() -> Self {
        Self {
            page: 1,
            per_page: 20,
            sort: None,
            order: "asc".to_string(),
        }
    }
}

impl PaginationQuery {
    /// Calculate the offset for database queries
    pub fn offset(&self) -> u32 {
        (self.page - 1) * self.per_page
    }

    /// Calculate the limit for database queries
    pub fn limit(&self) -> u32 {
        self.per_page
    }

    /// Validate pagination parameters
    pub fn validate(&self) -> Result<(), String> {
        if self.page == 0 {
            return Err("Page must be >= 1".to_string());
        }
        if self.per_page == 0 || self.per_page > 100 {
            return Err("Per page must be between 1 and 100".to_string());
        }
        if self.order != "asc" && self.order != "desc" {
            return Err("Order must be 'asc' or 'desc'".to_string());
        }
        Ok(())
    }
}

/// Helper for working with query parameters
#[allow(dead_code)] // Used as a namespace for static methods
pub struct QueryParams;

impl QueryParams {
    /// Get a query parameter value
    ///
    /// This is a convenience method for extracting individual query parameters.
    /// For multiple parameters, use `Query<T>` extractor instead.
    #[allow(dead_code)] // Public API method
    pub fn get<T: for<'de> Deserialize<'de>>(query_string: &str, key: &str) -> Option<T> {
        // Simple parsing - for more complex cases, use Query<T> extractor
        let pairs: Vec<&str> = query_string.split('&').collect();
        for pair in pairs {
            let parts: Vec<&str> = pair.splitn(2, '=').collect();
            if parts.len() == 2 && parts[0] == key {
                if let Ok(decoded) = urlencoding::decode(parts[1]) {
                    if let Ok(value) = serde_urlencoded::from_str::<T>(&format!("{}={}", key, decoded)) {
                        return Some(value);
                    }
                }
            }
        }
        None
    }

    /// Get an optional query parameter value
    #[allow(dead_code)] // Public API method
    pub fn get_optional<T: for<'de> Deserialize<'de>>(query_string: &str, key: &str) -> Option<Option<T>> {
        Self::get(query_string, key).map(Some)
    }

    /// Get multiple values for a query parameter (e.g., ?tags=foo&tags=bar)
    #[allow(dead_code)] // Public API method
    pub fn get_many<T: for<'de> Deserialize<'de>>(query_string: &str, key: &str) -> Vec<T> {
        let mut values = Vec::new();
        let pairs: Vec<&str> = query_string.split('&').collect();
        for pair in pairs {
            let parts: Vec<&str> = pair.splitn(2, '=').collect();
            if parts.len() == 2 && parts[0] == key {
                if let Ok(decoded) = urlencoding::decode(parts[1]) {
                    if let Ok(value) = serde_urlencoded::from_str::<T>(&format!("{}={}", key, decoded)) {
                        values.push(value);
                    }
                }
            }
        }
        values
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pagination_query_default() {
        let pagination = PaginationQuery::default();
        assert_eq!(pagination.page, 1);
        assert_eq!(pagination.per_page, 20);
        assert_eq!(pagination.order, "asc");
    }

    #[test]
    fn test_pagination_query_offset() {
        let pagination = PaginationQuery {
            page: 3,
            per_page: 10,
            ..Default::default()
        };
        assert_eq!(pagination.offset(), 20);
        assert_eq!(pagination.limit(), 10);
    }

    #[test]
    fn test_pagination_query_validation() {
        let valid = PaginationQuery {
            page: 1,
            per_page: 50,
            order: "desc".to_string(),
            ..Default::default()
        };
        assert!(valid.validate().is_ok());

        let invalid_page = PaginationQuery {
            page: 0,
            ..Default::default()
        };
        assert!(invalid_page.validate().is_err());

        let invalid_per_page = PaginationQuery {
            per_page: 101,
            ..Default::default()
        };
        assert!(invalid_per_page.validate().is_err());

        let invalid_order = PaginationQuery {
            order: "invalid".to_string(),
            ..Default::default()
        };
        assert!(invalid_order.validate().is_err());
    }
}
