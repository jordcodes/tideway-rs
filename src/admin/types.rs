//! Admin module types.
//!
//! These types are used for admin API requests and responses.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Platform-wide statistics for the admin dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformStats {
    /// Total number of registered users.
    pub total_users: u64,
    /// Total number of organizations.
    pub total_organizations: u64,
    /// Number of active subscriptions.
    pub active_subscriptions: u64,
    /// Monthly recurring revenue in cents.
    pub mrr_cents: u64,
    /// Number of users who signed up in the last 30 days.
    pub recent_signups: u64,
}

impl Default for PlatformStats {
    fn default() -> Self {
        Self {
            total_users: 0,
            total_organizations: 0,
            active_subscriptions: 0,
            mrr_cents: 0,
            recent_signups: 0,
        }
    }
}

/// Sort order for list queries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    #[default]
    Asc,
    Desc,
}

/// Parameters for listing users.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListUsersParams {
    /// Optional search term (matches email or name).
    pub search: Option<String>,
    /// Page number (1-indexed).
    #[serde(default = "default_page")]
    pub page: u32,
    /// Number of items per page.
    #[serde(default = "default_per_page")]
    pub per_page: u32,
    /// Field to sort by.
    pub sort_by: Option<String>,
    /// Sort direction.
    pub sort_order: Option<SortOrder>,
}

fn default_page() -> u32 {
    1
}

fn default_per_page() -> u32 {
    20
}

/// Parameters for listing organizations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListOrgsParams {
    /// Optional search term (matches name or slug).
    pub search: Option<String>,
    /// Page number (1-indexed).
    #[serde(default = "default_page")]
    pub page: u32,
    /// Number of items per page.
    #[serde(default = "default_per_page")]
    pub per_page: u32,
}

/// Parameters for updating a user.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateUser {
    /// New name for the user.
    pub name: Option<String>,
    /// Whether the user's email is verified.
    pub email_verified: Option<bool>,
    /// Whether the user is locked (cannot log in).
    pub locked: Option<bool>,
    /// Whether the user is a platform admin.
    pub is_platform_admin: Option<bool>,
}

/// Paginated result wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResult<T> {
    /// Items for the current page.
    pub items: Vec<T>,
    /// Total number of items across all pages.
    pub total: u64,
    /// Current page number (1-indexed).
    pub page: u32,
    /// Number of items per page.
    pub per_page: u32,
    /// Total number of pages.
    pub total_pages: u32,
}

impl<T> PaginatedResult<T> {
    /// Create a new paginated result.
    pub fn new(items: Vec<T>, total: u64, page: u32, per_page: u32) -> Self {
        let total_pages = if per_page > 0 {
            ((total as f64) / (per_page as f64)).ceil() as u32
        } else {
            0
        };

        Self {
            items,
            total,
            page,
            per_page,
            total_pages,
        }
    }

    /// Check if there is a next page.
    pub fn has_next(&self) -> bool {
        self.page < self.total_pages
    }

    /// Check if there is a previous page.
    pub fn has_prev(&self) -> bool {
        self.page > 1
    }
}

/// Parameters for querying the audit log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditLogParams {
    /// Filter by user ID.
    pub user_id: Option<String>,
    /// Filter by action type.
    pub action: Option<String>,
    /// Start date filter.
    pub from: Option<DateTime<Utc>>,
    /// End date filter.
    pub to: Option<DateTime<Utc>>,
    /// Page number (1-indexed).
    #[serde(default = "default_page")]
    pub page: u32,
    /// Number of items per page.
    #[serde(default = "default_per_page")]
    pub per_page: u32,
}

/// An entry in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique ID of the audit entry.
    pub id: String,
    /// User who performed the action.
    pub user_id: String,
    /// The action performed.
    pub action: String,
    /// Additional details about the action.
    pub details: Option<String>,
    /// IP address of the request.
    pub ip_address: Option<String>,
    /// When the action occurred.
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paginated_result() {
        let result: PaginatedResult<i32> = PaginatedResult::new(vec![1, 2, 3], 100, 1, 10);
        assert_eq!(result.total_pages, 10);
        assert!(result.has_next());
        assert!(!result.has_prev());

        let result2: PaginatedResult<i32> = PaginatedResult::new(vec![1, 2, 3], 100, 10, 10);
        assert!(!result2.has_next());
        assert!(result2.has_prev());
    }

    #[test]
    fn test_default_params() {
        let params = ListUsersParams::default();
        assert_eq!(params.page, 1);
        assert_eq!(params.per_page, 20);
    }
}
