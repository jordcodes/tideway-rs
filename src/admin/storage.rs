//! Admin storage trait.
//!
//! This module provides the trait abstraction for admin storage.
//! Applications implement this trait for their database layer.

use async_trait::async_trait;

use super::error::AdminError;
use super::types::{
    AuditEntry, AuditLogParams, ListOrgsParams, ListUsersParams, PaginatedResult, PlatformStats,
    UpdateUser,
};

/// Trait for platform admin storage operations.
///
/// Implement this trait for your database layer to enable admin functionality.
/// The `User` and `Organization` associated types are YOUR types from your application.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::admin::{AdminStore, AdminError, ListUsersParams, PaginatedResult, PlatformStats};
/// use async_trait::async_trait;
///
/// struct MyAdminStore { db: DatabaseConnection }
///
/// #[async_trait]
/// impl AdminStore for MyAdminStore {
///     type User = MyUser;
///     type Organization = MyOrganization;
///
///     async fn is_platform_admin(&self, user_id: &str) -> Result<bool, AdminError> {
///         let user = self.db.find_user(user_id).await?;
///         Ok(user.map(|u| u.is_platform_admin).unwrap_or(false))
///     }
///
///     async fn list_users(&self, params: ListUsersParams) -> Result<PaginatedResult<Self::User>, AdminError> {
///         // Query users with pagination and search
///     }
///
///     // ... implement other methods
/// }
/// ```
#[async_trait]
pub trait AdminStore: Send + Sync {
    /// Your user type.
    ///
    /// This is the struct that represents a user in your application.
    /// It must be Send + Sync for async operations.
    type User: Send + Sync;

    /// Your organization type.
    ///
    /// This is the struct that represents an organization in your application.
    /// It must be Send + Sync for async operations.
    type Organization: Send + Sync;

    // === Admin identification ===

    /// Check if a user is a platform admin.
    ///
    /// Platform admins have access to the admin dashboard and can manage
    /// all users and organizations on the platform.
    async fn is_platform_admin(&self, user_id: &str) -> Result<bool, AdminError>;

    // === User management ===

    /// List all users with pagination and optional search.
    async fn list_users(
        &self,
        params: ListUsersParams,
    ) -> Result<PaginatedResult<Self::User>, AdminError>;

    /// Get a user by ID.
    async fn get_user(&self, user_id: &str) -> Result<Option<Self::User>, AdminError>;

    /// Update a user's properties.
    async fn update_user(&self, user_id: &str, updates: UpdateUser) -> Result<(), AdminError>;

    /// Delete a user.
    ///
    /// This should handle cascading deletes for memberships, etc.
    async fn delete_user(&self, user_id: &str) -> Result<(), AdminError>;

    // === Organization management ===

    /// List all organizations with pagination and optional search.
    async fn list_organizations(
        &self,
        params: ListOrgsParams,
    ) -> Result<PaginatedResult<Self::Organization>, AdminError>;

    /// Get an organization by ID.
    async fn get_organization(
        &self,
        org_id: &str,
    ) -> Result<Option<Self::Organization>, AdminError>;

    // === Platform statistics ===

    /// Get platform-wide statistics for the admin dashboard.
    async fn get_platform_stats(&self) -> Result<PlatformStats, AdminError>;

    // === Audit log (optional) ===

    /// Get audit log entries.
    ///
    /// Default implementation returns an empty list.
    /// Override this if your application tracks admin actions.
    async fn get_audit_log(
        &self,
        _params: AuditLogParams,
    ) -> Result<Vec<AuditEntry>, AdminError> {
        Ok(vec![])
    }

    /// Record an audit log entry.
    ///
    /// Default implementation is a no-op.
    /// Override this if your application tracks admin actions.
    async fn record_audit(
        &self,
        _user_id: &str,
        _action: &str,
        _details: Option<&str>,
        _ip_address: Option<&str>,
    ) -> Result<(), AdminError> {
        Ok(())
    }
}
