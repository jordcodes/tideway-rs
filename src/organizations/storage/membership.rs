//! Membership storage trait.

use crate::error::Result;
use async_trait::async_trait;

/// Trait for membership storage operations.
///
/// The `Membership` and `Role` associated types are YOUR types.
/// This allows complete flexibility in how you structure memberships
/// and define roles/permissions.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::organizations::MembershipStore;
/// use async_trait::async_trait;
///
/// struct MyStore { db: DatabaseConnection }
///
/// #[derive(Clone)]
/// struct MyMembership {
///     org_id: String,
///     user_id: String,
///     role: MyRole,
///     title: Option<String>,  // Custom field
///     joined_at: u64,
/// }
///
/// #[derive(Clone, PartialEq)]
/// enum MyRole {
///     Owner,
///     Admin,
///     Developer,
///     Viewer,
/// }
///
/// #[async_trait]
/// impl MembershipStore for MyStore {
///     type Membership = MyMembership;
///     type Role = MyRole;
///
///     async fn add_member(&self, membership: &Self::Membership) -> Result<()> {
///         self.db.insert_membership(membership).await?;
///         Ok(())
///     }
///
///     fn membership_role(&self, m: &Self::Membership) -> Self::Role {
///         m.role.clone()
///     }
///
///     // Define your permission hierarchy
///     fn can_manage_members(&self, role: &Self::Role) -> bool {
///         matches!(role, MyRole::Owner | MyRole::Admin)
///     }
///
///     // ... implement other methods
/// }
/// ```
#[async_trait]
pub trait MembershipStore: Send + Sync {
    /// Your membership type (user-org-role association).
    type Membership: Send + Sync + Clone;

    /// Your role type (enum or string-based).
    type Role: Send + Sync + Clone + PartialEq;

    // === Required storage methods ===

    /// Add a new member to an organization.
    async fn add_member(&self, membership: &Self::Membership) -> Result<()>;

    /// Remove a member from an organization.
    async fn remove_member(&self, org_id: &str, user_id: &str) -> Result<()>;

    /// Get a specific membership.
    async fn get_membership(
        &self,
        org_id: &str,
        user_id: &str,
    ) -> Result<Option<Self::Membership>>;

    /// List all members of an organization.
    async fn list_members(&self, org_id: &str) -> Result<Vec<Self::Membership>>;

    /// Update an existing membership.
    async fn update_membership(&self, membership: &Self::Membership) -> Result<()>;

    // === Required accessor methods ===

    /// Get the user ID from a membership.
    fn membership_user_id(&self, m: &Self::Membership) -> String;

    /// Get the organization ID from a membership.
    fn membership_org_id(&self, m: &Self::Membership) -> String;

    /// Get the role from a membership.
    fn membership_role(&self, m: &Self::Membership) -> Self::Role;

    // === Required role permission methods (users define their hierarchy) ===

    /// Check if role can manage members (invite, remove, change roles).
    fn can_manage_members(&self, role: &Self::Role) -> bool;

    /// Check if role can manage organization settings.
    fn can_manage_settings(&self, role: &Self::Role) -> bool;

    /// Check if role can delete the organization.
    fn can_delete_org(&self, role: &Self::Role) -> bool;

    /// Check if role can transfer ownership.
    fn can_transfer_ownership(&self, role: &Self::Role) -> bool;

    /// Check if this role is the owner role.
    fn is_owner(&self, role: &Self::Role) -> bool;

    // === Optional methods with defaults ===

    /// Count members in an organization.
    async fn count_members(&self, org_id: &str) -> Result<u32> {
        Ok(self.list_members(org_id).await?.len() as u32)
    }

    /// Check if a user is a member of an organization.
    async fn is_member(&self, org_id: &str, user_id: &str) -> Result<bool> {
        Ok(self.get_membership(org_id, user_id).await?.is_some())
    }

    /// List all organizations a user is a member of.
    ///
    /// Default returns empty - override for proper implementation.
    async fn list_user_memberships(&self, _user_id: &str) -> Result<Vec<Self::Membership>> {
        Ok(vec![])
    }
}
