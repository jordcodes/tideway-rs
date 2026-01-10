//! Organization storage trait.

use crate::error::Result;
use async_trait::async_trait;

/// Trait for organization storage operations.
///
/// Implement this trait for your database layer.
/// The `Organization` associated type is YOUR organization struct.
///
/// # Important: Slug Uniqueness
///
/// Your database implementation **must** enforce a unique constraint on the `slug` column.
/// While this trait checks slug availability before creation, there is an inherent race
/// condition between the check and the insert. The database constraint is the authoritative
/// enforcement.
///
/// ```sql
/// CREATE TABLE organizations (
///     id VARCHAR(36) PRIMARY KEY,
///     slug VARCHAR(100) UNIQUE NOT NULL,  -- Unique constraint required!
///     -- other columns...
/// );
/// ```
///
/// # Example
///
/// ```rust,ignore
/// use tideway::organizations::OrganizationStore;
/// use async_trait::async_trait;
///
/// struct MyOrgStore { db: DatabaseConnection }
///
/// #[derive(Clone)]
/// struct MyOrganization {
///     id: String,
///     name: String,
///     slug: String,
///     owner_id: String,
///     contact_email: String,
///     // Your custom fields...
///     settings: MyOrgSettings,
/// }
///
/// #[async_trait]
/// impl OrganizationStore for MyOrgStore {
///     type Organization = MyOrganization;
///
///     async fn create(&self, org: &Self::Organization) -> Result<()> {
///         self.db.insert_org(org).await?;
///         Ok(())
///     }
///
///     async fn find_by_id(&self, id: &str) -> Result<Option<Self::Organization>> {
///         Ok(self.db.find_org(id).await?)
///     }
///
///     // ... implement other methods
///
///     fn org_id(&self, org: &Self::Organization) -> String {
///         org.id.clone()
///     }
///
///     fn org_name(&self, org: &Self::Organization) -> String {
///         org.name.clone()
///     }
///
///     // ... implement accessor methods
/// }
/// ```
#[async_trait]
pub trait OrganizationStore: Send + Sync {
    /// Your organization type.
    ///
    /// This is the struct that represents an organization in your application.
    /// It must be Clone + Send + Sync for async operations.
    type Organization: Send + Sync + Clone;

    // === Required storage methods (users must implement) ===

    /// Create a new organization.
    async fn create(&self, org: &Self::Organization) -> Result<()>;

    /// Find an organization by its ID.
    async fn find_by_id(&self, id: &str) -> Result<Option<Self::Organization>>;

    /// Find an organization by its slug.
    async fn find_by_slug(&self, slug: &str) -> Result<Option<Self::Organization>>;

    /// Update an organization.
    async fn update(&self, org: &Self::Organization) -> Result<()>;

    /// Delete an organization.
    async fn delete(&self, id: &str) -> Result<()>;

    // === Required accessor methods (users must implement) ===

    /// Get the organization's ID.
    fn org_id(&self, org: &Self::Organization) -> String;

    /// Get the organization's name.
    fn org_name(&self, org: &Self::Organization) -> String;

    /// Get the organization's slug.
    fn org_slug(&self, org: &Self::Organization) -> String;

    /// Get the owner's user ID.
    fn owner_id(&self, org: &Self::Organization) -> String;

    /// Get the billing/contact email.
    fn contact_email(&self, org: &Self::Organization) -> String;

    // === Optional methods with defaults ===

    /// List organizations for a user.
    ///
    /// Override this if you want optimized queries (e.g., JOIN with memberships).
    /// Default implementation returns empty - you should override this for
    /// production use.
    async fn list_for_user(&self, _user_id: &str) -> Result<Vec<Self::Organization>> {
        Ok(vec![])
    }

    /// Check if a slug is available.
    ///
    /// Default implementation checks if `find_by_slug` returns None.
    async fn is_slug_available(&self, slug: &str) -> Result<bool> {
        Ok(self.find_by_slug(slug).await?.is_none())
    }

    /// Count organizations owned by a user.
    ///
    /// Used to enforce `max_orgs_per_user` limit.
    /// Default implementation returns 0 - override for proper counting.
    async fn count_owned_by_user(&self, _user_id: &str) -> Result<u32> {
        Ok(0)
    }
}
