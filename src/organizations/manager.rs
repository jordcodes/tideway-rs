//! Organization manager.
//!
//! Handles organization CRUD operations with business logic and tracing.

use super::audit::{OrgAuditEntry, OrgAuditEvent};
use super::config::OrganizationConfig;
use super::error::{OrganizationError, Result};
use super::seats::{SeatChecker, UnlimitedSeats};
use super::storage::{MembershipStore, OptionalAuditStore, OrganizationStore, WithAuditStore, OrgAuditStore};
use super::utils::current_timestamp;
use tracing::{debug, info, instrument};
use uuid::Uuid;

/// Parameters passed to the organization factory function.
///
/// Users receive these parameters and construct their own Organization type.
#[derive(Debug, Clone)]
pub struct OrgCreateParams {
    /// Generated unique ID.
    pub id: String,
    /// Organization name.
    pub name: String,
    /// URL-safe slug.
    pub slug: String,
    /// User ID of the owner.
    pub owner_id: String,
    /// Contact/billing email.
    pub contact_email: String,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
}

/// Parameters passed to the membership factory function.
///
/// Users receive these parameters and construct their own Membership type.
#[derive(Debug, Clone)]
pub struct MembershipCreateParams {
    /// Organization ID.
    pub org_id: String,
    /// User ID.
    pub user_id: String,
    /// Whether this is the owner membership.
    pub is_owner: bool,
    /// Join timestamp (Unix seconds).
    pub joined_at: u64,
}

/// Organization manager - generic over store implementations.
///
/// Works with whatever Organization/Membership types the user defines.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::organizations::{
///     OrganizationManager, OrganizationConfig, UnlimitedSeats,
/// };
///
/// let manager = OrganizationManager::new(
///     org_store,
///     membership_store,
///     UnlimitedSeats,
///     OrganizationConfig::default(),
/// );
///
/// let org = manager.create(
///     "user_123",
///     "My Organization",
///     Some("my-org"),
///     "contact@example.com",
///     |params| MyOrganization {
///         id: params.id,
///         name: params.name,
///         // ... your fields
///     },
///     |params| MyMembership {
///         org_id: params.org_id,
///         user_id: params.user_id,
///         role: MyRole::Owner,
///         // ... your fields
///     },
/// ).await?;
/// ```
///
/// # Audit Logging
///
/// Enable audit logging with `with_audit_store`:
///
/// ```rust,ignore
/// let manager = OrganizationManager::new(...)
///     .with_audit_store(my_audit_store);
/// ```
pub struct OrganizationManager<O, M, S = UnlimitedSeats, A = ()>
where
    O: OrganizationStore,
    M: MembershipStore,
    S: SeatChecker,
    A: OptionalAuditStore,
{
    org_store: O,
    membership_store: M,
    seat_checker: S,
    audit_store: A,
    config: OrganizationConfig,
}

impl<O, M> OrganizationManager<O, M, UnlimitedSeats, ()>
where
    O: OrganizationStore,
    M: MembershipStore,
{
    /// Create a manager without seat checking.
    #[must_use]
    pub fn new_without_seats(
        org_store: O,
        membership_store: M,
        config: OrganizationConfig,
    ) -> Self {
        Self {
            org_store,
            membership_store,
            seat_checker: UnlimitedSeats,
            audit_store: (),
            config,
        }
    }
}

impl<O, M, S> OrganizationManager<O, M, S, ()>
where
    O: OrganizationStore,
    M: MembershipStore,
    S: SeatChecker,
{
    /// Create a new organization manager.
    #[must_use]
    pub fn new(
        org_store: O,
        membership_store: M,
        seat_checker: S,
        config: OrganizationConfig,
    ) -> Self {
        Self {
            org_store,
            membership_store,
            seat_checker,
            audit_store: (),
            config,
        }
    }

    /// Enable audit logging with the given store.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let manager = OrganizationManager::new(...)
    ///     .with_audit_store(my_audit_store);
    /// ```
    pub fn with_audit_store<AuditStore: OrgAuditStore + Clone + 'static>(
        self,
        audit_store: AuditStore,
    ) -> OrganizationManager<O, M, S, WithAuditStore<AuditStore>> {
        OrganizationManager {
            org_store: self.org_store,
            membership_store: self.membership_store,
            seat_checker: self.seat_checker,
            audit_store: WithAuditStore(audit_store),
            config: self.config,
        }
    }
}

impl<O, M, S, A> OrganizationManager<O, M, S, A>
where
    O: OrganizationStore,
    M: MembershipStore,
    S: SeatChecker,
    A: OptionalAuditStore,
{

    /// Get a reference to the organization store.
    pub fn org_store(&self) -> &O {
        &self.org_store
    }

    /// Get a reference to the membership store.
    pub fn membership_store(&self) -> &M {
        &self.membership_store
    }

    /// Get a reference to the seat checker.
    pub fn seat_checker(&self) -> &S {
        &self.seat_checker
    }

    /// Get a reference to the configuration.
    pub fn config(&self) -> &OrganizationConfig {
        &self.config
    }

    /// Create a new organization with the user as owner.
    ///
    /// Returns the store's Organization type.
    #[instrument(skip(self, org_factory, membership_factory), fields(org.name = %name))]
    pub async fn create<F, G>(
        &self,
        user_id: &str,
        name: &str,
        slug: Option<&str>,
        contact_email: &str,
        org_factory: F,
        membership_factory: G,
    ) -> Result<O::Organization>
    where
        F: FnOnce(OrgCreateParams) -> O::Organization,
        G: FnOnce(MembershipCreateParams) -> M::Membership,
    {
        // Check if user can create organizations
        if !self.config.allow_user_creation {
            debug!(user_id, "Organization creation not allowed");
            return Err(OrganizationError::InsufficientPermission {
                required: "organization_creation".to_string(),
            });
        }

        // Check max orgs per user limit
        if let Some(max) = self.config.max_orgs_per_user {
            let count = self.org_store.count_owned_by_user(user_id).await?;
            if count >= max {
                debug!(user_id, count, max, "Max organizations reached");
                return Err(OrganizationError::max_orgs_reached(max));
            }
        }

        // Generate or validate slug
        let slug = slug
            .map(|s| s.to_string())
            .unwrap_or_else(|| slugify(name));

        // Check slug availability
        if !self.org_store.is_slug_available(&slug).await? {
            debug!(slug, "Slug already taken");
            return Err(OrganizationError::slug_taken(&slug));
        }

        let now = current_timestamp();
        let org_id = Uuid::new_v4().to_string();

        // Create organization using user's factory
        let org = org_factory(OrgCreateParams {
            id: org_id.clone(),
            name: name.to_string(),
            slug: slug.clone(),
            owner_id: user_id.to_string(),
            contact_email: contact_email.to_string(),
            created_at: now,
        });

        // Create owner membership using user's factory
        let membership = membership_factory(MembershipCreateParams {
            org_id: org_id.clone(),
            user_id: user_id.to_string(),
            is_owner: true,
            joined_at: now,
        });

        // Persist organization and membership atomically
        // Uses rollback (delete org) if membership creation fails
        let membership_store = &self.membership_store;
        self.org_store
            .create_with_rollback(&org, || async {
                membership_store.add_member(&membership).await
            })
            .await?;

        info!(
            org_id,
            org_slug = %slug,
            owner_id = user_id,
            "Organization created"
        );

        // Record audit event
        self.audit_store
            .record(
                OrgAuditEntry::new(OrgAuditEvent::OrgCreated, &org_id, user_id)
                    .with_details(format!("name={name}, slug={slug}")),
            )
            .await;

        Ok(org)
    }

    /// Get organization by ID.
    #[instrument(skip(self))]
    pub async fn get(&self, org_id: &str) -> Result<Option<O::Organization>> {
        self.org_store.find_by_id(org_id).await.map_err(Into::into)
    }

    /// Get organization by ID, returning error if not found.
    #[instrument(skip(self))]
    pub async fn get_or_error(&self, org_id: &str) -> Result<O::Organization> {
        self.org_store
            .find_by_id(org_id)
            .await?
            .ok_or_else(|| OrganizationError::not_found(org_id))
    }

    /// Get organization by slug.
    #[instrument(skip(self))]
    pub async fn get_by_slug(&self, slug: &str) -> Result<Option<O::Organization>> {
        self.org_store.find_by_slug(slug).await.map_err(Into::into)
    }

    /// Update an organization.
    ///
    /// Requires `can_manage_settings` permission. The updater function receives
    /// the current organization and returns the updated version.
    ///
    /// # Note on Slug Changes
    ///
    /// If the updater changes the slug, this method will check availability.
    /// However, due to race conditions, the database should still enforce
    /// a unique constraint on the slug column.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// manager.update(
    ///     "org_123",
    ///     "actor_user_id",
    ///     |org| MyOrganization {
    ///         name: "New Name".to_string(),
    ///         updated_at: current_timestamp(),
    ///         ..org
    ///     },
    /// ).await?;
    /// ```
    #[instrument(skip(self, updater))]
    pub async fn update<F>(&self, org_id: &str, actor_id: &str, updater: F) -> Result<O::Organization>
    where
        F: FnOnce(O::Organization) -> O::Organization,
    {
        // Check actor has permission
        let membership = self
            .membership_store
            .get_membership(org_id, actor_id)
            .await?
            .ok_or(OrganizationError::NotMember)?;

        let role = self.membership_store.membership_role(&membership);
        if !self.membership_store.can_manage_settings(&role) {
            return Err(OrganizationError::insufficient_permission(
                "can_manage_settings",
            ));
        }

        // Get current organization
        let current = self
            .org_store
            .find_by_id(org_id)
            .await?
            .ok_or_else(|| OrganizationError::not_found(org_id))?;

        let current_slug = self.org_store.org_slug(&current);

        // Apply update
        let updated = updater(current);

        // Check if slug changed and is available
        let new_slug = self.org_store.org_slug(&updated);
        if new_slug != current_slug && !self.org_store.is_slug_available(&new_slug).await? {
            return Err(OrganizationError::slug_taken(&new_slug));
        }

        // Persist update
        self.org_store.update(&updated).await?;

        debug!(org_id, "Organization updated");

        // Record audit event
        self.audit_store
            .record(OrgAuditEntry::new(OrgAuditEvent::OrgUpdated, org_id, actor_id))
            .await;

        Ok(updated)
    }

    /// Delete organization (requires owner permission).
    #[instrument(skip(self))]
    pub async fn delete(&self, org_id: &str, actor_id: &str) -> Result<()> {
        // Check actor has permission
        let membership = self
            .membership_store
            .get_membership(org_id, actor_id)
            .await?
            .ok_or(OrganizationError::NotMember)?;

        let role = self.membership_store.membership_role(&membership);
        if !self.membership_store.can_delete_org(&role) {
            return Err(OrganizationError::insufficient_permission("can_delete_org"));
        }

        // Delete organization (should cascade to memberships)
        self.org_store.delete(org_id).await?;

        info!(org_id, actor_id, "Organization deleted");

        // Record audit event
        self.audit_store
            .record(OrgAuditEntry::new(OrgAuditEvent::OrgDeleted, org_id, actor_id))
            .await;

        Ok(())
    }

    /// List organizations for a user.
    #[instrument(skip(self))]
    pub async fn list_for_user(&self, user_id: &str) -> Result<Vec<O::Organization>> {
        self.org_store
            .list_for_user(user_id)
            .await
            .map_err(Into::into)
    }

    /// Check if a user is a member of an organization.
    pub async fn is_member(&self, org_id: &str, user_id: &str) -> Result<bool> {
        self.membership_store.is_member(org_id, user_id).await.map_err(Into::into)
    }
}

/// Generate a URL-safe slug from a name.
fn slugify(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slugify() {
        assert_eq!(slugify("My Organization"), "my-organization");
        assert_eq!(slugify("Acme Inc."), "acme-inc");
        assert_eq!(slugify("Test  --  Company"), "test-company");
        assert_eq!(slugify("123 ABC"), "123-abc");
    }
}
