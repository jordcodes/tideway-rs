//! Membership manager.
//!
//! Handles membership operations with permission checks and seat validation.

use super::audit::{OrgAuditEntry, OrgAuditEvent};
use super::error::{OrganizationError, Result};
use super::manager::MembershipCreateParams;
use super::seats::{SeatChecker, UnlimitedSeats};
use super::storage::{MembershipStore, OrgAuditStore, OptionalAuditStore, WithAuditStore};
use super::utils::current_timestamp;
use tracing::{debug, info, instrument};

/// Membership manager - handles member operations with permission checks.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::organizations::{MembershipManager, UnlimitedSeats};
///
/// let manager = MembershipManager::new(
///     membership_store,
///     org_store,
///     UnlimitedSeats,
/// );
///
/// // Add a member
/// let membership = manager.add_member(
///     "org_123",
///     "user_456",
///     "admin_user_id",
///     |params| MyMembership {
///         org_id: params.org_id,
///         user_id: params.user_id,
///         role: MyRole::Member,
///         joined_at: params.joined_at,
///     },
/// ).await?;
/// ```
///
/// # Audit Logging
///
/// Enable audit logging with `with_audit_store`:
///
/// ```rust,ignore
/// let manager = MembershipManager::new(...)
///     .with_audit_store(my_audit_store);
/// ```
pub struct MembershipManager<M, S = UnlimitedSeats, A = ()>
where
    M: MembershipStore,
    S: SeatChecker,
    A: OptionalAuditStore,
{
    membership_store: M,
    seat_checker: S,
    audit_store: A,
}

impl<M> MembershipManager<M, UnlimitedSeats, ()>
where
    M: MembershipStore,
{
    /// Create a manager without seat checking.
    #[must_use]
    pub fn new_without_seats(membership_store: M) -> Self {
        Self {
            membership_store,
            seat_checker: UnlimitedSeats,
            audit_store: (),
        }
    }
}

impl<M, S> MembershipManager<M, S, ()>
where
    M: MembershipStore,
    S: SeatChecker,
{
    /// Create a new membership manager.
    #[must_use]
    pub fn new(membership_store: M, seat_checker: S) -> Self {
        Self {
            membership_store,
            seat_checker,
            audit_store: (),
        }
    }

    /// Enable audit logging with the given store.
    pub fn with_audit_store<AuditStore: OrgAuditStore + Clone + 'static>(
        self,
        audit_store: AuditStore,
    ) -> MembershipManager<M, S, WithAuditStore<AuditStore>> {
        MembershipManager {
            membership_store: self.membership_store,
            seat_checker: self.seat_checker,
            audit_store: WithAuditStore(audit_store),
        }
    }
}

impl<M, S, A> MembershipManager<M, S, A>
where
    M: MembershipStore,
    S: SeatChecker,
    A: OptionalAuditStore,
{
    /// Get a reference to the membership store.
    pub fn membership_store(&self) -> &M {
        &self.membership_store
    }

    /// Get a reference to the seat checker.
    pub fn seat_checker(&self) -> &S {
        &self.seat_checker
    }

    /// Add a member to an organization (checks seat availability).
    ///
    /// User provides factory to create their Membership type with their Role.
    #[instrument(skip(self, membership_factory))]
    pub async fn add_member<F>(
        &self,
        org_id: &str,
        user_id: &str,
        actor_id: &str,
        membership_factory: F,
    ) -> Result<M::Membership>
    where
        F: FnOnce(MembershipCreateParams) -> M::Membership,
    {
        // Check actor has permission to add members
        let actor_membership = self
            .membership_store
            .get_membership(org_id, actor_id)
            .await?
            .ok_or(OrganizationError::NotMember)?;

        let actor_role = self.membership_store.membership_role(&actor_membership);
        if !self.membership_store.can_manage_members(&actor_role) {
            return Err(OrganizationError::insufficient_permission(
                "can_manage_members",
            ));
        }

        // Check user is not already a member
        if self.membership_store.is_member(org_id, user_id).await? {
            return Err(OrganizationError::AlreadyMember);
        }

        // Check seat availability
        let current_count = self.membership_store.count_members(org_id).await?;
        if !self
            .seat_checker
            .has_seat_available(org_id, current_count)
            .await?
        {
            let limit = self
                .seat_checker
                .get_seat_limit(org_id)
                .await?
                .unwrap_or(current_count);
            return Err(OrganizationError::seat_limit_reached(current_count, limit));
        }

        let now = current_timestamp();

        // Create membership using user's factory
        let membership = membership_factory(MembershipCreateParams {
            org_id: org_id.to_string(),
            user_id: user_id.to_string(),
            is_owner: false,
            joined_at: now,
        });

        // Persist membership
        self.membership_store.add_member(&membership).await?;

        info!(org_id, user_id, actor_id, "Member added");

        // Record audit event
        self.audit_store
            .record(
                OrgAuditEntry::new(OrgAuditEvent::MemberAdded, org_id, actor_id)
                    .with_target(user_id),
            )
            .await;

        Ok(membership)
    }

    /// Remove a member from an organization (Owner cannot be removed).
    #[instrument(skip(self))]
    pub async fn remove_member(
        &self,
        org_id: &str,
        user_id: &str,
        actor_id: &str,
    ) -> Result<()> {
        // Check actor has permission
        let actor_membership = self
            .membership_store
            .get_membership(org_id, actor_id)
            .await?
            .ok_or(OrganizationError::NotMember)?;

        let actor_role = self.membership_store.membership_role(&actor_membership);
        if !self.membership_store.can_manage_members(&actor_role) {
            return Err(OrganizationError::insufficient_permission(
                "can_manage_members",
            ));
        }

        // Check target is a member
        let target_membership = self
            .membership_store
            .get_membership(org_id, user_id)
            .await?
            .ok_or(OrganizationError::NotMember)?;

        // Cannot remove owner
        let target_role = self.membership_store.membership_role(&target_membership);
        if self.membership_store.is_owner(&target_role) {
            return Err(OrganizationError::CannotRemoveOwner);
        }

        // Remove membership
        self.membership_store.remove_member(org_id, user_id).await?;

        info!(org_id, user_id, actor_id, "Member removed");

        // Record audit event
        self.audit_store
            .record(
                OrgAuditEntry::new(OrgAuditEvent::MemberRemoved, org_id, actor_id)
                    .with_target(user_id),
            )
            .await;

        Ok(())
    }

    /// Leave an organization (member removes themselves).
    ///
    /// Owners cannot leave - they must transfer ownership first.
    #[instrument(skip(self))]
    pub async fn leave(&self, org_id: &str, user_id: &str) -> Result<()> {
        // Check user is a member
        let membership = self
            .membership_store
            .get_membership(org_id, user_id)
            .await?
            .ok_or(OrganizationError::NotMember)?;

        // Owners cannot leave
        let role = self.membership_store.membership_role(&membership);
        if self.membership_store.is_owner(&role) {
            return Err(OrganizationError::CannotRemoveOwner);
        }

        // Remove membership
        self.membership_store.remove_member(org_id, user_id).await?;

        info!(org_id, user_id, "Member left organization");

        // Record audit event (actor is the member themselves)
        self.audit_store
            .record(OrgAuditEntry::new(OrgAuditEvent::MemberLeft, org_id, user_id))
            .await;

        Ok(())
    }

    /// Update a member's data (role change, etc).
    #[instrument(skip(self, updater))]
    pub async fn update_membership<F>(
        &self,
        org_id: &str,
        user_id: &str,
        actor_id: &str,
        updater: F,
    ) -> Result<M::Membership>
    where
        F: FnOnce(&M::Membership) -> M::Membership,
    {
        // Check actor has permission
        let actor_membership = self
            .membership_store
            .get_membership(org_id, actor_id)
            .await?
            .ok_or(OrganizationError::NotMember)?;

        let actor_role = self.membership_store.membership_role(&actor_membership);
        if !self.membership_store.can_manage_members(&actor_role) {
            return Err(OrganizationError::insufficient_permission(
                "can_manage_members",
            ));
        }

        // Get current membership
        let current = self
            .membership_store
            .get_membership(org_id, user_id)
            .await?
            .ok_or(OrganizationError::NotMember)?;

        // Cannot modify owner role (use transfer_ownership instead)
        let current_role = self.membership_store.membership_role(&current);
        if self.membership_store.is_owner(&current_role) {
            return Err(OrganizationError::insufficient_permission(
                "cannot modify owner role directly",
            ));
        }

        // Apply update
        let updated = updater(&current);

        // Prevent promoting to owner via update (must use transfer_ownership)
        let new_role = self.membership_store.membership_role(&updated);
        if self.membership_store.is_owner(&new_role) {
            return Err(OrganizationError::insufficient_permission(
                "cannot promote to owner via update, use transfer_ownership instead",
            ));
        }

        // Persist
        self.membership_store.update_membership(&updated).await?;

        debug!(org_id, user_id, actor_id, "Membership updated");

        // Record audit event
        self.audit_store
            .record(
                OrgAuditEntry::new(OrgAuditEvent::MemberRoleChanged, org_id, actor_id)
                    .with_target(user_id),
            )
            .await;

        Ok(updated)
    }

    /// Transfer ownership to another member.
    #[instrument(skip(self, make_owner, demote_owner))]
    pub async fn transfer_ownership<F, G>(
        &self,
        org_id: &str,
        new_owner_id: &str,
        actor_id: &str,
        make_owner: F,
        demote_owner: G,
    ) -> Result<()>
    where
        F: FnOnce(&M::Membership) -> M::Membership,
        G: FnOnce(&M::Membership) -> M::Membership,
    {
        // Check actor has permission
        let actor_membership = self
            .membership_store
            .get_membership(org_id, actor_id)
            .await?
            .ok_or(OrganizationError::NotMember)?;

        let actor_role = self.membership_store.membership_role(&actor_membership);
        if !self.membership_store.can_transfer_ownership(&actor_role) {
            return Err(OrganizationError::insufficient_permission(
                "can_transfer_ownership",
            ));
        }

        // Check new owner is a member
        let new_owner_membership = self
            .membership_store
            .get_membership(org_id, new_owner_id)
            .await?
            .ok_or(OrganizationError::NotMember)?;

        // Prepare both updates
        let demoted = demote_owner(&actor_membership);
        let promoted = make_owner(&new_owner_membership);

        // Update both atomically (uses transaction in SeaORM, sequential in default impl)
        self.membership_store
            .update_memberships_atomic(&[demoted, promoted])
            .await?;

        info!(org_id, new_owner_id, former_owner = actor_id, "Ownership transferred");

        // Record audit event
        self.audit_store
            .record(
                OrgAuditEntry::new(OrgAuditEvent::OwnershipTransferred, org_id, actor_id)
                    .with_target(new_owner_id),
            )
            .await;

        Ok(())
    }

    /// Get membership for a user.
    pub async fn get_membership(
        &self,
        org_id: &str,
        user_id: &str,
    ) -> Result<Option<M::Membership>> {
        self.membership_store
            .get_membership(org_id, user_id)
            .await
            .map_err(Into::into)
    }

    /// List all members of an organization.
    pub async fn list_members(&self, org_id: &str) -> Result<Vec<M::Membership>> {
        self.membership_store
            .list_members(org_id)
            .await
            .map_err(Into::into)
    }

    /// Check if user is a member.
    pub async fn is_member(&self, org_id: &str, user_id: &str) -> Result<bool> {
        self.membership_store
            .is_member(org_id, user_id)
            .await
            .map_err(Into::into)
    }

    /// Check if user has can_manage_members permission.
    pub async fn can_manage_members(&self, org_id: &str, user_id: &str) -> Result<bool> {
        let membership = self.membership_store.get_membership(org_id, user_id).await?;
        Ok(membership.is_some_and(|m| {
            let role = self.membership_store.membership_role(&m);
            self.membership_store.can_manage_members(&role)
        }))
    }

    /// Check if user has can_manage_settings permission.
    pub async fn can_manage_settings(&self, org_id: &str, user_id: &str) -> Result<bool> {
        let membership = self.membership_store.get_membership(org_id, user_id).await?;
        Ok(membership.is_some_and(|m| {
            let role = self.membership_store.membership_role(&m);
            self.membership_store.can_manage_settings(&role)
        }))
    }

    /// Check if user has can_delete_org permission.
    pub async fn can_delete_org(&self, org_id: &str, user_id: &str) -> Result<bool> {
        let membership = self.membership_store.get_membership(org_id, user_id).await?;
        Ok(membership.is_some_and(|m| {
            let role = self.membership_store.membership_role(&m);
            self.membership_store.can_delete_org(&role)
        }))
    }

    /// Count members in an organization.
    pub async fn count_members(&self, org_id: &str) -> Result<u32> {
        self.membership_store
            .count_members(org_id)
            .await
            .map_err(Into::into)
    }
}
