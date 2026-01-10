//! Invitation manager.
//!
//! Handles invitation creation, acceptance, and revocation.

use super::config::InvitationConfig;
use super::error::{OrganizationError, Result};
use super::manager::MembershipCreateParams;
use super::seats::{SeatChecker, UnlimitedSeats};
use super::storage::{InvitationStore, MembershipStore, OrganizationStore};
use super::utils::current_timestamp;
use tracing::{debug, info, instrument};
use uuid::Uuid;

/// Parameters passed to the invitation factory function.
#[derive(Debug, Clone)]
pub struct InvitationCreateParams {
    /// Generated unique ID.
    pub id: String,
    /// Organization ID.
    pub org_id: String,
    /// Invitee email address.
    pub email: String,
    /// User ID of the person who sent the invitation.
    pub invited_by: String,
    /// Secret token for accepting the invitation.
    pub token: String,
    /// Expiration timestamp (Unix seconds).
    pub expires_at: u64,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
}

/// Invitation manager - handles invitation lifecycle.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::organizations::{
///     InvitationManager, InvitationConfig, UnlimitedSeats,
/// };
///
/// let manager = InvitationManager::new(
///     invitation_store,
///     membership_store,
///     org_store,
///     UnlimitedSeats,
///     InvitationConfig::default(),
/// );
///
/// // Create invitation
/// let invitation = manager.invite(
///     "org_123",
///     "newuser@example.com",
///     "admin_user_id",
///     |params| MyInvitation {
///         id: params.id,
///         org_id: params.org_id,
///         email: params.email,
///         role: MyRole::Member,
///         // ...
///     },
/// ).await?;
///
/// // Accept invitation
/// let membership = manager.accept(
///     &invitation_token,
///     "new_user_id",
///     |inv, params| MyMembership {
///         org_id: params.org_id,
///         user_id: params.user_id,
///         role: inv.role.clone(),
///         // ...
///     },
/// ).await?;
/// ```
pub struct InvitationManager<I, M, O, S = UnlimitedSeats>
where
    I: InvitationStore,
    M: MembershipStore,
    O: OrganizationStore,
    S: SeatChecker,
{
    invitation_store: I,
    membership_store: M,
    org_store: O,
    seat_checker: S,
    config: InvitationConfig,
}

impl<I, M, O> InvitationManager<I, M, O, UnlimitedSeats>
where
    I: InvitationStore,
    M: MembershipStore,
    O: OrganizationStore,
{
    /// Create a manager without seat checking.
    pub fn new_without_seats(
        invitation_store: I,
        membership_store: M,
        org_store: O,
        config: InvitationConfig,
    ) -> Self {
        Self {
            invitation_store,
            membership_store,
            org_store,
            seat_checker: UnlimitedSeats,
            config,
        }
    }
}

impl<I, M, O, S> InvitationManager<I, M, O, S>
where
    I: InvitationStore,
    M: MembershipStore,
    O: OrganizationStore,
    S: SeatChecker,
{
    /// Create a new invitation manager.
    pub fn new(
        invitation_store: I,
        membership_store: M,
        org_store: O,
        seat_checker: S,
        config: InvitationConfig,
    ) -> Self {
        Self {
            invitation_store,
            membership_store,
            org_store,
            seat_checker,
            config,
        }
    }

    /// Get a reference to the invitation store.
    pub fn invitation_store(&self) -> &I {
        &self.invitation_store
    }

    /// Get a reference to the configuration.
    pub fn config(&self) -> &InvitationConfig {
        &self.config
    }

    /// Create an invitation.
    ///
    /// Checks seat availability, pending invitation limit, and actor permissions.
    #[instrument(skip(self, invitation_factory))]
    pub async fn invite<F>(
        &self,
        org_id: &str,
        email: &str,
        actor_id: &str,
        invitation_factory: F,
    ) -> Result<I::Invitation>
    where
        F: FnOnce(InvitationCreateParams) -> I::Invitation,
    {
        // Check organization exists
        self.org_store
            .find_by_id(org_id)
            .await?
            .ok_or_else(|| OrganizationError::not_found(org_id))?;

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

        // Check if email already has pending invitation
        if self
            .invitation_store
            .find_pending_by_email(org_id, email)
            .await?
            .is_some()
        {
            return Err(OrganizationError::InvitationAlreadyExists);
        }

        // Check pending invitation limit
        let pending_count = self.invitation_store.count_pending(org_id).await?;
        if pending_count >= self.config.max_pending_per_org {
            return Err(OrganizationError::max_pending_invitations(
                self.config.max_pending_per_org,
            ));
        }

        // Check seat availability (members + pending invitations)
        let member_count = self.membership_store.count_members(org_id).await?;
        let total_count = member_count + pending_count;
        if !self
            .seat_checker
            .has_seat_available(org_id, total_count)
            .await?
        {
            let limit = self
                .seat_checker
                .get_seat_limit(org_id)
                .await?
                .unwrap_or(total_count);
            return Err(OrganizationError::seat_limit_reached(total_count, limit));
        }

        let now = current_timestamp();
        let expires_at = now + self.config.expiry_seconds();
        let token = generate_secure_token();

        // Create invitation using user's factory
        let invitation = invitation_factory(InvitationCreateParams {
            id: Uuid::new_v4().to_string(),
            org_id: org_id.to_string(),
            email: email.to_string(),
            invited_by: actor_id.to_string(),
            token,
            expires_at,
            created_at: now,
        });

        // Persist invitation
        self.invitation_store.create(&invitation).await?;

        info!(
            org_id,
            email,
            actor_id,
            invitation_id = %self.invitation_store.invitation_id(&invitation),
            "Invitation created"
        );

        Ok(invitation)
    }

    /// Accept an invitation by token.
    ///
    /// User provides factory for creating membership from invitation.
    #[instrument(skip(self, membership_factory))]
    pub async fn accept<F>(
        &self,
        token: &str,
        user_id: &str,
        membership_factory: F,
    ) -> Result<M::Membership>
    where
        F: FnOnce(&I::Invitation, MembershipCreateParams) -> M::Membership,
    {
        // Find invitation by token
        let invitation = self
            .invitation_store
            .find_by_token(token)
            .await?
            .ok_or(OrganizationError::InvalidToken)?;

        // Check not expired
        if self.invitation_store.is_expired(&invitation) {
            return Err(OrganizationError::InvitationExpired);
        }

        let org_id = self.invitation_store.invitation_org_id(&invitation);
        let invitation_id = self.invitation_store.invitation_id(&invitation);

        // Check user not already a member
        if self.membership_store.is_member(&org_id, user_id).await? {
            return Err(OrganizationError::AlreadyMember);
        }

        let now = current_timestamp();

        // Create membership using user's factory
        let membership = membership_factory(
            &invitation,
            MembershipCreateParams {
                org_id: org_id.clone(),
                user_id: user_id.to_string(),
                is_owner: false,
                joined_at: now,
            },
        );

        // Add member and mark invitation as accepted
        self.membership_store.add_member(&membership).await?;
        self.invitation_store.mark_accepted(&invitation_id).await?;

        info!(
            org_id,
            user_id,
            invitation_id,
            "Invitation accepted"
        );

        Ok(membership)
    }

    /// Revoke an invitation.
    #[instrument(skip(self))]
    pub async fn revoke(&self, invitation_id: &str, actor_id: &str) -> Result<()> {
        // Find invitation
        let invitation = self
            .invitation_store
            .find_by_id(invitation_id)
            .await?
            .ok_or_else(|| OrganizationError::invitation_not_found(invitation_id))?;

        let org_id = self.invitation_store.invitation_org_id(&invitation);

        // Check actor has permission
        let actor_membership = self
            .membership_store
            .get_membership(&org_id, actor_id)
            .await?
            .ok_or(OrganizationError::NotMember)?;

        let actor_role = self.membership_store.membership_role(&actor_membership);
        if !self.membership_store.can_manage_members(&actor_role) {
            return Err(OrganizationError::insufficient_permission(
                "can_manage_members",
            ));
        }

        // Revoke invitation
        self.invitation_store.mark_revoked(invitation_id).await?;

        info!(org_id, invitation_id, actor_id, "Invitation revoked");

        Ok(())
    }

    /// List pending invitations for an organization.
    pub async fn list_pending(&self, org_id: &str) -> Result<Vec<I::Invitation>> {
        self.invitation_store
            .list_pending(org_id)
            .await
            .map_err(Into::into)
    }

    /// Get invitation by ID.
    pub async fn get(&self, invitation_id: &str) -> Result<Option<I::Invitation>> {
        self.invitation_store
            .find_by_id(invitation_id)
            .await
            .map_err(Into::into)
    }

    /// Get invitation by token.
    pub async fn get_by_token(&self, token: &str) -> Result<Option<I::Invitation>> {
        self.invitation_store
            .find_by_token(token)
            .await
            .map_err(Into::into)
    }

    /// Clean up expired invitations.
    pub async fn cleanup_expired(&self) -> Result<usize> {
        let count = self.invitation_store.delete_expired().await?;
        if count > 0 {
            debug!(count, "Expired invitations cleaned up");
        }
        Ok(count)
    }
}

/// Generate a secure random token for invitations.
fn generate_secure_token() -> String {
    use base64::Engine;
    use rand::Rng;

    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
