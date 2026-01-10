//! Invitation storage trait.

use crate::error::Result;
use async_trait::async_trait;

/// Trait for invitation storage operations.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::organizations::InvitationStore;
/// use async_trait::async_trait;
///
/// struct MyStore { db: DatabaseConnection }
///
/// #[derive(Clone)]
/// struct MyInvitation {
///     id: String,
///     org_id: String,
///     email: String,
///     role: MyRole,
///     invited_by: String,
///     token: String,
///     expires_at: u64,
///     created_at: u64,
/// }
///
/// #[async_trait]
/// impl InvitationStore for MyStore {
///     type Invitation = MyInvitation;
///     type Role = MyRole;
///
///     async fn create(&self, invitation: &Self::Invitation) -> Result<()> {
///         self.db.insert_invitation(invitation).await?;
///         Ok(())
///     }
///
///     // ... implement other methods
/// }
/// ```
#[async_trait]
pub trait InvitationStore: Send + Sync {
    /// Your invitation type.
    type Invitation: Send + Sync + Clone;

    /// Your role type (same as MembershipStore::Role).
    type Role: Send + Sync + Clone;

    // === Required storage methods ===

    /// Create a new invitation.
    async fn create(&self, invitation: &Self::Invitation) -> Result<()>;

    /// Find an invitation by its token.
    async fn find_by_token(&self, token: &str) -> Result<Option<Self::Invitation>>;

    /// Find an invitation by its ID.
    async fn find_by_id(&self, id: &str) -> Result<Option<Self::Invitation>>;

    /// List pending invitations for an organization.
    async fn list_pending(&self, org_id: &str) -> Result<Vec<Self::Invitation>>;

    /// Mark an invitation as accepted.
    async fn mark_accepted(&self, id: &str) -> Result<()>;

    /// Mark an invitation as revoked.
    async fn mark_revoked(&self, id: &str) -> Result<()>;

    /// Delete expired invitations and return count deleted.
    async fn delete_expired(&self) -> Result<usize>;

    // === Required accessor methods ===

    /// Get the invitation ID.
    fn invitation_id(&self, inv: &Self::Invitation) -> String;

    /// Get the organization ID.
    fn invitation_org_id(&self, inv: &Self::Invitation) -> String;

    /// Get the invitee email.
    fn invitation_email(&self, inv: &Self::Invitation) -> String;

    /// Get the role being granted.
    fn invitation_role(&self, inv: &Self::Invitation) -> Self::Role;

    /// Get the invitation token.
    fn invitation_token(&self, inv: &Self::Invitation) -> String;

    /// Get the expiration timestamp.
    fn invitation_expires_at(&self, inv: &Self::Invitation) -> u64;

    /// Check if the invitation has expired.
    fn is_expired(&self, inv: &Self::Invitation) -> bool;

    /// Check if the invitation has been revoked.
    fn is_revoked(&self, inv: &Self::Invitation) -> bool;

    // === Optional methods with defaults ===

    /// Find pending invitation by email for an organization.
    async fn find_pending_by_email(
        &self,
        org_id: &str,
        email: &str,
    ) -> Result<Option<Self::Invitation>> {
        let pending = self.list_pending(org_id).await?;
        Ok(pending
            .into_iter()
            .find(|i| self.invitation_email(i) == email))
    }

    /// Count pending invitations for an organization.
    async fn count_pending(&self, org_id: &str) -> Result<u32> {
        Ok(self.list_pending(org_id).await?.len() as u32)
    }
}
