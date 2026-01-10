//! In-memory test implementations for organizations.
//!
//! Provides ready-to-use test types and stores for testing organization functionality.

use super::storage::{InvitationStore, MembershipStore, OrganizationStore};
use super::types::DefaultOrgRole;
use crate::error::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Test organization type.
#[derive(Clone, Debug)]
pub struct TestOrganization {
    /// Unique identifier.
    pub id: String,
    /// Organization name.
    pub name: String,
    /// URL-safe slug.
    pub slug: String,
    /// Owner user ID.
    pub owner_id: String,
    /// Contact email.
    pub contact_email: String,
    /// Creation timestamp.
    pub created_at: u64,
    /// Last update timestamp.
    pub updated_at: u64,
}

/// Test membership type.
#[derive(Clone, Debug)]
pub struct TestMembership {
    /// Organization ID.
    pub org_id: String,
    /// User ID.
    pub user_id: String,
    /// Role in the organization.
    pub role: DefaultOrgRole,
    /// Join timestamp.
    pub joined_at: u64,
}

/// Test invitation type.
#[derive(Clone, Debug)]
pub struct TestInvitation {
    /// Unique identifier.
    pub id: String,
    /// Organization ID.
    pub org_id: String,
    /// Invitee email.
    pub email: String,
    /// Role to be granted.
    pub role: DefaultOrgRole,
    /// User who sent the invitation.
    pub invited_by: String,
    /// Secret token for accepting.
    pub token: String,
    /// Expiration timestamp.
    pub expires_at: u64,
    /// Creation timestamp.
    pub created_at: u64,
    /// Whether the invitation has been accepted.
    pub accepted: bool,
    /// Whether the invitation has been revoked.
    pub revoked: bool,
}

/// Internal state for InMemoryOrgStore, wrapped in Arc for shared ownership.
struct InMemoryOrgStoreInner {
    orgs: RwLock<HashMap<String, TestOrganization>>,
    orgs_by_slug: RwLock<HashMap<String, String>>, // slug -> id
    memberships: RwLock<HashMap<(String, String), TestMembership>>, // (org_id, user_id) -> membership
    invitations: RwLock<HashMap<String, TestInvitation>>,
    invitations_by_token: RwLock<HashMap<String, String>>, // token -> id
}

/// In-memory store implementing all organization storage traits.
///
/// Uses the test types above for convenient testing.
/// Cloning shares the same underlying data (uses Arc internally).
#[derive(Clone)]
pub struct InMemoryOrgStore {
    inner: Arc<InMemoryOrgStoreInner>,
}

impl Default for InMemoryOrgStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryOrgStore {
    /// Create a new in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(InMemoryOrgStoreInner {
                orgs: RwLock::new(HashMap::new()),
                orgs_by_slug: RwLock::new(HashMap::new()),
                memberships: RwLock::new(HashMap::new()),
                invitations: RwLock::new(HashMap::new()),
                invitations_by_token: RwLock::new(HashMap::new()),
            }),
        }
    }

    /// Helper to insert an organization directly (for test setup).
    pub fn insert_org(&self, org: TestOrganization) {
        let id = org.id.clone();
        let slug = org.slug.clone();
        self.inner.orgs.write().unwrap().insert(id.clone(), org);
        self.inner.orgs_by_slug.write().unwrap().insert(slug, id);
    }

    /// Helper to insert a membership directly (for test setup).
    pub fn insert_membership(&self, membership: TestMembership) {
        let key = (membership.org_id.clone(), membership.user_id.clone());
        self.inner.memberships.write().unwrap().insert(key, membership);
    }

    /// Helper to insert an invitation directly (for test setup).
    pub fn insert_invitation(&self, invitation: TestInvitation) {
        let id = invitation.id.clone();
        let token = invitation.token.clone();
        self.inner.invitations.write().unwrap().insert(id.clone(), invitation);
        self.inner.invitations_by_token.write().unwrap().insert(token, id);
    }

    /// Get current timestamp.
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

#[async_trait]
impl OrganizationStore for InMemoryOrgStore {
    type Organization = TestOrganization;

    async fn create(&self, org: &Self::Organization) -> Result<()> {
        self.insert_org(org.clone());
        Ok(())
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<Self::Organization>> {
        Ok(self.inner.orgs.read().unwrap().get(id).cloned())
    }

    async fn find_by_slug(&self, slug: &str) -> Result<Option<Self::Organization>> {
        let id = self.inner.orgs_by_slug.read().unwrap().get(slug).cloned();
        match id {
            Some(id) => Ok(self.inner.orgs.read().unwrap().get(&id).cloned()),
            None => Ok(None),
        }
    }

    async fn update(&self, org: &Self::Organization) -> Result<()> {
        let mut orgs = self.inner.orgs.write().unwrap();
        if let Some(existing) = orgs.get_mut(&org.id) {
            // Update slug index if changed
            if existing.slug != org.slug {
                let mut by_slug = self.inner.orgs_by_slug.write().unwrap();
                by_slug.remove(&existing.slug);
                by_slug.insert(org.slug.clone(), org.id.clone());
            }
            *existing = org.clone();
        }
        Ok(())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let org = self.inner.orgs.write().unwrap().remove(id);
        if let Some(org) = org {
            self.inner.orgs_by_slug.write().unwrap().remove(&org.slug);
        }
        // Also remove all memberships for this org
        self.inner.memberships.write().unwrap().retain(|k, _| k.0 != id);
        // And invitations
        self.inner.invitations.write().unwrap().retain(|_, v| v.org_id != id);
        Ok(())
    }

    fn org_id(&self, org: &Self::Organization) -> String {
        org.id.clone()
    }

    fn org_name(&self, org: &Self::Organization) -> String {
        org.name.clone()
    }

    fn org_slug(&self, org: &Self::Organization) -> String {
        org.slug.clone()
    }

    fn owner_id(&self, org: &Self::Organization) -> String {
        org.owner_id.clone()
    }

    fn contact_email(&self, org: &Self::Organization) -> String {
        org.contact_email.clone()
    }

    async fn list_for_user(&self, user_id: &str) -> Result<Vec<Self::Organization>> {
        let memberships = self.inner.memberships.read().unwrap();
        let orgs = self.inner.orgs.read().unwrap();

        let result: Vec<_> = memberships
            .iter()
            .filter(|(_, m)| m.user_id == user_id)
            .filter_map(|((org_id, _), _)| orgs.get(org_id).cloned())
            .collect();

        Ok(result)
    }

    async fn count_owned_by_user(&self, user_id: &str) -> Result<u32> {
        let orgs = self.inner.orgs.read().unwrap();
        let count = orgs.values().filter(|o| o.owner_id == user_id).count();
        Ok(count as u32)
    }
}

#[async_trait]
impl MembershipStore for InMemoryOrgStore {
    type Membership = TestMembership;
    type Role = DefaultOrgRole;

    async fn add_member(&self, membership: &Self::Membership) -> Result<()> {
        self.insert_membership(membership.clone());
        Ok(())
    }

    async fn remove_member(&self, org_id: &str, user_id: &str) -> Result<()> {
        self.inner
            .memberships
            .write()
            .unwrap()
            .remove(&(org_id.to_string(), user_id.to_string()));
        Ok(())
    }

    async fn get_membership(
        &self,
        org_id: &str,
        user_id: &str,
    ) -> Result<Option<Self::Membership>> {
        Ok(self
            .inner
            .memberships
            .read()
            .unwrap()
            .get(&(org_id.to_string(), user_id.to_string()))
            .cloned())
    }

    async fn list_members(&self, org_id: &str) -> Result<Vec<Self::Membership>> {
        let memberships = self.inner.memberships.read().unwrap();
        let result: Vec<_> = memberships
            .iter()
            .filter(|((oid, _), _)| oid == org_id)
            .map(|(_, m)| m.clone())
            .collect();
        Ok(result)
    }

    async fn update_membership(&self, membership: &Self::Membership) -> Result<()> {
        let key = (membership.org_id.clone(), membership.user_id.clone());
        self.inner.memberships.write().unwrap().insert(key, membership.clone());
        Ok(())
    }

    fn membership_user_id(&self, m: &Self::Membership) -> String {
        m.user_id.clone()
    }

    fn membership_org_id(&self, m: &Self::Membership) -> String {
        m.org_id.clone()
    }

    fn membership_role(&self, m: &Self::Membership) -> Self::Role {
        m.role
    }

    fn can_manage_members(&self, role: &Self::Role) -> bool {
        matches!(role, DefaultOrgRole::Owner | DefaultOrgRole::Admin)
    }

    fn can_manage_settings(&self, role: &Self::Role) -> bool {
        matches!(role, DefaultOrgRole::Owner | DefaultOrgRole::Admin)
    }

    fn can_delete_org(&self, role: &Self::Role) -> bool {
        matches!(role, DefaultOrgRole::Owner)
    }

    fn can_transfer_ownership(&self, role: &Self::Role) -> bool {
        matches!(role, DefaultOrgRole::Owner)
    }

    fn is_owner(&self, role: &Self::Role) -> bool {
        matches!(role, DefaultOrgRole::Owner)
    }

    async fn list_user_memberships(&self, user_id: &str) -> Result<Vec<Self::Membership>> {
        let memberships = self.inner.memberships.read().unwrap();
        let result: Vec<_> = memberships
            .iter()
            .filter(|((_, uid), _)| uid == user_id)
            .map(|(_, m)| m.clone())
            .collect();
        Ok(result)
    }
}

#[async_trait]
impl InvitationStore for InMemoryOrgStore {
    type Invitation = TestInvitation;
    type Role = DefaultOrgRole;

    async fn create(&self, invitation: &Self::Invitation) -> Result<()> {
        self.insert_invitation(invitation.clone());
        Ok(())
    }

    async fn find_by_token(&self, token: &str) -> Result<Option<Self::Invitation>> {
        let id = self.inner.invitations_by_token.read().unwrap().get(token).cloned();
        match id {
            Some(id) => Ok(self.inner.invitations.read().unwrap().get(&id).cloned()),
            None => Ok(None),
        }
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<Self::Invitation>> {
        Ok(self.inner.invitations.read().unwrap().get(id).cloned())
    }

    async fn list_pending(&self, org_id: &str) -> Result<Vec<Self::Invitation>> {
        let invitations = self.inner.invitations.read().unwrap();
        let now = Self::now();
        let result: Vec<_> = invitations
            .values()
            .filter(|i| {
                i.org_id == org_id && !i.accepted && !i.revoked && i.expires_at > now
            })
            .cloned()
            .collect();
        Ok(result)
    }

    async fn mark_accepted(&self, id: &str) -> Result<()> {
        if let Some(inv) = self.inner.invitations.write().unwrap().get_mut(id) {
            inv.accepted = true;
        }
        Ok(())
    }

    async fn mark_revoked(&self, id: &str) -> Result<()> {
        if let Some(inv) = self.inner.invitations.write().unwrap().get_mut(id) {
            inv.revoked = true;
        }
        Ok(())
    }

    async fn delete_expired(&self) -> Result<usize> {
        let now = Self::now();
        let mut invitations = self.inner.invitations.write().unwrap();
        let mut by_token = self.inner.invitations_by_token.write().unwrap();

        let expired: Vec<_> = invitations
            .iter()
            .filter(|(_, i)| i.expires_at <= now && !i.accepted && !i.revoked)
            .map(|(id, i)| (id.clone(), i.token.clone()))
            .collect();

        let count = expired.len();
        for (id, token) in expired {
            invitations.remove(&id);
            by_token.remove(&token);
        }

        Ok(count)
    }

    fn invitation_id(&self, inv: &Self::Invitation) -> String {
        inv.id.clone()
    }

    fn invitation_org_id(&self, inv: &Self::Invitation) -> String {
        inv.org_id.clone()
    }

    fn invitation_email(&self, inv: &Self::Invitation) -> String {
        inv.email.clone()
    }

    fn invitation_role(&self, inv: &Self::Invitation) -> Self::Role {
        inv.role
    }

    fn invitation_token(&self, inv: &Self::Invitation) -> String {
        inv.token.clone()
    }

    fn invitation_expires_at(&self, inv: &Self::Invitation) -> u64 {
        inv.expires_at
    }

    fn is_expired(&self, inv: &Self::Invitation) -> bool {
        inv.expires_at <= Self::now()
    }

    fn is_revoked(&self, inv: &Self::Invitation) -> bool {
        inv.revoked
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::organizations::{
        InvitationConfig, InvitationManager, MembershipManager, OrganizationConfig,
        OrganizationManager, UnlimitedSeats,
    };
    use crate::organizations::error::OrganizationError;
    use crate::organizations::seats::SeatChecker;

    /// Helper to create a test organization.
    fn make_org(p: crate::organizations::manager::OrgCreateParams) -> TestOrganization {
        TestOrganization {
            id: p.id,
            name: p.name,
            slug: p.slug,
            owner_id: p.owner_id,
            contact_email: p.contact_email,
            created_at: p.created_at,
            updated_at: p.created_at,
        }
    }

    /// Helper to create a test membership.
    fn make_membership(
        p: crate::organizations::manager::MembershipCreateParams,
        role: DefaultOrgRole,
    ) -> TestMembership {
        TestMembership {
            org_id: p.org_id,
            user_id: p.user_id,
            role,
            joined_at: p.joined_at,
        }
    }

    /// Seat checker that limits to a specific number.
    #[derive(Clone)]
    struct LimitedSeats(u32);

    #[async_trait]
    impl SeatChecker for LimitedSeats {
        async fn has_seat_available(
            &self,
            _org_id: &str,
            current_count: u32,
        ) -> crate::error::Result<bool> {
            Ok(current_count < self.0)
        }

        async fn get_seat_limit(&self, _org_id: &str) -> crate::error::Result<Option<u32>> {
            Ok(Some(self.0))
        }
    }

    #[tokio::test]
    async fn test_org_creation() {
        let store = InMemoryOrgStore::new();
        let manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );

        let org = manager
            .create(
                "user_1",
                "Test Org",
                Some("test-org"),
                "test@example.com",
                |p| TestOrganization {
                    id: p.id,
                    name: p.name,
                    slug: p.slug,
                    owner_id: p.owner_id,
                    contact_email: p.contact_email,
                    created_at: p.created_at,
                    updated_at: p.created_at,
                },
                |p| TestMembership {
                    org_id: p.org_id,
                    user_id: p.user_id,
                    role: DefaultOrgRole::Owner,
                    joined_at: p.joined_at,
                },
            )
            .await
            .unwrap();

        assert_eq!(org.name, "Test Org");
        assert_eq!(org.slug, "test-org");
        assert!(manager.is_member(&org.id, "user_1").await.unwrap());
    }

    #[tokio::test]
    async fn test_membership_management() {
        let store = InMemoryOrgStore::new();
        let org_manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );
        let mem_manager = MembershipManager::new(store.clone(), UnlimitedSeats);

        // Create org with owner
        let org = org_manager
            .create(
                "owner",
                "Test Org",
                None,
                "owner@example.com",
                |p| TestOrganization {
                    id: p.id,
                    name: p.name,
                    slug: p.slug,
                    owner_id: p.owner_id,
                    contact_email: p.contact_email,
                    created_at: p.created_at,
                    updated_at: p.created_at,
                },
                |p| TestMembership {
                    org_id: p.org_id,
                    user_id: p.user_id,
                    role: DefaultOrgRole::Owner,
                    joined_at: p.joined_at,
                },
            )
            .await
            .unwrap();

        // Add a member
        let membership = mem_manager
            .add_member(&org.id, "member_1", "owner", |p| TestMembership {
                org_id: p.org_id,
                user_id: p.user_id,
                role: DefaultOrgRole::Member,
                joined_at: p.joined_at,
            })
            .await
            .unwrap();

        assert_eq!(membership.role, DefaultOrgRole::Member);

        // Check membership count
        let count = mem_manager.count_members(&org.id).await.unwrap();
        assert_eq!(count, 2);

        // Remove member
        mem_manager
            .remove_member(&org.id, "member_1", "owner")
            .await
            .unwrap();

        assert!(!mem_manager.is_member(&org.id, "member_1").await.unwrap());
    }

    #[tokio::test]
    async fn test_cannot_remove_owner() {
        let store = InMemoryOrgStore::new();
        let org_manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );
        let mem_manager = MembershipManager::new(store.clone(), UnlimitedSeats);

        let org = org_manager
            .create(
                "owner",
                "Test Org",
                None,
                "owner@example.com",
                |p| TestOrganization {
                    id: p.id,
                    name: p.name,
                    slug: p.slug,
                    owner_id: p.owner_id,
                    contact_email: p.contact_email,
                    created_at: p.created_at,
                    updated_at: p.created_at,
                },
                |p| TestMembership {
                    org_id: p.org_id,
                    user_id: p.user_id,
                    role: DefaultOrgRole::Owner,
                    joined_at: p.joined_at,
                },
            )
            .await
            .unwrap();

        // Try to remove owner
        let result = mem_manager.remove_member(&org.id, "owner", "owner").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_slug_uniqueness() {
        let store = InMemoryOrgStore::new();
        let manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );

        // Create first org
        let _org1 = manager
            .create(
                "user_1",
                "First Org",
                Some("my-slug"),
                "first@example.com",
                |p| TestOrganization {
                    id: p.id,
                    name: p.name,
                    slug: p.slug,
                    owner_id: p.owner_id,
                    contact_email: p.contact_email,
                    created_at: p.created_at,
                    updated_at: p.created_at,
                },
                |p| TestMembership {
                    org_id: p.org_id,
                    user_id: p.user_id,
                    role: DefaultOrgRole::Owner,
                    joined_at: p.joined_at,
                },
            )
            .await
            .unwrap();

        // Try to create second org with same slug
        let result = manager
            .create(
                "user_2",
                "Second Org",
                Some("my-slug"),
                "second@example.com",
                |p| TestOrganization {
                    id: p.id,
                    name: p.name,
                    slug: p.slug,
                    owner_id: p.owner_id,
                    contact_email: p.contact_email,
                    created_at: p.created_at,
                    updated_at: p.created_at,
                },
                |p| TestMembership {
                    org_id: p.org_id,
                    user_id: p.user_id,
                    role: DefaultOrgRole::Owner,
                    joined_at: p.joined_at,
                },
            )
            .await;

        assert!(result.is_err());
    }

    // =========================================================================
    // Organization Manager Error Tests
    // =========================================================================

    #[tokio::test]
    async fn test_create_org_max_orgs_limit() {
        let store = InMemoryOrgStore::new();
        let config = OrganizationConfig::default().max_orgs_per_user(Some(1));
        let manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            config,
        );

        // Create first org - should succeed
        let _org1 = manager
            .create("user_1", "Org 1", Some("org-1"), "test@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await
            .unwrap();

        // Create second org - should fail (max 1 per user)
        let result = manager
            .create("user_1", "Org 2", Some("org-2"), "test@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await;

        assert!(matches!(
            result.unwrap_err(),
            OrganizationError::MaxOrgsReached { .. }
        ));
    }

    #[tokio::test]
    async fn test_create_org_creation_disabled() {
        let store = InMemoryOrgStore::new();
        let config = OrganizationConfig::default().allow_user_creation(false);
        let manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            config,
        );

        let result = manager
            .create("user_1", "My Org", None, "test@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await;

        assert!(matches!(
            result.unwrap_err(),
            OrganizationError::InsufficientPermission { .. }
        ));
    }

    #[tokio::test]
    async fn test_update_org_requires_permission() {
        let store = InMemoryOrgStore::new();
        let manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );

        // Create org with owner
        let org = manager
            .create("owner", "Test Org", None, "owner@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await
            .unwrap();

        // Add a regular member
        store.insert_membership(TestMembership {
            org_id: org.id.clone(),
            user_id: "member".to_string(),
            role: DefaultOrgRole::Member,
            joined_at: 0,
        });

        // Member tries to update - should fail
        let result = manager
            .update(&org.id, "member", |mut o| {
                o.name = "New Name".to_string();
                o
            })
            .await;

        assert!(matches!(
            result.unwrap_err(),
            OrganizationError::InsufficientPermission { .. }
        ));
    }

    #[tokio::test]
    async fn test_delete_org_requires_owner() {
        let store = InMemoryOrgStore::new();
        let manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );

        // Create org
        let org = manager
            .create("owner", "Test Org", None, "owner@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await
            .unwrap();

        // Add an admin
        store.insert_membership(TestMembership {
            org_id: org.id.clone(),
            user_id: "admin".to_string(),
            role: DefaultOrgRole::Admin,
            joined_at: 0,
        });

        // Admin tries to delete - should fail
        let result = manager.delete(&org.id, "admin").await;

        assert!(matches!(
            result.unwrap_err(),
            OrganizationError::InsufficientPermission { .. }
        ));

        // Owner deletes - should succeed
        manager.delete(&org.id, "owner").await.unwrap();
    }

    // =========================================================================
    // Membership Manager Error Tests
    // =========================================================================

    #[tokio::test]
    async fn test_add_member_requires_permission() {
        let store = InMemoryOrgStore::new();
        let org_manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );
        let mem_manager = MembershipManager::new(store.clone(), UnlimitedSeats);

        let org = org_manager
            .create("owner", "Test Org", None, "owner@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await
            .unwrap();

        // Add a regular member
        store.insert_membership(TestMembership {
            org_id: org.id.clone(),
            user_id: "member".to_string(),
            role: DefaultOrgRole::Member,
            joined_at: 0,
        });

        // Member tries to add another member - should fail
        let result = mem_manager
            .add_member(&org.id, "new_user", "member", |p| {
                make_membership(p, DefaultOrgRole::Member)
            })
            .await;

        assert!(matches!(
            result.unwrap_err(),
            OrganizationError::InsufficientPermission { .. }
        ));
    }

    #[tokio::test]
    async fn test_add_member_already_member() {
        let store = InMemoryOrgStore::new();
        let org_manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );
        let mem_manager = MembershipManager::new(store.clone(), UnlimitedSeats);

        let org = org_manager
            .create("owner", "Test Org", None, "owner@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await
            .unwrap();

        // Try to add owner again - should fail
        let result = mem_manager
            .add_member(&org.id, "owner", "owner", |p| {
                make_membership(p, DefaultOrgRole::Member)
            })
            .await;

        assert!(matches!(result.unwrap_err(), OrganizationError::AlreadyMember));
    }

    #[tokio::test]
    async fn test_add_member_seat_limit() {
        let store = InMemoryOrgStore::new();
        let org_manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );
        // Limit to 1 seat
        let mem_manager = MembershipManager::new(store.clone(), LimitedSeats(1));

        let org = org_manager
            .create("owner", "Test Org", None, "owner@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await
            .unwrap();

        // Try to add member when at seat limit - should fail
        let result = mem_manager
            .add_member(&org.id, "new_user", "owner", |p| {
                make_membership(p, DefaultOrgRole::Member)
            })
            .await;

        assert!(matches!(
            result.unwrap_err(),
            OrganizationError::SeatLimitReached { .. }
        ));
    }

    #[tokio::test]
    async fn test_remove_member_requires_permission() {
        let store = InMemoryOrgStore::new();
        let org_manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );
        let mem_manager = MembershipManager::new(store.clone(), UnlimitedSeats);

        let org = org_manager
            .create("owner", "Test Org", None, "owner@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await
            .unwrap();

        // Add two regular members
        store.insert_membership(TestMembership {
            org_id: org.id.clone(),
            user_id: "member1".to_string(),
            role: DefaultOrgRole::Member,
            joined_at: 0,
        });
        store.insert_membership(TestMembership {
            org_id: org.id.clone(),
            user_id: "member2".to_string(),
            role: DefaultOrgRole::Member,
            joined_at: 0,
        });

        // Member1 tries to remove member2 - should fail
        let result = mem_manager.remove_member(&org.id, "member2", "member1").await;

        assert!(matches!(
            result.unwrap_err(),
            OrganizationError::InsufficientPermission { .. }
        ));
    }

    #[tokio::test]
    async fn test_update_membership_cannot_promote_to_owner() {
        let store = InMemoryOrgStore::new();
        let org_manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );
        let mem_manager = MembershipManager::new(store.clone(), UnlimitedSeats);

        let org = org_manager
            .create("owner", "Test Org", None, "owner@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await
            .unwrap();

        // Add a member
        mem_manager
            .add_member(&org.id, "member", "owner", |p| {
                make_membership(p, DefaultOrgRole::Member)
            })
            .await
            .unwrap();

        // Try to promote member to owner via update - should fail
        let result = mem_manager
            .update_membership(&org.id, "member", "owner", |m| TestMembership {
                role: DefaultOrgRole::Owner,
                ..m.clone()
            })
            .await;

        assert!(matches!(
            result.unwrap_err(),
            OrganizationError::InsufficientPermission { .. }
        ));
    }

    #[tokio::test]
    async fn test_transfer_ownership_requires_permission() {
        let store = InMemoryOrgStore::new();
        let org_manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );
        let mem_manager = MembershipManager::new(store.clone(), UnlimitedSeats);

        let org = org_manager
            .create("owner", "Test Org", None, "owner@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await
            .unwrap();

        // Add admin and member
        store.insert_membership(TestMembership {
            org_id: org.id.clone(),
            user_id: "admin".to_string(),
            role: DefaultOrgRole::Admin,
            joined_at: 0,
        });
        store.insert_membership(TestMembership {
            org_id: org.id.clone(),
            user_id: "member".to_string(),
            role: DefaultOrgRole::Member,
            joined_at: 0,
        });

        // Admin tries to transfer ownership - should fail
        let result = mem_manager
            .transfer_ownership(
                &org.id,
                "member",
                "admin",
                |m| TestMembership {
                    role: DefaultOrgRole::Owner,
                    ..m.clone()
                },
                |m| TestMembership {
                    role: DefaultOrgRole::Admin,
                    ..m.clone()
                },
            )
            .await;

        assert!(matches!(
            result.unwrap_err(),
            OrganizationError::InsufficientPermission { .. }
        ));
    }

    #[tokio::test]
    async fn test_transfer_ownership_target_must_be_member() {
        let store = InMemoryOrgStore::new();
        let org_manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );
        let mem_manager = MembershipManager::new(store.clone(), UnlimitedSeats);

        let org = org_manager
            .create("owner", "Test Org", None, "owner@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await
            .unwrap();

        // Try to transfer to non-member - should fail
        let result = mem_manager
            .transfer_ownership(
                &org.id,
                "non_member",
                "owner",
                |m| TestMembership {
                    role: DefaultOrgRole::Owner,
                    ..m.clone()
                },
                |m| TestMembership {
                    role: DefaultOrgRole::Admin,
                    ..m.clone()
                },
            )
            .await;

        assert!(matches!(result.unwrap_err(), OrganizationError::NotMember));
    }

    #[tokio::test]
    async fn test_leave_owner_cannot_leave() {
        let store = InMemoryOrgStore::new();
        let org_manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );
        let mem_manager = MembershipManager::new(store.clone(), UnlimitedSeats);

        let org = org_manager
            .create("owner", "Test Org", None, "owner@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await
            .unwrap();

        // Owner tries to leave - should fail
        let result = mem_manager.leave(&org.id, "owner").await;

        assert!(matches!(
            result.unwrap_err(),
            OrganizationError::CannotRemoveOwner
        ));
    }

    #[tokio::test]
    async fn test_member_can_leave() {
        let store = InMemoryOrgStore::new();
        let org_manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );
        let mem_manager = MembershipManager::new(store.clone(), UnlimitedSeats);

        let org = org_manager
            .create("owner", "Test Org", None, "owner@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await
            .unwrap();

        // Add a member
        mem_manager
            .add_member(&org.id, "member", "owner", |p| {
                make_membership(p, DefaultOrgRole::Member)
            })
            .await
            .unwrap();

        // Member leaves - should succeed
        mem_manager.leave(&org.id, "member").await.unwrap();
        assert!(!mem_manager.is_member(&org.id, "member").await.unwrap());
    }

    // =========================================================================
    // Invitation Manager Tests
    // =========================================================================

    #[tokio::test]
    async fn test_invite_requires_permission() {
        let store = InMemoryOrgStore::new();
        let org_manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );
        let inv_manager = InvitationManager::new(
            store.clone(),
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            InvitationConfig::default(),
        );

        let org = org_manager
            .create("owner", "Test Org", None, "owner@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await
            .unwrap();

        // Add a regular member
        store.insert_membership(TestMembership {
            org_id: org.id.clone(),
            user_id: "member".to_string(),
            role: DefaultOrgRole::Member,
            joined_at: 0,
        });

        // Member tries to invite - should fail
        let result = inv_manager
            .invite(&org.id, "invitee@example.com", "member", |p| TestInvitation {
                id: p.id,
                org_id: p.org_id,
                email: p.email,
                role: DefaultOrgRole::Member,
                invited_by: p.invited_by,
                token: p.token,
                expires_at: p.expires_at,
                created_at: p.created_at,
                accepted: false,
                revoked: false,
            })
            .await;

        assert!(matches!(
            result.unwrap_err(),
            OrganizationError::InsufficientPermission { .. }
        ));
    }

    #[tokio::test]
    async fn test_invite_invalid_email() {
        let store = InMemoryOrgStore::new();
        let org_manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );
        let inv_manager = InvitationManager::new(
            store.clone(),
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            InvitationConfig::default(),
        );

        let org = org_manager
            .create("owner", "Test Org", None, "owner@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await
            .unwrap();

        // Try to invite with invalid email
        let result = inv_manager
            .invite(&org.id, "not-an-email", "owner", |p| TestInvitation {
                id: p.id,
                org_id: p.org_id,
                email: p.email,
                role: DefaultOrgRole::Member,
                invited_by: p.invited_by,
                token: p.token,
                expires_at: p.expires_at,
                created_at: p.created_at,
                accepted: false,
                revoked: false,
            })
            .await;

        assert!(matches!(
            result.unwrap_err(),
            OrganizationError::InvalidEmail { .. }
        ));
    }

    #[tokio::test]
    async fn test_invite_max_pending_reached() {
        let store = InMemoryOrgStore::new();
        let org_manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );
        let inv_manager = InvitationManager::new(
            store.clone(),
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            InvitationConfig::default().max_pending_per_org(1),
        );

        let org = org_manager
            .create("owner", "Test Org", None, "owner@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await
            .unwrap();

        // First invitation
        inv_manager
            .invite(&org.id, "first@example.com", "owner", |p| TestInvitation {
                id: p.id,
                org_id: p.org_id,
                email: p.email,
                role: DefaultOrgRole::Member,
                invited_by: p.invited_by,
                token: p.token,
                expires_at: p.expires_at,
                created_at: p.created_at,
                accepted: false,
                revoked: false,
            })
            .await
            .unwrap();

        // Second invitation - should fail (max 1)
        let result = inv_manager
            .invite(&org.id, "second@example.com", "owner", |p| TestInvitation {
                id: p.id,
                org_id: p.org_id,
                email: p.email,
                role: DefaultOrgRole::Member,
                invited_by: p.invited_by,
                token: p.token,
                expires_at: p.expires_at,
                created_at: p.created_at,
                accepted: false,
                revoked: false,
            })
            .await;

        assert!(matches!(
            result.unwrap_err(),
            OrganizationError::MaxPendingInvitationsReached { .. }
        ));
    }

    #[tokio::test]
    async fn test_accept_expired_invitation() {
        let store = InMemoryOrgStore::new();
        let org_manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );
        let inv_manager = InvitationManager::new(
            store.clone(),
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            InvitationConfig::default(),
        );

        let org = org_manager
            .create("owner", "Test Org", None, "owner@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await
            .unwrap();

        // Insert an expired invitation directly
        store.insert_invitation(TestInvitation {
            id: "inv_1".to_string(),
            org_id: org.id.clone(),
            email: "invitee@example.com".to_string(),
            role: DefaultOrgRole::Member,
            invited_by: "owner".to_string(),
            token: "expired_token".to_string(),
            expires_at: 0, // Already expired
            created_at: 0,
            accepted: false,
            revoked: false,
        });

        // Try to accept expired invitation
        let result = inv_manager
            .accept("expired_token", "invitee", |inv, p| TestMembership {
                org_id: p.org_id,
                user_id: p.user_id,
                role: inv.role,
                joined_at: p.joined_at,
            })
            .await;

        assert!(matches!(
            result.unwrap_err(),
            OrganizationError::InvitationExpired
        ));
    }

    #[tokio::test]
    async fn test_accept_revoked_invitation() {
        let store = InMemoryOrgStore::new();
        let org_manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );
        let inv_manager = InvitationManager::new(
            store.clone(),
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            InvitationConfig::default(),
        );

        let org = org_manager
            .create("owner", "Test Org", None, "owner@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await
            .unwrap();

        // Insert a revoked invitation directly
        let future_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 86400; // Tomorrow

        store.insert_invitation(TestInvitation {
            id: "inv_1".to_string(),
            org_id: org.id.clone(),
            email: "invitee@example.com".to_string(),
            role: DefaultOrgRole::Member,
            invited_by: "owner".to_string(),
            token: "revoked_token".to_string(),
            expires_at: future_time,
            created_at: 0,
            accepted: false,
            revoked: true, // Revoked
        });

        // Try to accept revoked invitation
        let result = inv_manager
            .accept("revoked_token", "invitee", |inv, p| TestMembership {
                org_id: p.org_id,
                user_id: p.user_id,
                role: inv.role,
                joined_at: p.joined_at,
            })
            .await;

        assert!(matches!(
            result.unwrap_err(),
            OrganizationError::InvalidToken
        ));
    }

    #[tokio::test]
    async fn test_revoke_requires_permission() {
        let store = InMemoryOrgStore::new();
        let org_manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );
        let inv_manager = InvitationManager::new(
            store.clone(),
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            InvitationConfig::default(),
        );

        let org = org_manager
            .create("owner", "Test Org", None, "owner@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await
            .unwrap();

        // Create invitation
        let invitation = inv_manager
            .invite(&org.id, "invitee@example.com", "owner", |p| TestInvitation {
                id: p.id,
                org_id: p.org_id,
                email: p.email,
                role: DefaultOrgRole::Member,
                invited_by: p.invited_by,
                token: p.token,
                expires_at: p.expires_at,
                created_at: p.created_at,
                accepted: false,
                revoked: false,
            })
            .await
            .unwrap();

        // Add a regular member
        store.insert_membership(TestMembership {
            org_id: org.id.clone(),
            user_id: "member".to_string(),
            role: DefaultOrgRole::Member,
            joined_at: 0,
        });

        // Member tries to revoke - should fail
        let result = inv_manager.revoke(&invitation.id, "member").await;

        assert!(matches!(
            result.unwrap_err(),
            OrganizationError::InsufficientPermission { .. }
        ));
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let store = InMemoryOrgStore::new();
        let org_manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );
        let inv_manager = InvitationManager::new(
            store.clone(),
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            InvitationConfig::default(),
        );

        let org = org_manager
            .create("owner", "Test Org", None, "owner@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await
            .unwrap();

        // Insert expired invitations
        for i in 0..3 {
            store.insert_invitation(TestInvitation {
                id: format!("inv_{i}"),
                org_id: org.id.clone(),
                email: format!("user{i}@example.com"),
                role: DefaultOrgRole::Member,
                invited_by: "owner".to_string(),
                token: format!("token_{i}"),
                expires_at: 0, // Expired
                created_at: 0,
                accepted: false,
                revoked: false,
            });
        }

        // Cleanup
        let count = inv_manager.cleanup_expired().await.unwrap();
        assert_eq!(count, 3);

        // Verify they're gone
        let pending = inv_manager.list_pending(&org.id).await.unwrap();
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn test_successful_invitation_flow() {
        let store = InMemoryOrgStore::new();
        let org_manager = OrganizationManager::new(
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            OrganizationConfig::default(),
        );
        let inv_manager = InvitationManager::new(
            store.clone(),
            store.clone(),
            store.clone(),
            UnlimitedSeats,
            InvitationConfig::default(),
        );
        let mem_manager = MembershipManager::new(store.clone(), UnlimitedSeats);

        let org = org_manager
            .create("owner", "Test Org", None, "owner@example.com", make_org, |p| {
                make_membership(p, DefaultOrgRole::Owner)
            })
            .await
            .unwrap();

        // Create invitation
        let invitation = inv_manager
            .invite(&org.id, "invitee@example.com", "owner", |p| TestInvitation {
                id: p.id,
                org_id: p.org_id,
                email: p.email,
                role: DefaultOrgRole::Member,
                invited_by: p.invited_by,
                token: p.token,
                expires_at: p.expires_at,
                created_at: p.created_at,
                accepted: false,
                revoked: false,
            })
            .await
            .unwrap();

        // Accept invitation
        let membership = inv_manager
            .accept(&invitation.token, "invitee", |inv, p| TestMembership {
                org_id: p.org_id,
                user_id: p.user_id,
                role: inv.role,
                joined_at: p.joined_at,
            })
            .await
            .unwrap();

        assert_eq!(membership.role, DefaultOrgRole::Member);
        assert!(mem_manager.is_member(&org.id, "invitee").await.unwrap());
    }
}
