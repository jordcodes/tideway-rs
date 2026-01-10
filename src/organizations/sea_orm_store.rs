//! SeaORM-backed organization storage.
//!
//! Provides production-ready database persistence for organizations, memberships,
//! and invitations using SeaORM.
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::organizations::SeaOrmOrgStore;
//! use sea_orm::DatabaseConnection;
//!
//! let org_store = SeaOrmOrgStore::new(db.clone());
//!
//! // Use with organization managers
//! let org_manager = OrganizationManager::new(
//!     org_store.clone(),
//!     org_store.clone(),
//!     UnlimitedSeats,
//!     OrganizationConfig::default(),
//! );
//! ```
//!
//! # Database Schema
//!
//! This store expects the following tables. You can create these using SeaORM migrations
//! or adapt them to your existing schema:
//!
//! ```sql
//! CREATE TABLE organizations (
//!     id VARCHAR(36) PRIMARY KEY,
//!     name VARCHAR(255) NOT NULL,
//!     slug VARCHAR(100) UNIQUE NOT NULL,
//!     owner_id VARCHAR(36) NOT NULL,
//!     contact_email VARCHAR(255) NOT NULL,
//!     created_at BIGINT NOT NULL,
//!     updated_at BIGINT NOT NULL
//! );
//!
//! CREATE INDEX idx_organizations_slug ON organizations(slug);
//! CREATE INDEX idx_organizations_owner ON organizations(owner_id);
//!
//! CREATE TABLE organization_members (
//!     org_id VARCHAR(36) NOT NULL,
//!     user_id VARCHAR(36) NOT NULL,
//!     role VARCHAR(20) NOT NULL,
//!     joined_at BIGINT NOT NULL,
//!     PRIMARY KEY (org_id, user_id),
//!     FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
//! );
//!
//! CREATE INDEX idx_members_user ON organization_members(user_id);
//!
//! CREATE TABLE organization_invitations (
//!     id VARCHAR(36) PRIMARY KEY,
//!     org_id VARCHAR(36) NOT NULL,
//!     email VARCHAR(255) NOT NULL,
//!     role VARCHAR(20) NOT NULL,
//!     invited_by VARCHAR(36) NOT NULL,
//!     token VARCHAR(64) UNIQUE NOT NULL,
//!     status VARCHAR(20) NOT NULL,
//!     expires_at BIGINT NOT NULL,
//!     created_at BIGINT NOT NULL,
//!     FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
//! );
//!
//! CREATE INDEX idx_invitations_token ON organization_invitations(token);
//! CREATE INDEX idx_invitations_org_email ON organization_invitations(org_id, email);
//! ```

use async_trait::async_trait;
use sea_orm::{
    entity::prelude::*, sea_query::OnConflict, ColumnTrait, DatabaseConnection, EntityTrait,
    QueryFilter, Set, TransactionTrait,
};
use std::str::FromStr;

use super::storage::{InvitationStore, MembershipStore, OrganizationStore};
use super::types::DefaultOrgRole;
use super::utils::current_timestamp;
use crate::error::Result;
use crate::TidewayError;

// =============================================================================
// SeaORM Entities
// =============================================================================

mod entity {
    use sea_orm::entity::prelude::*;

    // -------------------------------------------------------------------------
    // Organization Entity
    // -------------------------------------------------------------------------
    pub mod organization {
        use super::*;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
        #[sea_orm(table_name = "organizations")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub id: String,
            pub name: String,
            #[sea_orm(unique)]
            pub slug: String,
            pub owner_id: String,
            pub contact_email: String,
            pub created_at: i64,
            pub updated_at: i64,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}

        impl ActiveModelBehavior for ActiveModel {}
    }

    // -------------------------------------------------------------------------
    // Membership Entity
    // -------------------------------------------------------------------------
    pub mod membership {
        use super::*;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
        #[sea_orm(table_name = "organization_members")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub org_id: String,
            #[sea_orm(primary_key, auto_increment = false)]
            pub user_id: String,
            pub role: String,
            pub joined_at: i64,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}

        impl ActiveModelBehavior for ActiveModel {}
    }

    // -------------------------------------------------------------------------
    // Invitation Entity
    // -------------------------------------------------------------------------
    pub mod invitation {
        use super::*;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
        #[sea_orm(table_name = "organization_invitations")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub id: String,
            pub org_id: String,
            pub email: String,
            pub role: String,
            pub invited_by: String,
            #[sea_orm(unique)]
            pub token: String,
            pub status: String,
            pub expires_at: i64,
            pub created_at: i64,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}

        impl ActiveModelBehavior for ActiveModel {}
    }
}

use entity::{invitation, membership, organization};

// =============================================================================
// Exported Types
// =============================================================================

/// Organization record from the database.
///
/// This is the concrete type used by `SeaOrmOrgStore`.
/// If you need custom fields, implement the storage traits yourself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeaOrmOrganization {
    /// Unique identifier (UUID).
    pub id: String,
    /// Organization display name.
    pub name: String,
    /// URL-safe slug (unique).
    pub slug: String,
    /// Owner's user ID.
    pub owner_id: String,
    /// Contact/billing email.
    pub contact_email: String,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
    /// Last update timestamp (Unix seconds).
    pub updated_at: u64,
}

/// Membership record from the database.
///
/// This is the concrete type used by `SeaOrmOrgStore`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeaOrmMembership {
    /// Organization ID.
    pub org_id: String,
    /// User ID.
    pub user_id: String,
    /// Role in the organization.
    pub role: DefaultOrgRole,
    /// Join timestamp (Unix seconds).
    pub joined_at: u64,
}

/// Invitation record from the database.
///
/// This is the concrete type used by `SeaOrmOrgStore`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeaOrmInvitation {
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
    /// Status: "pending", "accepted", "revoked".
    pub status: InvitationStatus,
    /// Expiration timestamp (Unix seconds).
    pub expires_at: u64,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
}

/// Invitation status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum InvitationStatus {
    /// Invitation is pending acceptance.
    #[default]
    Pending,
    /// Invitation has been accepted.
    Accepted,
    /// Invitation has been revoked.
    Revoked,
}

impl InvitationStatus {
    /// Convert to string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Revoked => "revoked",
        }
    }
}

impl std::str::FromStr for InvitationStatus {
    type Err = std::convert::Infallible;

    /// Parse from string. Unknown values default to `Pending`.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "accepted" => Self::Accepted,
            "revoked" => Self::Revoked,
            _ => Self::Pending,
        })
    }
}

impl std::fmt::Display for InvitationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Convert i64 to u64 safely (negative values become 0).
#[inline]
fn i64_to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

/// Convert u64 to i64 safely (values > i64::MAX become i64::MAX).
#[inline]
fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Convert u64 to u32 safely (values > u32::MAX become u32::MAX).
#[inline]
fn saturating_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Convert organization model to exported type.
fn model_to_organization(model: organization::Model) -> SeaOrmOrganization {
    SeaOrmOrganization {
        id: model.id,
        name: model.name,
        slug: model.slug,
        owner_id: model.owner_id,
        contact_email: model.contact_email,
        created_at: i64_to_u64(model.created_at),
        updated_at: i64_to_u64(model.updated_at),
    }
}

/// Convert membership model to exported type.
fn model_to_membership(model: membership::Model) -> SeaOrmMembership {
    SeaOrmMembership {
        org_id: model.org_id,
        user_id: model.user_id,
        role: DefaultOrgRole::from_str(&model.role).unwrap_or(DefaultOrgRole::Member),
        joined_at: i64_to_u64(model.joined_at),
    }
}

/// Convert invitation model to exported type.
fn model_to_invitation(model: invitation::Model) -> SeaOrmInvitation {
    SeaOrmInvitation {
        id: model.id,
        org_id: model.org_id,
        email: model.email,
        role: DefaultOrgRole::from_str(&model.role).unwrap_or(DefaultOrgRole::Member),
        invited_by: model.invited_by,
        token: model.token,
        status: model.status.parse().unwrap_or_default(),
        expires_at: i64_to_u64(model.expires_at),
        created_at: i64_to_u64(model.created_at),
    }
}

// =============================================================================
// SeaOrmOrgStore
// =============================================================================

/// SeaORM-backed organization store implementing all storage traits.
///
/// Uses `DefaultOrgRole` for roles. If you need custom roles or additional
/// fields, implement the storage traits for your own store.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::organizations::{
///     SeaOrmOrgStore, OrganizationManager, OrganizationConfig, UnlimitedSeats,
/// };
/// use sea_orm::DatabaseConnection;
///
/// // Create from existing database connection
/// let org_store = SeaOrmOrgStore::new(db.clone());
///
/// // Use with organization managers
/// let org_manager = OrganizationManager::new(
///     org_store.clone(),
///     org_store.clone(),
///     UnlimitedSeats,
///     OrganizationConfig::default(),
/// );
///
/// // Create an organization
/// let org = org_manager.create(
///     "user_123",
///     "Acme Inc",
///     Some("acme"),
///     "billing@acme.com",
///     |p| SeaOrmOrganization {
///         id: p.id,
///         name: p.name,
///         slug: p.slug,
///         owner_id: p.owner_id,
///         contact_email: p.contact_email,
///         created_at: p.created_at,
///         updated_at: p.created_at,
///     },
///     |p| SeaOrmMembership {
///         org_id: p.org_id,
///         user_id: p.user_id,
///         role: DefaultOrgRole::Owner,
///         joined_at: p.joined_at,
///     },
/// ).await?;
/// ```
#[derive(Clone, Debug)]
pub struct SeaOrmOrgStore {
    db: DatabaseConnection,
}

impl SeaOrmOrgStore {
    /// Create a new SeaORM organization store.
    ///
    /// # Arguments
    ///
    /// * `db` - A SeaORM database connection
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Get a reference to the underlying database connection.
    #[must_use]
    pub fn connection(&self) -> &DatabaseConnection {
        &self.db
    }

    /// Create organization and initial owner membership atomically.
    ///
    /// This method uses a database transaction to ensure both the organization
    /// and the owner membership are created together or not at all.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let org = SeaOrmOrganization { /* ... */ };
    /// let membership = SeaOrmMembership { /* ... */ };
    ///
    /// store.create_org_and_member_atomic(&org, &membership).await?;
    /// ```
    pub async fn create_org_and_member_atomic(
        &self,
        org: &SeaOrmOrganization,
        membership: &SeaOrmMembership,
    ) -> Result<()> {
        tracing::debug!(
            org_id = %org.id,
            user_id = %membership.user_id,
            "creating organization and member atomically"
        );

        let txn = self
            .db
            .begin()
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        // Create organization
        let org_model = organization::ActiveModel {
            id: Set(org.id.clone()),
            name: Set(org.name.clone()),
            slug: Set(org.slug.clone()),
            owner_id: Set(org.owner_id.clone()),
            contact_email: Set(org.contact_email.clone()),
            created_at: Set(u64_to_i64(org.created_at)),
            updated_at: Set(u64_to_i64(org.updated_at)),
        };

        organization::Entity::insert(org_model)
            .exec(&txn)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        // Create membership
        let member_model = membership::ActiveModel {
            org_id: Set(membership.org_id.clone()),
            user_id: Set(membership.user_id.clone()),
            role: Set(membership.role.as_str().to_string()),
            joined_at: Set(u64_to_i64(membership.joined_at)),
        };

        membership::Entity::insert(member_model)
            .exec(&txn)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        tracing::info!(
            org_id = %org.id,
            owner_id = %membership.user_id,
            "organization and owner created atomically"
        );

        Ok(())
    }
}

// =============================================================================
// OrganizationStore Implementation
// =============================================================================

#[async_trait]
impl OrganizationStore for SeaOrmOrgStore {
    type Organization = SeaOrmOrganization;

    async fn create(&self, org: &Self::Organization) -> Result<()> {
        tracing::debug!(org_id = %org.id, slug = %org.slug, "creating organization");

        let model = organization::ActiveModel {
            id: Set(org.id.clone()),
            name: Set(org.name.clone()),
            slug: Set(org.slug.clone()),
            owner_id: Set(org.owner_id.clone()),
            contact_email: Set(org.contact_email.clone()),
            created_at: Set(u64_to_i64(org.created_at)),
            updated_at: Set(u64_to_i64(org.updated_at)),
        };

        organization::Entity::insert(model)
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<Self::Organization>> {
        tracing::debug!(org_id = %id, "finding organization by id");

        let org = organization::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(org.map(model_to_organization))
    }

    async fn find_by_slug(&self, slug: &str) -> Result<Option<Self::Organization>> {
        tracing::debug!(slug = %slug, "finding organization by slug");

        let org = organization::Entity::find()
            .filter(organization::Column::Slug.eq(slug))
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(org.map(model_to_organization))
    }

    async fn update(&self, org: &Self::Organization) -> Result<()> {
        tracing::debug!(org_id = %org.id, "updating organization");

        let model = organization::ActiveModel {
            id: Set(org.id.clone()),
            name: Set(org.name.clone()),
            slug: Set(org.slug.clone()),
            owner_id: Set(org.owner_id.clone()),
            contact_email: Set(org.contact_email.clone()),
            created_at: Set(u64_to_i64(org.created_at)),
            updated_at: Set(u64_to_i64(org.updated_at)),
        };

        // Use upsert to handle both insert and update
        organization::Entity::insert(model)
            .on_conflict(
                OnConflict::column(organization::Column::Id)
                    .update_columns([
                        organization::Column::Name,
                        organization::Column::Slug,
                        organization::Column::OwnerId,
                        organization::Column::ContactEmail,
                        organization::Column::UpdatedAt,
                    ])
                    .to_owned(),
            )
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        tracing::debug!(org_id = %id, "deleting organization");

        organization::Entity::delete_by_id(id)
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

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
        tracing::debug!(user_id = %user_id, "listing organizations for user");

        // Get org IDs from memberships, then load orgs
        let memberships = membership::Entity::find()
            .filter(membership::Column::UserId.eq(user_id))
            .all(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        if memberships.is_empty() {
            return Ok(vec![]);
        }

        let org_ids: Vec<String> = memberships.into_iter().map(|m| m.org_id).collect();

        let orgs = organization::Entity::find()
            .filter(organization::Column::Id.is_in(org_ids))
            .all(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(orgs.into_iter().map(model_to_organization).collect())
    }

    async fn count_owned_by_user(&self, user_id: &str) -> Result<u32> {
        tracing::debug!(user_id = %user_id, "counting organizations owned by user");

        let count = organization::Entity::find()
            .filter(organization::Column::OwnerId.eq(user_id))
            .count(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(saturating_u32(count))
    }
}

// =============================================================================
// MembershipStore Implementation
// =============================================================================

#[async_trait]
impl MembershipStore for SeaOrmOrgStore {
    type Membership = SeaOrmMembership;
    type Role = DefaultOrgRole;

    async fn add_member(&self, m: &Self::Membership) -> Result<()> {
        tracing::debug!(
            org_id = %m.org_id,
            user_id = %m.user_id,
            role = %m.role.as_str(),
            "adding member"
        );

        let model = membership::ActiveModel {
            org_id: Set(m.org_id.clone()),
            user_id: Set(m.user_id.clone()),
            role: Set(m.role.as_str().to_string()),
            joined_at: Set(u64_to_i64(m.joined_at)),
        };

        membership::Entity::insert(model)
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    async fn remove_member(&self, org_id: &str, user_id: &str) -> Result<()> {
        tracing::debug!(org_id = %org_id, user_id = %user_id, "removing member");

        membership::Entity::delete_many()
            .filter(membership::Column::OrgId.eq(org_id))
            .filter(membership::Column::UserId.eq(user_id))
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    async fn get_membership(&self, org_id: &str, user_id: &str) -> Result<Option<Self::Membership>> {
        tracing::debug!(org_id = %org_id, user_id = %user_id, "getting membership");

        let m = membership::Entity::find()
            .filter(membership::Column::OrgId.eq(org_id))
            .filter(membership::Column::UserId.eq(user_id))
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(m.map(model_to_membership))
    }

    async fn list_members(&self, org_id: &str) -> Result<Vec<Self::Membership>> {
        tracing::debug!(org_id = %org_id, "listing members");

        let members = membership::Entity::find()
            .filter(membership::Column::OrgId.eq(org_id))
            .all(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(members.into_iter().map(model_to_membership).collect())
    }

    async fn update_membership(&self, m: &Self::Membership) -> Result<()> {
        tracing::debug!(
            org_id = %m.org_id,
            user_id = %m.user_id,
            role = %m.role.as_str(),
            "updating membership"
        );

        let model = membership::ActiveModel {
            org_id: Set(m.org_id.clone()),
            user_id: Set(m.user_id.clone()),
            role: Set(m.role.as_str().to_string()),
            joined_at: Set(u64_to_i64(m.joined_at)),
        };

        // Use upsert
        membership::Entity::insert(model)
            .on_conflict(
                OnConflict::columns([membership::Column::OrgId, membership::Column::UserId])
                    .update_columns([membership::Column::Role])
                    .to_owned(),
            )
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

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

    async fn count_members(&self, org_id: &str) -> Result<u32> {
        tracing::debug!(org_id = %org_id, "counting members");

        let count = membership::Entity::find()
            .filter(membership::Column::OrgId.eq(org_id))
            .count(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(saturating_u32(count))
    }

    async fn list_user_memberships(&self, user_id: &str) -> Result<Vec<Self::Membership>> {
        tracing::debug!(user_id = %user_id, "listing user memberships");

        let members = membership::Entity::find()
            .filter(membership::Column::UserId.eq(user_id))
            .all(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(members.into_iter().map(model_to_membership).collect())
    }

    async fn update_memberships_atomic(&self, memberships: &[Self::Membership]) -> Result<()> {
        if memberships.is_empty() {
            return Ok(());
        }

        tracing::debug!(count = memberships.len(), "updating memberships atomically");

        let txn = self
            .db
            .begin()
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        for m in memberships {
            let model = membership::ActiveModel {
                org_id: Set(m.org_id.clone()),
                user_id: Set(m.user_id.clone()),
                role: Set(m.role.as_str().to_string()),
                joined_at: Set(u64_to_i64(m.joined_at)),
            };

            membership::Entity::insert(model)
                .on_conflict(
                    OnConflict::columns([membership::Column::OrgId, membership::Column::UserId])
                        .update_columns([membership::Column::Role])
                        .to_owned(),
                )
                .exec(&txn)
                .await
                .map_err(|e| TidewayError::Database(e.to_string()))?;
        }

        txn.commit()
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        tracing::debug!(count = memberships.len(), "memberships updated atomically");

        Ok(())
    }
}

// =============================================================================
// InvitationStore Implementation
// =============================================================================

#[async_trait]
impl InvitationStore for SeaOrmOrgStore {
    type Invitation = SeaOrmInvitation;
    type Role = DefaultOrgRole;

    async fn create(&self, inv: &Self::Invitation) -> Result<()> {
        tracing::debug!(
            invitation_id = %inv.id,
            org_id = %inv.org_id,
            email = %inv.email,
            "creating invitation"
        );

        let model = invitation::ActiveModel {
            id: Set(inv.id.clone()),
            org_id: Set(inv.org_id.clone()),
            email: Set(inv.email.clone()),
            role: Set(inv.role.as_str().to_string()),
            invited_by: Set(inv.invited_by.clone()),
            token: Set(inv.token.clone()),
            status: Set(inv.status.as_str().to_string()),
            expires_at: Set(u64_to_i64(inv.expires_at)),
            created_at: Set(u64_to_i64(inv.created_at)),
        };

        invitation::Entity::insert(model)
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    async fn find_by_token(&self, token: &str) -> Result<Option<Self::Invitation>> {
        tracing::debug!("finding invitation by token");

        let inv = invitation::Entity::find()
            .filter(invitation::Column::Token.eq(token))
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(inv.map(model_to_invitation))
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<Self::Invitation>> {
        tracing::debug!(invitation_id = %id, "finding invitation by id");

        let inv = invitation::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(inv.map(model_to_invitation))
    }

    async fn list_pending(&self, org_id: &str) -> Result<Vec<Self::Invitation>> {
        tracing::debug!(org_id = %org_id, "listing pending invitations");

        let now = u64_to_i64(current_timestamp());

        let invitations = invitation::Entity::find()
            .filter(invitation::Column::OrgId.eq(org_id))
            .filter(invitation::Column::Status.eq("pending"))
            .filter(invitation::Column::ExpiresAt.gt(now))
            .all(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(invitations.into_iter().map(model_to_invitation).collect())
    }

    async fn mark_accepted(&self, id: &str) -> Result<()> {
        tracing::debug!(invitation_id = %id, "marking invitation as accepted");

        invitation::Entity::update_many()
            .col_expr(invitation::Column::Status, Expr::value("accepted"))
            .filter(invitation::Column::Id.eq(id))
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    async fn mark_revoked(&self, id: &str) -> Result<()> {
        tracing::debug!(invitation_id = %id, "marking invitation as revoked");

        invitation::Entity::update_many()
            .col_expr(invitation::Column::Status, Expr::value("revoked"))
            .filter(invitation::Column::Id.eq(id))
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    async fn delete_expired(&self) -> Result<usize> {
        tracing::debug!("deleting expired invitations");

        let now = u64_to_i64(current_timestamp());

        let result = invitation::Entity::delete_many()
            .filter(invitation::Column::Status.eq("pending"))
            .filter(invitation::Column::ExpiresAt.lte(now))
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        let count = result.rows_affected as usize;
        if count > 0 {
            tracing::info!(count, "deleted expired invitations");
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
        inv.expires_at <= current_timestamp()
    }

    async fn find_pending_by_email(
        &self,
        org_id: &str,
        email: &str,
    ) -> Result<Option<Self::Invitation>> {
        tracing::debug!(org_id = %org_id, email = %email, "finding pending invitation by email");

        let now = u64_to_i64(current_timestamp());

        let inv = invitation::Entity::find()
            .filter(invitation::Column::OrgId.eq(org_id))
            .filter(invitation::Column::Email.eq(email))
            .filter(invitation::Column::Status.eq("pending"))
            .filter(invitation::Column::ExpiresAt.gt(now))
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(inv.map(model_to_invitation))
    }

    async fn count_pending(&self, org_id: &str) -> Result<u32> {
        tracing::debug!(org_id = %org_id, "counting pending invitations");

        let now = u64_to_i64(current_timestamp());

        let count = invitation::Entity::find()
            .filter(invitation::Column::OrgId.eq(org_id))
            .filter(invitation::Column::Status.eq("pending"))
            .filter(invitation::Column::ExpiresAt.gt(now))
            .count(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(saturating_u32(count))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invitation_status_roundtrip() {
        assert_eq!(InvitationStatus::Pending.as_str(), "pending");
        assert_eq!(InvitationStatus::Accepted.as_str(), "accepted");
        assert_eq!(InvitationStatus::Revoked.as_str(), "revoked");

        assert_eq!("pending".parse::<InvitationStatus>().unwrap(), InvitationStatus::Pending);
        assert_eq!("accepted".parse::<InvitationStatus>().unwrap(), InvitationStatus::Accepted);
        assert_eq!("revoked".parse::<InvitationStatus>().unwrap(), InvitationStatus::Revoked);
        assert_eq!("unknown".parse::<InvitationStatus>().unwrap(), InvitationStatus::Pending);
        // Case insensitive
        assert_eq!("ACCEPTED".parse::<InvitationStatus>().unwrap(), InvitationStatus::Accepted);
    }

    #[test]
    fn test_safe_integer_conversions() {
        // i64 to u64: negative becomes 0
        assert_eq!(i64_to_u64(100), 100);
        assert_eq!(i64_to_u64(0), 0);
        assert_eq!(i64_to_u64(-1), 0);
        assert_eq!(i64_to_u64(i64::MIN), 0);
        assert_eq!(i64_to_u64(i64::MAX), i64::MAX as u64);

        // u64 to i64: values > i64::MAX become i64::MAX
        assert_eq!(u64_to_i64(100), 100);
        assert_eq!(u64_to_i64(0), 0);
        assert_eq!(u64_to_i64(i64::MAX as u64), i64::MAX);
        assert_eq!(u64_to_i64(u64::MAX), i64::MAX);

        // u64 to u32: values > u32::MAX become u32::MAX
        assert_eq!(saturating_u32(100), 100);
        assert_eq!(saturating_u32(0), 0);
        assert_eq!(saturating_u32(u32::MAX as u64), u32::MAX);
        assert_eq!(saturating_u32(u64::MAX), u32::MAX);
    }

    #[test]
    fn test_model_to_organization() {
        let model = organization::Model {
            id: "org_123".to_string(),
            name: "Test Org".to_string(),
            slug: "test-org".to_string(),
            owner_id: "user_456".to_string(),
            contact_email: "test@example.com".to_string(),
            created_at: 1700000000,
            updated_at: 1700000100,
        };

        let org = model_to_organization(model);

        assert_eq!(org.id, "org_123");
        assert_eq!(org.name, "Test Org");
        assert_eq!(org.slug, "test-org");
        assert_eq!(org.owner_id, "user_456");
        assert_eq!(org.contact_email, "test@example.com");
        assert_eq!(org.created_at, 1700000000);
        assert_eq!(org.updated_at, 1700000100);
    }

    #[test]
    fn test_model_to_membership() {
        let model = membership::Model {
            org_id: "org_123".to_string(),
            user_id: "user_456".to_string(),
            role: "admin".to_string(),
            joined_at: 1700000000,
        };

        let m = model_to_membership(model);

        assert_eq!(m.org_id, "org_123");
        assert_eq!(m.user_id, "user_456");
        assert_eq!(m.role, DefaultOrgRole::Admin);
        assert_eq!(m.joined_at, 1700000000);
    }

    #[test]
    fn test_model_to_invitation() {
        let model = invitation::Model {
            id: "inv_123".to_string(),
            org_id: "org_456".to_string(),
            email: "new@example.com".to_string(),
            role: "member".to_string(),
            invited_by: "user_789".to_string(),
            token: "secret_token".to_string(),
            status: "pending".to_string(),
            expires_at: 1700100000,
            created_at: 1700000000,
        };

        let inv = model_to_invitation(model);

        assert_eq!(inv.id, "inv_123");
        assert_eq!(inv.org_id, "org_456");
        assert_eq!(inv.email, "new@example.com");
        assert_eq!(inv.role, DefaultOrgRole::Member);
        assert_eq!(inv.invited_by, "user_789");
        assert_eq!(inv.token, "secret_token");
        assert_eq!(inv.status, InvitationStatus::Pending);
        assert_eq!(inv.expires_at, 1700100000);
        assert_eq!(inv.created_at, 1700000000);
    }
}
