//! Ownership transfer with the SeaORM organization store against SQLite.
#![cfg(feature = "organizations-seaorm")]

use sea_orm::{ConnectionTrait, Database, DatabaseConnection};
use tideway::organizations::{
    DefaultOrgRole, MembershipStore, OrganizationConfig, OrganizationError, OrganizationManager,
    OrganizationStore, SeaOrmMembership, SeaOrmOrgStore,
};

async fn setup(
    max_orgs_per_user: Option<u32>,
) -> (
    SeaOrmOrgStore,
    OrganizationManager<SeaOrmOrgStore, SeaOrmOrgStore>,
) {
    let db: DatabaseConnection = Database::connect("sqlite::memory:").await.unwrap();
    db.execute_unprepared(
        r#"CREATE TABLE organizations (
               id VARCHAR(36) PRIMARY KEY,
               name VARCHAR(255) NOT NULL,
               slug VARCHAR(100) UNIQUE NOT NULL,
               owner_id VARCHAR(36) NOT NULL,
               contact_email VARCHAR(255) NOT NULL,
               created_at BIGINT NOT NULL,
               updated_at BIGINT NOT NULL
           );
           CREATE TABLE organization_members (
               org_id VARCHAR(36) NOT NULL,
               user_id VARCHAR(36) NOT NULL,
               role VARCHAR(20) NOT NULL,
               joined_at BIGINT NOT NULL,
               PRIMARY KEY (org_id, user_id),
               FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
           );"#,
    )
    .await
    .unwrap();

    let store = SeaOrmOrgStore::new(db);
    let manager = OrganizationManager::new_without_seats(
        store.clone(),
        store.clone(),
        OrganizationConfig::new().max_orgs_per_user(max_orgs_per_user),
    );
    (store, manager)
}

async fn add_member(store: &SeaOrmOrgStore, org_id: &str, user_id: &str) {
    store
        .add_member(&SeaOrmMembership {
            org_id: org_id.to_string(),
            user_id: user_id.to_string(),
            role: DefaultOrgRole::Member,
            joined_at: 0,
        })
        .await
        .unwrap();
}

async fn role_of(store: &SeaOrmOrgStore, org_id: &str, user_id: &str) -> Option<DefaultOrgRole> {
    store
        .get_membership(org_id, user_id)
        .await
        .unwrap()
        .map(|m| m.role)
}

#[tokio::test]
async fn transfer_ownership_atomic_updates_owner_and_memberships() {
    let (store, manager) = setup(Some(1)).await;
    let org = manager
        .create_atomic("owner", "Acme", None, "owner@example.com")
        .await
        .unwrap();
    add_member(&store, &org.id, "member").await;

    let updated = manager
        .transfer_ownership_atomic(&org.id, "member", "owner", DefaultOrgRole::Admin)
        .await
        .unwrap();

    assert_eq!(updated.owner_id, "member");
    assert_eq!(
        role_of(&store, &org.id, "member").await,
        Some(DefaultOrgRole::Owner)
    );
    assert_eq!(
        role_of(&store, &org.id, "owner").await,
        Some(DefaultOrgRole::Admin)
    );
    assert_eq!(store.count_owned_by_user("owner").await.unwrap(), 0);
    assert_eq!(store.count_owned_by_user("member").await.unwrap(), 1);

    // The former owner can create an organization again; the new owner is at the limit.
    manager
        .create_atomic("owner", "Second", None, "owner@example.com")
        .await
        .unwrap();
    let result = manager
        .create_atomic("member", "Third", None, "member@example.com")
        .await;
    assert!(matches!(
        result.unwrap_err(),
        OrganizationError::MaxOrgsReached { limit: 1 }
    ));
}

#[tokio::test]
async fn transfer_ownership_atomic_rejects_new_owner_at_org_limit() {
    let (store, manager) = setup(Some(1)).await;
    let org = manager
        .create_atomic("owner", "Acme", None, "owner@example.com")
        .await
        .unwrap();
    manager
        .create_atomic("member", "Member Org", None, "member@example.com")
        .await
        .unwrap();
    add_member(&store, &org.id, "member").await;

    let result = manager
        .transfer_ownership_atomic(&org.id, "member", "owner", DefaultOrgRole::Admin)
        .await;

    assert!(matches!(
        result.unwrap_err(),
        OrganizationError::MaxOrgsReached { limit: 1 }
    ));
    assert_eq!(
        manager.get_or_error(&org.id).await.unwrap().owner_id,
        "owner"
    );
    assert_eq!(
        role_of(&store, &org.id, "owner").await,
        Some(DefaultOrgRole::Owner)
    );
}

#[tokio::test]
async fn transfer_ownership_atomic_rolls_back_when_new_owner_is_missing() {
    let (store, manager) = setup(None).await;
    let org = manager
        .create_atomic("owner", "Acme", None, "owner@example.com")
        .await
        .unwrap();

    // Call the store directly: the manager would reject a non-member before writing.
    let result = store
        .transfer_ownership_atomic(&org.id, "owner", "ghost", DefaultOrgRole::Admin)
        .await;

    assert!(result.is_err());
    assert_eq!(
        manager.get_or_error(&org.id).await.unwrap().owner_id,
        "owner"
    );
    assert_eq!(
        role_of(&store, &org.id, "owner").await,
        Some(DefaultOrgRole::Owner)
    );
}

#[tokio::test]
async fn transfer_ownership_atomic_rejects_owner_as_former_owner_role() {
    let (store, manager) = setup(None).await;
    let org = manager
        .create_atomic("owner", "Acme", None, "owner@example.com")
        .await
        .unwrap();
    add_member(&store, &org.id, "member").await;

    let result = manager
        .transfer_ownership_atomic(&org.id, "member", "owner", DefaultOrgRole::Owner)
        .await;

    assert!(result.is_err());
    assert_eq!(
        manager.get_or_error(&org.id).await.unwrap().owner_id,
        "owner"
    );
    assert_eq!(
        role_of(&store, &org.id, "member").await,
        Some(DefaultOrgRole::Member)
    );
}

#[tokio::test]
async fn transfer_ownership_atomic_requires_owner() {
    let (store, manager) = setup(None).await;
    let org = manager
        .create_atomic("owner", "Acme", None, "owner@example.com")
        .await
        .unwrap();
    add_member(&store, &org.id, "member").await;

    let result = manager
        .transfer_ownership_atomic(&org.id, "member", "member", DefaultOrgRole::Admin)
        .await;

    assert!(matches!(
        result.unwrap_err(),
        OrganizationError::InsufficientPermission { .. }
    ));
}
