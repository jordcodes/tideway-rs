//! SeaORM organization store integrity under concurrent and stale writes.
#![cfg(feature = "organizations-seaorm")]

use sea_orm::{ConnectionTrait, Database, DatabaseConnection};
use tideway::organizations::{
    DefaultOrgRole, MembershipStore, OrganizationConfig, OrganizationError, OrganizationManager,
    OrganizationStore, SeaOrmMembership, SeaOrmOrgStore,
};

const SCHEMA: &str = r#"CREATE TABLE organizations (
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
   );"#;

async fn connect(url: &str) -> DatabaseConnection {
    let db = Database::connect(url).await.unwrap();
    db.execute_unprepared(SCHEMA).await.unwrap();
    db
}

fn manager(
    db: DatabaseConnection,
    max: Option<u32>,
) -> OrganizationManager<SeaOrmOrgStore, SeaOrmOrgStore> {
    let store = SeaOrmOrgStore::new(db);
    OrganizationManager::new_without_seats(
        store.clone(),
        store,
        OrganizationConfig::new().max_orgs_per_user(max),
    )
}

#[tokio::test]
async fn stale_updates_do_not_resurrect_removed_members_or_deleted_orgs() {
    let manager = manager(connect("sqlite::memory:").await, None);
    let store = manager.org_store().clone();
    let org = manager
        .create_atomic("owner", "Acme", Some("acme"), "billing@acme.test")
        .await
        .unwrap();
    store
        .add_member(&SeaOrmMembership {
            org_id: org.id.clone(),
            user_id: "admin".to_string(),
            role: DefaultOrgRole::Admin,
            joined_at: 0,
        })
        .await
        .unwrap();
    let stale_admin = store
        .get_membership(&org.id, "admin")
        .await
        .unwrap()
        .unwrap();

    // The owner removes the admin while the admin's own update is in flight.
    store.remove_member(&org.id, "admin").await.unwrap();
    assert!(store.update_membership(&stale_admin).await.is_err());
    assert!(
        store
            .update_memberships_atomic(&[stale_admin])
            .await
            .is_err()
    );
    assert!(
        store
            .get_membership(&org.id, "admin")
            .await
            .unwrap()
            .is_none()
    );

    // A stale organization write after deletion must not re-create the row.
    let stale_org = store.find_by_id(&org.id).await.unwrap().unwrap();
    store.delete(&org.id).await.unwrap();
    assert!(store.update(&stale_org).await.is_err());
    assert!(store.find_by_id(&org.id).await.unwrap().is_none());
    assert_eq!(store.count_owned_by_user("owner").await.unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_create_atomic_respects_max_orgs_per_user() {
    let path = std::env::temp_dir().join(format!("tideway-org-limit-{}.db", uuid::Uuid::new_v4()));
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let manager = std::sync::Arc::new(manager(connect(&url).await, Some(2)));

    let attempts = (0..10).map(|i| {
        let manager = manager.clone();
        tokio::spawn(async move {
            manager
                .create_atomic(
                    "owner",
                    &format!("Org {i}"),
                    Some(&format!("org-{i}")),
                    "a@b.test",
                )
                .await
        })
    });
    let results = futures::future::join_all(attempts).await;

    let created = results.iter().filter(|r| matches!(r, Ok(Ok(_)))).count();
    assert!(results.iter().all(|r| matches!(
        r,
        Ok(Ok(_)) | Ok(Err(OrganizationError::MaxOrgsReached { .. }))
    )));
    assert_eq!(created, 2);
    assert_eq!(
        manager
            .org_store()
            .count_owned_by_user("owner")
            .await
            .unwrap(),
        2
    );

    drop(manager);
    let _ = std::fs::remove_file(&path);
}
