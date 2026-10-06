//! Checks that per-test PostgreSQL databases are dropped instead of leaking on the server.
#![cfg(feature = "database")]

use sea_orm::{ConnectionTrait, Database, DatabaseBackend, Statement};
use tideway::testing::TestDb;

fn admin_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_string())
}

async fn current_db_name(test_db: &TestDb) -> String {
    test_db
        .connection
        .query_one(Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT current_database() AS name",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get::<String>("", "name")
        .unwrap()
}

async fn database_exists(name: &str) -> bool {
    let admin = Database::connect(admin_url()).await.unwrap();
    let row = admin
        .query_one(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "SELECT 1 AS found FROM pg_database WHERE datname = $1",
            [name.into()],
        ))
        .await
        .unwrap();
    admin.close().await.unwrap();
    row.is_some()
}

#[tokio::test]
#[ignore = "requires PostgreSQL via TEST_DATABASE_URL"]
async fn cleanup_drops_the_postgres_test_database() {
    let test_db = TestDb::new_postgres().await.unwrap();
    let name = current_db_name(&test_db).await;
    assert!(database_exists(&name).await);

    test_db.cleanup().await.unwrap();
    assert!(!database_exists(&name).await);
}

#[tokio::test]
#[ignore = "requires PostgreSQL via TEST_DATABASE_URL"]
async fn drop_removes_the_postgres_test_database() {
    if std::env::var("TIDEWAY_TEST_KEEP_DBS").is_ok_and(|value| value == "1") {
        return;
    }
    let test_db = TestDb::new_postgres().await.unwrap();
    let name = current_db_name(&test_db).await;
    assert!(database_exists(&name).await);

    drop(test_db);
    assert!(!database_exists(&name).await);
}
