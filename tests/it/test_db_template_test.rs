//! Checks that PostgreSQL test databases are copied from a migrated template, and that databases
//! left behind by dead test processes are swept.
#![cfg(feature = "database")]

use sea_orm::{ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Statement};
use sea_orm_migration::prelude::*;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tideway::testing::TestDb;

fn admin_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_string())
}

/// Unique per run, so each run gets fresh templates and counts migrations from zero.
static RUN_ID: LazyLock<u128> = LazyLock::new(|| {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
});

/// How many times each test's migration has run in this process.
static MIGRATION_RUNS: [AtomicUsize; 3] = [const { AtomicUsize::new(0) }; 3];

/// A one-migration migrator per test, so tests don't share templates or counters.
struct CountingMigrator<const N: usize>;

struct CountingMigration<const N: usize> {
    name: String,
}

impl<const N: usize> MigrationName for CountingMigration<N> {
    fn name(&self) -> &str {
        &self.name
    }
}

#[async_trait::async_trait]
impl<const N: usize> MigrationTrait for CountingMigration<N> {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        MIGRATION_RUNS[N].fetch_add(1, Ordering::SeqCst);
        manager
            .get_connection()
            .execute_unprepared("CREATE TABLE widgets (id SERIAL PRIMARY KEY)")
            .await
            .map(|_| ())
    }
}

impl<const N: usize> MigratorTrait for CountingMigrator<N> {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(CountingMigration::<N> {
            name: format!("m_template_test_{N}_{}", *RUN_ID),
        })]
    }
}

async fn admin() -> DatabaseConnection {
    Database::connect(admin_url()).await.unwrap()
}

async fn database_exists(name: &str) -> bool {
    let admin = admin().await;
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

async fn execute_admin(sql: &str) {
    let admin = admin().await;
    admin.execute_unprepared(sql).await.unwrap();
    admin.close().await.unwrap();
}

async fn has_widgets_table(test_db: &TestDb) -> bool {
    test_db
        .connection
        .query_one(Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT to_regclass('public.widgets') IS NOT NULL AS found",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get::<bool>("", "found")
        .unwrap()
}

#[tokio::test]
#[ignore = "requires PostgreSQL via TEST_DATABASE_URL"]
async fn second_database_is_copied_from_the_template_without_migrating() {
    type Migrator = CountingMigrator<0>;
    let template = TestDb::postgres_template_name::<Migrator>();

    let first = TestDb::new_postgres_with_migrator::<Migrator>()
        .await
        .unwrap();
    assert_eq!(MIGRATION_RUNS[0].load(Ordering::SeqCst), 1);
    assert!(database_exists(&template).await);

    let second = TestDb::new_postgres_with_migrator::<Migrator>()
        .await
        .unwrap();
    assert_eq!(MIGRATION_RUNS[0].load(Ordering::SeqCst), 1);
    assert!(has_widgets_table(&first).await);
    assert!(has_widgets_table(&second).await);

    first.cleanup().await.unwrap();
    second.cleanup().await.unwrap();
    execute_admin(&format!("DROP DATABASE \"{template}\"")).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL via TEST_DATABASE_URL"]
async fn falls_back_to_migrating_when_the_template_cannot_be_copied() {
    type Migrator = CountingMigrator<1>;
    let template = TestDb::postgres_template_name::<Migrator>();

    let first = TestDb::new_postgres_with_migrator::<Migrator>()
        .await
        .unwrap();
    assert_eq!(MIGRATION_RUNS[1].load(Ordering::SeqCst), 1);

    // PostgreSQL refuses to copy a template that has open connections.
    let mut template_url = url::Url::parse(&admin_url()).unwrap();
    template_url.set_path(&format!("/{template}"));
    let blocker = Database::connect(template_url.as_str()).await.unwrap();
    blocker.execute_unprepared("SELECT 1").await.unwrap();

    let second = TestDb::new_postgres_with_migrator::<Migrator>()
        .await
        .unwrap();
    assert_eq!(MIGRATION_RUNS[1].load(Ordering::SeqCst), 2);
    assert!(has_widgets_table(&second).await);

    blocker.close().await.unwrap();
    first.cleanup().await.unwrap();
    second.cleanup().await.unwrap();
    execute_admin(&format!(
        "DROP DATABASE IF EXISTS \"{template}\" WITH (FORCE)"
    ))
    .await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL via TEST_DATABASE_URL"]
async fn sweep_drops_databases_of_dead_processes_and_keeps_live_ones() {
    type Migrator = CountingMigrator<2>;
    let current_template = TestDb::postgres_template_name::<Migrator>();
    let own_db = TestDb::new_postgres_with_migrator::<Migrator>()
        .await
        .unwrap();

    let mut exited = std::process::Command::new("true").spawn().unwrap();
    let dead_pid = exited.id();
    exited.wait().unwrap();
    let mut running = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .unwrap();
    let live_pid = running.id();

    let dead_db = format!("test_db_{dead_pid}_0");
    let live_db = format!("test_db_{live_pid}_0");
    let stale_template = format!("test_tpl_{:016x}", *RUN_ID as u64);
    let stale_build = format!("test_tpl_{:016x}_{dead_pid}", *RUN_ID as u64);
    for name in [&dead_db, &live_db, &stale_template, &stale_build] {
        execute_admin(&format!("CREATE DATABASE \"{name}\"")).await;
    }

    let dropped = TestDb::sweep_orphaned_postgres_databases(&admin_url())
        .await
        .unwrap();

    for name in [&dead_db, &stale_template, &stale_build] {
        assert!(
            dropped.contains(name),
            "{name} should be swept: {dropped:?}"
        );
        assert!(!database_exists(name).await, "{name} should be gone");
    }
    for name in [&live_db, &current_template] {
        assert!(!dropped.contains(name), "{name} should be kept");
        assert!(database_exists(name).await, "{name} should still exist");
    }
    assert!(has_widgets_table(&own_db).await);

    running.kill().unwrap();
    running.wait().unwrap();
    execute_admin(&format!("DROP DATABASE \"{live_db}\"")).await;
    own_db.cleanup().await.unwrap();
    execute_admin(&format!("DROP DATABASE \"{current_template}\"")).await;
}
