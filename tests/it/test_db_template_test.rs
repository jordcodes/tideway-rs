//! Checks that PostgreSQL test databases are copied from a migrated template, and that databases
//! left behind by dead test processes are swept.
#![cfg(feature = "database")]

use crate::support;
use sea_orm::{ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Statement};
use sea_orm_migration::prelude::*;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tideway::testing::TestDb;
use tokio::sync::{Mutex, OnceCell};

const KEEP_DBS_ENV: &str = "TIDEWAY_TEST_KEEP_DBS";

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
static MIGRATION_RUNS: [AtomicUsize; 6] = [const { AtomicUsize::new(0) }; 6];

/// Held by tests that sweep, or whose child process does, so one sweep can't remove another
/// test's orphan fixtures.
static SWEEP_LOCK: Mutex<()> = Mutex::const_new(());

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
    let _sweeping = SWEEP_LOCK.lock().await;
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

/// Databases that look left behind by a dead test process: a test database, a stale template
/// for another migration list, and a half-built template.
struct OrphanFixtures {
    names: [String; 3],
}

impl OrphanFixtures {
    async fn create() -> Self {
        let mut exited = std::process::Command::new("true").spawn().unwrap();
        let dead_pid = exited.id();
        exited.wait().unwrap();
        let hash = format!("{:016x}", *RUN_ID as u64);
        let names = [
            format!("test_db_{dead_pid}_0"),
            format!("test_tpl_{hash}"),
            format!("test_tpl_{hash}_{dead_pid}"),
        ];
        for name in &names {
            execute_admin(&format!("CREATE DATABASE \"{name}\"")).await;
        }
        Self { names }
    }

    async fn drop_all(&self) {
        for name in &self.names {
            execute_admin(&format!("DROP DATABASE IF EXISTS \"{name}\"")).await;
        }
    }
}

/// Run a sweep test alone in a child process, so it starts with no sweep done yet and its
/// `TIDEWAY_TEST_KEEP_DBS` setting can't leak. Returns `true` in the parent once the child passed.
async fn run_sweep_child(test: &str, keep_dbs: Option<&str>) -> bool {
    // In the child, skip the parent-side setup below: creating a TestDb here would run the
    // child's sweep before the test creates its fixtures.
    if std::env::var("IT_CHILD_TEST").is_ok() {
        return support::isolated(module_path!(), test, |_| {});
    }
    let _sweeping = SWEEP_LOCK.lock().await;
    // Finish this process's own once-per-process sweeps first, so they can't remove the
    // child's fixtures while it runs.
    static PARENT_SWEPT: OnceCell<()> = OnceCell::const_new();
    PARENT_SWEPT
        .get_or_init(|| async {
            type Migrator = CountingMigrator<5>;
            TestDb::new_postgres_with_migrator::<Migrator>()
                .await
                .unwrap()
                .cleanup()
                .await
                .unwrap();
            let template = TestDb::postgres_template_name::<Migrator>();
            execute_admin(&format!("DROP DATABASE \"{template}\"")).await;
        })
        .await;
    support::isolated(module_path!(), test, |command| {
        command.arg("--include-ignored");
        match keep_dbs {
            Some(value) => command.env(KEEP_DBS_ENV, value),
            None => command.env_remove(KEEP_DBS_ENV),
        };
    })
}

#[tokio::test]
#[ignore = "requires PostgreSQL via TEST_DATABASE_URL"]
async fn first_test_database_sweeps_orphans_automatically() {
    if run_sweep_child("first_test_database_sweeps_orphans_automatically", None).await {
        return;
    }
    type Migrator = CountingMigrator<3>;
    let orphans = OrphanFixtures::create().await;

    let test_db = TestDb::new_postgres_with_migrator::<Migrator>()
        .await
        .unwrap();

    for name in &orphans.names {
        assert!(!database_exists(name).await, "{name} should be swept");
    }
    assert!(has_widgets_table(&test_db).await);
    test_db.cleanup().await.unwrap();
    let template = TestDb::postgres_template_name::<Migrator>();
    execute_admin(&format!("DROP DATABASE \"{template}\"")).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL via TEST_DATABASE_URL"]
async fn keep_dbs_skips_the_sweep_and_keeps_dropped_test_databases() {
    if run_sweep_child(
        "keep_dbs_skips_the_sweep_and_keeps_dropped_test_databases",
        Some("1"),
    )
    .await
    {
        return;
    }
    type Migrator = CountingMigrator<4>;
    let orphans = OrphanFixtures::create().await;

    let test_db = TestDb::new_postgres_with_migrator::<Migrator>()
        .await
        .unwrap();
    let name = test_db
        .connection
        .query_one(Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT current_database() AS name",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get::<String>("", "name")
        .unwrap();
    drop(test_db);

    for orphan in &orphans.names {
        assert!(database_exists(orphan).await, "{orphan} should be kept");
    }
    assert!(database_exists(&name).await, "{name} should be kept");
    let template = TestDb::postgres_template_name::<Migrator>();
    assert!(database_exists(&template).await);

    orphans.drop_all().await;
    execute_admin(&format!("DROP DATABASE \"{name}\" WITH (FORCE)")).await;
    execute_admin(&format!("DROP DATABASE \"{template}\"")).await;
}
