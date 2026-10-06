//! Database testing utilities
//!
//! This module provides helpers for setting up test databases with SQLite in-memory
//! or PostgreSQL (requires PostgreSQL running on localhost:5432), running migrations,
//! and seeding test data.
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::testing::TestDb;
//! use sea_orm_migration::MigratorTrait;
//!
//! // Your app's migrator
//! struct MyMigrator;
//! impl MigratorTrait for MyMigrator {
//!     fn migrations() -> Vec<Box<dyn sea_orm_migration::MigrationTrait>> {
//!         vec![]
//!     }
//! }
//!
//! #[tokio::test]
//! async fn test_with_database() {
//!     let test_db = TestDb::new_with_migrator::<MyMigrator>()
//!         .await
//!         .expect("Failed to create test database");
//!
//!     // Use test_db.connection in your tests
//! }
//! ```

use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbErr, Statement};
use sea_orm_migration::MigratorTrait;
#[cfg(feature = "test-containers")]
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use url::Url;

#[cfg(feature = "test-containers")]
mod postgres_container;

static TEST_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Set to `1` to keep per-test PostgreSQL databases instead of dropping them.
const KEEP_DBS_ENV: &str = "TIDEWAY_TEST_KEEP_DBS";

/// Supported test database backends.
#[derive(Debug, Clone, Copy, Default)]
pub enum TestDbBackend {
    /// Fast, in-memory sqlite. Default behavior.
    #[default]
    SqliteMemory,
    /// A PostgreSQL database created from `TEST_DATABASE_URL`.
    Postgres,
    /// A temporary PostgreSQL container for end-to-end integration parity.
    #[cfg(feature = "test-containers")]
    PostgresContainer,
}

/// Options for constructing a `TestDb`.
#[derive(Debug, Default)]
pub struct TestDbConfig {
    pub backend: TestDbBackend,
    pub database_url: Option<String>,
}

/// Manages a test database connection
///
/// Supports both SQLite in-memory (fast, no external dependencies) and PostgreSQL
/// (requires PostgreSQL running on localhost:5432, matches production better).
///
/// **Note on PostgreSQL cleanup**: Each `Postgres`-backend `TestDb` creates its own
/// `test_db_<pid>_<n>` database on the server. Call [`TestDb::cleanup`] to drop it
/// explicitly; otherwise `Drop` makes a best-effort, blocking drop on a separate
/// thread. Set `TIDEWAY_TEST_KEEP_DBS=1` to keep the databases for inspection.
pub struct TestDb {
    pub connection: DatabaseConnection,
    backend: TestDbBackend,
    /// The per-test database to drop, for the `Postgres` backend only.
    postgres: Option<PostgresTestDatabase>,
    #[cfg(feature = "test-containers")]
    #[allow(dead_code)]
    container: Option<Arc<postgres_container::PostgresContainer>>,
}

impl TestDb {
    /// Create a new test database with explicit options.
    pub async fn new_with_config(config: TestDbConfig) -> Result<Self, DbErr> {
        match config.backend {
            TestDbBackend::SqliteMemory => Self::new().await,
            TestDbBackend::Postgres => {
                if let Some(url) = config.database_url {
                    Self::create_postgres_db_from_base_url(&url).await
                } else {
                    Self::new_postgres().await
                }
            }
            #[cfg(feature = "test-containers")]
            TestDbBackend::PostgresContainer => Self::new_postgres_container().await,
        }
    }

    /// Create a new sqlite-memory test database without migrations.
    pub async fn new_with_sqlite() -> Result<Self, DbErr> {
        Self::new().await
    }

    /// Create a new PostgreSQL test database without migrations.
    pub async fn new_with_postgres_url(database_url: &str) -> Result<Self, DbErr> {
        Self::create_postgres_db_from_base_url(database_url).await
    }

    /// Create a new test database with SQLite in-memory and run migrations
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use tideway::testing::TestDb;
    /// use sea_orm_migration::MigratorTrait;
    ///
    /// struct MyMigrator;
    /// impl MigratorTrait for MyMigrator {
    ///     fn migrations() -> Vec<Box<dyn sea_orm_migration::MigrationTrait>> {
    ///         vec![]
    ///     }
    /// }
    ///
    /// #[tokio::test]
    /// async fn test_with_migrations() {
    ///     let test_db = TestDb::new_with_migrator::<MyMigrator>()
    ///         .await
    ///         .expect("Failed to create test database");
    /// }
    /// ```
    pub async fn new_with_migrator<M: MigratorTrait>() -> Result<Self, DbErr> {
        // Use SQLite with optimized settings for tests:
        // - WAL mode for better concurrency
        // - Shared cache to allow multiple connections
        let connection = Database::connect("sqlite::memory:?mode=rwc&cache=shared").await?;

        // Enable WAL mode for better concurrent access
        connection
            .execute_unprepared("PRAGMA journal_mode=WAL;")
            .await?;
        connection
            .execute_unprepared("PRAGMA busy_timeout=5000;")
            .await?;

        M::up(&connection, None).await?;
        Ok(Self {
            connection,
            backend: TestDbBackend::SqliteMemory,
            postgres: None,
            #[cfg(feature = "test-containers")]
            container: None,
        })
    }

    /// Create a new test database without running migrations
    ///
    /// Use this when you don't need migrations or want to run them manually.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use tideway::testing::TestDb;
    ///
    /// #[tokio::test]
    /// async fn test_without_migrations() {
    ///     let test_db = TestDb::new()
    ///         .await
    ///         .expect("Failed to create test database");
    /// }
    /// ```
    pub async fn new() -> Result<Self, DbErr> {
        // Use SQLite with optimized settings for tests
        let connection = Database::connect("sqlite::memory:?mode=rwc&cache=shared").await?;

        // Enable WAL mode for better concurrent access
        connection
            .execute_unprepared("PRAGMA journal_mode=WAL;")
            .await?;
        connection
            .execute_unprepared("PRAGMA busy_timeout=5000;")
            .await?;

        Ok(Self {
            connection,
            backend: TestDbBackend::SqliteMemory,
            postgres: None,
            #[cfg(feature = "test-containers")]
            container: None,
        })
    }

    /// Create a new PostgreSQL test database and run migrations
    ///
    /// **Requires PostgreSQL to be running on localhost:5432** with default credentials
    /// (postgres/postgres). This provides a test environment that matches production PostgreSQL,
    /// especially for tests that use transactions or concurrent operations.
    ///
    /// Creates a unique database for this test. It is dropped by [`TestDb::cleanup`], or on a
    /// best-effort basis when the `TestDb` is dropped (unless `TIDEWAY_TEST_KEEP_DBS=1`).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use tideway::testing::TestDb;
    /// use sea_orm_migration::MigratorTrait;
    ///
    /// struct MyMigrator;
    /// impl MigratorTrait for MyMigrator {
    ///     fn migrations() -> Vec<Box<dyn sea_orm_migration::MigrationTrait>> {
    ///         vec![]
    ///     }
    /// }
    ///
    /// #[tokio::test]
    /// async fn test_with_postgres() {
    ///     let test_db = TestDb::new_postgres_with_migrator::<MyMigrator>()
    ///         .await
    ///         .expect("Failed to create PostgreSQL test database");
    ///
    ///     // ... test code ...
    /// }
    /// ```
    pub async fn new_postgres_with_migrator<M: MigratorTrait>() -> Result<Self, DbErr> {
        let instance = Self::create_postgres_db().await?;
        M::up(&instance.connection, None).await?;
        Ok(instance)
    }

    /// Create a new PostgreSQL test database without migrations
    ///
    /// Requires PostgreSQL to be running on localhost:5432.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use tideway::testing::TestDb;
    ///
    /// #[tokio::test]
    /// async fn test_with_postgres_no_migrations() {
    ///     let test_db = TestDb::new_postgres()
    ///         .await
    ///         .expect("Failed to create PostgreSQL test database");
    ///
    ///     // ... test code ...
    /// }
    /// ```
    pub async fn new_postgres() -> Result<Self, DbErr> {
        Self::create_postgres_db().await
    }

    /// Create a new PostgreSQL test database in a container with an ephemeral database.
    ///
    /// Requires:
    /// - Docker available to `testcontainers`
    /// - `test-containers` feature enabled
    #[cfg(feature = "test-containers")]
    pub async fn new_postgres_container() -> Result<Self, DbErr> {
        let container = postgres_container::PostgresContainer::start().await?;
        let connection = Database::connect(&container.connection_url).await?;
        Ok(Self {
            connection,
            backend: TestDbBackend::PostgresContainer,
            postgres: None,
            container: Some(Arc::new(container)),
        })
    }

    /// Create a new PostgreSQL test database in a container and run migrations.
    #[cfg(feature = "test-containers")]
    pub async fn new_postgres_container_with_migrator<M: MigratorTrait>() -> Result<Self, DbErr> {
        let instance = Self::new_postgres_container().await?;
        M::up(&instance.connection, None).await?;
        Ok(instance)
    }

    /// Internal helper for PostgreSQL database creation to avoid code duplication
    async fn create_postgres_db() -> Result<Self, DbErr> {
        let base_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_string());
        Self::create_postgres_db_from_base_url(&base_url).await
    }

    async fn create_postgres_db_from_base_url(base_url: &str) -> Result<Self, DbErr> {
        // Connect to the default postgres database to create a new test database
        let admin_connection = Database::connect(base_url).await?;

        let counter = TEST_DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        let db_name = format!("test_db_{}_{}", std::process::id(), counter);

        // Create the test database with proper identifier quoting
        let create_db_stmt = format!("CREATE DATABASE \"{}\"", escape_identifier(&db_name));
        admin_connection
            .execute(Statement::from_string(
                sea_orm::DatabaseBackend::Postgres,
                create_db_stmt,
            ))
            .await
            .map_err(|e| {
                DbErr::Custom(format!(
                    "Failed to create test database '{}': {}",
                    db_name, e
                ))
            })?;

        // Close admin connection explicitly
        admin_connection
            .close()
            .await
            .map_err(|e| DbErr::Custom(format!("Failed to close admin connection: {}", e)))?;

        // Parse the base URL and replace the database name
        let test_db_url = build_test_db_url(base_url, &db_name)?;
        let connection = Database::connect(&test_db_url).await.map_err(|e| {
            DbErr::Custom(format!(
                "Failed to connect to test database '{}': {}",
                db_name, e
            ))
        })?;

        Ok(Self {
            connection,
            backend: TestDbBackend::Postgres,
            postgres: Some(PostgresTestDatabase {
                admin_url: base_url.to_string(),
                db_name,
            }),
            #[cfg(feature = "test-containers")]
            container: None,
        })
    }

    /// Close the connection and drop the per-test PostgreSQL database.
    ///
    /// Prefer this over relying on `Drop` when you want cleanup errors reported. For the
    /// SQLite and container backends this only closes the connection.
    pub async fn cleanup(mut self) -> Result<(), DbErr> {
        let postgres = self.postgres.take();
        std::mem::take(&mut self.connection).close().await?;
        match postgres {
            Some(postgres) => postgres.drop_database().await,
            None => Ok(()),
        }
    }

    /// Get a clone of the database connection
    ///
    /// This is useful for passing to services or handlers that need a connection.
    pub fn connection(&self) -> DatabaseConnection {
        self.connection.clone()
    }

    /// Seed the database with test data
    ///
    /// Executes the provided SQL statements to populate the database with test data.
    /// Useful for setting up consistent test fixtures.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use tideway::testing::TestDb;
    ///
    /// #[tokio::test]
    /// async fn test_with_seed() {
    ///     let db = TestDb::new().await.unwrap();
    ///     db.seed(&[
    ///         "INSERT INTO users (id, email) VALUES ('1', 'test@example.com')",
    ///         "INSERT INTO users (id, email) VALUES ('2', 'user@example.com')",
    ///     ]).await.unwrap();
    /// }
    /// ```
    pub async fn seed(&self, statements: &[&str]) -> Result<(), DbErr> {
        for statement in statements {
            self.connection.execute_unprepared(statement).await?;
        }
        Ok(())
    }

    /// Reset the database by dropping all tables
    ///
    /// **Warning**: This will delete all data in the database.
    /// Useful for cleaning up between tests or test isolation.
    pub async fn reset(&self) -> Result<(), DbErr> {
        match self.backend {
            TestDbBackend::SqliteMemory => self.reset_sqlite().await,
            TestDbBackend::Postgres => self.reset_postgres().await,
            #[cfg(feature = "test-containers")]
            TestDbBackend::PostgresContainer => self.reset_postgres().await,
        }
    }

    /// Run a test within a transaction that will be rolled back
    ///
    /// This provides test isolation by wrapping the test function in a transaction
    /// that is automatically rolled back, ensuring no test data persists.
    ///
    /// The closure receives a reference to the transaction connection, which should
    /// be used for all database operations within the test.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use tideway::testing::TestDb;
    /// use sea_orm::TransactionTrait;
    ///
    /// #[tokio::test]
    /// async fn test_with_rollback() {
    ///     let db = TestDb::new().await.unwrap();
    ///     db.with_transaction_rollback(|txn| async move {
    ///         // Test code here - changes will be rolled back
    ///         txn.execute_unprepared(
    ///             "INSERT INTO users (id, email) VALUES ('1', 'test@example.com')"
    ///         ).await.unwrap();
    ///         Ok(())
    ///     }).await.unwrap();
    /// }
    /// ```
    pub async fn with_transaction_rollback<F, Fut>(&self, f: F) -> Result<(), DbErr>
    where
        F: for<'a> FnOnce(&'a sea_orm::DatabaseTransaction) -> Fut,
        Fut: std::future::Future<Output = Result<(), DbErr>>,
    {
        use sea_orm::TransactionTrait;

        let txn = self.connection.begin().await?;

        // Execute the test function with a reference to the transaction
        let result = f(&txn).await;

        // Always rollback regardless of result
        txn.rollback().await?;

        result
    }

    async fn reset_sqlite(&self) -> Result<(), DbErr> {
        let drop_tables_stmt = Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                .to_string(),
        );
        let rows = self.connection.query_all(drop_tables_stmt).await?;

        for row in rows {
            let table_name = row.try_get::<String>("", "name")?;
            let drop_stmt = format!(
                "DROP TABLE IF EXISTS \"{}\"",
                escape_identifier(&table_name)
            );
            self.connection.execute_unprepared(&drop_stmt).await?;
        }

        Ok(())
    }

    async fn reset_postgres(&self) -> Result<(), DbErr> {
        let list_tables_stmt = Statement::from_string(
            sea_orm::DatabaseBackend::Postgres,
            "SELECT schemaname, tablename FROM pg_tables WHERE schemaname = 'public'".to_string(),
        );
        let rows = self.connection.query_all(list_tables_stmt).await?;

        let tables = rows
            .into_iter()
            .map(|row| {
                let schema = row.try_get::<String>("", "schemaname")?;
                let table = row.try_get::<String>("", "tablename")?;
                Ok(format!(
                    "\"{}\".\"{}\"",
                    escape_identifier(&schema),
                    escape_identifier(&table)
                ))
            })
            .collect::<Result<Vec<_>, DbErr>>()?;

        if tables.is_empty() {
            return Ok(());
        }

        let truncate_stmt = format!(
            "TRUNCATE TABLE {} RESTART IDENTITY CASCADE",
            tables.join(", ")
        );
        self.connection
            .execute(Statement::from_string(
                sea_orm::DatabaseBackend::Postgres,
                truncate_stmt,
            ))
            .await?;

        Ok(())
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let Some(postgres) = self.postgres.take() else {
            return;
        };
        if std::env::var(KEEP_DBS_ENV).is_ok_and(|value| value == "1") {
            return;
        }
        // Drop can't await, and blocking on the caller's runtime would panic or deadlock,
        // so run the drop on its own thread with a small runtime and wait for it.
        let handle = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            let _ = runtime.block_on(postgres.drop_database());
        });
        let _ = handle.join();
    }
}

/// A per-test PostgreSQL database and the admin URL used to create it.
struct PostgresTestDatabase {
    admin_url: String,
    db_name: String,
}

impl PostgresTestDatabase {
    async fn drop_database(&self) -> Result<(), DbErr> {
        let mut options = ConnectOptions::new(&self.admin_url);
        options
            .max_connections(1)
            .connect_timeout(Duration::from_secs(5))
            .acquire_timeout(Duration::from_secs(5))
            .sqlx_logging(false);
        let admin_connection = Database::connect(options).await?;
        // FORCE terminates any connections still open to the test database (PostgreSQL 13+).
        let drop_db_stmt = format!(
            "DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)",
            escape_identifier(&self.db_name)
        );
        let result = admin_connection
            .execute(Statement::from_string(
                sea_orm::DatabaseBackend::Postgres,
                drop_db_stmt,
            ))
            .await
            .map(|_| ())
            .map_err(|e| {
                DbErr::Custom(format!(
                    "Failed to drop test database '{}': {}",
                    self.db_name, e
                ))
            });
        let _ = admin_connection.close().await;
        result
    }
}

/// Escape a PostgreSQL identifier to prevent SQL injection
///
/// Doubles any quotes in the identifier to properly escape them.
fn escape_identifier(identifier: &str) -> String {
    identifier.replace('"', "\"\"")
}

/// Build a test database URL by replacing the database name in the base URL
///
/// Uses proper URL parsing to handle edge cases like query parameters, ports, etc.
fn build_test_db_url(base_url: &str, new_db_name: &str) -> Result<String, DbErr> {
    let mut url = Url::parse(base_url)
        .map_err(|e| DbErr::Custom(format!("Invalid database URL '{}': {}", base_url, e)))?;

    // Get the path and replace the database name (last segment)
    let path = url.path();
    let new_path = if let Some(idx) = path.rfind('/') {
        format!("{}/{}", &path[..idx], new_db_name)
    } else {
        format!("/{}", new_db_name)
    };

    url.set_path(&new_path);
    Ok(url.to_string())
}

/// Helper macro to create a test database for each test
///
/// # Example
///
/// ```rust,ignore
/// use tideway::test_db;
///
/// #[tokio::test]
/// async fn my_test() {
///     let db = test_db!();
///     // Use db.connection() in your test
/// }
/// ```
#[macro_export]
macro_rules! test_db {
    () => {{
        $crate::testing::TestDb::new()
            .await
            .expect("Failed to create test database")
    }};
    ($migrator:ty) => {{
        $crate::testing::TestDb::new_with_migrator::<$migrator>()
            .await
            .expect("Failed to create test database")
    }};
}
