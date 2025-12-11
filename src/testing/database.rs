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

use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbErr, Statement};
use sea_orm_migration::MigratorTrait;
use std::sync::atomic::{AtomicU64, Ordering};
use url::Url;

static TEST_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Manages a test database connection
///
/// Supports both SQLite in-memory (fast, no external dependencies) and PostgreSQL
/// (requires PostgreSQL running on localhost:5432, matches production better).
///
/// **Note on PostgreSQL cleanup**: Test databases are NOT automatically cleaned up
/// to avoid async operations in Drop which can cause hangs. Use a periodic cleanup
/// script or CI/CD step to remove orphaned test databases.
pub struct TestDb {
    pub connection: DatabaseConnection,
}

impl TestDb {
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
        Ok(Self { connection })
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

        Ok(Self { connection })
    }

    /// Create a new PostgreSQL test database and run migrations
    ///
    /// **Requires PostgreSQL to be running on localhost:5432** with default credentials
    /// (postgres/postgres). This provides a test environment that matches production PostgreSQL,
    /// especially for tests that use transactions or concurrent operations.
    ///
    /// Creates a unique database for this test. **Note:** Test databases are NOT automatically
    /// cleaned up. Run `scripts/cleanup_test_dbs.sh` periodically to remove orphaned databases.
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

    /// Internal helper for PostgreSQL database creation to avoid code duplication
    async fn create_postgres_db() -> Result<Self, DbErr> {
        let base_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_string());

        // Connect to the default postgres database to create a new test database
        let admin_connection = Database::connect(&base_url).await?;

        // Generate a unique database name using process ID and atomic counter
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
        let test_db_url = build_test_db_url(&base_url, &db_name)?;
        let connection = Database::connect(&test_db_url).await.map_err(|e| {
            DbErr::Custom(format!(
                "Failed to connect to test database '{}': {}",
                db_name, e
            ))
        })?;

        Ok(Self { connection })
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
    ///
    /// For SQLite, this clears all tables. For PostgreSQL, you may want to
    /// recreate the database instead.
    pub async fn reset(&self) -> Result<(), DbErr> {
        // For SQLite, drop all tables
        let drop_tables_stmt = Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'".to_string(),
        );

        let result = self.connection.query_all(drop_tables_stmt).await;

        if let Ok(rows) = result {
            for row in rows {
                if let Ok(table_name) = row.try_get::<String>("", "name") {
                    let drop_stmt = format!("DROP TABLE IF EXISTS \"{}\"", table_name);
                    self.connection.execute_unprepared(&drop_stmt).await?;
                }
            }
        }

        Ok(())
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
