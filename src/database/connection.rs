use super::config::DatabaseConfig;
use crate::error::{Result, TidewayError};
use sea_orm::{ConnectOptions, Database, DatabaseConnection as SeaOrmConnection};
use std::time::Duration;

pub(super) async fn connect(config: &DatabaseConfig) -> Result<SeaOrmConnection> {
    let result = async {
        if config.idle_timeout == 0 {
            // SeaORM 1.1 cannot express an explicit `None` idle timeout:
            // omitting it retains SQLx's default, while Duration::ZERO expires
            // idle connections immediately. Build the supported pools directly.
            let scheme = url::Url::parse(&config.url)
                .map(|url| url.scheme().to_owned())
                .unwrap_or_default();
            match scheme.as_str() {
                "postgres" | "postgresql" => {
                    return connect_without_idle_timeout::<sea_orm::sqlx::Postgres>(config)
                        .await
                        .map(sea_orm::SqlxPostgresConnector::from_sqlx_postgres_pool);
                }
                "sqlite" => {
                    return connect_without_idle_timeout::<sea_orm::sqlx::Sqlite>(config)
                        .await
                        .map(sea_orm::SqlxSqliteConnector::from_sqlx_sqlite_pool);
                }
                _ => {}
            }
        }
        Database::connect(connect_options(config)).await
    }
    .await;
    result.map_err(|e| TidewayError::internal(format!("Failed to connect to database: {}", e)))
}

async fn connect_without_idle_timeout<DB: sea_orm::sqlx::Database>(
    config: &DatabaseConfig,
) -> std::result::Result<sea_orm::sqlx::Pool<DB>, sea_orm::DbErr> {
    use sea_orm::sqlx::{ConnectOptions as _, Connection};

    let result = async {
        let mut options = config
            .url
            .parse::<<DB::Connection as Connection>::Options>()?;
        if !cfg!(debug_assertions) {
            options = options.disable_statement_logging();
        }
        connect_options(config)
            .sqlx_pool_options::<DB>()
            .idle_timeout(None)
            .connect_with(options)
            .await
    }
    .await;
    result.map_err(|e| sea_orm::DbErr::Conn(sea_orm::RuntimeErr::SqlxError(e)))
}

pub(super) fn connect_options(config: &DatabaseConfig) -> ConnectOptions {
    let mut opt = ConnectOptions::new(&config.url);
    opt.max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .connect_timeout(Duration::from_secs(config.connect_timeout))
        .idle_timeout(Duration::from_secs(config.idle_timeout))
        // Query text may contain sensitive data; only log it in debug builds.
        .sqlx_logging(cfg!(debug_assertions));
    opt
}

/// Wrapper around SeaORM database connection
#[derive(Clone)]
pub struct DatabaseConnection {
    pub conn: SeaOrmConnection,
}

impl DatabaseConnection {
    /// Create a new database connection from config
    pub async fn connect(config: &DatabaseConfig) -> Result<Self> {
        let conn = connect(config).await?;

        tracing::info!(
            "Database connected with {} max connections",
            config.max_connections
        );

        Ok(Self { conn })
    }

    /// Ping the database to check connection health
    pub async fn ping(&self) -> Result<()> {
        self.conn
            .ping()
            .await
            .map_err(|e| TidewayError::internal(format!("Database ping failed: {}", e)))
    }

    /// Close the database connection
    pub async fn close(self) -> Result<()> {
        self.conn
            .close()
            .await
            .map_err(|e| TidewayError::internal(format!("Failed to close database: {}", e)))
    }

    /// Get the inner SeaORM connection
    pub fn inner(&self) -> &SeaOrmConnection {
        &self.conn
    }
}

impl std::ops::Deref for DatabaseConnection {
    type Target = SeaOrmConnection;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn zero_idle_timeout_disables_expiry_and_reuses_connections() {
        use sea_orm::{ConnectionTrait, DbBackend, Statement};

        let config = DatabaseConfig {
            url: "sqlite::memory:".into(),
            max_connections: 1,
            min_connections: 0,
            idle_timeout: 0,
            ..Default::default()
        };
        let direct = DatabaseConnection::connect(&config).await.unwrap();
        let pool = crate::database::SeaOrmPool::from_config(&config)
            .await
            .unwrap();

        for conn in [direct.inner(), pool.inner()] {
            assert_eq!(
                conn.get_sqlite_connection_pool()
                    .options()
                    .get_idle_timeout(),
                None,
                "zero must disable idle expiry in the actual SQLx pool"
            );
            // TEMP tables belong to a physical connection, so a replacement
            // connection cannot satisfy the subsequent queries.
            conn.execute(Statement::from_string(
                DbBackend::Sqlite,
                "CREATE TEMP TABLE connection_marker (value INTEGER)",
            ))
            .await
            .unwrap();
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_millis(20)).await;
                conn.execute(Statement::from_string(
                    DbBackend::Sqlite,
                    "INSERT INTO connection_marker VALUES (1)",
                ))
                .await
                .unwrap();
            }
            let row = conn
                .query_one(Statement::from_string(
                    DbBackend::Sqlite,
                    "SELECT COUNT(*) AS count FROM connection_marker",
                ))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.try_get::<i64>("", "count").unwrap(), 3);
            conn.clone().close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn positive_idle_timeout_is_preserved() {
        for timeout in [1, 42, DatabaseConfig::default().idle_timeout] {
            let config = DatabaseConfig {
                url: "sqlite::memory:".into(),
                idle_timeout: timeout,
                ..Default::default()
            };
            let conn = DatabaseConnection::connect(&config).await.unwrap();
            assert_eq!(
                conn.inner()
                    .get_sqlite_connection_pool()
                    .options()
                    .get_idle_timeout(),
                Some(Duration::from_secs(timeout))
            );
            conn.close().await.unwrap();
        }
    }

    #[test]
    fn sql_logging_matches_build_profile() {
        let options = connect_options(&DatabaseConfig::default());
        assert_eq!(
            options.get_sqlx_logging(),
            cfg!(debug_assertions),
            "SQL statement logging must be disabled in release builds"
        );
    }
}
