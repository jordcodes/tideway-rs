use sea_orm::DbErr;
use std::mem;
use std::sync::atomic::{AtomicU64, Ordering};
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{ImageExt, core::ContainerAsync, runners::AsyncRunner},
};

#[derive(Debug)]
pub struct PostgresContainer {
    pub(crate) connection_url: String,
    container: Option<ContainerAsync<Postgres>>,
    keep_running: bool,
}

static CONTAINER_COUNTER: AtomicU64 = AtomicU64::new(0);

impl PostgresContainer {
    pub async fn start() -> Result<Self, DbErr> {
        let username =
            std::env::var("TIDEWAY_TEST_PG_USER").unwrap_or_else(|_| "postgres".to_string());
        let password =
            std::env::var("TIDEWAY_TEST_PG_PASSWORD").unwrap_or_else(|_| "postgres".to_string());
        let db_name = format!(
            "tideway_test_{}_{}",
            std::process::id(),
            CONTAINER_COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let keep_running = std::env::var("TIDEWAY_TEST_KEEP_CONTAINERS")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let request = Postgres::default()
            .with_user(&username)
            .with_password(&password)
            .with_db_name(&db_name);
        let request = if let Ok(tag) = std::env::var("TIDEWAY_TEST_POSTGRES_IMAGE") {
            request.with_tag(tag)
        } else {
            request.into()
        };
        let container = request.start().await.map_err(|error| {
            DbErr::Custom(format!("Failed to start postgres container: {error}"))
        })?;
        let host = container
            .get_host()
            .await
            .map_err(|error| DbErr::Custom(format!("Failed to resolve postgres host: {error}")))?;
        let port = container.get_host_port_ipv4(5432).await.map_err(|error| {
            DbErr::Custom(format!("Failed to resolve postgres host port: {error}"))
        })?;

        let connection_url = format!(
            "postgres://{}:{}@{}:{}/{}",
            urlencoding::encode(&username),
            urlencoding::encode(&password),
            host,
            port,
            db_name
        );

        Ok(Self {
            connection_url,
            container: Some(container),
            keep_running,
        })
    }
}

impl Drop for PostgresContainer {
    fn drop(&mut self) {
        if self.keep_running
            && let Some(container) = self.container.take()
        {
            mem::forget(container);
        }
    }
}
