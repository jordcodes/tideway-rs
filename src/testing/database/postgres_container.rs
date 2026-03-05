use sea_orm::{Database, DbErr};
use std::net::TcpListener;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[derive(Debug)]
pub struct PostgresContainer {
    pub(crate) connection_url: String,
    container_name: String,
    keep_running: bool,
}

static CONTAINER_COUNTER: AtomicU64 = AtomicU64::new(0);

impl PostgresContainer {
    pub async fn start() -> Result<Self, DbErr> {
        let image = std::env::var("TIDEWAY_TEST_POSTGRES_IMAGE")
            .unwrap_or_else(|_| "postgres:16-alpine".to_string());

        let username =
            std::env::var("TIDEWAY_TEST_PG_USER").unwrap_or_else(|_| "postgres".to_string());

        let password =
            std::env::var("TIDEWAY_TEST_PG_PASSWORD").unwrap_or_else(|_| "postgres".to_string());

        let port = allocate_host_port()?;

        let db_name = format!(
            "tideway_test_{}_{}",
            std::process::id(),
            CONTAINER_COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let container_name = format!(
            "tideway-test-{}-{}",
            std::process::id(),
            CONTAINER_COUNTER.fetch_add(1, Ordering::SeqCst)
        );

        let container_spec = format!("{}:5432", port);
        let args = [
            "run",
            "-d",
            "--name",
            &container_name,
            "-e",
            &format!("POSTGRES_USER={}", username),
            "-e",
            &format!("POSTGRES_PASSWORD={}", password),
            "-e",
            &format!("POSTGRES_DB={}", db_name),
            "-p",
            &container_spec,
            &image,
        ];

        let output = Command::new("docker")
            .args(args)
            .output()
            .map_err(|e| DbErr::Custom(format!("Failed to run docker: {}", e)))?;

        if !output.status.success() {
            let details = String::from_utf8_lossy(&output.stderr);
            return Err(DbErr::Custom(format!(
                "Failed to start postgres container: {}",
                details.trim()
            )));
        }

        let connection_url = format!(
            "postgres://{}:{}@127.0.0.1:{}/{}",
            urlencoding::encode(&username),
            urlencoding::encode(&password),
            port,
            db_name
        );

        wait_for_postgres_readiness(&connection_url).await?;

        Ok(Self {
            connection_url,
            container_name,
            keep_running: std::env::var("TIDEWAY_TEST_KEEP_CONTAINERS")
                .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
        })
    }
}

impl Drop for PostgresContainer {
    fn drop(&mut self) {
        if self.keep_running {
            return;
        }

        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container_name])
            .status();
    }
}

fn allocate_host_port() -> Result<u16, DbErr> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| DbErr::Custom(format!("Failed to allocate host port: {}", e)))?;

    listener
        .local_addr()
        .map_err(|e| DbErr::Custom(format!("Failed to read local address: {}", e)))
        .map(|address| address.port())
}

async fn wait_for_postgres_readiness(connection_url: &str) -> Result<(), DbErr> {
    let deadline = Instant::now() + Duration::from_secs(45);

    while Instant::now() < deadline {
        let connection = Database::connect(connection_url).await;
        if let Ok(connection) = connection {
            let _ = connection.close().await;
            return Ok(());
        }

        sleep(Duration::from_millis(200)).await;
    }

    Err(DbErr::Custom(
        "Timed out waiting for postgres container readiness".to_string(),
    ))
}
