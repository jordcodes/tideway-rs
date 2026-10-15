//! Migrated template databases for PostgreSQL tests, and the sweep of databases left behind by
//! test processes that crashed or were killed.
//!
//! Each distinct migration list gets one template, `test_tpl_<hash>`, where `<hash>` is derived
//! from the migration names. It is built once (under a PostgreSQL advisory lock, so parallel test
//! binaries don't race) and every test database is then a `CREATE DATABASE … TEMPLATE` copy of it.

use super::{KEEP_DBS_ENV, build_test_db_url, escape_identifier};
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, DbErr,
    Statement,
};
use sea_orm_migration::MigratorTrait;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use tokio::sync::OnceCell;

const TEST_DB_PREFIX: &str = "test_db_";
const TEMPLATE_PREFIX: &str = "test_tpl_";
/// Length of the hex migration hash in template names.
const HASH_LEN: usize = 16;

/// Template state per `(admin URL, template name)`: `Ok` once the template exists, `Err` with the
/// reason it couldn't be built.
type TemplateCell = Arc<OnceCell<Result<(), String>>>;

static TEMPLATES: LazyLock<Mutex<HashMap<(String, String), TemplateCell>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static TEST_DB_SWEEP: OnceCell<()> = OnceCell::const_new();
static TEMPLATE_SWEEP: OnceCell<()> = OnceCell::const_new();

/// Name of the template database for `M`'s migration list.
pub(super) fn template_name<M: MigratorTrait>() -> String {
    let mut hasher = Sha256::new();
    for migration in M::migrations() {
        hasher.update(migration.name().as_bytes());
        hasher.update([0]);
    }
    let hash: String = hasher.finalize()[..HASH_LEN / 2]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{TEMPLATE_PREFIX}{hash}")
}

/// Make sure `M`'s template exists on the server, building it once per process if needed.
/// Returns the template name.
pub(super) async fn ensure_template<M: MigratorTrait>(admin_url: &str) -> Result<String, DbErr> {
    let name = template_name::<M>();
    let cell = TEMPLATES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry((admin_url.to_string(), name.clone()))
        .or_default()
        .clone();
    let state = cell
        .get_or_init(|| async {
            sweep_templates_once(admin_url).await;
            build_template::<M>(admin_url, &name).await.map_err(|e| {
                tracing::warn!(
                    template = %name,
                    error = %e,
                    "could not build the test database template; running migrations per test database instead"
                );
                e.to_string()
            })
        })
        .await;
    state.clone().map(|()| name).map_err(DbErr::Custom)
}

/// Forget that `template` exists, so the next test database checks for it (and rebuilds it)
/// again. Used after copying from the template fails.
pub(super) fn forget_template(admin_url: &str, template: &str) {
    TEMPLATES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&(admin_url.to_string(), template.to_string()));
}

/// Create `db_name` as a copy of `template`. Holds the template's advisory lock in shared mode
/// so a concurrent sweep can't drop the template mid-copy.
pub(super) async fn create_from_template(
    admin: &DatabaseConnection,
    db_name: &str,
    template: &str,
) -> Result<(), DbErr> {
    let key = lock_key(template);
    execute_with_key(admin, "SELECT pg_advisory_lock_shared($1)", key).await?;
    let result = admin
        .execute_unprepared(&format!(
            "CREATE DATABASE \"{}\" TEMPLATE \"{}\"",
            escape_identifier(db_name),
            escape_identifier(template)
        ))
        .await
        .map(|_| ());
    let _ = execute_with_key(admin, "SELECT pg_advisory_unlock_shared($1)", key).await;
    result
}

async fn build_template<M: MigratorTrait>(admin_url: &str, template: &str) -> Result<(), DbErr> {
    let admin = connect_admin(admin_url).await?;
    let key = lock_key(template);
    let result = match execute_with_key(&admin, "SELECT pg_advisory_lock($1)", key).await {
        Ok(()) => {
            let result = build_template_locked::<M>(&admin, admin_url, template).await;
            let _ = execute_with_key(&admin, "SELECT pg_advisory_unlock($1)", key).await;
            result
        }
        Err(e) => Err(e),
    };
    let _ = admin.close().await;
    result
}

async fn build_template_locked<M: MigratorTrait>(
    admin: &DatabaseConnection,
    admin_url: &str,
    template: &str,
) -> Result<(), DbErr> {
    if database_exists(admin, template).await? {
        return Ok(());
    }
    // Migrate under a per-process name and rename at the end, so a crash mid-migration never
    // leaves a half-built database under the template's name. The sweep removes such leftovers.
    let building = format!("{template}_{}", std::process::id());
    drop_database(admin, &building, true).await?;
    admin
        .execute_unprepared(&format!(
            "CREATE DATABASE \"{}\"",
            escape_identifier(&building)
        ))
        .await?;

    let migrated = async {
        let connection = Database::connect(build_test_db_url(admin_url, &building)?).await?;
        let result = M::up(&connection, None).await;
        let _ = connection.close().await;
        result
    }
    .await;
    let result = match migrated {
        Ok(()) => admin
            .execute_unprepared(&format!(
                "ALTER DATABASE \"{}\" RENAME TO \"{}\"",
                escape_identifier(&building),
                escape_identifier(template)
            ))
            .await
            .map(|_| ()),
        Err(e) => Err(e),
    };
    if result.is_err() {
        let _ = drop_database(admin, &building, true).await;
    }
    result
}

/// Drop leftover `test_db_<pid>_<n>` databases once per process. Skipped with
/// `TIDEWAY_TEST_KEEP_DBS=1` so kept databases survive later runs too.
pub(super) async fn sweep_test_dbs_once(admin_url: &str) {
    if keep_dbs() {
        return;
    }
    TEST_DB_SWEEP
        .get_or_init(|| async {
            let _ = sweep(admin_url, false).await;
        })
        .await;
}

async fn sweep_templates_once(admin_url: &str) {
    if keep_dbs() {
        return;
    }
    TEMPLATE_SWEEP
        .get_or_init(|| async {
            let _ = sweep(admin_url, true).await;
        })
        .await;
}

fn keep_dbs() -> bool {
    std::env::var(KEEP_DBS_ENV).is_ok_and(|value| value == "1")
}

/// Drop test databases whose creating process is no longer running on this machine, and (if
/// `include_templates`) templates that this process isn't using and no other process holds.
/// Databases with open connections are never dropped, which also protects databases created by
/// live processes on other machines. Returns the dropped database names.
pub(super) async fn sweep(admin_url: &str, include_templates: bool) -> Result<Vec<String>, DbErr> {
    let admin = connect_admin(admin_url).await?;
    let rows = admin
        .query_all(Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT datname FROM pg_database",
        ))
        .await;
    let names = match rows {
        Ok(rows) => rows
            .into_iter()
            .filter_map(|row| row.try_get::<String>("", "datname").ok())
            .collect::<Vec<_>>(),
        Err(e) => {
            let _ = admin.close().await;
            return Err(e);
        }
    };
    let in_use: HashSet<String> = TEMPLATES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .keys()
        .map(|(_, template)| template.clone())
        .collect();

    let mut dropped = Vec::new();
    for name in names {
        let drop = match classify(&name) {
            Some(Leftover::TestDb { pid }) | Some(Leftover::TemplateBuild { pid }) => {
                !process_is_running(pid) && drop_database(&admin, &name, false).await.is_ok()
            }
            Some(Leftover::Template) if include_templates && !in_use.contains(&name) => {
                drop_unused_template(&admin, &name).await
            }
            _ => false,
        };
        if drop {
            dropped.push(name);
        }
    }
    let _ = admin.close().await;
    Ok(dropped)
}

/// Drop a template unless another process is building or copying it.
async fn drop_unused_template(admin: &DatabaseConnection, template: &str) -> bool {
    let key = lock_key(template);
    let locked = admin
        .query_one(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "SELECT pg_try_advisory_lock($1) AS locked",
            [key.into()],
        ))
        .await
        .ok()
        .flatten()
        .and_then(|row| row.try_get::<bool>("", "locked").ok())
        .unwrap_or(false);
    if !locked {
        return false;
    }
    let dropped = drop_database(admin, template, false).await.is_ok();
    let _ = execute_with_key(admin, "SELECT pg_advisory_unlock($1)", key).await;
    dropped
}

#[derive(Debug, PartialEq, Eq)]
enum Leftover {
    /// `test_db_<pid>_<n>`
    TestDb { pid: u32 },
    /// `test_tpl_<hash>_<pid>`, a template that was still being migrated
    TemplateBuild { pid: u32 },
    /// `test_tpl_<hash>`
    Template,
}

fn classify(name: &str) -> Option<Leftover> {
    if let Some(rest) = name.strip_prefix(TEST_DB_PREFIX) {
        let (pid, counter) = rest.split_once('_')?;
        return (is_digits(counter))
            .then(|| parse_pid(pid))
            .flatten()
            .map(|pid| Leftover::TestDb { pid });
    }
    let rest = name.strip_prefix(TEMPLATE_PREFIX)?;
    match rest.split_once('_') {
        None => is_hash(rest).then_some(Leftover::Template),
        Some((hash, pid)) => is_hash(hash)
            .then(|| parse_pid(pid))
            .flatten()
            .map(|pid| Leftover::TemplateBuild { pid }),
    }
}

fn is_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn parse_pid(value: &str) -> Option<u32> {
    is_digits(value).then(|| value.parse().ok()).flatten()
}

fn is_hash(value: &str) -> bool {
    value.len() == HASH_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(unix)]
fn process_is_running(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return true;
    };
    if pid <= 0 {
        return true;
    }
    // SAFETY: signal 0 only checks that the process exists and can be signalled.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    // EPERM means the process exists but belongs to another user.
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// Without a portable liveness check, treat every process as running so nothing is swept.
#[cfg(not(unix))]
fn process_is_running(_pid: u32) -> bool {
    true
}

/// The advisory lock key for a template: its hash read as a 64-bit integer.
fn lock_key(template: &str) -> i64 {
    let hash = template.strip_prefix(TEMPLATE_PREFIX).unwrap_or(template);
    u64::from_str_radix(hash, 16).unwrap_or(0) as i64
}

/// A single-connection admin pool, so session-level advisory locks stay on one connection.
pub(super) async fn connect_admin(admin_url: &str) -> Result<DatabaseConnection, DbErr> {
    let mut options = ConnectOptions::new(admin_url);
    options
        .max_connections(1)
        .connect_timeout(Duration::from_secs(5))
        .acquire_timeout(Duration::from_secs(5))
        .sqlx_logging(false);
    Database::connect(options).await
}

async fn execute_with_key(admin: &DatabaseConnection, sql: &str, key: i64) -> Result<(), DbErr> {
    admin
        .execute(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            sql,
            [key.into()],
        ))
        .await
        .map(|_| ())
}

async fn database_exists(admin: &DatabaseConnection, name: &str) -> Result<bool, DbErr> {
    let row = admin
        .query_one(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "SELECT 1 AS found FROM pg_database WHERE datname = $1",
            [name.into()],
        ))
        .await?;
    Ok(row.is_some())
}

/// Drop a database if it exists. Without `force`, PostgreSQL refuses while anything is connected.
pub(super) async fn drop_database(
    admin: &DatabaseConnection,
    name: &str,
    force: bool,
) -> Result<(), DbErr> {
    let force = if force { " WITH (FORCE)" } else { "" };
    admin
        .execute_unprepared(&format!(
            "DROP DATABASE IF EXISTS \"{}\"{force}",
            escape_identifier(name)
        ))
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_test_database_names() {
        assert_eq!(
            classify("test_db_123_4"),
            Some(Leftover::TestDb { pid: 123 })
        );
        assert_eq!(
            classify("test_tpl_0123456789abcdef"),
            Some(Leftover::Template)
        );
        assert_eq!(
            classify("test_tpl_0123456789abcdef_77"),
            Some(Leftover::TemplateBuild { pid: 77 })
        );
        for other in [
            "postgres",
            "test_db",
            "test_db_123",
            "test_db_abc_1",
            "test_db_1_2_3",
            "test_tpl_short",
            "test_tpl_0123456789ABCDEF",
            "test_tpl_0123456789abcdef_x",
        ] {
            assert_eq!(classify(other), None, "{other}");
        }
    }

    #[test]
    fn lock_key_reads_the_template_hash() {
        assert_eq!(lock_key("test_tpl_00000000000000ff"), 255);
        assert_eq!(lock_key("test_tpl_ffffffffffffffff"), -1);
    }

    #[test]
    fn this_process_is_running() {
        assert!(process_is_running(std::process::id()));
    }
}
