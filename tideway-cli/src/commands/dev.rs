//! Dev command - run a Tideway app with sensible defaults.

mod watch;

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::fs;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgConnection};
use sqlx::{Connection, Executor};
use toml_edit::DocumentMut;
use url::Url;

use crate::cli::DevArgs;
use crate::commands::messaging::DEV_FIX_ENV_COMMAND;
use crate::database::{
    DatabaseUrlKind, redact_database_url, resolve_database_url, validate_database_url,
};
use crate::env::{ensure_env, ensure_project_dir, read_env_map};
use crate::{
    CommandRuntime, ExecutionPlan, PlannedCommand, error_contract, print_info, print_success,
    print_warning,
};

use self::watch::WatchConfig;

pub fn run(args: DevArgs) -> Result<()> {
    run_with_runtime(args, CommandRuntime::from_process_state())
}

pub fn run_with_runtime(args: DevArgs, runtime: CommandRuntime) -> Result<()> {
    runtime.install();

    if runtime.plan_mode() {
        build_dev_plan(&args).emit(runtime);
        return Ok(());
    }
    let project_dir = PathBuf::from(&args.path);
    ensure_project_dir(&project_dir)?;

    if !args.no_env {
        ensure_env(&project_dir, args.fix_env)?;
    }

    let env_map = if !args.no_env {
        read_env_map(&project_dir.join(".env"))
    } else {
        None
    };

    preflight_database(&project_dir, &env_map)?;
    print_local_urls(&project_dir, &env_map)?;

    let mut child_env = BTreeMap::new();
    let mut forced_env = BTreeMap::new();

    if !args.no_env
        && let Some(env_map) = &env_map
    {
        child_env.extend(
            env_map
                .iter()
                .filter(|(key, _)| std::env::var_os(key).is_none())
                .map(|(key, value)| (key.clone(), value.clone())),
        );
    }

    if args.no_migrate {
        forced_env.insert("DATABASE_AUTO_MIGRATE".into(), "false".into());
        print_info("Disabling automatic migrations for this run (--no-migrate).");
    } else {
        if let Some(auto_migrate) = explicit_auto_migrate(&env_map) {
            if auto_migrate.eq_ignore_ascii_case("true") {
                print_info("DATABASE_AUTO_MIGRATE already set; honoring existing value");
            } else {
                print_warning(&format!(
                    "DATABASE_AUTO_MIGRATE is set to '{}'; skipping automatic override",
                    auto_migrate
                ));
            }
        } else {
            forced_env.insert("DATABASE_AUTO_MIGRATE".into(), "true".into());
            print_info(
                "Setting DATABASE_AUTO_MIGRATE=true for this run. Use --no-migrate to disable.",
            );
        }
    }
    child_env.extend(forced_env.clone());

    if !args.no_watch {
        return watch::run(WatchConfig {
            project_dir,
            cargo_args: args.args,
            load_env: !args.no_env,
            forced_env,
        });
    }

    let mut command = Command::new("cargo");
    command
        .arg("run")
        .args(&args.args)
        .current_dir(&project_dir)
        .envs(&child_env);

    print_info("Starting Tideway app (primary local run command)...");
    let status = command.status().context("Failed to run cargo")?;

    if status.success() {
        print_success("Process exited cleanly");
        Ok(())
    } else {
        Err(anyhow::anyhow!("cargo exited with status {}", status))
    }
}

fn build_dev_plan(args: &DevArgs) -> ExecutionPlan {
    let mode = if args.no_watch {
        "cargo run once"
    } else {
        "watch, build, and restart"
    };
    let summary = if args.no_migrate {
        format!("would {mode} without auto-migrations")
    } else {
        format!("would {mode} with env + migrations")
    };

    let cargo_action = if args.no_watch { "run" } else { "build" };
    let (cargo_args, app_args) = if args.no_watch {
        (args.args.clone(), Vec::new())
    } else {
        watch::split_args(args.args.clone())
    };
    let mut command = PlannedCommand::new("cargo")
        .arg(cargo_action)
        .cwd(args.path.clone());
    if !cargo_args.is_empty() {
        command = command.args(cargo_args);
    }

    let mut plan = ExecutionPlan::new(summary)
        .command(command)
        .info("Primary run command for local development.");
    plan = if args.no_watch {
        plan.info("One-shot local run (--no-watch).")
    } else {
        plan.info("Would watch source and manifest changes, rebuild, and restart on success.")
    };
    if !app_args.is_empty() {
        plan = plan.info(format!(
            "Would pass application arguments after rebuild: {}",
            app_args.join(" ")
        ));
    }

    if args.no_env {
        plan = plan.info("Skipping `.env` loading (--no-env).");
    } else if args.fix_env {
        plan = plan.info("Would bootstrap `.env` from `.env.example` when missing.");
    }

    if args.no_migrate {
        plan.info("Skipping automatic migrations (--no-migrate).")
    } else {
        plan.info("Would set `DATABASE_AUTO_MIGRATE=true` when not already defined.")
    }
}

fn explicit_auto_migrate(env_map: &Option<BTreeMap<String, String>>) -> Option<String> {
    effective_env_value(env_map, "DATABASE_AUTO_MIGRATE").map(|value| value.trim().to_string())
}

fn preflight_database(
    project_dir: &Path,
    env_map: &Option<BTreeMap<String, String>>,
) -> Result<()> {
    if !project_uses_database(project_dir)? {
        return Ok(());
    }

    let database_url = resolve_database_url(env_map).ok_or_else(|| {
        anyhow::anyhow!(error_contract(
            "DATABASE_URL is missing.",
            "Set DATABASE_URL in `.env` or your shell, then rerun `tideway dev`.",
            &format!(
                "Run {} to bootstrap `.env` from `.env.example`.",
                DEV_FIX_ENV_COMMAND
            )
        ))
    })?;

    match validate_database_url(&database_url).map_err(|err| {
        anyhow::anyhow!(error_contract(
            &err.to_string(),
            "Use a URL like `postgres://...` or `sqlite:...`.",
            "Regenerate config with `tideway doctor --fix` and update DATABASE_URL."
        ))
    })? {
        DatabaseUrlKind::Sqlite => Ok(()),
        DatabaseUrlKind::Postgres => preflight_postgres(project_dir, &database_url),
    }
}

fn project_uses_database(project_dir: &Path) -> Result<bool> {
    let cargo_path = project_dir.join("Cargo.toml");
    let contents = fs::read_to_string(&cargo_path)
        .with_context(|| format!("Failed to read {}", cargo_path.display()))?;
    let doc = contents
        .parse::<DocumentMut>()
        .context("Failed to parse Cargo.toml")?;

    Ok(has_dependency(&doc, "sea-orm") || has_tideway_feature(&doc, "database"))
}

fn print_local_urls(project_dir: &Path, env_map: &Option<BTreeMap<String, String>>) -> Result<()> {
    let port = effective_env_value(env_map, "TIDEWAY_PORT")
        .or_else(|| effective_env_value(env_map, "PORT"))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "8000".to_string());
    let base_url = format!("http://localhost:{port}");
    print_info("Local URLs once the server is ready:");
    print_info(&format!("API: {base_url}"));
    print_info(&format!("Health: {base_url}/health"));

    if project_uses_tideway_feature(project_dir, "openapi")? {
        let openapi_enabled = env_flag(env_map, "OPENAPI_ENABLED", false);
        if openapi_enabled && env_flag(env_map, "OPENAPI_SWAGGER_UI", false) {
            print_info(&format!("Swagger UI: {base_url}/swagger-ui"));
        }
        if openapi_enabled && env_flag(env_map, "OPENAPI_SERVE_SPEC", false) {
            print_info(&format!("OpenAPI: {base_url}/api-docs/openapi.json"));
        }
    }
    Ok(())
}

fn env_flag(env_map: &Option<BTreeMap<String, String>>, key: &str, default: bool) -> bool {
    effective_env_value(env_map, key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn effective_env_value(env_map: &Option<BTreeMap<String, String>>, key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => {
            env_map.as_ref().and_then(|env| env.get(key)).cloned()
        }
        Err(std::env::VarError::NotUnicode(_)) => None,
    }
}

fn project_uses_tideway_feature(project_dir: &Path, feature: &str) -> Result<bool> {
    let cargo_path = project_dir.join("Cargo.toml");
    let contents = fs::read_to_string(&cargo_path)
        .with_context(|| format!("Failed to read {}", cargo_path.display()))?;
    let doc = contents
        .parse::<DocumentMut>()
        .context("Failed to parse Cargo.toml")?;
    Ok(has_tideway_feature(&doc, feature))
}

fn has_tideway_feature(doc: &DocumentMut, feature: &str) -> bool {
    runtime_dependency_sections(doc)
        .into_iter()
        .filter_map(|deps| deps.get("tideway"))
        .filter_map(|tideway| tideway.get("features"))
        .filter_map(|features| features.as_array())
        .any(|arr| arr.iter().any(|value| value.as_str() == Some(feature)))
}

fn has_dependency(doc: &DocumentMut, dependency: &str) -> bool {
    runtime_dependency_sections(doc)
        .into_iter()
        .any(|deps| deps.get(dependency).is_some())
}

fn runtime_dependency_sections(doc: &DocumentMut) -> Vec<&toml_edit::Item> {
    let mut sections = Vec::new();

    if let Some(item) = doc.get("dependencies") {
        sections.push(item);
    }

    if let Some(targets) = doc.get("target").and_then(|item| item.as_table()) {
        for (_, target) in targets.iter() {
            if let Some(deps) = target.get("dependencies") {
                sections.push(deps);
            }
        }
    }

    sections
}

fn preflight_postgres(project_dir: &Path, database_url: &str) -> Result<()> {
    let parsed = Url::parse(database_url).map_err(|err| {
        anyhow::anyhow!(error_contract(
            &format!("DATABASE_URL could not be parsed: {}", err),
            "Use a URL like `postgres://user:password@host:5432/database`.",
            "Regenerate config with `tideway doctor --fix` and update DATABASE_URL."
        ))
    })?;
    let host = parsed.host_str().ok_or_else(|| {
        anyhow::anyhow!(error_contract(
            &format!(
                "DATABASE_URL is missing a host: {}",
                redact_database_url(database_url)
            ),
            "Set DATABASE_URL to a valid Postgres host and rerun `tideway dev`.",
            "Regenerate config with `tideway doctor --fix` and update DATABASE_URL."
        ))
    })?;
    let port = parsed.port_or_known_default().unwrap_or(5432);
    let host = host.to_string();

    if !tcp_connectable(&host, port, Duration::from_secs(1)) {
        let redacted = redact_database_url(database_url);
        return Err(anyhow::anyhow!(error_contract(
            &format!("Postgres is not reachable at {}", redacted),
            &postgres_primary_fix(project_dir, &host),
            "Start Postgres or update DATABASE_URL to a reachable server, then rerun `tideway dev`."
        )));
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("Failed to create Tokio runtime for Postgres preflight")?;

    rt.block_on(async move {
        if can_connect_to_postgres(database_url).await? {
            return Ok(());
        }

        if is_local_postgres_host(&host) {
            ensure_local_postgres_database(project_dir, &parsed).await
        } else {
            Err(anyhow::anyhow!(error_contract(
                &format!(
                    "Failed to open the configured Postgres database at {}",
                    redact_database_url(database_url)
                ),
                "Ensure the database exists and the credentials in DATABASE_URL are correct, then rerun `tideway dev`.",
                "Point DATABASE_URL at an existing Postgres database if this environment should not auto-provision."
            )))
        }
    })
}

async fn can_connect_to_postgres(database_url: &str) -> Result<bool> {
    let options = postgres_connect_options(database_url)?;
    match PgConnection::connect_with(&options).await {
        Ok(connection) => {
            connection.close().await.ok();
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

async fn ensure_local_postgres_database(project_dir: &Path, parsed: &Url) -> Result<()> {
    let database_name = postgres_database_name(parsed).ok_or_else(|| {
        anyhow::anyhow!(error_contract(
            &format!(
                "DATABASE_URL is missing a database name: {}",
                redact_database_url(parsed.as_str())
            ),
            "Set DATABASE_URL to include the Postgres database name and rerun `tideway dev`.",
            "Regenerate config with `tideway doctor --fix` and update DATABASE_URL."
        ))
    })?;
    let admin_url = build_postgres_admin_url(parsed)?;
    let redacted_target = redact_database_url(parsed.as_str());
    let redacted_admin = redact_database_url(&admin_url);

    let mut connection = PgConnection::connect_with(&postgres_connect_options(&admin_url)?)
        .await
        .map_err(|err| {
            anyhow::anyhow!(error_contract(
                &format!(
                    "Failed to connect to Postgres for database preflight at {}: {}",
                    redacted_admin, err
                ),
                &postgres_primary_fix(project_dir, parsed.host_str().unwrap_or("localhost")),
                "Check DATABASE_URL credentials or create the database manually, then rerun `tideway dev`."
            ))
        })?;

    let exists = sqlx::query_scalar::<_, i64>("SELECT 1 FROM pg_database WHERE datname = $1")
        .bind(database_name.as_str())
        .fetch_optional(&mut connection)
        .await
        .map_err(|err| {
            anyhow::anyhow!(error_contract(
                &format!(
                    "Failed to inspect Postgres databases at {}: {}",
                    redacted_admin, err
                ),
                "Check DATABASE_URL credentials and server permissions, then rerun `tideway dev`.",
                "Create the database manually if this Postgres role cannot inspect `pg_database`."
            ))
        })?;

    if exists.is_some() {
        return Err(anyhow::anyhow!(error_contract(
            &format!(
                "Failed to open the configured Postgres database at {}",
                redacted_target
            ),
            "Check DATABASE_URL credentials and permissions, then rerun `tideway dev`.",
            "Create the database manually or point DATABASE_URL at a database this role can access."
        )));
    }

    let create_statement = format!(
        "CREATE DATABASE \"{}\"",
        escape_postgres_identifier(&database_name)
    );
    connection
        .execute(sqlx::query(&create_statement))
        .await
        .map_err(|err| {
            anyhow::anyhow!(error_contract(
                &format!(
                    "Failed to create local Postgres database `{}` via {}: {}",
                    database_name, redacted_admin, err
                ),
                "Create the database manually or grant CREATEDB to the configured Postgres role, then rerun `tideway dev`.",
                "Update DATABASE_URL to an existing database if local auto-provisioning is not appropriate."
            ))
        })?;

    print_success(&format!(
        "Created local Postgres database `{}` before launch",
        database_name
    ));

    Ok(())
}

fn postgres_connect_options(database_url: &str) -> Result<PgConnectOptions> {
    PgConnectOptions::from_str(database_url)
        .map_err(|err| anyhow::anyhow!("invalid Postgres DATABASE_URL: {}", err))
}

fn build_postgres_admin_url(parsed: &Url) -> Result<String> {
    let mut admin_url = parsed.clone();
    admin_url.set_path("/postgres");
    Ok(admin_url.to_string())
}

fn postgres_database_name(parsed: &Url) -> Option<String> {
    parsed
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(ToString::to_string)
}

fn escape_postgres_identifier(identifier: &str) -> String {
    identifier.replace('"', "\"\"")
}

fn tcp_connectable(host: &str, port: u16, timeout: Duration) -> bool {
    let Ok(addrs) = (host, port).to_socket_addrs() else {
        return false;
    };

    addrs
        .into_iter()
        .any(|addr| TcpStream::connect_timeout(&addr, timeout).is_ok())
}

fn is_local_postgres_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn postgres_primary_fix(project_dir: &Path, host: &str) -> String {
    if is_local_postgres_host(host) && project_dir.join("docker-compose.yml").exists() {
        "Run `docker compose up -d` in the project root, then rerun `tideway dev`.".to_string()
    } else {
        "Start Postgres for the configured DATABASE_URL, then rerun `tideway dev`.".to_string()
    }
}
