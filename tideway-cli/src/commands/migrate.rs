//! Migrate command - run database migrations via the configured backend.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli::{MigrateArgs, MigrateBackend};
use crate::env::{ensure_env, ensure_project_dir, read_env_map};
use crate::{is_plan_mode, print_info, print_success, print_warning};

pub fn run(args: MigrateArgs) -> Result<()> {
    if is_plan_mode() {
        print_info(&format!("Plan: would run migrations ({})", args.action));
        return Ok(());
    }
    let project_dir = PathBuf::from(&args.path);
    ensure_project_dir(&project_dir)?;

    if !args.no_env {
        ensure_env(&project_dir, args.fix_env)?;
    }

    if args.action == "init" {
        let backend = resolve_backend(&project_dir, args.backend)?;
        return match backend {
            MigrateBackend::SeaOrm => init_sea_orm_migration(&project_dir),
            MigrateBackend::Auto => Err(anyhow::anyhow!(
                "Unable to detect migration backend; pass --backend"
            )),
        };
    }

    let backend = resolve_backend(&project_dir, args.backend)?;
    match backend {
        MigrateBackend::SeaOrm => run_sea_orm_cli(&project_dir, &args),
        MigrateBackend::Auto => Err(anyhow::anyhow!(
            "Unable to detect migration backend; pass --backend"
        )),
    }
}

fn resolve_backend(project_dir: &Path, backend: MigrateBackend) -> Result<MigrateBackend> {
    match backend {
        MigrateBackend::Auto => detect_backend(project_dir),
        MigrateBackend::SeaOrm => Ok(MigrateBackend::SeaOrm),
    }
}

fn detect_backend(project_dir: &Path) -> Result<MigrateBackend> {
    let cargo_path = project_dir.join("Cargo.toml");
    let contents = fs::read_to_string(&cargo_path)
        .with_context(|| format!("Failed to read {}", cargo_path.display()))?;
    let doc = contents
        .parse::<toml_edit::DocumentMut>()
        .context("Failed to parse Cargo.toml")?;

    let deps = doc.get("dependencies");
    let has_sea_orm = deps.and_then(|deps| deps.get("sea-orm")).is_some();
    let has_tideway_db = deps
        .and_then(|deps| deps.get("tideway"))
        .and_then(|item| item.get("features"))
        .and_then(|item| item.as_array())
        .map(|arr| arr.iter().any(|v| v.as_str() == Some("database")))
        .unwrap_or(false);

    if has_sea_orm || has_tideway_db {
        Ok(MigrateBackend::SeaOrm)
    } else {
        Err(anyhow::anyhow!(
            "Could not detect migration backend (add sea-orm or pass --backend)"
        ))
    }
}

fn run_sea_orm_cli(project_dir: &Path, args: &MigrateArgs) -> Result<()> {
    let migrations_dir = project_dir.join("migration");
    if !migrations_dir.exists() {
        print_warning("migration/ directory not found; sea-orm-cli may fail");
    }

    if args.action == "status"
        || args.action == "up"
        || args.action == "down"
        || args.action == "reset"
    {
        ensure_database_url(project_dir)?;
    }

    let mut command = Command::new("sea-orm-cli");
    command
        .arg("migrate")
        .arg(&args.action)
        .current_dir(project_dir);

    if !args.args.is_empty() {
        command.args(&args.args);
    }

    if !args.no_env {
        if let Some(env_map) = read_env_map(&project_dir.join(".env")) {
            command.envs(env_map);
        }
    }

    print_info(&format!("Running sea-orm-cli migrate {}...", args.action));
    let status = command
        .status()
        .context("Failed to run sea-orm-cli (is it installed?)")?;

    if status.success() {
        print_success("Migrations completed");
        Ok(())
    } else {
        Err(anyhow::anyhow!("sea-orm-cli exited with status {}", status))
    }
}

fn ensure_database_url(project_dir: &Path) -> Result<()> {
    if let Some(env_map) = read_env_map(&project_dir.join(".env")) {
        if let Some(value) = env_map.get("DATABASE_URL") {
            validate_database_url(value)?;
            return Ok(());
        }
    }

    if let Ok(value) = std::env::var("DATABASE_URL") {
        validate_database_url(&value)?;
        return Ok(());
    }

    Err(anyhow::anyhow!(
        "DATABASE_URL is missing (set it in .env or the environment)"
    ))
}

fn validate_database_url(value: &str) -> Result<()> {
    if !value.contains("://") {
        return Err(anyhow::anyhow!(
            "DATABASE_URL looks invalid (missing scheme): {}",
            value
        ));
    }

    let lower = value.to_lowercase();
    let valid = lower.starts_with("postgres://")
        || lower.starts_with("postgresql://")
        || lower.starts_with("sqlite:");

    if !valid {
        return Err(anyhow::anyhow!(
            "DATABASE_URL scheme looks invalid: {}",
            value
        ));
    }

    Ok(())
}

fn init_sea_orm_migration(project_dir: &Path) -> Result<()> {
    let migration_root = project_dir.join("migration");
    if migration_root.exists() {
        print_warning("migration/ already exists; skipping init");
        return Ok(());
    }

    let mut command = Command::new("sea-orm-cli");
    command.arg("migrate").arg("init").current_dir(project_dir);

    if let Some(env_map) = read_env_map(&project_dir.join(".env")) {
        command.envs(env_map);
    }

    print_info("Initializing SeaORM migration crate...");
    let status = command
        .status()
        .context("Failed to run sea-orm-cli (is it installed?)")?;

    if status.success() {
        print_success("Migration crate initialized");
        Ok(())
    } else {
        Err(anyhow::anyhow!("sea-orm-cli exited with status {}", status))
    }
}
