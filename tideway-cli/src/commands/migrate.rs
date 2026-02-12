//! Migrate command - run database migrations via the configured backend.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli::{MigrateArgs, MigrateBackend};
use crate::env::{ensure_env, ensure_project_dir, read_env_map};
use crate::{error_contract, is_plan_mode, print_info, print_success, print_warning};

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
            MigrateBackend::Auto => Err(anyhow::anyhow!(error_contract(
                "Unable to detect migration backend.",
                "Pass `--backend sea-orm`.",
                "Add SeaORM dependencies and Tideway `database` feature, then rerun."
            ))),
        };
    }

    let backend = resolve_backend(&project_dir, args.backend)?;
    match backend {
        MigrateBackend::SeaOrm => run_sea_orm_cli(&project_dir, &args),
        MigrateBackend::Auto => Err(anyhow::anyhow!(error_contract(
            "Unable to detect migration backend.",
            "Pass `--backend sea-orm`.",
            "Add SeaORM dependencies and Tideway `database` feature, then rerun."
        ))),
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

    let has_sea_orm = has_dependency(&doc, "sea-orm");
    let has_tideway_db = has_tideway_feature(&doc, "database");

    if has_sea_orm || has_tideway_db {
        Ok(MigrateBackend::SeaOrm)
    } else {
        Err(anyhow::anyhow!(error_contract(
            "Could not detect migration backend.",
            "Add SeaORM dependencies or use `--backend sea-orm`.",
            "For greenfield apps, run `tideway new <app> --preset api`."
        )))
    }
}

fn has_tideway_feature(doc: &toml_edit::DocumentMut, feature: &str) -> bool {
    dependency_sections(doc)
        .into_iter()
        .filter_map(|deps| deps.get("tideway"))
        .filter_map(|tideway| tideway.get("features"))
        .filter_map(|features| features.as_array())
        .any(|arr| arr.iter().any(|value| value.as_str() == Some(feature)))
}

fn has_dependency(doc: &toml_edit::DocumentMut, dependency: &str) -> bool {
    dependency_sections(doc)
        .into_iter()
        .any(|deps| deps.get(dependency).is_some())
}

fn dependency_sections<'a>(doc: &'a toml_edit::DocumentMut) -> Vec<&'a toml_edit::Item> {
    let mut sections = Vec::new();

    if let Some(item) = doc.get("dependencies") {
        sections.push(item);
    }

    if let Some(item) = doc.get("build-dependencies") {
        sections.push(item);
    }

    if let Some(item) = doc.get("dev-dependencies") {
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
        "{}",
        error_contract(
            "DATABASE_URL is missing.",
            "Set DATABASE_URL in `.env` and rerun `tideway migrate`.",
            "Run `tideway dev --fix-env` to bootstrap `.env` from `.env.example`."
        )
    ))
}

fn validate_database_url(value: &str) -> Result<()> {
    if !value.contains("://") {
        return Err(anyhow::anyhow!(
            "{}",
            error_contract(
                &format!("DATABASE_URL looks invalid (missing scheme): {}", value),
                "Use a URL like `postgres://...` or `sqlite:...`.",
                "Regenerate config with `tideway doctor --fix` and update DATABASE_URL."
            )
        ));
    }

    let lower = value.to_lowercase();
    let valid = lower.starts_with("postgres://")
        || lower.starts_with("postgresql://")
        || lower.starts_with("sqlite:");

    if !valid {
        return Err(anyhow::anyhow!(
            "{}",
            error_contract(
                &format!("DATABASE_URL scheme looks invalid: {}", value),
                "Use `postgres://`, `postgresql://`, or `sqlite:`.",
                "Update `.env` and rerun `tideway migrate status`."
            )
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
