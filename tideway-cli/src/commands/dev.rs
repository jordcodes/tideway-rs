//! Dev command - run a Tideway app with sensible defaults.

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use crate::cli::DevArgs;
use crate::env::{ensure_env, ensure_project_dir, read_env_map};
use crate::is_plan_mode;
use crate::{print_info, print_success, print_warning};

pub fn run(args: DevArgs) -> Result<()> {
    if is_plan_mode() {
        print_info("Plan: would run tideway dev (cargo run) with env + migrations");
        print_info("Primary run command for local development.");
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

    let mut command = Command::new("cargo");
    command.arg("run").current_dir(&project_dir);

    if !args.args.is_empty() {
        command.args(&args.args);
    }

    if !args.no_env {
        if let Some(env_map) = &env_map {
            command.envs(env_map);
        }
    }

    if !args.no_migrate {
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
            command.env("DATABASE_AUTO_MIGRATE", "true");
            print_info(
                "Setting DATABASE_AUTO_MIGRATE=true for this run. Use --no-migrate to disable.",
            );
        }
    }

    print_info("Starting Tideway app (primary local run command)...");
    let status = command.status().context("Failed to run cargo")?;

    if status.success() {
        print_success("Process exited cleanly");
        Ok(())
    } else {
        Err(anyhow::anyhow!("cargo exited with status {}", status))
    }
}

fn explicit_auto_migrate(env_map: &Option<BTreeMap<String, String>>) -> Option<String> {
    if let Ok(value) = std::env::var("DATABASE_AUTO_MIGRATE") {
        return Some(value.trim().to_string());
    }

    if let Some(map) = env_map {
        if let Some(value) = map.get("DATABASE_AUTO_MIGRATE") {
            return Some(value.trim().to_string());
        }
    }

    None
}
