//! Dev command - run a Tideway app with sensible defaults.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::Command;

use crate::cli::DevArgs;
use crate::env::{ensure_env, ensure_project_dir, read_env_map};
use crate::is_plan_mode;
use crate::{print_info, print_success};

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

    let mut command = Command::new("cargo");
    command.arg("run").current_dir(&project_dir);

    if !args.args.is_empty() {
        command.args(&args.args);
    }

    if !args.no_env {
        if let Some(env_map) = read_env_map(&project_dir.join(".env")) {
            command.envs(env_map);
        }
    }

    if !args.no_migrate {
        command.env("DATABASE_AUTO_MIGRATE", "true");
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
