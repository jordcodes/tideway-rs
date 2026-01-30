//! Dev command - run a Tideway app with sensible defaults.

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli::DevArgs;
use crate::{print_info, print_success, print_warning};

pub fn run(args: DevArgs) -> Result<()> {
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

    print_info("Starting Tideway app...");
    let status = command.status().context("Failed to run cargo")?;

    if status.success() {
        print_success("Process exited cleanly");
        Ok(())
    } else {
        Err(anyhow::anyhow!("cargo exited with status {}", status))
    }
}

fn ensure_project_dir(project_dir: &Path) -> Result<()> {
    let cargo_toml = project_dir.join("Cargo.toml");
    if !cargo_toml.exists() {
        return Err(anyhow::anyhow!(
            "Cargo.toml not found in {}",
            project_dir.display()
        ));
    }

    let main_rs = project_dir.join("src").join("main.rs");
    if !main_rs.exists() {
        print_warning("src/main.rs not found (run `tideway init` if this is a Tideway project)");
    }

    Ok(())
}

fn ensure_env(project_dir: &Path, fix_env: bool) -> Result<()> {
    let env_path = project_dir.join(".env");
    if env_path.exists() {
        return Ok(());
    }

    let env_example_path = project_dir.join(".env.example");
    if !env_example_path.exists() {
        print_warning(".env not found and .env.example is missing");
        return Ok(());
    }

    if fix_env {
        fs::copy(&env_example_path, &env_path)
            .with_context(|| format!("Failed to copy {}", env_example_path.display()))?;
        print_success("Created .env from .env.example");
        return Ok(());
    }

    print_warning("Missing .env (copy .env.example or run with --fix-env)");
    Ok(())
}

fn read_env_map(path: &Path) -> Option<BTreeMap<String, String>> {
    let contents = fs::read_to_string(path).ok()?;
    Some(parse_env_map(&contents))
}

fn parse_env_map(contents: &str) -> BTreeMap<String, String> {
    let mut vars = BTreeMap::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim();
            if !key.is_empty() {
                let value = value.trim().trim_matches('"').trim_matches('\'');
                vars.insert(key.to_string(), value.to_string());
            }
        }
    }
    vars
}
