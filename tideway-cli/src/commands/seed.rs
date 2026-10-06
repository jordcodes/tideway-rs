//! Seed command - load development/demo data by running the app's seed binary.
//!
//! Convention: database-backed apps own an idempotent `src/bin/seed.rs` binary. `tideway seed`
//! loads `.env`, validates `DATABASE_URL`, and runs `cargo run --bin seed`.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli::SeedArgs;
use crate::commands::migrate::ensure_database_url;
use crate::env::{ensure_env, ensure_project_dir, read_env_map};
use crate::{
    CommandRuntime, ExecutionPlan, PlannedCommand, error_contract, print_info, print_success,
};

pub fn run(args: SeedArgs) -> Result<()> {
    run_with_runtime(args, CommandRuntime::from_process_state())
}

pub fn run_with_runtime(args: SeedArgs, runtime: CommandRuntime) -> Result<()> {
    runtime.install();

    if runtime.plan_mode() {
        build_seed_plan(&args).emit(runtime);
        return Ok(());
    }
    let project_dir = PathBuf::from(&args.path);
    ensure_project_dir(&project_dir)?;

    if !has_seed_binary(&project_dir, &args.bin)? {
        return Err(anyhow::anyhow!(error_contract(
            &format!("No `{}` binary found for seeding.", args.bin),
            &format!(
                "Create `src/bin/{}.rs` that connects with DATABASE_URL and inserts demo rows idempotently.",
                args.bin
            ),
            "New database-backed apps from `tideway new` include one; see docs/cli.md#tideway-seed."
        )));
    }

    if !args.no_env {
        ensure_env(&project_dir, args.fix_env)?;
    }
    ensure_database_url(&project_dir)?;

    let mut command = Command::new("cargo");
    command
        .arg("run")
        .arg("--bin")
        .arg(&args.bin)
        .current_dir(&project_dir);

    if !args.args.is_empty() {
        command.arg("--").args(&args.args);
    }

    // Shell variables win over `.env`, matching how DATABASE_URL was validated above.
    if !args.no_env
        && let Some(env_map) = read_env_map(&project_dir.join(".env"))
    {
        command.envs(
            env_map
                .into_iter()
                .filter(|(key, _)| std::env::var_os(key).is_none()),
        );
    }

    print_info(&format!("Running cargo run --bin {}...", args.bin));
    let status = command.status().context("Failed to run cargo")?;

    if status.success() {
        print_success("Database seeded");
        Ok(())
    } else {
        Err(anyhow::anyhow!("seed binary exited with status {}", status))
    }
}

fn build_seed_plan(args: &SeedArgs) -> ExecutionPlan {
    let mut command = PlannedCommand::new("cargo")
        .arg("run")
        .arg("--bin")
        .arg(args.bin.clone())
        .cwd(args.path.clone());

    if !args.args.is_empty() {
        command = command.arg("--").args(args.args.clone());
    }

    let mut plan = ExecutionPlan::new(format!("would seed the database ({})", args.bin))
        .command(command)
        .info("DATABASE_URL will be validated at execution time.");

    if args.no_env {
        plan = plan.info("Skipping `.env` loading (--no-env).");
    } else if args.fix_env {
        plan = plan.info("Would bootstrap `.env` from `.env.example` when missing.");
    }

    plan
}

/// Whether the project defines the seed binary, either by Cargo's `src/bin` auto-discovery or
/// an explicit `[[bin]]` target.
fn has_seed_binary(project_dir: &Path, bin: &str) -> Result<bool> {
    let bin_dir = project_dir.join("src/bin");
    if bin_dir.join(format!("{bin}.rs")).exists() || bin_dir.join(bin).join("main.rs").exists() {
        return Ok(true);
    }

    let cargo_path = project_dir.join("Cargo.toml");
    let contents = fs::read_to_string(&cargo_path)
        .with_context(|| format!("Failed to read {}", cargo_path.display()))?;
    let doc = contents
        .parse::<toml_edit::DocumentMut>()
        .context("Failed to parse Cargo.toml")?;

    Ok(doc
        .get("bin")
        .and_then(|item| item.as_array_of_tables())
        .is_some_and(|bins| {
            bins.iter()
                .any(|target| target.get("name").and_then(|name| name.as_str()) == Some(bin))
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, contents: &str) {
        crate::ensure_dir(path.parent().expect("parent")).expect("create dir");
        crate::write_file(path, contents).expect("write file");
    }

    #[test]
    fn detects_seed_binary_from_src_bin_and_manifest() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path();
        write(&root.join("Cargo.toml"), "[package]\nname = \"app\"\n");
        assert!(!has_seed_binary(root, "seed").expect("detect"));

        write(&root.join("src/bin/seed.rs"), "fn main() {}\n");
        assert!(has_seed_binary(root, "seed").expect("detect"));
        assert!(!has_seed_binary(root, "demo").expect("detect"));

        write(
            &root.join("Cargo.toml"),
            "[package]\nname = \"app\"\n\n[[bin]]\nname = \"demo\"\npath = \"tools/demo.rs\"\n",
        );
        assert!(has_seed_binary(root, "demo").expect("detect"));
    }
}
