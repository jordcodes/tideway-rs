//! New command - scaffold a minimal Tideway app.

use anyhow::{anyhow, Context, Result};
use colored::Colorize;
use dialoguer::{console::Term, theme::ColorfulTheme, Confirm, MultiSelect};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::NewArgs;
use crate::templates::{BackendTemplateContext, BackendTemplateEngine};
use crate::{print_info, print_success, print_warning};

/// Run the new command
pub fn run(mut args: NewArgs) -> Result<()> {
    if should_prompt(&args) {
        prompt_for_options(&mut args)?;
    }

    let dir_name = args.path.clone().unwrap_or_else(|| args.name.clone());
    let project_name = normalize_project_name(&args.name);
    let project_name_pascal = to_pascal_case(&project_name);
    let features = normalize_features(&args.features);
    let has_auth_feature = features.contains("auth");
    let has_database_feature = features.contains("database");
    let has_tideway_features = !features.is_empty();

    let target_dir = PathBuf::from(&dir_name);
    if target_dir.exists() {
        if !args.force {
            return Err(anyhow!(
                "Destination already exists: {} (use --force to overwrite)",
                target_dir.display()
            ));
        }
        print_warning(&format!(
            "Destination exists, files may be overwritten: {}",
            target_dir.display()
        ));
    }

    fs::create_dir_all(&target_dir)
        .with_context(|| format!("Failed to create {}", target_dir.display()))?;

    let needs_arc = has_auth_feature || has_database_feature;
    let context = BackendTemplateContext {
        project_name: project_name.clone(),
        project_name_pascal,
        has_organizations: false,
        database: "postgres".to_string(),
        tideway_features: features.iter().cloned().collect(),
        has_tideway_features,
        has_auth_feature,
        has_database_feature,
        needs_arc,
        has_config: args.with_config,
    };
    let engine = BackendTemplateEngine::new(context)?;

    let needs_env = needs_env_from_args(&args);
    scaffold_files(&target_dir, &engine, &args, needs_env)?;
    let created = expected_files(&args);

    println!(
        "\n{} {}\n",
        "tideway".cyan().bold(),
        "starter app created".green().bold()
    );

    print_info(&format!("Project name: {}", project_name.green()));
    print_info(&format!("Location: {}", target_dir.display().to_string().yellow()));
    if has_tideway_features {
        print_info(&format!(
            "Tideway features: {}",
            features
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
                .green()
        ));
    }

    if args.summary {
        println!("\n{}", "Generated files:".yellow().bold());
        for path in &created {
            println!("  - {}", path);
        }
    }

    println!("\n{}", "Next steps:".yellow().bold());
    println!("  1. cd {}", dir_name);
    let mut step = 2;
    if args.with_docker {
        println!("  {}. docker compose up -d", step);
        step += 1;
    }
    if has_auth_feature || has_database_feature || args.with_config {
        println!("  {}. cp .env.example .env", step);
        step += 1;
    }
    println!("  {}. cargo run", step);
    println!();

    print_success("Ready to build");
    Ok(())
}

fn scaffold_files(
    target_dir: &Path,
    engine: &BackendTemplateEngine,
    args: &NewArgs,
    needs_env: bool,
) -> Result<()> {
    write_file(
        &target_dir.join("Cargo.toml"),
        &engine.render("starter/Cargo.toml")?,
        args.force,
    )?;
    write_file(
        &target_dir.join("src/main.rs"),
        &engine.render("starter/src/main.rs")?,
        args.force,
    )?;
    write_file(
        &target_dir.join("src/routes/mod.rs"),
        &engine.render("starter/src/routes/mod.rs")?,
        args.force,
    )?;

    if args.with_config {
        write_file(
            &target_dir.join("src/config.rs"),
            &engine.render("starter/src/config.rs")?,
            args.force,
        )?;
        write_file(
            &target_dir.join("src/error.rs"),
            &engine.render("starter/src/error.rs")?,
            args.force,
        )?;
    }
    if args.with_docker {
        write_file(
            &target_dir.join("docker-compose.yml"),
            &engine.render("starter/docker-compose")?,
            args.force,
        )?;
    }
    if args.with_ci {
        write_file(
            &target_dir.join(".github/workflows/ci.yml"),
            &engine.render("starter/github-ci")?,
            args.force,
        )?;
    }
    write_file(
        &target_dir.join(".gitignore"),
        &engine.render("starter/gitignore")?,
        args.force,
    )?;

    write_file(
        &target_dir.join("tests/health.rs"),
        &engine.render("starter/tests/health")?,
        args.force,
    )?;

    if needs_env {
        write_file(
            &target_dir.join(".env.example"),
            &engine.render("starter/env_example")?,
            args.force,
        )?;
    }

    Ok(())
}

pub fn expected_files(args: &NewArgs) -> Vec<String> {
    let needs_env = needs_env_from_args(args);
    let mut files = vec![
        "Cargo.toml".to_string(),
        "src/main.rs".to_string(),
        "src/routes/mod.rs".to_string(),
    ];

    if args.with_config {
        files.push("src/config.rs".to_string());
        files.push("src/error.rs".to_string());
    }
    if args.with_docker {
        files.push("docker-compose.yml".to_string());
    }
    if args.with_ci {
        files.push(".github/workflows/ci.yml".to_string());
    }

    files.push(".gitignore".to_string());
    files.push("tests/health.rs".to_string());

    if needs_env {
        files.push(".env.example".to_string());
    }

    files
}
fn write_file(path: &Path, contents: &str, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(anyhow!(
            "File already exists: {} (use --force to overwrite)",
            path.display()
        ));
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }

    fs::write(path, contents)
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

fn normalize_project_name(name: &str) -> String {
    name.trim().replace('-', "_")
}

fn normalize_features(features: &[String]) -> BTreeSet<String> {
    let mut normalized = BTreeSet::new();
    for feature in features {
        let trimmed = feature.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lowered = trimmed.to_lowercase();
        let mapped = match lowered.as_str() {
            "db" => "database",
            "session" => "sessions",
            other => other,
        };
        normalized.insert(mapped.to_string());
    }
    normalized
}

fn needs_env_from_args(args: &NewArgs) -> bool {
    let features = normalize_features(&args.features);
    features.contains("auth") || features.contains("database") || args.with_config
}

fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .filter(|part| !part.is_empty())
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().chain(chars).collect(),
            }
        })
        .collect()
}

fn should_prompt(args: &NewArgs) -> bool {
    args.features.is_empty()
        && !args.with_config
        && !args.with_docker
        && !args.with_ci
        && !args.no_prompt
        && Term::stdout().is_term()
}

fn prompt_for_options(args: &mut NewArgs) -> Result<()> {
    let theme = ColorfulTheme::default();

    let options = [
        "auth",
        "database",
        "cache",
        "sessions",
        "jobs",
        "email",
        "websocket",
        "metrics",
        "validation",
        "openapi",
    ];

    let selections = MultiSelect::with_theme(&theme)
        .with_prompt("Select Tideway features (space to select)")
        .items(&options)
        .interact()
        .map_err(|e| anyhow!("Prompt failed: {}", e))?;

    args.features = selections
        .iter()
        .map(|idx| options[*idx].to_string())
        .collect();

    args.with_config = Confirm::with_theme(&theme)
        .with_prompt("Generate config.rs and error.rs?")
        .default(false)
        .interact()
        .map_err(|e| anyhow!("Prompt failed: {}", e))?;

    args.with_docker = Confirm::with_theme(&theme)
        .with_prompt("Generate docker-compose.yml for Postgres?")
        .default(false)
        .interact()
        .map_err(|e| anyhow!("Prompt failed: {}", e))?;

    args.with_ci = Confirm::with_theme(&theme)
        .with_prompt("Generate GitHub Actions CI workflow?")
        .default(false)
        .interact()
        .map_err(|e| anyhow!("Prompt failed: {}", e))?;

    Ok(())
}
