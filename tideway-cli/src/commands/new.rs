//! New command - scaffold a minimal Tideway app.

use anyhow::{anyhow, Context, Result};
use colored::Colorize;
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::NewArgs;
use crate::templates::{BackendTemplateContext, BackendTemplateEngine};
use crate::{print_info, print_success, print_warning};

/// Run the new command
pub fn run(args: NewArgs) -> Result<()> {
    let dir_name = args.path.clone().unwrap_or_else(|| args.name.clone());
    let project_name = normalize_project_name(&args.name);
    let project_name_pascal = to_pascal_case(&project_name);

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

    let context = BackendTemplateContext {
        project_name: project_name.clone(),
        project_name_pascal,
        has_organizations: false,
        database: "postgres".to_string(),
    };
    let engine = BackendTemplateEngine::new(context)?;

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
    write_file(
        &target_dir.join(".gitignore"),
        &engine.render("starter/gitignore")?,
        args.force,
    )?;

    println!(
        "\n{} {}\n",
        "tideway".cyan().bold(),
        "starter app created".green().bold()
    );

    print_info(&format!("Project name: {}", project_name.green()));
    print_info(&format!("Location: {}", target_dir.display().to_string().yellow()));

    println!("\n{}", "Next steps:".yellow().bold());
    println!("  1. cd {}", dir_name);
    println!("  2. cargo run");
    println!();

    print_success("Ready to build");
    Ok(())
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
