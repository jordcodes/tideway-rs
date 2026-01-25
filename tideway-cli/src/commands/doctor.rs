//! Doctor command - diagnose Tideway project setup issues.

use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::DoctorArgs;
use crate::{print_info, print_success, print_warning};

#[derive(Debug, Default)]
pub struct DoctorReport {
    pub warnings: Vec<String>,
    pub info: Vec<String>,
}

pub fn run(args: DoctorArgs) -> Result<()> {
    let project_dir = PathBuf::from(args.path);
    let report = analyze_project(&project_dir)?;

    println!(
        "\n{} {}\n",
        "tideway".cyan().bold(),
        "doctor report".blue().bold()
    );

    if report.info.is_empty() && report.warnings.is_empty() {
        print_success("No issues found");
        return Ok(());
    }

    for line in report.info {
        print_info(&line);
    }

    if !report.warnings.is_empty() {
        println!();
        for warning in report.warnings {
            print_warning(&warning);
        }
    }

    Ok(())
}

pub fn analyze_project(project_dir: &Path) -> Result<DoctorReport> {
    let mut report = DoctorReport::default();

    let cargo_toml_path = project_dir.join("Cargo.toml");
    let cargo_toml = read_cargo_toml(&cargo_toml_path)?;
    let tideway_features = tideway_features(&cargo_toml);

    let src_dir = project_dir.join("src");
    let detected = detect_modules(&src_dir);

    if detected.is_empty() {
        report.info.push("No Tideway modules detected in src/".to_string());
    }

    for module in &detected {
        let feature = module_to_feature(module);
        if !tideway_features.contains(feature) {
            report.warnings.push(format!(
                "Detected {} module but Tideway feature '{}' is not enabled in Cargo.toml",
                module, feature
            ));
        }
    }

    if !tideway_features.is_empty() && cargo_toml_path.exists() {
        report.info.push(format!(
            "Tideway features enabled: {}",
            tideway_features
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    Ok(report)
}

fn read_cargo_toml(path: &Path) -> Result<toml::Value> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    contents
        .parse::<toml::Value>()
        .with_context(|| format!("Failed to parse {}", path.display()))
}

fn tideway_features(cargo_toml: &toml::Value) -> BTreeSet<String> {
    let mut features = BTreeSet::new();

    let deps = cargo_toml.get("dependencies");
    let tideway = deps.and_then(|d| d.get("tideway"));

    match tideway {
        Some(toml::Value::Table(table)) => {
            if let Some(toml::Value::Array(values)) = table.get("features") {
                for value in values {
                    if let Some(feature) = value.as_str() {
                        features.insert(feature.to_string());
                    }
                }
            }
        }
        Some(toml::Value::String(_)) => {
            // No features listed; keep empty.
        }
        _ => {}
    }

    features
}

fn detect_modules(src_dir: &Path) -> BTreeSet<String> {
    let mut modules = BTreeSet::new();

    let module_dirs = [
        "auth",
        "billing",
        "organizations",
        "admin",
        "jobs",
        "cache",
        "session",
        "email",
        "websocket",
        "metrics",
        "validation",
        "openapi",
    ];

    for module in module_dirs {
        let path = src_dir.join(module);
        if path.is_dir() {
            modules.insert(module.to_string());
        }
    }

    modules
}

fn module_to_feature(module: &str) -> &str {
    match module {
        "session" => "sessions",
        other => other,
    }
}
