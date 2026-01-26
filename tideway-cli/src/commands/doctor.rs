//! Doctor command - diagnose Tideway project setup issues.

use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::{BTreeMap, BTreeSet};
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

    if !tideway_dependency_present(&cargo_toml) {
        report.warnings.push("Cargo.toml is missing a tideway dependency".to_string());
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

    let env_file = project_dir.join(".env");
    let env_example_file = project_dir.join(".env.example");
    let env_vars = read_env_map(&env_file).unwrap_or_default();
    let env_example_vars = read_env_map(&env_example_file).unwrap_or_default();

    let needs_database = tideway_features.contains("database") || detected.contains("database");
    let needs_auth = tideway_features.contains("auth") || detected.contains("auth");

    if needs_database {
        let db_value = check_env_var(
            "DATABASE_URL",
            &env_file,
            &env_example_file,
            &env_vars,
            &env_example_vars,
            &mut report,
        );
        if let Some(value) = db_value {
            if let Some(message) = validate_database_url(&value) {
                report.warnings.push(message);
            }
        }
    }

    if needs_auth {
        check_env_var(
            "JWT_SECRET",
            &env_file,
            &env_example_file,
            &env_vars,
            &env_example_vars,
            &mut report,
        );
    }

    if !has_log_config(&env_vars, &env_example_vars) {
        report.info.push(
            "No log level configured (set TIDEWAY_LOG_LEVEL or RUST_LOG for more output)"
                .to_string(),
        );
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

fn tideway_dependency_present(cargo_toml: &toml::Value) -> bool {
    cargo_toml
        .get("dependencies")
        .and_then(|deps| deps.get("tideway"))
        .is_some()
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

fn read_env_map(path: &Path) -> Result<BTreeMap<String, String>> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    Ok(parse_env_map(&contents))
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

fn check_env_var(
    key: &str,
    env_path: &Path,
    env_example_path: &Path,
    env_vars: &BTreeMap<String, String>,
    env_example_vars: &BTreeMap<String, String>,
    report: &mut DoctorReport,
) -> Option<String> {
    if let Some(value) = env_vars.get(key) {
        return Some(value.clone());
    }

    if env_example_vars.contains_key(key) {
        report.warnings.push(format!(
            "{} missing in .env (found in .env.example) - copy .env.example and fill values",
            key
        ));
        return env_example_vars.get(key).cloned();
    }

    if env_path.exists() || env_example_path.exists() {
        report.warnings.push(format!(
            "{} missing in .env and .env.example",
            key
        ));
        return None;
    }

    report.warnings.push(format!(
        "{} missing - create .env.example (and .env) for local setup",
        key
    ));
    None
}

fn validate_database_url(value: &str) -> Option<String> {
    if !value.contains("://") {
        return Some("DATABASE_URL format looks invalid (missing scheme)".to_string());
    }

    let lower = value.to_lowercase();
    let valid = lower.starts_with("postgres://")
        || lower.starts_with("postgresql://")
        || lower.starts_with("sqlite:");

    if !valid {
        return Some(format!(
            "DATABASE_URL scheme looks invalid: {}",
            value
        ));
    }

    None
}

fn has_log_config(
    env_vars: &BTreeMap<String, String>,
    env_example_vars: &BTreeMap<String, String>,
) -> bool {
    env_vars.contains_key("TIDEWAY_LOG_LEVEL")
        || env_vars.contains_key("RUST_LOG")
        || env_example_vars.contains_key("TIDEWAY_LOG_LEVEL")
        || env_example_vars.contains_key("RUST_LOG")
}
