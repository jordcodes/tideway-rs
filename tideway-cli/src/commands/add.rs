//! Add command - enable Tideway features and scaffold modules.

use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::{AddArgs, AddFeature};
use crate::templates::{BackendTemplateContext, BackendTemplateEngine};
use crate::{print_info, print_success, print_warning};

pub fn run(args: AddArgs) -> Result<()> {
    let project_dir = PathBuf::from(&args.path);
    let cargo_path = project_dir.join("Cargo.toml");

    if !cargo_path.exists() {
        return Err(anyhow::anyhow!(
            "Cargo.toml not found in {}",
            project_dir.display()
        ));
    }

    let cargo_contents = fs::read_to_string(&cargo_path)
        .with_context(|| format!("Failed to read {}", cargo_path.display()))?;

    let project_name = project_name_from_cargo(&cargo_contents, &project_dir);
    let project_name_pascal = to_pascal_case(&project_name);

    update_cargo_toml(&cargo_path, &cargo_contents, args.feature)?;
    update_env_example(&project_dir, args.feature, &project_name)?;

    if args.feature == AddFeature::Auth {
        scaffold_auth(&project_dir, &project_name, &project_name_pascal, args.force)?;
        print_info("Auth scaffold created in src/auth/");
        print_info("Next steps: wire AuthModule + SimpleAuthProvider in main.rs");
    }

    print_success(&format!("Added {}", args.feature));
    Ok(())
}

fn update_cargo_toml(path: &Path, contents: &str, feature: AddFeature) -> Result<()> {
    let mut doc = contents.parse::<toml_edit::DocumentMut>()?;

    let deps = doc["dependencies"].or_insert(toml_edit::Item::Table(toml_edit::Table::new()));

    let tideway_item = deps
        .as_table_mut()
        .expect("dependencies should be a table")
        .entry("tideway");

    let feature_name = feature.to_string();

    match tideway_item {
        toml_edit::Entry::Vacant(entry) => {
            let mut table = toml_edit::InlineTable::new();
            table.get_or_insert("version", "0.7");
            table.get_or_insert("features", array_value(&[feature_name.as_str()]));
            entry.insert(toml_edit::Item::Value(toml_edit::Value::InlineTable(table)));
        }
        toml_edit::Entry::Occupied(mut entry) => {
            if entry.get().is_str() {
                let version = entry.get().as_str().unwrap_or("0.7").to_string();
                let mut table = toml_edit::InlineTable::new();
                table.get_or_insert("version", version);
                table.get_or_insert("features", array_value(&[feature_name.as_str()]));
                entry.insert(toml_edit::Item::Value(toml_edit::Value::InlineTable(table)));
            } else {
                let item = entry.get_mut();
                let features = item["features"]
                    .or_insert(toml_edit::Item::Value(toml_edit::Value::Array(toml_edit::Array::new())))
                    .as_array_mut()
                    .expect("features should be an array");

                if !features.iter().any(|v| v.as_str() == Some(&feature_name)) {
                    features.push(feature_name);
                }
            }
        }
    }

    if feature == AddFeature::Database {
        let deps_table = deps.as_table_mut().expect("dependencies should be a table");
        deps_table
            .entry("sea-orm")
            .or_insert(toml_edit::Item::Value(toml_edit::Value::InlineTable(
                {
                    let mut table = toml_edit::InlineTable::new();
                    table.get_or_insert("version", "1.1");
                    table.get_or_insert(
                        "features",
                        array_value(&["sqlx-postgres", "runtime-tokio-rustls"]),
                    );
                    table
                },
            )));
    }

    if feature == AddFeature::Auth {
        let deps_table = deps.as_table_mut().expect("dependencies should be a table");
        deps_table
            .entry("async-trait")
            .or_insert(toml_edit::value("0.1"));
        deps_table
            .entry("serde")
            .or_insert(toml_edit::Item::Value(toml_edit::Value::InlineTable(
                {
                    let mut table = toml_edit::InlineTable::new();
                    table.get_or_insert("version", "1.0");
                    table.get_or_insert("features", array_value(&["derive"]));
                    table
                },
            )));
        deps_table
            .entry("serde_json")
            .or_insert(toml_edit::value("1.0"));
    }

    fs::write(path, doc.to_string())
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

fn update_env_example(project_dir: &Path, feature: AddFeature, project_name: &str) -> Result<()> {
    let env_path = project_dir.join(".env.example");
    let mut lines = if env_path.exists() {
        fs::read_to_string(&env_path)
            .with_context(|| format!("Failed to read {}", env_path.display()))?
            .lines()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
    } else {
        vec![
            "# Server".to_string(),
            "TIDEWAY_HOST=0.0.0.0".to_string(),
            "TIDEWAY_PORT=8000".to_string(),
            String::new(),
        ]
    };

    let mut existing = BTreeSet::new();
    for line in &lines {
        if let Some((key, _)) = line.split_once('=') {
            existing.insert(key.trim().to_string());
        }
    }

    match feature {
        AddFeature::Database => {
            if !existing.contains("DATABASE_URL") {
                lines.push("# Database".to_string());
                lines.push(format!(
                    "DATABASE_URL=postgres://postgres:postgres@localhost:5432/{}",
                    project_name
                ));
                lines.push(String::new());
            }
        }
        AddFeature::Auth => {
            if !existing.contains("JWT_SECRET") {
                lines.push("# Auth".to_string());
                lines.push("JWT_SECRET=your-super-secret-jwt-key-change-in-production".to_string());
                lines.push(String::new());
            }
        }
        _ => {}
    }

    fs::write(&env_path, lines.join("\n"))
        .with_context(|| format!("Failed to write {}", env_path.display()))?;
    Ok(())
}

fn scaffold_auth(
    project_dir: &Path,
    project_name: &str,
    project_name_pascal: &str,
    force: bool,
) -> Result<()> {
    let context = BackendTemplateContext {
        project_name: project_name.to_string(),
        project_name_pascal: project_name_pascal.to_string(),
        has_organizations: false,
        database: "postgres".to_string(),
        tideway_features: vec!["auth".to_string()],
        has_tideway_features: true,
        has_auth_feature: true,
        has_database_feature: false,
        needs_arc: true,
        has_config: false,
    };

    let engine = BackendTemplateEngine::new(context)?;
    let auth_dir = project_dir.join("src").join("auth");

    write_file(
        &auth_dir.join("mod.rs"),
        &engine.render("starter/src/auth/mod.rs")?,
        force,
    )?;
    write_file(
        &auth_dir.join("provider.rs"),
        &engine.render("starter/src/auth/provider.rs")?,
        force,
    )?;
    write_file(
        &auth_dir.join("routes.rs"),
        &engine.render("starter/src/auth/routes.rs")?,
        force,
    )?;

    Ok(())
}

fn write_file(path: &Path, contents: &str, force: bool) -> Result<()> {
    if path.exists() && !force {
        print_warning(&format!(
            "Skipping {} (use --force to overwrite)",
            path.display()
        ));
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }

    fs::write(path, contents)
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

fn project_name_from_cargo(contents: &str, project_dir: &Path) -> String {
    let doc = contents
        .parse::<toml_edit::DocumentMut>()
        .ok()
        .and_then(|doc| doc["package"]["name"].as_str().map(|s| s.to_string()));

    doc.unwrap_or_else(|| {
        project_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("my_app")
            .to_string()
    })
    .replace('-', "_")
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

fn array_value(values: &[&str]) -> toml_edit::Value {
    let mut array = toml_edit::Array::new();
    for value in values {
        array.push(*value);
    }
    toml_edit::Value::Array(array)
}
