//! Add command - enable Tideway features and scaffold modules.

use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::{AddArgs, AddFeature};
use crate::commands::app_builder::{
    find_app_builder_end_insert_at, find_app_builder_marker_range, find_app_builder_start,
    find_app_builder_var_name, find_unmarked_app_builder_statement_range,
    insert_snippet_into_builder_block,
};
use crate::commands::file_ops::{ensure_module_decl, to_pascal_case, write_file_with_force};
use crate::commands::messaging::GREENFIELD_NEW_APP_FIRST;
use crate::templates::{BackendTemplateContext, BackendTemplateEngine};
use crate::{
    TIDEWAY_VERSION, ensure_dir, error_contract, print_info, print_success, print_warning,
    write_file,
};

pub fn run(args: AddArgs) -> Result<()> {
    let project_dir = PathBuf::from(&args.path);
    let cargo_path = project_dir.join("Cargo.toml");

    if !cargo_path.exists() {
        return Err(anyhow::anyhow!(error_contract(
            &format!("Cargo.toml not found in {}", project_dir.display()),
            "Run this command inside a Rust project root.",
            GREENFIELD_NEW_APP_FIRST,
        )));
    }

    let cargo_contents = fs::read_to_string(&cargo_path)
        .with_context(|| format!("Failed to read {}", cargo_path.display()))?;

    let project_name = project_name_from_cargo(&cargo_contents, &project_dir);
    let project_name_pascal = to_pascal_case(&project_name);

    update_cargo_toml(&cargo_path, &cargo_contents, args.feature)?;
    update_env_example(&project_dir, args.feature, &project_name)?;

    if args.feature == AddFeature::Auth {
        scaffold_auth(
            &project_dir,
            &project_name,
            &project_name_pascal,
            args.force,
        )?;
        print_info("Auth scaffold created in src/auth/");
        if args.wire {
            wire_auth_in_main(&project_dir, &project_name)?;
        } else {
            print_info("Next steps: wire AuthModule + SimpleAuthProvider in main.rs");
        }
    }

    if args.feature == AddFeature::Database && args.wire {
        wire_database_in_main(&project_dir)?;
    }

    if args.feature == AddFeature::Openapi {
        ensure_openapi_docs_file(&project_dir)?;
        if args.wire {
            wire_openapi_in_main(&project_dir)?;
        } else {
            print_info("Next steps: wire OpenAPI in main.rs");
        }
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
            table.get_or_insert("version", TIDEWAY_VERSION);
            table.get_or_insert("features", array_value(&[feature_name.as_str()]));
            entry.insert(toml_edit::Item::Value(toml_edit::Value::InlineTable(table)));
        }
        toml_edit::Entry::Occupied(mut entry) => {
            if entry.get().is_str() {
                let version = entry.get().as_str().unwrap_or(TIDEWAY_VERSION).to_string();
                let mut table = toml_edit::InlineTable::new();
                table.get_or_insert("version", version);
                table.get_or_insert("features", array_value(&[feature_name.as_str()]));
                entry.insert(toml_edit::Item::Value(toml_edit::Value::InlineTable(table)));
            } else {
                let item = entry.get_mut();
                let features = item["features"]
                    .or_insert(toml_edit::Item::Value(toml_edit::Value::Array(
                        toml_edit::Array::new(),
                    )))
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
            .or_insert(toml_edit::Item::Value(toml_edit::Value::InlineTable({
                let mut table = toml_edit::InlineTable::new();
                table.get_or_insert("version", "1.1");
                table.get_or_insert(
                    "features",
                    array_value(&["sqlx-postgres", "runtime-tokio-rustls"]),
                );
                table
            })));
    }

    if feature == AddFeature::Auth {
        let deps_table = deps.as_table_mut().expect("dependencies should be a table");
        deps_table
            .entry("async-trait")
            .or_insert(toml_edit::value("0.1"));
        deps_table
            .entry("serde")
            .or_insert(toml_edit::Item::Value(toml_edit::Value::InlineTable({
                let mut table = toml_edit::InlineTable::new();
                table.get_or_insert("version", "1.0");
                table.get_or_insert("features", array_value(&["derive"]));
                table
            })));
        deps_table
            .entry("serde_json")
            .or_insert(toml_edit::value("1.0"));
    }

    write_file(path, &doc.to_string())
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

    write_file(&env_path, &lines.join("\n"))
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
        database_url: format!(
            "postgres://postgres:postgres@localhost:5432/{}",
            project_name
        ),
        is_sqlite_database: false,
        tideway_version: TIDEWAY_VERSION.to_string(),
        tideway_features: vec!["auth".to_string()],
        has_tideway_features: true,
        has_auth_feature: true,
        has_database_feature: false,
        has_openapi_feature: false,
        needs_arc: true,
        has_config: false,
    };

    let engine = BackendTemplateEngine::new(context)?;
    let auth_dir = project_dir.join("src").join("auth");

    write_file_with_force(
        &auth_dir.join("mod.rs"),
        &engine.render("starter/src/auth/mod.rs")?,
        force,
    )?;
    write_file_with_force(
        &auth_dir.join("provider.rs"),
        &engine.render("starter/src/auth/provider.rs")?,
        force,
    )?;
    write_file_with_force(
        &auth_dir.join("routes.rs"),
        &engine.render("starter/src/auth/routes.rs")?,
        force,
    )?;

    Ok(())
}

fn wire_auth_in_main(project_dir: &Path, project_name: &str) -> Result<()> {
    let main_path = project_dir.join("src").join("main.rs");
    if !main_path.exists() {
        print_warning("src/main.rs not found; skipping auto-wiring");
        return Ok(());
    }

    let mut contents = fs::read_to_string(&main_path)
        .with_context(|| format!("Failed to read {}", main_path.display()))?;

    contents = ensure_module_decl(&contents, "auth");

    contents = ensure_use_line(contents, "use axum::Extension;", "use tideway::auth");
    contents = ensure_use_line(
        contents,
        "use crate::auth::{AuthModule, SimpleAuthProvider};",
        "use tideway::auth",
    );
    contents = ensure_use_line(contents, "use std::sync::Arc;", "use tideway::");
    contents = ensure_use_line(
        contents,
        "use tideway::auth::{JwtIssuer, JwtIssuerConfig};",
        "use tideway::auth",
    );

    let has_jwt_secret = contents.contains("let jwt_secret");
    let has_jwt_issuer = contents.contains("let jwt_issuer");
    let has_auth_provider = contents.contains("auth_provider");
    let has_auth_module = contents.contains("auth_module");

    if has_jwt_secret && has_jwt_issuer {
        if !has_auth_provider || !has_auth_module {
            if let Some(insert_at) = contents.find("let jwt_issuer") {
                let after = contents[insert_at..]
                    .find(";\n")
                    .map(|idx| insert_at + idx + 2)
                    .unwrap_or(insert_at);
                let insert = "    let auth_provider = SimpleAuthProvider::from_secret(&jwt_secret);\n    let auth_module = AuthModule::new(jwt_issuer.clone());\n".to_string();
                contents.insert_str(after, &insert);
            }
        }
    } else {
        let block = format!(
            "    let jwt_secret = std::env::var(\"JWT_SECRET\").expect(\"JWT_SECRET is not set\");\n    let jwt_issuer = Arc::new(JwtIssuer::new(JwtIssuerConfig::with_secret(\n        &jwt_secret,\n        \"{}\",\n    )).expect(\"Failed to create JWT issuer\"));\n    let auth_provider = SimpleAuthProvider::from_secret(&jwt_secret);\n    let auth_module = AuthModule::new(jwt_issuer.clone());\n\n",
            project_name
        );
        contents = insert_before_app_builder(contents, &block)?;
    }

    contents = insert_auth_into_app_builder(contents)?;

    write_file(&main_path, &contents)
        .with_context(|| format!("Failed to write {}", main_path.display()))?;
    print_success("Wired auth into src/main.rs");
    Ok(())
}

pub fn wire_database_in_main(project_dir: &Path) -> Result<()> {
    let main_path = project_dir.join("src").join("main.rs");
    if !main_path.exists() {
        print_warning("src/main.rs not found; skipping auto-wiring");
        return Ok(());
    }

    let mut contents = fs::read_to_string(&main_path)
        .with_context(|| format!("Failed to read {}", main_path.display()))?;

    if !contents.contains("async fn main") {
        print_warning("main.rs is not async; skipping database wiring");
        return Ok(());
    }

    let has_database_block = contents.contains("DATABASE_URL")
        || contents.contains("sea_orm::Database::connect")
        || contents.contains("with_database");
    let has_database_context = contents.contains(".with_database(");

    if has_database_block && has_database_context {
        return Ok(());
    }

    contents = ensure_use_line(
        contents,
        "use tideway::{AppContext, SeaOrmPool};",
        "use tideway::",
    );
    contents = ensure_use_line(contents, "use std::sync::Arc;", "use tideway::");

    if !has_database_block {
        let block = "    let database_url = std::env::var(\"DATABASE_URL\").expect(\"DATABASE_URL is not set\");\n    let db = sea_orm::Database::connect(&database_url)\n        .await\n        .expect(\"Failed to connect to database\");\n\n";
        contents = insert_before_app_builder(contents, block)?;
    }

    if !contents.contains(".with_database(") {
        contents = insert_database_into_app_builder(contents)?;
    }

    write_file(&main_path, &contents)
        .with_context(|| format!("Failed to write {}", main_path.display()))?;
    print_success("Wired database into src/main.rs");
    Ok(())
}

fn ensure_use_line(mut contents: String, line: &str, anchor: &str) -> String {
    if contents.contains(line) {
        return contents;
    }

    if let Some(pos) = contents.find(anchor) {
        let mut insert_at = pos;
        let mut lines = contents[pos..].split_inclusive('\n');

        if let Some(first_line) = lines.next() {
            insert_at += first_line.len();
            let mut in_group = first_line.contains('{') && !first_line.trim_end().ends_with("};");

            while in_group {
                let Some(group_line) = lines.next() else {
                    break;
                };
                insert_at += group_line.len();
                if group_line.trim_end().ends_with("};") {
                    in_group = false;
                }
            }

            contents.insert_str(insert_at, &format!("{}\n", line));
            return contents;
        }
    }

    contents = format!("{}\n{}", line, contents);
    contents
}

fn insert_before_app_builder(mut contents: String, block: &str) -> Result<String> {
    if let Some((start, _)) = find_app_builder_marker_range(&contents) {
        contents.insert_str(start, block);
        return Ok(contents);
    }

    if let Some((start, _)) = find_unmarked_app_builder_statement_range(&contents) {
        contents.insert_str(start, block);
        return Ok(contents);
    }

    print_warning("Could not find app builder; skipping auth wiring");
    Ok(contents)
}

fn insert_auth_into_app_builder(mut contents: String) -> Result<String> {
    if contents.contains("register_module(auth_module)") {
        return Ok(contents);
    }

    let insert = ".with_global_layer(Extension(auth_provider))\n.register_module(auth_module)";
    if let Some((start, end)) = find_app_builder_marker_range(&contents) {
        let statement = &contents[start..=end];
        if let Some(updated) = insert_snippet_into_builder_block(statement, insert) {
            contents.replace_range(start..=end, &updated);
            return Ok(contents);
        }
        print_warning("Could not update app builder; skipping auth module registration");
        return Ok(contents);
    }

    if let Some((start, end)) = find_unmarked_app_builder_statement_range(&contents) {
        let statement = &contents[start..=end];
        if let Some(updated) = insert_snippet_into_builder_block(statement, insert) {
            contents.replace_range(start..=end, &updated);
            return Ok(contents);
        }
        print_warning("Could not update app builder; skipping auth module registration");
        return Ok(contents);
    }

    print_warning("Could not find app builder; skipping auth module registration");
    Ok(contents)
}

fn insert_database_into_app_builder(mut contents: String) -> Result<String> {
    if contents.contains(".with_database(") {
        return Ok(contents);
    }

    let insert = ".with_context(\n    AppContext::builder()\n        .with_database(Arc::new(SeaOrmPool::new(db, database_url)))\n        .build()\n)";

    if let Some((start, end)) = find_app_builder_marker_range(&contents) {
        let statement = &contents[start..=end];
        if let Some(updated) = insert_snippet_into_builder_block(statement, insert) {
            contents.replace_range(start..=end, &updated);
            return Ok(contents);
        }
        print_warning("Could not update app builder; skipping database wiring");
        return Ok(contents);
    }

    if let Some((start, end)) = find_unmarked_app_builder_statement_range(&contents) {
        let statement = &contents[start..=end];
        if let Some(updated) = insert_snippet_into_builder_block(statement, insert) {
            contents.replace_range(start..=end, &updated);
            return Ok(contents);
        }
        print_warning("Could not update app builder; skipping database wiring");
        return Ok(contents);
    }

    print_warning("Could not find app builder; skipping database wiring");
    Ok(contents)
}

fn wire_openapi_in_main(project_dir: &Path) -> Result<()> {
    let main_path = project_dir.join("src").join("main.rs");
    if !main_path.exists() {
        print_warning("src/main.rs not found; skipping auto-wiring");
        return Ok(());
    }

    let mut contents = fs::read_to_string(&main_path)
        .with_context(|| format!("Failed to read {}", main_path.display()))?;

    if contents.contains("openapi::create_openapi_router")
        || contents.contains("openapi_merge_module")
    {
        print_info("OpenAPI already appears wired in main.rs");
        return Ok(());
    }

    contents = ensure_use_line(contents, "use tideway::ConfigBuilder;", "use tideway::");
    if contents.contains("mod config;") {
        contents = ensure_use_line(contents, "use crate::config::AppConfig;", "use tideway::");
    }
    contents = ensure_use_line(contents, "use tideway::openapi;", "use tideway::");

    if !contents.contains("mod openapi_docs;") {
        contents = ensure_module_decl(&contents, "openapi_docs");
    }

    let has_config_var = contents.contains("let config = ConfigBuilder::new()")
        || contents.contains("let config = AppConfig::from_env()");
    let config_available =
        contents.contains("ConfigBuilder::new()") || contents.contains("AppConfig::from_env()");

    if !has_config_var && config_available {
        let config_block = "    let config = ConfigBuilder::new()\n        .from_env()\n        .build()\n        .expect(\"Invalid TIDEWAY_* config\");\n\n";
        contents = insert_before_app_builder(contents, config_block)?;
    }

    if contents.contains("let config = AppConfig::from_env()") {
        contents = insert_openapi_into_app_builder(contents, "config.tideway")?;
    } else {
        contents = insert_openapi_into_app_builder(contents, "config")?;
    }

    write_file(&main_path, &contents)
        .with_context(|| format!("Failed to write {}", main_path.display()))?;
    print_success("Wired OpenAPI into src/main.rs");
    Ok(())
}

fn insert_openapi_into_app_builder(mut contents: String, config_ref: &str) -> Result<String> {
    if contents.contains("create_openapi_router") {
        return Ok(contents);
    }

    if let Some(pos) = find_app_builder_start(&contents) {
        let app_var =
            find_app_builder_var_name(&contents, pos).unwrap_or_else(|| "app".to_string());
        // Insert after app builder block to keep code readable.
        if let Some(insert_at) = find_app_builder_end_insert_at(&contents, pos) {
            let block = format!(
                "\n    if {config_ref}.openapi.enabled {{\n        let openapi = tideway::openapi_merge_module!(openapi_docs, ApiDoc);\n        let openapi_router = tideway::openapi::create_openapi_router(openapi, &{config_ref}.openapi);\n        {app_var} = {app_var}.merge_router(openapi_router);\n    }}\n"
            );
            contents.insert_str(insert_at, &block);
        } else {
            print_warning("Could not find app builder termination; skipping OpenAPI wiring");
        }
        Ok(contents)
    } else {
        print_warning("Could not find app builder; skipping OpenAPI wiring");
        Ok(contents)
    }
}

fn ensure_openapi_docs_file(project_dir: &Path) -> Result<()> {
    let docs_path = project_dir.join("src").join("openapi_docs.rs");
    if docs_path.exists() {
        return Ok(());
    }

    let contents = r#"tideway::openapi_doc!(pub(crate) ApiDoc, paths());
"#;

    if let Some(parent) = docs_path.parent() {
        ensure_dir(parent).with_context(|| format!("Failed to create {}", parent.display()))?;
    }

    write_file(&docs_path, contents)
        .with_context(|| format!("Failed to write {}", docs_path.display()))?;
    print_success("Created src/openapi_docs.rs");
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

pub fn array_value(values: &[&str]) -> toml_edit::Value {
    let mut array = toml_edit::Array::new();
    for value in values {
        array.push(*value);
    }
    toml_edit::Value::Array(array)
}
