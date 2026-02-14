//! Doctor command - diagnose Tideway project setup issues.

use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::DoctorArgs;
use crate::commands::messaging::{
    DEV_FIX_ENV_COMMAND, GREENFIELD_NEW_APP_PRESET_API, NEW_APP_COMMAND, PRIMARY_PATH_REMINDER_CHAIN,
    RESOURCE_WIRE_FLOW, SEA_ORM_MIGRATE_INIT_COMMAND, TIDEWAY_ADD_DATABASE_WIRE_COMMAND,
    TIDEWAY_ADD_OPENAPI_COMMAND, TIDEWAY_ADD_OPENAPI_WIRE_COMMAND, TIDEWAY_BACKEND_COMMAND,
    TIDEWAY_RESOURCE_WIRE_COMMAND, TIDEWAY_DEV_COMMAND,
};
use crate::{is_json_output, print_info, print_success, print_warning, write_file};

#[derive(Debug, Default)]
pub struct DoctorReport {
    pub warnings: Vec<String>,
    pub info: Vec<String>,
    pub fixes: Vec<String>,
}

pub fn run(args: DoctorArgs) -> Result<()> {
    let project_dir = PathBuf::from(args.path);
    let report = analyze_project(&project_dir, args.fix)?;

    if !is_json_output() {
        println!(
            "\n{} {}\n",
            "tideway".cyan().bold(),
            "doctor report".blue().bold()
        );
    }

    if report.info.is_empty() && report.warnings.is_empty() {
        print_success("No issues found");
        print_info(PRIMARY_PATH_REMINDER_CHAIN);
        return Ok(());
    }

    for line in &report.info {
        print_info(line);
    }

    for line in &report.fixes {
        print_success(line);
    }

    if !report.warnings.is_empty() {
        if !is_json_output() {
            println!();
        }
        for warning in &report.warnings {
            print_warning(warning);
        }
    }

    let summary = format!(
        "Doctor summary: {} info, {} fixes, {} warnings",
        report.info.len(),
        report.fixes.len(),
        report.warnings.len()
    );
    print_info(&summary);
    print_info(
        &format!(
            "Primary path reminder: for greenfield apps use {}; treat `add`/`init`/`backend` as advanced commands.",
            NEW_APP_COMMAND
        ),
    );

    Ok(())
}

pub fn analyze_project(project_dir: &Path, fix: bool) -> Result<DoctorReport> {
    let mut report = DoctorReport::default();

    let cargo_toml_path = project_dir.join("Cargo.toml");
    let cargo_toml = read_cargo_toml(&cargo_toml_path)?;
    let tideway_features = tideway_features(&cargo_toml);

    let src_dir = project_dir.join("src");
    let detected = detect_modules(&src_dir);

    if detected.is_empty() {
        report
            .info
            .push("No Tideway modules detected in src/".to_string());
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
        report
            .warnings
            .push("Cargo.toml is missing a tideway dependency".to_string());
    }

    if let Some(message) = validate_package_metadata(&cargo_toml) {
        report.info.push(message);
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
    let project_name = project_name_from_cargo(&cargo_toml, project_dir);

    let needs_database = tideway_features.contains("database") || detected.contains("database");
    let needs_auth = tideway_features.contains("auth") || detected.contains("auth");

    if fix {
        apply_env_fixes(
            &env_file,
            &env_example_file,
            &project_name,
            needs_database,
            needs_auth,
            &mut report,
        )?;
    }

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

    if !has_port_config(&env_vars, &env_example_vars) {
        report.info.push(
            "No port configured (set TIDEWAY_PORT or PORT for deploy environments)".to_string(),
        );
    }

    let main_contents = fs::read_to_string(src_dir.join("main.rs")).ok();

    if tideway_features.contains("openapi") {
        check_openapi_setup(&src_dir, main_contents.as_deref(), &mut report);
        check_openapi_doc_coverage(&src_dir, &mut report);
    }

    if needs_database {
        check_migration_setup(project_dir, &mut report);
        check_database_wiring(&src_dir, main_contents.as_deref(), &mut report);
        check_webhook_idempotency_setup(project_dir, &src_dir, fix, &mut report);
        check_migration_execution_hint(
            project_dir,
            &env_vars,
            &env_example_vars,
            main_contents.as_deref(),
            &mut report,
        );
    }

    Ok(report)
}

fn read_cargo_toml(path: &Path) -> Result<toml::Value> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
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
    let contents =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
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
            "{} missing in .env (found in .env.example) - copy .env.example and fill values (or use the primary flow: {})",
            key,
            DEV_FIX_ENV_COMMAND
        ));
        return env_example_vars.get(key).cloned();
    }

    if env_path.exists() || env_example_path.exists() {
        report
            .warnings
            .push(format!("{} missing in .env and .env.example", key));
        return None;
    }

    report.warnings.push(format!(
        "{} missing - create .env.example (and .env) for local setup (for greenfield apps, prefer {})",
        key,
        NEW_APP_COMMAND
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
        return Some(format!("DATABASE_URL scheme looks invalid: {}", value));
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

fn has_port_config(
    env_vars: &BTreeMap<String, String>,
    env_example_vars: &BTreeMap<String, String>,
) -> bool {
    env_vars.contains_key("TIDEWAY_PORT")
        || env_vars.contains_key("PORT")
        || env_example_vars.contains_key("TIDEWAY_PORT")
        || env_example_vars.contains_key("PORT")
}

fn validate_package_metadata(cargo_toml: &toml::Value) -> Option<String> {
    let package = cargo_toml.get("package")?.as_table()?;
    let missing = ["description", "license", "repository"]
        .iter()
        .filter(|key| !package.contains_key(**key))
        .cloned()
        .collect::<Vec<_>>();

    if missing.is_empty() {
        return None;
    }

    Some(format!("Package metadata missing: {}", missing.join(", ")))
}

fn env_example_template(
    project_name: &str,
    needs_database: bool,
    needs_auth: bool,
) -> Option<Vec<String>> {
    let mut lines = Vec::new();
    if needs_database || needs_auth {
        lines.push("# Server".to_string());
        lines.push("TIDEWAY_HOST=0.0.0.0".to_string());
        lines.push("TIDEWAY_PORT=8000".to_string());
        lines.push(String::new());
    }

    if needs_database {
        lines.push("# Database".to_string());
        lines.push(format!(
            "DATABASE_URL=postgres://postgres:postgres@localhost:5432/{}",
            project_name
        ));
        lines.push(String::new());
    }

    if needs_auth {
        lines.push("# Auth".to_string());
        lines.push("JWT_SECRET=your-super-secret-jwt-key-change-in-production".to_string());
        lines.push(String::new());
    }

    if lines.is_empty() { None } else { Some(lines) }
}

fn project_name_from_cargo(cargo_toml: &toml::Value, project_dir: &Path) -> String {
    if let Some(name) = cargo_toml
        .get("package")
        .and_then(|pkg| pkg.get("name"))
        .and_then(|value| value.as_str())
    {
        return name.replace('-', "_");
    }

    project_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("my_app")
        .replace('-', "_")
}
fn write_env_example(path: &Path, lines: &[String]) -> Result<()> {
    let contents = lines.join("\n");
    write_file(path, &contents).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

fn apply_env_fixes(
    env_file: &Path,
    env_example_file: &Path,
    project_name: &str,
    needs_database: bool,
    needs_auth: bool,
    report: &mut DoctorReport,
) -> Result<()> {
    let Some(lines) = env_example_template(project_name, needs_database, needs_auth) else {
        return Ok(());
    };
    let expected_vars = parse_env_map(&lines.join("\n"));

    if !env_example_file.exists() {
        write_env_example(env_example_file, &lines)?;
        report.fixes.push("Created .env.example".to_string());
    } else {
        let existing = fs::read_to_string(env_example_file).with_context(|| {
            format!(
                "Failed to read {} while applying doctor fixes",
                env_example_file.display()
            )
        })?;
        let existing_vars = parse_env_map(&existing);
        let mut missing_keys = Vec::new();
        for key in expected_vars.keys() {
            if !existing_vars.contains_key(key) {
                missing_keys.push(key.clone());
            }
        }

        if !missing_keys.is_empty() {
            let mut merged = existing.trim_end().to_string();
            merged.push_str("\n\n# Added by tideway doctor --fix\n");
            for key in &missing_keys {
                if let Some(value) = expected_vars.get(key) {
                    merged.push_str(&format!("{}={}\n", key, value));
                }
            }
            write_file(env_example_file, &merged).with_context(|| {
                format!(
                    "Failed to write {} while applying doctor fixes",
                    env_example_file.display()
                )
            })?;
            report.fixes.push(format!(
                "Updated .env.example with missing keys: {}",
                missing_keys.join(", ")
            ));
        }
    }

    if !env_file.exists() && env_example_file.exists() {
        let source = fs::read_to_string(env_example_file).with_context(|| {
            format!(
                "Failed to read {} while creating .env",
                env_example_file.display()
            )
        })?;
        write_file(env_file, &source)
            .with_context(|| format!("Failed to write {}", env_file.display()))?;
        report
            .fixes
            .push("Created .env from .env.example".to_string());
    }

    Ok(())
}

fn check_openapi_setup(
    src_dir: &Path,
    main_contents: Option<&str>,
    report: &mut DoctorReport,
) {
    let openapi_docs = src_dir.join("openapi_docs.rs");
    if !openapi_docs.exists() {
        report.warnings.push(format!(
            "OpenAPI is enabled but src/openapi_docs.rs is missing (advanced fix: run {}; greenfield path: {})",
            TIDEWAY_ADD_OPENAPI_COMMAND,
            GREENFIELD_NEW_APP_PRESET_API
        ));
    }

    let main_rs = src_dir.join("main.rs");
    if let Some(contents) = main_contents {
        let has_module = contents.contains("mod openapi_docs;");
        let has_router =
            contents.contains("openapi_merge_module") || contents.contains("create_openapi_router");
        if !has_module || !has_router {
            report.warnings.push(format!(
                "OpenAPI is enabled but main.rs is not wired (advanced fix: run {}; greenfield path: {})",
                TIDEWAY_ADD_OPENAPI_WIRE_COMMAND,
                GREENFIELD_NEW_APP_PRESET_API
            ));
        }
    } else if main_rs.exists() {
        report
            .warnings
            .push("Failed to read src/main.rs for OpenAPI wiring check".to_string());
    }
}

fn check_openapi_doc_coverage(src_dir: &Path, report: &mut DoctorReport) {
    let openapi_docs = src_dir.join("openapi_docs.rs");
    if !openapi_docs.exists() {
        return;
    }

    let Ok(docs_contents) = fs::read_to_string(&openapi_docs) else {
        report
            .warnings
            .push("Failed to read src/openapi_docs.rs".to_string());
        return;
    };

    let paths_block = extract_openapi_paths(&docs_contents);
    if paths_block.is_empty() {
        report.warnings.push(
            format!(
                "OpenAPI docs file has no paths() entries (add routes or run {}; primary path reminder: {})",
                TIDEWAY_RESOURCE_WIRE_COMMAND,
                RESOURCE_WIRE_FLOW
            ),
        );
        return;
    }

    let routes_dir = src_dir.join("routes");
    if !routes_dir.exists() {
        return;
    }

    let mut missing = Vec::new();
    if let Ok(entries) = fs::read_dir(&routes_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let file_name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if file_name == "mod" {
                continue;
            }
            if let Ok(contents) = fs::read_to_string(&path) {
                if !contents.contains("cfg_attr(feature = \"openapi\"") {
                    continue;
                }
            }

            let expected_prefix = format!("crate::routes::{}::", file_name);
            if !paths_block
                .iter()
                .any(|path| path.starts_with(&expected_prefix))
            {
                missing.push(file_name.to_string());
            }
        }
    }

    if !missing.is_empty() {
        report.warnings.push(format!(
            "OpenAPI docs missing routes for: {} (run {} to add; this is part of the primary flow)",
            TIDEWAY_RESOURCE_WIRE_COMMAND,
            missing.join(", ")
        ));
    }
}

fn extract_openapi_paths(contents: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut in_paths = false;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("paths(") {
            in_paths = true;
            continue;
        }
        if in_paths && trimmed.starts_with(')') {
            break;
        }
        if in_paths {
            let trimmed = trimmed.trim_end_matches(',');
            if !trimmed.is_empty() {
                lines.push(trimmed.to_string());
            }
        }
    }
    lines
}

fn check_migration_setup(project_dir: &Path, report: &mut DoctorReport) {
    let migration_lib = project_dir.join("migration").join("src").join("lib.rs");
    if !migration_lib.exists() {
        report.warnings.push(format!(
            "Missing migration/src/lib.rs (advanced fix: run {} or {}; greenfield path: {})",
            SEA_ORM_MIGRATE_INIT_COMMAND,
            TIDEWAY_BACKEND_COMMAND,
            GREENFIELD_NEW_APP_PRESET_API
        ));
    }
}

fn check_database_wiring(src_dir: &Path, main_contents: Option<&str>, report: &mut DoctorReport) {
    let routes_dir = src_dir.join("routes");
    if !routes_dir.exists() {
        return;
    }

    let mut has_db_routes = false;
    if let Ok(entries) = fs::read_dir(&routes_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            if let Ok(contents) = fs::read_to_string(&path) {
                if contents.contains("sea_orm_connection()")
                    || contents.contains("Entity::find")
                    || contents.contains("ActiveModel")
                {
                    has_db_routes = true;
                    break;
                }
            }
        }
    }

    if !has_db_routes {
        return;
    }

    if let Some(contents) = main_contents {
        if !contents.contains("with_database(") {
            report.warnings.push(
                format!(
                    "DB-backed routes detected but AppContext is not wired (advanced fix: run {}; primary path for new resources: {})",
                    TIDEWAY_ADD_DATABASE_WIRE_COMMAND,
                    RESOURCE_WIRE_FLOW
                ),
            );
        }
    } else if src_dir.join("main.rs").exists() {
        report
            .warnings
            .push("Failed to read src/main.rs for database wiring check".to_string());
    }
}

fn check_migration_execution_hint(
    project_dir: &Path,
    env_vars: &BTreeMap<String, String>,
    env_example_vars: &BTreeMap<String, String>,
    main_contents: Option<&str>,
    report: &mut DoctorReport,
) {
    let migration_lib = project_dir.join("migration").join("src").join("lib.rs");
    if !migration_lib.exists() {
        return;
    }

    let has_auto_migrate = env_vars.contains_key("DATABASE_AUTO_MIGRATE")
        || env_example_vars.contains_key("DATABASE_AUTO_MIGRATE");
    let has_migration_call = main_contents
        .map(|contents| {
            contents.contains("run_migrations(") || contents.contains("run_migrations_now(")
        })
        .unwrap_or(false);

    if !has_auto_migrate && !has_migration_call {
        report.info.push(
            format!(
                "Migrations detected but not auto-run (set DATABASE_AUTO_MIGRATE=true, call run_migrations, or use {}; primary local run command is {})",
                TIDEWAY_DEV_COMMAND,
                DEV_FIX_ENV_COMMAND
            ),
        );
    }
}

fn check_webhook_idempotency_setup(
    project_dir: &Path,
    src_dir: &Path,
    fix: bool,
    report: &mut DoctorReport,
) {
    if !project_uses_database_webhook_idempotency(src_dir) {
        return;
    }

    if has_webhook_idempotency_migration(project_dir) {
        report.info.push(
            "Webhook DB idempotency detected and migration marker found (webhook_processed_events)"
                .to_string(),
        );
        return;
    }

    report.warnings.push(
        "DatabaseIdempotencyStore detected, but webhook_processed_events migration marker is missing (add migration e.g. m009_create_webhook_processed_events.rs and register it in migration/src/lib.rs)".to_string(),
    );

    if fix {
        report.fixes.push(
            "Webhook idempotency migration TODO: create migration/src/m009_create_webhook_processed_events.rs (or equivalent) that creates `webhook_processed_events(event_id PRIMARY KEY, processed_at TIMESTAMPTZ NOT NULL)` and register it in migration/src/lib.rs".to_string(),
        );
    }
}

fn project_uses_database_webhook_idempotency(src_dir: &Path) -> bool {
    any_rs_file_contains(src_dir, "DatabaseIdempotencyStore")
}

fn has_webhook_idempotency_migration(project_dir: &Path) -> bool {
    let migration_src = project_dir.join("migration").join("src");
    if !migration_src.exists() {
        return false;
    }

    // Accept either explicit lib registration or table marker in migration files.
    let migration_marker = "webhook_processed_events";

    let lib_rs = migration_src.join("lib.rs");
    if lib_rs.exists()
        && fs::read_to_string(&lib_rs)
            .map(|s| s.contains(migration_marker))
            .unwrap_or(false)
    {
        return true;
    }

    any_rs_file_contains(&migration_src, migration_marker)
}

fn any_rs_file_contains(root: &Path, needle: &str) -> bool {
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            let Ok(entries) = fs::read_dir(&path) else {
                continue;
            };
            for entry in entries.flatten() {
                stack.push(entry.path());
            }
            continue;
        }

        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }

        if fs::read_to_string(&path)
            .map(|contents| contents.contains(needle))
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}
