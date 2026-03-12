//! New command - scaffold a Tideway app.

use anyhow::{Context, Result, anyhow};
use colored::Colorize;
use dialoguer::{Confirm, Input, MultiSelect, Select, console::Term, theme::ColorfulTheme};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use toml_edit::{Array, InlineTable, Item, Table, Value};

use crate::cli::{
    BackendPreset, DbBackend, NewArgs, NewPreset, ResourceArgs, ResourceIdType, ResourceProfile,
};
use crate::commands::file_ops::{to_pascal_case, write_file_with_force_or_error_default};
use crate::commands::messaging::PRIMARY_PATH;
use crate::templates::{BackendTemplateContext, BackendTemplateEngine};
use crate::{
    TIDEWAY_VERSION, ensure_dir, error_contract, is_json_output, print_info, print_success,
    print_warning, write_file,
};

#[derive(Default)]
struct WizardOptions {
    backend_preset: Option<BackendPreset>,
    resource: Option<ResourceWizardOptions>,
}

struct ResourceWizardOptions {
    name: String,
    db: bool,
    repo: bool,
    repo_tests: bool,
    service: bool,
    paginate: bool,
    search: bool,
    with_tests: bool,
}

/// Run the new command
pub fn run(mut args: NewArgs) -> Result<()> {
    if let Some(NewPreset::List) = args.preset {
        print_presets();
        return Ok(());
    }

    let name = args.name.clone().ok_or_else(|| {
        anyhow!(error_contract(
            "Project name is required.",
            "Run `tideway new my_app`.",
            "Use `--path` to control output location separately from project name."
        ))
    })?;

    let mut wizard = WizardOptions::default();
    if should_prompt(&args) {
        wizard = prompt_for_options(&mut args)?;
    } else if should_default_to_api_preset(&args) {
        args.preset = Some(NewPreset::Api);
    }

    if let Some(preset) = args.preset {
        apply_preset(preset, &mut args);
    }

    let dir_name = args.path.clone().unwrap_or_else(|| name.clone());
    let project_name = normalize_project_name(&name);
    let project_name_pascal = to_pascal_case(&project_name);
    let features = normalize_features(&args.features);
    let has_auth_feature = features.contains("auth");
    let has_database_feature = features.contains("database");
    let has_openapi_feature = features.contains("openapi");
    let has_tideway_features = !features.is_empty();
    let starter_database = starter_database_for(&args);

    let target_dir = PathBuf::from(&dir_name);
    if target_dir.exists() {
        if !args.force {
            return Err(anyhow!(error_contract(
                &format!("Destination already exists: {}", target_dir.display()),
                "Choose a new app name/path for a clean scaffold.",
                "Rerun with `--force` to overwrite existing files."
            )));
        }
        print_warning(&format!(
            "Destination exists, files may be overwritten: {}",
            target_dir.display()
        ));
    }

    ensure_dir(&target_dir)
        .with_context(|| format!("Failed to create {}", target_dir.display()))?;

    let needs_arc = has_auth_feature || has_database_feature;
    let context = BackendTemplateContext {
        project_name: project_name.clone(),
        project_name_pascal,
        has_organizations: false,
        database: starter_database.to_string(),
        database_url: starter_database_url(&project_name, starter_database),
        is_sqlite_database: starter_database == "sqlite",
        tideway_version: TIDEWAY_VERSION.to_string(),
        tideway_features: features.iter().cloned().collect(),
        has_tideway_features,
        has_auth_feature,
        has_database_feature,
        has_openapi_feature,
        needs_arc,
        has_config: args.with_config,
    };
    let engine = BackendTemplateEngine::new(context)?;

    let needs_env = needs_env_from_args(&args);
    scaffold_files(&target_dir, &engine, &args, needs_env)?;
    if matches!(args.preset, Some(NewPreset::Api)) {
        scaffold_api_preset(&target_dir)?;
    }
    if let Some(preset) = args.preset {
        if let Some(backend_preset) = preset_backend_preset(preset) {
            scaffold_backend_preset(&target_dir, &project_name, backend_preset)?;
            ensure_backend_dependencies(&target_dir.join("Cargo.toml"))?;
        }
    }
    if let Some(backend_preset) = wizard.backend_preset {
        scaffold_backend_preset(&target_dir, &project_name, backend_preset)?;
        ensure_backend_dependencies(&target_dir.join("Cargo.toml"))?;
    }
    if let Some(resource) = wizard.resource {
        scaffold_wizard_resource(&target_dir, resource)?;
    }
    let created = expected_files(&args);

    if !is_json_output() {
        println!(
            "\n{} {}\n",
            "tideway".cyan().bold(),
            "starter app created".green().bold()
        );
    }

    print_info(&format!("Project name: {}", project_name.green()));
    print_info(&format!(
        "Location: {}",
        target_dir.display().to_string().yellow()
    ));
    if let Some(preset) = args.preset {
        print_info(&format!("Preset: {}", preset_label(preset).green()));
    }
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

    if !is_json_output() {
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
        println!("  {}. tideway dev --fix-env", step);
        println!();
        println!("Optional: run `tideway doctor` for a project/setup audit.");
        println!();
        if should_suggest_migrate(args.preset, has_database_feature) {
            println!("Tip: run `tideway migrate` when you need explicit migration control.");
            println!();
        }

        print_preset_next_steps(args.preset);
    }

    print_info(PRIMARY_PATH);
    print_success("Ready to build");
    Ok(())
}

fn scaffold_files(
    target_dir: &Path,
    engine: &BackendTemplateEngine,
    args: &NewArgs,
    needs_env: bool,
) -> Result<()> {
    let has_auth_feature = normalize_features(&args.features).contains("auth");
    let is_api_preset = matches!(args.preset, Some(NewPreset::Api));

    write_file_with_force_or_error_default(
        &target_dir.join("Cargo.toml"),
        &engine.render("starter/Cargo.toml")?,
        args.force,
    )?;
    write_file_with_force_or_error_default(
        &target_dir.join("src/main.rs"),
        &clean_rust_source(&engine.render("starter/src/main.rs")?),
        args.force,
    )?;
    write_file_with_force_or_error_default(
        &target_dir.join("src/routes/mod.rs"),
        &engine.render("starter/src/routes/mod.rs")?,
        args.force,
    )?;

    if has_auth_feature {
        write_file_with_force_or_error_default(
            &target_dir.join("src/auth/mod.rs"),
            &engine.render("starter/src/auth/mod.rs")?,
            args.force,
        )?;
        write_file_with_force_or_error_default(
            &target_dir.join("src/auth/provider.rs"),
            &engine.render("starter/src/auth/provider.rs")?,
            args.force,
        )?;
        write_file_with_force_or_error_default(
            &target_dir.join("src/auth/routes.rs"),
            &engine.render("starter/src/auth/routes.rs")?,
            args.force,
        )?;
    }

    if args.with_config {
        write_file_with_force_or_error_default(
            &target_dir.join("src/config.rs"),
            &engine.render("starter/src/config.rs")?,
            args.force,
        )?;
        write_file_with_force_or_error_default(
            &target_dir.join("src/error.rs"),
            &engine.render("starter/src/error.rs")?,
            args.force,
        )?;
    }
    if args.with_docker {
        write_file_with_force_or_error_default(
            &target_dir.join("docker-compose.yml"),
            &engine.render("starter/docker-compose")?,
            args.force,
        )?;
    }
    if args.with_ci {
        write_file_with_force_or_error_default(
            &target_dir.join(".github/workflows/ci.yml"),
            &engine.render("starter/github-ci")?,
            args.force,
        )?;
    }
    write_file_with_force_or_error_default(
        &target_dir.join(".gitignore"),
        &engine.render("starter/gitignore")?,
        args.force,
    )?;

    write_file_with_force_or_error_default(
        &target_dir.join("tests/health.rs"),
        &engine.render("starter/tests/health")?,
        args.force,
    )?;

    if needs_env {
        write_file_with_force_or_error_default(
            &target_dir.join(".env.example"),
            &engine.render("starter/env_example")?,
            args.force,
        )?;
    }

    if is_api_preset {
        write_file_with_force_or_error_default(
            &target_dir.join("migration/Cargo.toml"),
            &engine.render("starter/migration/Cargo.toml")?,
            args.force,
        )?;
        write_file_with_force_or_error_default(
            &target_dir.join("migration/src/lib.rs"),
            &engine.render("starter/migration/src/lib.rs")?,
            args.force,
        )?;
    }

    Ok(())
}

pub fn expected_files(args: &NewArgs) -> Vec<String> {
    let needs_env = needs_env_from_args(args);
    let has_auth_feature = normalize_features(&args.features).contains("auth");
    let mut files = vec![
        "Cargo.toml".to_string(),
        "src/main.rs".to_string(),
        "src/routes/mod.rs".to_string(),
    ];

    if has_auth_feature {
        files.push("src/auth/mod.rs".to_string());
        files.push("src/auth/provider.rs".to_string());
        files.push("src/auth/routes.rs".to_string());
    }

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

    if matches!(args.preset, Some(NewPreset::Api)) {
        files.push("migration/Cargo.toml".to_string());
        files.push("migration/src/lib.rs".to_string());
        files.push("migration/src/m001_create_todos.rs".to_string());
        files.push("src/entities/mod.rs".to_string());
        files.push("src/entities/todo.rs".to_string());
        files.push("src/routes/todo.rs".to_string());
        files.push("src/openapi_docs.rs".to_string());
    }

    files
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
            "dbs" => "database",
            "session" => "sessions",
            other => other,
        };
        normalized.insert(mapped.to_string());
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_features_aliases() {
        let features = vec![
            "db".to_string(),
            "session".to_string(),
            "auth".to_string(),
            "SESSIONS".to_string(),
        ];

        let normalized = normalize_features(&features);
        assert!(normalized.contains("database"));
        assert!(normalized.contains("sessions"));
        assert!(normalized.contains("auth"));
        assert_eq!(normalized.len(), 3);
    }
}

fn apply_preset(preset: NewPreset, args: &mut NewArgs) {
    let preset_features: &[&str] = match preset {
        NewPreset::Minimal => &[],
        NewPreset::Api => &["auth", "database", "openapi", "validation"],
        NewPreset::Saas => &[
            "auth",
            "auth-mfa",
            "database",
            "billing",
            "billing-seaorm",
            "organizations",
            "admin",
            "openapi",
            "validation",
            "metrics",
        ],
        NewPreset::Worker => &["database", "jobs", "jobs-redis", "metrics"],
        NewPreset::List => &[],
    };

    for feature in preset_features {
        if !args
            .features
            .iter()
            .any(|item| item.eq_ignore_ascii_case(feature))
        {
            args.features.push(feature.to_string());
        }
    }

    match preset {
        NewPreset::Api => {
            args.with_config = true;
            args.with_ci = true;
            args.with_env = true;
        }
        NewPreset::Saas => {
            args.with_config = true;
            args.with_docker = true;
            args.with_ci = true;
            args.with_env = true;
        }
        NewPreset::Worker => {
            args.with_config = true;
            args.with_docker = true;
            args.with_ci = true;
            args.with_env = true;
        }
        NewPreset::Minimal | NewPreset::List => {}
    }
}

fn apply_backend_defaults(args: &mut NewArgs, has_organizations: bool) {
    let mut features = vec![
        "auth",
        "auth-mfa",
        "database",
        "billing",
        "billing-seaorm",
        "admin",
    ];
    if has_organizations {
        features.push("organizations");
    }

    args.features = features
        .into_iter()
        .map(|feature| feature.to_string())
        .collect();
    args.with_config = true;
    args.with_docker = true;
    args.with_ci = true;
    args.with_env = true;
}

fn preset_label(preset: NewPreset) -> &'static str {
    match preset {
        NewPreset::Minimal => "minimal",
        NewPreset::Api => "api",
        NewPreset::Saas => "saas",
        NewPreset::Worker => "worker",
        NewPreset::List => "list",
    }
}

fn print_presets() {
    if is_json_output() {
        return;
    }
    println!("Available presets:");
    println!("  - minimal: basic starter (no extra features)");
    println!(
        "  - api: auth + database + openapi + validation, plus config, CI, env, and a sample DB-backed resource (SQLite local dev by default; add --with-docker for Postgres)"
    );
    println!(
        "  - saas: b2b backend modules (auth, billing, organizations, admin) + api defaults + production scaffolding"
    );
    println!(
        "  - worker: jobs-first starter (database + jobs + redis + metrics) with config, docker, CI, and env"
    );
}

fn preset_backend_preset(preset: NewPreset) -> Option<BackendPreset> {
    match preset {
        NewPreset::Saas => Some(BackendPreset::B2b),
        _ => None,
    }
}

fn scaffold_api_preset(target_dir: &Path) -> Result<()> {
    let args = ResourceArgs {
        name: "todo".to_string(),
        path: target_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: true,
        db: true,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: DbBackend::Auto,
        profile: ResourceProfile::Stub,
    };

    crate::commands::resource::run(args)?;
    Ok(())
}

fn scaffold_backend_preset(
    target_dir: &Path,
    project_name: &str,
    preset: BackendPreset,
) -> Result<()> {
    let has_organizations = matches!(preset, BackendPreset::B2b);
    let backend_args = crate::cli::BackendArgs {
        preset,
        name: project_name.to_string(),
        output: target_dir.join("src").to_string_lossy().to_string(),
        migrations_output: target_dir
            .join("migration/src")
            .to_string_lossy()
            .to_string(),
        force: true,
        database: "postgres".to_string(),
    };

    crate::commands::backend::run(backend_args)?;

    let context = BackendTemplateContext {
        project_name: project_name.to_string(),
        project_name_pascal: to_pascal_case(project_name),
        has_organizations,
        database: "postgres".to_string(),
        database_url: starter_database_url(project_name, "postgres"),
        is_sqlite_database: false,
        tideway_version: TIDEWAY_VERSION.to_string(),
        tideway_features: Vec::new(),
        has_tideway_features: false,
        has_auth_feature: false,
        has_database_feature: false,
        has_openapi_feature: false,
        needs_arc: false,
        has_config: false,
    };
    let engine = BackendTemplateEngine::new(context)?;
    write_file_with_force_or_error_default(
        &target_dir.join("migration/Cargo.toml"),
        &engine.render("starter/migration/Cargo.toml")?,
        true,
    )?;

    Ok(())
}

fn scaffold_wizard_resource(target_dir: &Path, resource: ResourceWizardOptions) -> Result<()> {
    let args = ResourceArgs {
        name: resource.name,
        path: target_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: resource.with_tests,
        db: resource.db,
        repo: resource.repo,
        repo_tests: resource.repo_tests,
        service: resource.service,
        id_type: ResourceIdType::Int,
        add_uuid: false,
        paginate: resource.paginate,
        search: resource.search,
        db_backend: DbBackend::Auto,
        profile: ResourceProfile::Stub,
    };

    crate::commands::resource::run(args)?;
    Ok(())
}

fn ensure_backend_dependencies(cargo_path: &Path) -> Result<()> {
    let contents = fs::read_to_string(cargo_path)
        .with_context(|| format!("Failed to read {}", cargo_path.display()))?;
    let mut doc = contents.parse::<toml_edit::DocumentMut>()?;

    let deps = doc["dependencies"].or_insert(Item::Table(Table::new()));
    let deps_table = deps.as_table_mut().expect("dependencies should be a table");

    ensure_dependency_value(deps_table, "tracing", Value::from("0.1"));
    ensure_dependency_value(deps_table, "dotenvy", Value::from("0.15"));
    ensure_dependency_inline(deps_table, "uuid", "1", &["v4", "serde"]);
    ensure_dependency_inline(deps_table, "chrono", "0.4", &["serde"]);

    write_file(cargo_path, &doc.to_string())
        .with_context(|| format!("Failed to write {}", cargo_path.display()))?;
    Ok(())
}

fn ensure_dependency_value(deps: &mut Table, name: &str, value: Value) {
    if !deps.contains_key(name) {
        deps.insert(name, Item::Value(value));
    }
}

fn ensure_dependency_inline(deps: &mut Table, name: &str, version: &str, features: &[&str]) {
    if deps.contains_key(name) {
        return;
    }

    let mut table = InlineTable::new();
    table.get_or_insert("version", version);
    let mut array = Array::new();
    for feature in features {
        array.push(*feature);
    }
    table.get_or_insert("features", Value::Array(array));
    deps.insert(name, Item::Value(Value::InlineTable(table)));
}

fn needs_env_from_args(args: &NewArgs) -> bool {
    let features = normalize_features(&args.features);
    features.contains("auth") || features.contains("database") || args.with_config || args.with_env
}

fn starter_database_for(args: &NewArgs) -> &'static str {
    match args.preset {
        Some(NewPreset::Api) if !args.with_docker => "sqlite",
        _ => "postgres",
    }
}

fn starter_database_url(project_name: &str, database: &str) -> String {
    match database {
        "sqlite" => format!("sqlite:./{}.db?mode=rwc", project_name),
        _ => format!(
            "postgres://postgres:postgres@localhost:5432/{}",
            project_name
        ),
    }
}

fn should_default_to_api_preset(args: &NewArgs) -> bool {
    args.preset.is_none()
        && args.features.is_empty()
        && !args.with_config
        && !args.with_docker
        && !args.with_ci
        && !args.with_env
        && (args.no_prompt || !Term::stdout().is_term())
}

fn should_suggest_migrate(preset: Option<NewPreset>, has_database_feature: bool) -> bool {
    if !has_database_feature {
        return false;
    }
    !matches!(preset, Some(NewPreset::Worker))
}

fn print_preset_next_steps(preset: Option<NewPreset>) {
    match preset {
        Some(NewPreset::Api) => {
            println!("{}", "First request:".yellow().bold());
            println!("  curl http://localhost:8000/api/todos");
            println!("  # OpenAPI (if enabled): http://localhost:8000/swagger-ui");
            println!();
        }
        Some(NewPreset::Saas) => {
            println!("{}", "SaaS smoke checks:".yellow().bold());
            println!("  curl http://localhost:8000/health");
            println!("  # OpenAPI (if enabled): http://localhost:8000/swagger-ui");
            println!();
        }
        Some(NewPreset::Worker) => {
            println!("{}", "Worker smoke checks:".yellow().bold());
            println!("  # Ensure REDIS_URL and DATABASE_URL are set in .env");
            println!("  tideway dev --fix-env");
            println!();
        }
        _ => {}
    }
}

fn clean_rust_source(source: &str) -> String {
    let mut out = String::new();
    let mut empty_run = 0usize;
    for line in source.lines() {
        if line.trim().is_empty() {
            empty_run += 1;
            if empty_run > 1 {
                continue;
            }
            out.push('\n');
        } else {
            empty_run = 0;
            out.push_str(line);
            out.push('\n');
        }
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn should_prompt(args: &NewArgs) -> bool {
    args.features.is_empty()
        && args.preset.is_none()
        && !args.with_config
        && !args.with_docker
        && !args.with_ci
        && !args.no_prompt
        && Term::stdout().is_term()
}

fn prompt_for_options(args: &mut NewArgs) -> Result<WizardOptions> {
    let theme = ColorfulTheme::default();
    let mut wizard = WizardOptions::default();

    let preset_options = [
        "Minimal (no extra features)",
        "API preset (auth + database + openapi + validation)",
        "SaaS preset (b2b backend + api defaults)",
        "Worker preset (jobs + redis + metrics)",
        "Backend preset: B2C (auth + billing + admin)",
        "Backend preset: B2B (auth + billing + orgs + admin)",
        "Custom (pick features)",
    ];

    let preset_choice = Select::with_theme(&theme)
        .with_prompt("Choose a starter preset")
        .items(&preset_options)
        .default(1)
        .interact()
        .map_err(|e| anyhow!("Prompt failed: {}", e))?;

    match preset_choice {
        0 => {
            args.preset = Some(NewPreset::Minimal);
        }
        1 => {
            args.preset = Some(NewPreset::Api);
        }
        2 => {
            args.preset = Some(NewPreset::Saas);
        }
        3 => {
            args.preset = Some(NewPreset::Worker);
        }
        4 => {
            wizard.backend_preset = Some(BackendPreset::B2c);
            apply_backend_defaults(args, false);
        }
        5 => {
            wizard.backend_preset = Some(BackendPreset::B2b);
            apply_backend_defaults(args, true);
        }
        _ => {
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
        }
    }

    if Confirm::with_theme(&theme)
        .with_prompt("Generate your first resource now?")
        .default(true)
        .interact()
        .map_err(|e| anyhow!("Prompt failed: {}", e))?
    {
        let name = Input::<String>::with_theme(&theme)
            .with_prompt("Resource name (singular, e.g. carehome)")
            .interact_text()
            .map_err(|e| anyhow!("Prompt failed: {}", e))?;

        let has_database_feature = normalize_features(&args.features).contains("database");
        let db = Confirm::with_theme(&theme)
            .with_prompt("Use database-backed CRUD?")
            .default(has_database_feature)
            .interact()
            .map_err(|e| anyhow!("Prompt failed: {}", e))?;

        let mut repo = false;
        let mut repo_tests = false;
        let mut service = false;
        let mut paginate = false;
        let mut search = false;

        if db {
            repo = Confirm::with_theme(&theme)
                .with_prompt("Generate a repository layer?")
                .default(true)
                .interact()
                .map_err(|e| anyhow!("Prompt failed: {}", e))?;
            if repo {
                repo_tests = Confirm::with_theme(&theme)
                    .with_prompt("Generate repository tests? (requires DATABASE_URL)")
                    .default(false)
                    .interact()
                    .map_err(|e| anyhow!("Prompt failed: {}", e))?;
                service = Confirm::with_theme(&theme)
                    .with_prompt("Generate a service layer?")
                    .default(true)
                    .interact()
                    .map_err(|e| anyhow!("Prompt failed: {}", e))?;
            }
            paginate = Confirm::with_theme(&theme)
                .with_prompt("Add pagination to list endpoints?")
                .default(true)
                .interact()
                .map_err(|e| anyhow!("Prompt failed: {}", e))?;
            if paginate {
                search = Confirm::with_theme(&theme)
                    .with_prompt("Add a search filter (q) to list endpoints?")
                    .default(true)
                    .interact()
                    .map_err(|e| anyhow!("Prompt failed: {}", e))?;
            }
        }

        let with_tests = Confirm::with_theme(&theme)
            .with_prompt("Generate route tests?")
            .default(true)
            .interact()
            .map_err(|e| anyhow!("Prompt failed: {}", e))?;

        wizard.resource = Some(ResourceWizardOptions {
            name,
            db,
            repo,
            repo_tests,
            service,
            paginate,
            search,
            with_tests,
        });
    }

    Ok(wizard)
}
