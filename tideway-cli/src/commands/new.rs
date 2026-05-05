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
    CommandRuntime, ExecutionPlan, PlanStep, TIDEWAY_VERSION, ensure_dir, error_contract,
    print_info, print_success, print_warning, write_file,
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

const PRIMARY_PRESET_OPTIONS: [&str; 4] = [
    "API preset (recommended: auth + database + openapi + validation + full-stack todo sample)",
    "SaaS preset (b2b auth + billing + orgs + admin)",
    "Worker preset (jobs + redis + metrics)",
    "Advanced options (minimal, backend presets, custom)",
];

const ADVANCED_PRESET_OPTIONS: [&str; 4] = [
    "Minimal (no extra features)",
    "Backend preset: B2C (auth + billing + admin)",
    "Backend preset: B2B (auth + billing + orgs + admin)",
    "Custom (pick features)",
];

/// Run the new command
pub fn run(args: NewArgs) -> Result<()> {
    run_with_runtime(args, CommandRuntime::from_process_state())
}

pub fn run_with_runtime(mut args: NewArgs, runtime: CommandRuntime) -> Result<()> {
    runtime.install();

    if let Some(NewPreset::List) = args.preset {
        print_presets(runtime);
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
    let backend_preset = args
        .preset
        .and_then(preset_backend_preset)
        .or(wizard.backend_preset.clone());

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

    let created = planned_files_for(&args, backend_preset.as_ref(), wizard.resource.as_ref());
    if runtime.plan_mode() {
        return emit_new_plan(
            &target_dir,
            &project_name,
            args.preset,
            &features,
            args.summary,
            &created,
            runtime,
        );
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
        has_billing_feature: features.contains("billing"),
        has_openapi_feature,
        needs_arc,
        has_config: args.with_config,
    };
    let engine = BackendTemplateEngine::new(context)?;

    let needs_env = needs_env_from_args(&args);
    scaffold_files(
        &target_dir,
        &engine,
        &args,
        needs_env,
        backend_preset.is_some(),
    )?;
    if matches!(args.preset, Some(NewPreset::Api)) {
        scaffold_api_preset(&target_dir, runtime)?;
    }
    if let Some(backend_preset) = backend_preset.clone() {
        scaffold_backend_preset(&target_dir, &project_name, backend_preset, runtime)?;
        ensure_backend_dependencies(&target_dir.join("Cargo.toml"))?;
    }
    if let Some(resource) = wizard.resource {
        scaffold_wizard_resource(&target_dir, resource, runtime)?;
    }

    if !runtime.json_output() {
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

    if !runtime.json_output() {
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
        println!("  {}. tideway dev", step);
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
    is_backend_scaffold: bool,
) -> Result<()> {
    let has_auth_feature = normalize_features(&args.features).contains("auth");
    let is_api_preset = matches!(args.preset, Some(NewPreset::Api));

    write_file_with_force_or_error_default(
        &target_dir.join("Cargo.toml"),
        &engine.render("starter/Cargo.toml")?,
        args.force,
    )?;
    if !is_backend_scaffold {
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

    if needs_env && !is_backend_scaffold {
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
    expected_files_for(args, None)
}

fn planned_files_for(
    args: &NewArgs,
    backend_preset: Option<&BackendPreset>,
    wizard_resource: Option<&ResourceWizardOptions>,
) -> Vec<String> {
    let mut files = expected_files_for(args, backend_preset);
    if let Some(resource) = wizard_resource {
        for file in wizard_resource_expected_files(args, &files, resource) {
            append_unique_file(&mut files, file);
        }
    }
    files
}

fn expected_files_for(args: &NewArgs, backend_preset: Option<&BackendPreset>) -> Vec<String> {
    let needs_env = needs_env_from_args(args);
    let has_auth_feature = normalize_features(&args.features).contains("auth");
    let mut files = vec!["Cargo.toml".to_string()];

    if let Some(backend_preset) = backend_preset {
        files.extend(backend_preset_expected_files(backend_preset));
    } else {
        files.push("src/main.rs".to_string());
        files.push("src/routes/mod.rs".to_string());

        if has_auth_feature {
            files.push("src/auth/mod.rs".to_string());
            files.push("src/auth/provider.rs".to_string());
            files.push("src/auth/routes.rs".to_string());
        }

        if args.with_config {
            files.push("src/config.rs".to_string());
            files.push("src/error.rs".to_string());
        }
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
        files.push("src/repositories/mod.rs".to_string());
        files.push("src/repositories/todo.rs".to_string());
        files.push("src/services/mod.rs".to_string());
        files.push("src/services/todo.rs".to_string());
        files.push("src/routes/todo.rs".to_string());
        files.push("src/openapi_docs.rs".to_string());
    }

    files
}

fn wizard_resource_expected_files(
    args: &NewArgs,
    planned_files: &[String],
    resource: &ResourceWizardOptions,
) -> Vec<String> {
    let resource_name = normalize_resource_name(&resource.name);
    let resource_plural = pluralize_resource_name(&resource_name);
    let mut files = vec![format!("src/routes/{resource_name}.rs")];

    if resource.db {
        files.push("src/entities/mod.rs".to_string());
        files.push(format!("src/entities/{resource_name}.rs"));
        if !planned_files
            .iter()
            .any(|file| file == "migration/src/lib.rs")
        {
            files.push("migration/src/lib.rs".to_string());
        }
        files.push(next_planned_migration_file(planned_files, &resource_plural));

        if resource.repo {
            files.push("src/repositories/mod.rs".to_string());
            files.push(format!("src/repositories/{resource_name}.rs"));
            if resource.repo_tests {
                files.push(format!("tests/repository_{resource_name}.rs"));
            }
            if resource.service {
                files.push("src/services/mod.rs".to_string());
                files.push(format!("src/services/{resource_name}.rs"));
            }
        }
    }

    if normalize_features(&args.features).contains("openapi") {
        append_unique_file(&mut files, "src/openapi_docs.rs".to_string());
    }

    append_unique_file(&mut files, "src/main.rs".to_string());
    append_unique_file(&mut files, "src/routes/mod.rs".to_string());
    files
}

fn append_unique_file(files: &mut Vec<String>, path: String) {
    if !files.iter().any(|existing| existing == &path) {
        files.push(path);
    }
}

fn next_planned_migration_file(planned_files: &[String], resource_plural: &str) -> String {
    let next_index = planned_files
        .iter()
        .filter_map(|path| path.strip_prefix("migration/src/m"))
        .filter_map(|rest| {
            let digits = rest
                .chars()
                .take_while(|ch| ch.is_ascii_digit())
                .collect::<String>();
            digits.parse::<u32>().ok()
        })
        .max()
        .unwrap_or(0)
        + 1;

    format!(
        "migration/src/m{next_index:03}_create_{resource_plural}.rs",
        next_index = next_index,
        resource_plural = resource_plural,
    )
}

fn normalize_resource_name(name: &str) -> String {
    name.trim().to_lowercase().replace('-', "_")
}

fn pluralize_resource_name(name: &str) -> String {
    if name.ends_with('s') {
        format!("{name}es")
    } else {
        format!("{name}s")
    }
}

fn emit_new_plan(
    target_dir: &Path,
    project_name: &str,
    preset: Option<NewPreset>,
    features: &BTreeSet<String>,
    summary: bool,
    files: &[String],
    runtime: CommandRuntime,
) -> Result<()> {
    if !runtime.json_output() {
        println!(
            "\n{} {}\n",
            "tideway".cyan().bold(),
            "planning starter app".yellow().bold()
        );
    }

    print_info(&format!("Project name: {}", project_name.green()));
    print_info(&format!(
        "Location: {}",
        target_dir.display().to_string().yellow()
    ));
    if let Some(preset) = preset {
        print_info(&format!("Preset: {}", preset_label(preset).green()));
    }
    if !features.is_empty() {
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

    let mut created_dirs = BTreeSet::new();
    let mut plan = ExecutionPlan::new(format!(
        "would scaffold Tideway starter app in {}",
        target_dir.display()
    ));
    for file in files {
        let path = target_dir.join(file);
        append_plan_write_steps(&path, &mut created_dirs, &mut plan);
    }
    plan.emit(runtime);

    if summary && !runtime.json_output() {
        println!("\n{}", "Planned files:".yellow().bold());
        for path in files {
            println!("  - {}", path);
        }
    }

    print_info("Plan complete: no files were written");
    Ok(())
}

fn append_plan_write_steps(
    path: &Path,
    created_dirs: &mut BTreeSet<PathBuf>,
    plan: &mut ExecutionPlan,
) {
    let mut missing_dirs = Vec::new();
    let mut current = path.parent();
    while let Some(dir) = current {
        if dir.exists() {
            break;
        }
        let dir_path = dir.to_path_buf();
        if created_dirs.insert(dir_path.clone()) {
            missing_dirs.push(dir_path);
        }
        current = dir.parent();
    }

    missing_dirs.reverse();
    for dir in missing_dirs {
        *plan = plan
            .clone()
            .step(PlanStep::create_directory(dir.display().to_string()));
    }
    *plan = plan
        .clone()
        .step(PlanStep::write_file(path.display().to_string()));
}

fn backend_preset_expected_files(preset: &BackendPreset) -> Vec<String> {
    let mut files = vec![
        "src/main.rs".to_string(),
        "src/lib.rs".to_string(),
        "src/config.rs".to_string(),
        "src/error.rs".to_string(),
        "src/entities/mod.rs".to_string(),
        "src/entities/prelude.rs".to_string(),
        "src/entities/user.rs".to_string(),
        "src/entities/refresh_token_family.rs".to_string(),
        "src/entities/verification_token.rs".to_string(),
        "src/auth/actor.rs".to_string(),
        "src/auth/mod.rs".to_string(),
        "src/auth/routes.rs".to_string(),
        "src/auth/store.rs".to_string(),
        "src/billing/mod.rs".to_string(),
        "src/billing/routes.rs".to_string(),
        "src/admin/mod.rs".to_string(),
        "src/admin/routes.rs".to_string(),
        "migration/Cargo.toml".to_string(),
        "migration/src/lib.rs".to_string(),
        "migration/src/m001_create_users.rs".to_string(),
        "migration/src/m002_create_refresh_token_families.rs".to_string(),
        "migration/src/m003_create_verification_tokens.rs".to_string(),
        "migration/src/m004_create_billing.rs".to_string(),
        "migration/src/m008_create_billing_plans.rs".to_string(),
        "migration/src/m009_create_webhook_processed_events.rs".to_string(),
    ];

    if *preset == BackendPreset::B2b {
        files.push("src/entities/organization.rs".to_string());
        files.push("src/entities/organization_member.rs".to_string());
        files.push("src/organizations/mod.rs".to_string());
        files.push("src/organizations/routes.rs".to_string());
        files.push("migration/src/m005_create_organizations.rs".to_string());
        files.push("migration/src/m006_create_organization_members.rs".to_string());
        files.push("migration/src/m007_add_admin_flag.rs".to_string());
    } else {
        files.push("migration/src/m005_add_admin_flag.rs".to_string());
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

    #[test]
    fn test_primary_preset_options_focus_on_three_paths() {
        assert_eq!(
            PRIMARY_PRESET_OPTIONS[0],
            "API preset (recommended: auth + database + openapi + validation + full-stack todo sample)"
        );
        assert_eq!(
            PRIMARY_PRESET_OPTIONS[1],
            "SaaS preset (b2b auth + billing + orgs + admin)"
        );
        assert_eq!(
            PRIMARY_PRESET_OPTIONS[2],
            "Worker preset (jobs + redis + metrics)"
        );
        assert_eq!(
            PRIMARY_PRESET_OPTIONS[3],
            "Advanced options (minimal, backend presets, custom)"
        );
    }

    #[test]
    fn test_apply_primary_wizard_choice_maps_to_promoted_presets() {
        let mut args = NewArgs {
            name: None,
            preset: None,
            features: Vec::new(),
            with_config: false,
            with_docker: false,
            with_ci: false,
            no_prompt: false,
            summary: true,
            with_env: false,
            path: None,
            force: false,
        };
        assert!(!apply_primary_wizard_choice(0, &mut args));
        assert_eq!(args.preset, Some(NewPreset::Api));

        args.preset = None;
        assert!(!apply_primary_wizard_choice(1, &mut args));
        assert_eq!(args.preset, Some(NewPreset::Saas));

        args.preset = None;
        assert!(!apply_primary_wizard_choice(2, &mut args));
        assert_eq!(args.preset, Some(NewPreset::Worker));

        args.preset = None;
        assert!(apply_primary_wizard_choice(3, &mut args));
        assert_eq!(args.preset, None);
    }

    #[test]
    fn test_apply_advanced_wizard_choice_preserves_advanced_paths() {
        let mut args = NewArgs {
            name: None,
            preset: None,
            features: Vec::new(),
            with_config: false,
            with_docker: false,
            with_ci: false,
            no_prompt: false,
            summary: true,
            with_env: false,
            path: None,
            force: false,
        };
        let mut wizard = WizardOptions::default();

        apply_advanced_wizard_choice(0, &mut args, &mut wizard);
        assert_eq!(args.preset, Some(NewPreset::Minimal));

        args.preset = None;
        wizard = WizardOptions::default();
        apply_advanced_wizard_choice(1, &mut args, &mut wizard);
        assert_eq!(wizard.backend_preset, Some(BackendPreset::B2c));
        assert!(args.with_config);
        assert!(args.with_docker);
        assert!(args.with_ci);
        assert!(args.with_env);

        args = NewArgs {
            name: None,
            preset: None,
            features: Vec::new(),
            with_config: false,
            with_docker: false,
            with_ci: false,
            no_prompt: false,
            summary: true,
            with_env: false,
            path: None,
            force: false,
        };
        wizard = WizardOptions::default();
        apply_advanced_wizard_choice(2, &mut args, &mut wizard);
        assert_eq!(wizard.backend_preset, Some(BackendPreset::B2b));
        assert!(
            args.features
                .iter()
                .any(|feature| feature == "organizations")
        );

        args = NewArgs {
            name: None,
            preset: None,
            features: Vec::new(),
            with_config: false,
            with_docker: false,
            with_ci: false,
            no_prompt: false,
            summary: true,
            with_env: false,
            path: None,
            force: false,
        };
        wizard = WizardOptions::default();
        apply_advanced_wizard_choice(3, &mut args, &mut wizard);
        assert_eq!(args.preset, None);
        assert_eq!(wizard.backend_preset, None);
    }
}

fn apply_primary_wizard_choice(preset_choice: usize, args: &mut NewArgs) -> bool {
    match preset_choice {
        0 => {
            args.preset = Some(NewPreset::Api);
            false
        }
        1 => {
            args.preset = Some(NewPreset::Saas);
            false
        }
        2 => {
            args.preset = Some(NewPreset::Worker);
            false
        }
        3 => true,
        _ => unreachable!("unexpected primary preset choice: {preset_choice}"),
    }
}

fn apply_advanced_wizard_choice(
    preset_choice: usize,
    args: &mut NewArgs,
    wizard: &mut WizardOptions,
) {
    match preset_choice {
        0 => {
            args.preset = Some(NewPreset::Minimal);
        }
        1 => {
            wizard.backend_preset = Some(BackendPreset::B2c);
            apply_backend_defaults(args, false);
        }
        2 => {
            wizard.backend_preset = Some(BackendPreset::B2b);
            apply_backend_defaults(args, true);
        }
        3 => {}
        _ => unreachable!("unexpected advanced preset choice: {preset_choice}"),
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

fn print_presets(runtime: CommandRuntime) {
    if runtime.json_output() {
        return;
    }
    println!("Available presets:");
    println!("  - minimal: basic starter (no extra features)");
    println!(
        "  - api: auth + database + openapi + validation, plus config, CI, env, and a sample todo resource with entity/repository/service layers, pagination, and search (SQLite local dev by default; add --with-docker for Postgres)"
    );
    println!(
        "  - saas: b2b backend scaffold with auth, billing, organizations, admin, docker, CI, env, and billing-ready defaults"
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

fn scaffold_api_preset(target_dir: &Path, runtime: CommandRuntime) -> Result<()> {
    let args = ResourceArgs {
        name: "todo".to_string(),
        path: target_dir.to_string_lossy().to_string(),
        wire: false,
        with_tests: true,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: DbBackend::Auto,
        profile: ResourceProfile::Api,
    };

    crate::commands::resource::run_with_runtime(args, runtime)?;
    Ok(())
}

fn scaffold_backend_preset(
    target_dir: &Path,
    project_name: &str,
    preset: BackendPreset,
    runtime: CommandRuntime,
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

    crate::commands::backend::scaffold(
        &backend_args,
        crate::commands::backend::BackendScaffoldMode::EmbeddedInNew,
        runtime,
    )?;

    let engine = backend_template_engine(project_name, has_organizations)?;
    write_file_with_force_or_error_default(
        &target_dir.join("migration/Cargo.toml"),
        &engine.render("starter/migration/Cargo.toml")?,
        true,
    )?;
    write_file(
        &target_dir.join(".env.example"),
        &engine.render("shared/env_example")?,
    )?;

    Ok(())
}

fn backend_template_engine(
    project_name: &str,
    has_organizations: bool,
) -> Result<BackendTemplateEngine> {
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
        has_billing_feature: true,
        has_openapi_feature: false,
        needs_arc: false,
        has_config: false,
    };

    BackendTemplateEngine::new(context)
}

fn scaffold_wizard_resource(
    target_dir: &Path,
    resource: ResourceWizardOptions,
    runtime: CommandRuntime,
) -> Result<()> {
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

    crate::commands::resource::run_with_runtime(args, runtime)?;
    Ok(())
}

fn ensure_backend_dependencies(cargo_path: &Path) -> Result<()> {
    let contents = fs::read_to_string(cargo_path)
        .with_context(|| format!("Failed to read {}", cargo_path.display()))?;
    let mut doc = contents.parse::<toml_edit::DocumentMut>()?;

    let deps = doc["dependencies"].or_insert(Item::Table(Table::new()));
    let deps_table = deps.as_table_mut().expect("dependencies should be a table");

    ensure_dependency_value(deps_table, "anyhow", Value::from("1"));
    ensure_dependency_value(deps_table, "tracing", Value::from("0.1"));
    ensure_dependency_value(deps_table, "dotenvy", Value::from("0.15"));
    ensure_dependency_path(deps_table, "migration", "migration");
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

fn ensure_dependency_path(deps: &mut Table, name: &str, path: &str) {
    if deps.contains_key(name) {
        return;
    }

    let mut table = InlineTable::new();
    table.get_or_insert("path", path);
    deps.insert(name, Item::Value(Value::InlineTable(table)));
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
            println!("  curl \"http://localhost:8000/api/todos?limit=20&offset=0&q=Example\"");
            println!("  # OpenAPI (if enabled): http://localhost:8000/swagger-ui");
            println!();
        }
        Some(NewPreset::Saas) => {
            println!("{}", "SaaS smoke checks:".yellow().bold());
            println!("  curl http://localhost:8000/health");
            println!("  curl http://localhost:8000/billing/public/plans");
            println!();
        }
        Some(NewPreset::Worker) => {
            println!("{}", "Worker smoke checks:".yellow().bold());
            println!("  # Ensure REDIS_URL and DATABASE_URL are set in .env");
            println!("  tideway dev");
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

    let preset_choice = Select::with_theme(&theme)
        .with_prompt("Choose a starter path")
        .items(&PRIMARY_PRESET_OPTIONS)
        .default(0)
        .interact()
        .map_err(|e| anyhow!("Prompt failed: {}", e))?;

    let use_advanced_options = apply_primary_wizard_choice(preset_choice, args);

    if use_advanced_options {
        let advanced_choice = Select::with_theme(&theme)
            .with_prompt("Choose an advanced starter path")
            .items(&ADVANCED_PRESET_OPTIONS)
            .default(0)
            .interact()
            .map_err(|e| anyhow!("Prompt failed: {}", e))?;

        apply_advanced_wizard_choice(advanced_choice, args, &mut wizard);

        if advanced_choice == 3 {
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
