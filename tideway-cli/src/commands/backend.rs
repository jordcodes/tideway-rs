//! Backend command - generates Rust backend scaffolding from templates.

use anyhow::{Context, Result};
use colored::Colorize;
use std::path::Path;

use crate::cli::{BackendArgs, BackendPreset};
use crate::commands::file_ops::{
    BACKEND_FORCE_OVERWRITE_MESSAGE, to_pascal_case, write_file_with_force_with_message,
};
use crate::commands::messaging::NEW_APP_COMMAND;
use crate::templates::{BackendTemplateContext, BackendTemplateEngine};
use crate::{TIDEWAY_VERSION, ensure_dir, is_json_output, is_plan_mode, print_info, print_success};

#[derive(Copy, Clone)]
pub(crate) enum BackendScaffoldMode {
    Cli,
    EmbeddedInNew,
}

impl BackendScaffoldMode {
    fn emit_header(self) -> bool {
        matches!(self, Self::Cli)
    }

    fn emit_progress(self) -> bool {
        matches!(self, Self::Cli)
    }

    fn emit_summary(self) -> bool {
        matches!(self, Self::Cli)
    }
}

/// Run the backend command
pub fn run(args: BackendArgs) -> Result<()> {
    scaffold(&args, BackendScaffoldMode::Cli)
}

pub(crate) fn scaffold(args: &BackendArgs, mode: BackendScaffoldMode) -> Result<()> {
    let plan_mode = is_plan_mode();
    let has_organizations = args.preset == BackendPreset::B2b;
    let preset_name = match args.preset {
        BackendPreset::B2c => "B2C (Auth + Billing + Admin)",
        BackendPreset::B2b => "B2B (Auth + Billing + Organizations + Admin)",
    };

    if mode.emit_header() && !is_json_output() {
        if plan_mode {
            println!(
                "\n{} Planning {} backend scaffolding\n",
                "tideway".cyan().bold(),
                preset_name.green()
            );
        } else {
            println!(
                "\n{} Generating {} backend scaffolding\n",
                "tideway".cyan().bold(),
                preset_name.green()
            );
        }
        println!(
            "  Project: {}\n  Database: {}\n  Output: {}\n",
            args.name.yellow(),
            args.database.yellow(),
            args.output.yellow()
        );
    }

    // Create output directories
    let output_path = Path::new(&args.output);
    let migrations_path = Path::new(&args.migrations_output);

    if !output_path.exists() {
        ensure_dir(output_path)
            .with_context(|| format!("Failed to create output directory: {}", args.output))?;
        if mode.emit_progress() {
            print_info(&format!("Created directory: {}", args.output));
        }
    }

    if !migrations_path.exists() {
        ensure_dir(migrations_path).with_context(|| {
            format!(
                "Failed to create migrations directory: {}",
                args.migrations_output
            )
        })?;
        if mode.emit_progress() {
            print_info(&format!("Created directory: {}", args.migrations_output));
        }
    }

    // Create template context
    let context = BackendTemplateContext {
        project_name: args.name.clone(),
        project_name_pascal: to_pascal_case(&args.name),
        has_organizations,
        database: args.database.clone(),
        database_url: match args.database.as_str() {
            "sqlite" => format!("sqlite:./{}.db?mode=rwc", args.name),
            _ => format!("postgres://postgres:postgres@localhost:5432/{}", args.name),
        },
        is_sqlite_database: args.database == "sqlite",
        tideway_version: TIDEWAY_VERSION.to_string(),
        tideway_features: Vec::new(),
        has_tideway_features: false,
        has_auth_feature: false,
        has_database_feature: false,
        has_openapi_feature: false,
        needs_arc: false,
        has_config: false,
    };

    // Initialize template engine
    let engine = BackendTemplateEngine::new(context)?;

    // Generate shared files
    generate_shared(&engine, output_path, args, mode.emit_progress())?;

    // Generate entities
    generate_entities(&engine, output_path, args, mode.emit_progress())?;

    // Generate auth module
    generate_auth(&engine, output_path, args, mode.emit_progress())?;

    // Generate billing module
    generate_billing(&engine, output_path, args, mode.emit_progress())?;

    // Generate organizations module (B2B only)
    if has_organizations {
        generate_organizations(&engine, output_path, args, mode.emit_progress())?;
    }

    // Generate admin module
    generate_admin(&engine, output_path, args, mode.emit_progress())?;

    // Generate migrations
    generate_migrations(&engine, migrations_path, args, mode.emit_progress())?;

    if plan_mode {
        if mode.emit_summary() {
            print_info("Plan complete: no files were written");
        }
        return Ok(());
    }

    if mode.emit_summary() && !is_json_output() {
        println!(
            "\n{} Backend scaffolding generated successfully!\n",
            "✓".green().bold()
        );
        print_info(&format!(
            "Note: `tideway backend` is advanced. For greenfield apps, prefer {}.",
            NEW_APP_COMMAND
        ));

        // Print next steps
        println!("{}", "Next steps:".yellow().bold());
        println!("  1. Add dependencies to Cargo.toml:");
        println!(
            "     tideway = {{ version = \"{}\", features = [\"auth\", \"auth-mfa\", \"database\", \"billing\", \"billing-seaorm\", \"organizations\", \"admin\"] }}",
            TIDEWAY_VERSION
        );
        println!("     axum = {{ version = \"0.8\", features = [\"macros\"] }}");
        println!(
            "     sea-orm = {{ version = \"1.1\", features = [\"sqlx-postgres\", \"runtime-tokio-rustls\"] }}"
        );
        println!("     tokio = {{ version = \"1\", features = [\"full\"] }}");
        println!("     serde = {{ version = \"1\", features = [\"derive\"] }}");
        println!("     serde_json = \"1\"");
        println!("     anyhow = \"1\"");
        println!("     dotenvy = \"0.15\"");
        println!("     tracing = \"0.1\"");
        println!("     async-trait = \"0.1\"");
        println!("     chrono = {{ version = \"0.4\", features = [\"serde\"] }}");
        println!("     uuid = {{ version = \"1\", features = [\"v4\", \"serde\"] }}");
        println!("     migration = {{ path = \"migration\" }}");
        println!();
        println!("  2. Run migrations:");
        println!("     sea-orm-cli migrate up");
        println!();
        println!("  3. Start the server:");
        println!("     cargo run");
        println!();
    }

    Ok(())
}

fn report_generated(emit_progress: bool, path: &str) {
    if emit_progress {
        print_success(&format!("Generated {}", path));
    }
}

fn generate_shared(
    engine: &BackendTemplateEngine,
    output_path: &Path,
    args: &BackendArgs,
    emit_progress: bool,
) -> Result<()> {
    // Generate main.rs
    if engine.has_template("shared/main") {
        let content = engine.render("shared/main")?;
        let file_path = output_path.join("main.rs");
        write_file_with_force_with_message(
            &file_path,
            &content,
            args.force,
            BACKEND_FORCE_OVERWRITE_MESSAGE,
        )?;
        report_generated(emit_progress, "main.rs");
    }

    // Generate lib.rs
    if engine.has_template("shared/lib") {
        let content = engine.render("shared/lib")?;
        let file_path = output_path.join("lib.rs");
        write_file_with_force_with_message(
            &file_path,
            &content,
            args.force,
            BACKEND_FORCE_OVERWRITE_MESSAGE,
        )?;
        report_generated(emit_progress, "lib.rs");
    }

    // Generate config.rs
    if engine.has_template("shared/config") {
        let content = engine.render("shared/config")?;
        let file_path = output_path.join("config.rs");
        write_file_with_force_with_message(
            &file_path,
            &content,
            args.force,
            BACKEND_FORCE_OVERWRITE_MESSAGE,
        )?;
        report_generated(emit_progress, "config.rs");
    }

    // Generate error.rs
    if engine.has_template("shared/error") {
        let content = engine.render("shared/error")?;
        let file_path = output_path.join("error.rs");
        write_file_with_force_with_message(
            &file_path,
            &content,
            args.force,
            BACKEND_FORCE_OVERWRITE_MESSAGE,
        )?;
        report_generated(emit_progress, "error.rs");
    }

    Ok(())
}

fn generate_entities(
    engine: &BackendTemplateEngine,
    output_path: &Path,
    args: &BackendArgs,
    emit_progress: bool,
) -> Result<()> {
    let entities_path = output_path.join("entities");
    ensure_dir(&entities_path)?;

    // Generate entities/mod.rs
    if engine.has_template("entities/mod") {
        let content = engine.render("entities/mod")?;
        let file_path = entities_path.join("mod.rs");
        write_file_with_force_with_message(
            &file_path,
            &content,
            args.force,
            BACKEND_FORCE_OVERWRITE_MESSAGE,
        )?;
        report_generated(emit_progress, "entities/mod.rs");
    }

    // Generate entities/prelude.rs
    if engine.has_template("entities/prelude") {
        let content = engine.render("entities/prelude")?;
        let file_path = entities_path.join("prelude.rs");
        write_file_with_force_with_message(
            &file_path,
            &content,
            args.force,
            BACKEND_FORCE_OVERWRITE_MESSAGE,
        )?;
        report_generated(emit_progress, "entities/prelude.rs");
    }

    // Generate core entities
    let core_entities = [
        ("user.rs", "entities/user"),
        ("refresh_token_family.rs", "entities/refresh_token_family"),
        ("verification_token.rs", "entities/verification_token"),
    ];

    for (filename, template_name) in core_entities {
        if engine.has_template(template_name) {
            let content = engine.render(template_name)?;
            let file_path = entities_path.join(filename);
            write_file_with_force_with_message(
                &file_path,
                &content,
                args.force,
                BACKEND_FORCE_OVERWRITE_MESSAGE,
            )?;
            report_generated(emit_progress, &format!("entities/{}", filename));
        }
    }

    // Generate organization entities (B2B only)
    if args.preset == BackendPreset::B2b {
        let org_entities = [
            ("organization.rs", "entities/organization"),
            ("organization_member.rs", "entities/organization_member"),
        ];

        for (filename, template_name) in org_entities {
            if engine.has_template(template_name) {
                let content = engine.render(template_name)?;
                let file_path = entities_path.join(filename);
                write_file_with_force_with_message(
                    &file_path,
                    &content,
                    args.force,
                    BACKEND_FORCE_OVERWRITE_MESSAGE,
                )?;
                report_generated(emit_progress, &format!("entities/{}", filename));
            }
        }
    }

    Ok(())
}

fn generate_auth(
    engine: &BackendTemplateEngine,
    output_path: &Path,
    args: &BackendArgs,
    emit_progress: bool,
) -> Result<()> {
    let auth_path = output_path.join("auth");
    ensure_dir(&auth_path)?;

    let templates = [
        ("mod.rs", "auth/mod"),
        ("routes.rs", "auth/routes"),
        ("store.rs", "auth/store"),
    ];

    for (filename, template_name) in templates {
        if engine.has_template(template_name) {
            let content = engine.render(template_name)?;
            let file_path = auth_path.join(filename);
            write_file_with_force_with_message(
                &file_path,
                &content,
                args.force,
                BACKEND_FORCE_OVERWRITE_MESSAGE,
            )?;
            report_generated(emit_progress, &format!("auth/{}", filename));
        }
    }

    Ok(())
}

fn generate_billing(
    engine: &BackendTemplateEngine,
    output_path: &Path,
    args: &BackendArgs,
    emit_progress: bool,
) -> Result<()> {
    let billing_path = output_path.join("billing");
    ensure_dir(&billing_path)?;

    let templates = [
        ("mod.rs", "billing/mod"),
        ("routes.rs", "billing/routes"),
        ("store.rs", "billing/store"),
    ];

    for (filename, template_name) in templates {
        if engine.has_template(template_name) {
            let content = engine.render(template_name)?;
            let file_path = billing_path.join(filename);
            write_file_with_force_with_message(
                &file_path,
                &content,
                args.force,
                BACKEND_FORCE_OVERWRITE_MESSAGE,
            )?;
            report_generated(emit_progress, &format!("billing/{}", filename));
        }
    }

    Ok(())
}

fn generate_organizations(
    engine: &BackendTemplateEngine,
    output_path: &Path,
    args: &BackendArgs,
    emit_progress: bool,
) -> Result<()> {
    let orgs_path = output_path.join("organizations");
    ensure_dir(&orgs_path)?;

    let templates = [
        ("mod.rs", "organizations/mod"),
        ("routes.rs", "organizations/routes"),
        ("store.rs", "organizations/store"),
    ];

    for (filename, template_name) in templates {
        if engine.has_template(template_name) {
            let content = engine.render(template_name)?;
            let file_path = orgs_path.join(filename);
            write_file_with_force_with_message(
                &file_path,
                &content,
                args.force,
                BACKEND_FORCE_OVERWRITE_MESSAGE,
            )?;
            report_generated(emit_progress, &format!("organizations/{}", filename));
        }
    }

    Ok(())
}

fn generate_admin(
    engine: &BackendTemplateEngine,
    output_path: &Path,
    args: &BackendArgs,
    emit_progress: bool,
) -> Result<()> {
    let admin_path = output_path.join("admin");
    ensure_dir(&admin_path)?;

    let templates = [
        ("mod.rs", "admin/mod"),
        ("routes.rs", "admin/routes"),
        ("store.rs", "admin/store"),
    ];

    for (filename, template_name) in templates {
        if engine.has_template(template_name) {
            let content = engine.render(template_name)?;
            let file_path = admin_path.join(filename);
            write_file_with_force_with_message(
                &file_path,
                &content,
                args.force,
                BACKEND_FORCE_OVERWRITE_MESSAGE,
            )?;
            report_generated(emit_progress, &format!("admin/{}", filename));
        }
    }

    Ok(())
}

fn generate_migrations(
    engine: &BackendTemplateEngine,
    migrations_path: &Path,
    args: &BackendArgs,
    emit_progress: bool,
) -> Result<()> {
    // Generate migration lib.rs
    if engine.has_template("migrations/lib") {
        let content = engine.render("migrations/lib")?;
        let file_path = migrations_path.join("lib.rs");
        write_file_with_force_with_message(
            &file_path,
            &content,
            args.force,
            BACKEND_FORCE_OVERWRITE_MESSAGE,
        )?;
        report_generated(emit_progress, "migration/src/lib.rs");
    }

    // Core migrations (always generated)
    let core_migrations = [
        ("m001_create_users.rs", "migrations/m001_create_users"),
        (
            "m002_create_refresh_token_families.rs",
            "migrations/m002_create_refresh_token_families",
        ),
        (
            "m003_create_verification_tokens.rs",
            "migrations/m003_create_verification_tokens",
        ),
        ("m004_create_billing.rs", "migrations/m004_create_billing"),
        (
            "m008_create_billing_plans.rs",
            "migrations/m008_create_billing_plans",
        ),
        (
            "m009_create_webhook_processed_events.rs",
            "migrations/m009_create_webhook_processed_events",
        ),
    ];

    for (filename, template_name) in core_migrations {
        if engine.has_template(template_name) {
            let content = engine.render(template_name)?;
            let file_path = migrations_path.join(filename);
            write_file_with_force_with_message(
                &file_path,
                &content,
                args.force,
                BACKEND_FORCE_OVERWRITE_MESSAGE,
            )?;
            report_generated(emit_progress, &format!("migration/src/{}", filename));
        }
    }

    // B2B-specific migrations
    if args.preset == BackendPreset::B2b {
        let b2b_migrations = [
            (
                "m005_create_organizations.rs",
                "migrations/m005_create_organizations",
            ),
            (
                "m006_create_organization_members.rs",
                "migrations/m006_create_organization_members",
            ),
            ("m007_add_admin_flag.rs", "migrations/m007_add_admin_flag"),
        ];

        for (filename, template_name) in b2b_migrations {
            if engine.has_template(template_name) {
                let content = engine.render(template_name)?;
                let file_path = migrations_path.join(filename);
                write_file_with_force_with_message(
                    &file_path,
                    &content,
                    args.force,
                    BACKEND_FORCE_OVERWRITE_MESSAGE,
                )?;
                report_generated(emit_progress, &format!("migration/src/{}", filename));
            }
        }
    } else {
        // B2C admin flag migration (different numbering)
        if engine.has_template("migrations/m005_add_admin_flag") {
            let content = engine.render("migrations/m005_add_admin_flag")?;
            let file_path = migrations_path.join("m005_add_admin_flag.rs");
            write_file_with_force_with_message(
                &file_path,
                &content,
                args.force,
                BACKEND_FORCE_OVERWRITE_MESSAGE,
            )?;
            report_generated(emit_progress, "migration/src/m005_add_admin_flag.rs");
        }
    }

    Ok(())
}
