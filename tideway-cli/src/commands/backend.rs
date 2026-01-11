//! Backend command - generates Rust backend scaffolding from templates.

use anyhow::{Context, Result};
use colored::Colorize;
use std::fs;
use std::path::Path;

use crate::cli::{BackendArgs, BackendPreset};
use crate::templates::{BackendTemplateContext, BackendTemplateEngine};
use crate::{print_info, print_success, print_warning};

/// Convert snake_case to PascalCase
fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().chain(chars).collect(),
            }
        })
        .collect()
}

/// Run the backend command
pub fn run(args: BackendArgs) -> Result<()> {
    let has_organizations = args.preset == BackendPreset::B2b;
    let preset_name = match args.preset {
        BackendPreset::B2c => "B2C (Auth + Billing + Admin)",
        BackendPreset::B2b => "B2B (Auth + Billing + Organizations + Admin)",
    };

    println!(
        "\n{} Generating {} backend scaffolding\n",
        "tideway".cyan().bold(),
        preset_name.green()
    );
    println!(
        "  Project: {}\n  Database: {}\n  Output: {}\n",
        args.name.yellow(),
        args.database.yellow(),
        args.output.yellow()
    );

    // Create output directories
    let output_path = Path::new(&args.output);
    let migrations_path = Path::new(&args.migrations_output);

    if !output_path.exists() {
        fs::create_dir_all(output_path)
            .with_context(|| format!("Failed to create output directory: {}", args.output))?;
        print_info(&format!("Created directory: {}", args.output));
    }

    if !migrations_path.exists() {
        fs::create_dir_all(migrations_path).with_context(|| {
            format!(
                "Failed to create migrations directory: {}",
                args.migrations_output
            )
        })?;
        print_info(&format!("Created directory: {}", args.migrations_output));
    }

    // Create template context
    let context = BackendTemplateContext {
        project_name: args.name.clone(),
        project_name_pascal: to_pascal_case(&args.name),
        has_organizations,
        database: args.database.clone(),
    };

    // Initialize template engine
    let engine = BackendTemplateEngine::new(context)?;

    // Generate shared files
    generate_shared(&engine, output_path, &args)?;

    // Generate entities
    generate_entities(&engine, output_path, &args)?;

    // Generate auth module
    generate_auth(&engine, output_path, &args)?;

    // Generate billing module
    generate_billing(&engine, output_path, &args)?;

    // Generate organizations module (B2B only)
    if has_organizations {
        generate_organizations(&engine, output_path, &args)?;
    }

    // Generate admin module
    generate_admin(&engine, output_path, &args)?;

    // Generate migrations
    generate_migrations(&engine, migrations_path, &args)?;

    println!(
        "\n{} Backend scaffolding generated successfully!\n",
        "✓".green().bold()
    );

    // Print next steps
    println!("{}", "Next steps:".yellow().bold());
    println!("  1. Add dependencies to Cargo.toml:");
    println!("     tideway = {{ path = \"../tideway-rs\" }}");
    println!("     axum = \"0.8\"");
    println!("     sea-orm = {{ version = \"1.1\", features = [\"sqlx-postgres\", \"runtime-tokio-rustls\"] }}");
    println!("     tokio = {{ version = \"1\", features = [\"full\"] }}");
    println!("     serde = {{ version = \"1\", features = [\"derive\"] }}");
    println!();
    println!("  2. Run migrations:");
    println!("     sea-orm-cli migrate up");
    println!();
    println!("  3. Start the server:");
    println!("     cargo run");
    println!();

    Ok(())
}

fn generate_shared(
    engine: &BackendTemplateEngine,
    output_path: &Path,
    args: &BackendArgs,
) -> Result<()> {
    // Generate main.rs
    if engine.has_template("shared/main") {
        let content = engine.render("shared/main")?;
        let file_path = output_path.join("main.rs");
        write_file(&file_path, &content, args.force)?;
        print_success("Generated main.rs");
    }

    // Generate lib.rs
    if engine.has_template("shared/lib") {
        let content = engine.render("shared/lib")?;
        let file_path = output_path.join("lib.rs");
        write_file(&file_path, &content, args.force)?;
        print_success("Generated lib.rs");
    }

    // Generate config.rs
    if engine.has_template("shared/config") {
        let content = engine.render("shared/config")?;
        let file_path = output_path.join("config.rs");
        write_file(&file_path, &content, args.force)?;
        print_success("Generated config.rs");
    }

    // Generate error.rs
    if engine.has_template("shared/error") {
        let content = engine.render("shared/error")?;
        let file_path = output_path.join("error.rs");
        write_file(&file_path, &content, args.force)?;
        print_success("Generated error.rs");
    }

    Ok(())
}

fn generate_entities(
    engine: &BackendTemplateEngine,
    output_path: &Path,
    args: &BackendArgs,
) -> Result<()> {
    let entities_path = output_path.join("entities");
    fs::create_dir_all(&entities_path)?;

    // Generate entities/mod.rs
    if engine.has_template("entities/mod") {
        let content = engine.render("entities/mod")?;
        let file_path = entities_path.join("mod.rs");
        write_file(&file_path, &content, args.force)?;
        print_success("Generated entities/mod.rs");
    }

    // Generate entities/prelude.rs
    if engine.has_template("entities/prelude") {
        let content = engine.render("entities/prelude")?;
        let file_path = entities_path.join("prelude.rs");
        write_file(&file_path, &content, args.force)?;
        print_success("Generated entities/prelude.rs");
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
            write_file(&file_path, &content, args.force)?;
            print_success(&format!("Generated entities/{}", filename));
        }
    }

    // Generate organization entities (B2B only)
    if args.preset == BackendPreset::B2b {
        let org_entities = [
            ("organization.rs", "entities/organization"),
            ("membership.rs", "entities/membership"),
        ];

        for (filename, template_name) in org_entities {
            if engine.has_template(template_name) {
                let content = engine.render(template_name)?;
                let file_path = entities_path.join(filename);
                write_file(&file_path, &content, args.force)?;
                print_success(&format!("Generated entities/{}", filename));
            }
        }
    }

    Ok(())
}

fn generate_auth(
    engine: &BackendTemplateEngine,
    output_path: &Path,
    args: &BackendArgs,
) -> Result<()> {
    let auth_path = output_path.join("auth");
    fs::create_dir_all(&auth_path)?;

    let templates = [
        ("mod.rs", "auth/mod"),
        ("routes.rs", "auth/routes"),
        ("store.rs", "auth/store"),
    ];

    for (filename, template_name) in templates {
        if engine.has_template(template_name) {
            let content = engine.render(template_name)?;
            let file_path = auth_path.join(filename);
            write_file(&file_path, &content, args.force)?;
            print_success(&format!("Generated auth/{}", filename));
        }
    }

    Ok(())
}

fn generate_billing(
    engine: &BackendTemplateEngine,
    output_path: &Path,
    args: &BackendArgs,
) -> Result<()> {
    let billing_path = output_path.join("billing");
    fs::create_dir_all(&billing_path)?;

    let templates = [
        ("mod.rs", "billing/mod"),
        ("routes.rs", "billing/routes"),
        ("store.rs", "billing/store"),
    ];

    for (filename, template_name) in templates {
        if engine.has_template(template_name) {
            let content = engine.render(template_name)?;
            let file_path = billing_path.join(filename);
            write_file(&file_path, &content, args.force)?;
            print_success(&format!("Generated billing/{}", filename));
        }
    }

    Ok(())
}

fn generate_organizations(
    engine: &BackendTemplateEngine,
    output_path: &Path,
    args: &BackendArgs,
) -> Result<()> {
    let orgs_path = output_path.join("organizations");
    fs::create_dir_all(&orgs_path)?;

    let templates = [
        ("mod.rs", "organizations/mod"),
        ("routes.rs", "organizations/routes"),
        ("store.rs", "organizations/store"),
    ];

    for (filename, template_name) in templates {
        if engine.has_template(template_name) {
            let content = engine.render(template_name)?;
            let file_path = orgs_path.join(filename);
            write_file(&file_path, &content, args.force)?;
            print_success(&format!("Generated organizations/{}", filename));
        }
    }

    Ok(())
}

fn generate_admin(
    engine: &BackendTemplateEngine,
    output_path: &Path,
    args: &BackendArgs,
) -> Result<()> {
    let admin_path = output_path.join("admin");
    fs::create_dir_all(&admin_path)?;

    let templates = [
        ("mod.rs", "admin/mod"),
        ("routes.rs", "admin/routes"),
        ("store.rs", "admin/store"),
    ];

    for (filename, template_name) in templates {
        if engine.has_template(template_name) {
            let content = engine.render(template_name)?;
            let file_path = admin_path.join(filename);
            write_file(&file_path, &content, args.force)?;
            print_success(&format!("Generated admin/{}", filename));
        }
    }

    Ok(())
}

fn generate_migrations(
    engine: &BackendTemplateEngine,
    migrations_path: &Path,
    args: &BackendArgs,
) -> Result<()> {
    // Generate migration lib.rs
    if engine.has_template("migrations/lib") {
        let content = engine.render("migrations/lib")?;
        let file_path = migrations_path.join("lib.rs");
        write_file(&file_path, &content, args.force)?;
        print_success("Generated migration/src/lib.rs");
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
    ];

    for (filename, template_name) in core_migrations {
        if engine.has_template(template_name) {
            let content = engine.render(template_name)?;
            let file_path = migrations_path.join(filename);
            write_file(&file_path, &content, args.force)?;
            print_success(&format!("Generated migration/src/{}", filename));
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
                "m006_create_memberships.rs",
                "migrations/m006_create_memberships",
            ),
            ("m007_add_admin_flag.rs", "migrations/m007_add_admin_flag"),
        ];

        for (filename, template_name) in b2b_migrations {
            if engine.has_template(template_name) {
                let content = engine.render(template_name)?;
                let file_path = migrations_path.join(filename);
                write_file(&file_path, &content, args.force)?;
                print_success(&format!("Generated migration/src/{}", filename));
            }
        }
    } else {
        // B2C admin flag migration (different numbering)
        if engine.has_template("migrations/m005_add_admin_flag") {
            let content = engine.render("migrations/m005_add_admin_flag")?;
            let file_path = migrations_path.join("m005_add_admin_flag.rs");
            write_file(&file_path, &content, args.force)?;
            print_success("Generated migration/src/m005_add_admin_flag.rs");
        }
    }

    Ok(())
}

fn write_file(path: &Path, content: &str, force: bool) -> Result<()> {
    if path.exists() && !force {
        print_warning(&format!(
            "Skipping {} (use --force to overwrite)",
            path.display()
        ));
        return Ok(());
    }
    fs::write(path, content).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}
