//! Init command - scans for modules and generates main.rs with proper wiring.

use anyhow::{Context, Result};
use colored::Colorize;
use std::fs;
use std::path::Path;

use crate::cli::InitArgs;
use crate::{print_info, print_success, print_warning};

/// Detected modules in the project
#[derive(Debug, Default)]
struct DetectedModules {
    auth: bool,
    billing: bool,
    organizations: bool,
    admin: bool,
}

impl DetectedModules {
    fn any(&self) -> bool {
        self.auth || self.billing || self.organizations || self.admin
    }
}

/// Run the init command
pub fn run(args: InitArgs) -> Result<()> {
    let src_path = Path::new(&args.src);

    println!(
        "\n{} Scanning {} for modules...\n",
        "tideway".cyan().bold(),
        args.src.yellow()
    );

    // Detect project name
    let project_name = detect_project_name(&args)?;
    let _project_name_pascal = to_pascal_case(&project_name);

    print_info(&format!("Project name: {}", project_name.green()));

    // Scan for modules
    let modules = scan_modules(src_path)?;

    if !modules.any() {
        print_warning("No modules detected. Run 'tideway backend' first to generate modules.");
        return Ok(());
    }

    // Print detected modules
    println!("\n{}", "Detected modules:".yellow().bold());
    if modules.auth {
        println!("  {} auth", "✓".green());
    }
    if modules.billing {
        println!("  {} billing", "✓".green());
    }
    if modules.organizations {
        println!("  {} organizations", "✓".green());
    }
    if modules.admin {
        println!("  {} admin", "✓".green());
    }
    println!();

    // Generate main.rs
    let main_rs = generate_main_rs(&project_name, &modules, &args);
    let main_path = src_path.join("main.rs");
    write_file(&main_path, &main_rs, args.force)?;
    print_success("Generated main.rs");

    // Generate config.rs if it doesn't exist
    let config_path = src_path.join("config.rs");
    if !config_path.exists() || args.force {
        let config_rs = generate_config_rs(&modules, &args);
        write_file(&config_path, &config_rs, args.force)?;
        print_success("Generated config.rs");
    } else {
        print_info("config.rs already exists, skipping (use --force to overwrite)");
    }

    // Generate .env.example
    if args.env_example {
        let env_example = generate_env_example(&modules, &args);
        let env_path = Path::new(".env.example");
        // Always overwrite .env.example
        fs::write(env_path, env_example).context("Failed to write .env.example")?;
        print_success("Generated .env.example");
    }

    println!(
        "\n{} Initialization complete!\n",
        "✓".green().bold()
    );

    // Print next steps
    println!("{}", "Next steps:".yellow().bold());
    println!("  1. Copy .env.example to .env and fill in values:");
    println!("     cp .env.example .env");
    println!();
    println!("  2. Ensure dependencies in Cargo.toml:");
    println!("     tideway = {{ version = \"0.7\", features = [\"auth\", \"auth-mfa\", \"database\", \"billing\", \"billing-seaorm\"] }}");
    println!();
    if !args.no_migrations {
        println!("  3. Run migrations:");
        println!("     cargo run -- migrate");
        println!("     # or: sea-orm-cli migrate up");
        println!();
    }
    println!("  4. Start the server:");
    println!("     cargo run");
    println!();

    Ok(())
}

/// Detect project name from Cargo.toml or directory name
fn detect_project_name(args: &InitArgs) -> Result<String> {
    if let Some(name) = &args.name {
        return Ok(name.clone());
    }

    // Try to read from Cargo.toml
    let cargo_toml = Path::new("Cargo.toml");
    if cargo_toml.exists() {
        let content = fs::read_to_string(cargo_toml)?;
        for line in content.lines() {
            if line.starts_with("name") {
                if let Some(name) = line.split('=').nth(1) {
                    let name = name.trim().trim_matches('"').trim_matches('\'');
                    return Ok(name.replace('-', "_"));
                }
            }
        }
    }

    // Fall back to current directory name
    let cwd = std::env::current_dir()?;
    let dir_name = cwd
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("my_app");

    Ok(dir_name.replace('-', "_"))
}

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

/// Scan source directory for modules
fn scan_modules(src_path: &Path) -> Result<DetectedModules> {
    let mut modules = DetectedModules::default();

    // Check for auth module
    let auth_path = src_path.join("auth");
    if auth_path.is_dir() && has_module_file(&auth_path) {
        modules.auth = true;
    }

    // Check for billing module
    let billing_path = src_path.join("billing");
    if billing_path.is_dir() && has_module_file(&billing_path) {
        modules.billing = true;
    }

    // Check for organizations module
    let orgs_path = src_path.join("organizations");
    if orgs_path.is_dir() && has_module_file(&orgs_path) {
        modules.organizations = true;
    }

    // Check for admin module
    let admin_path = src_path.join("admin");
    if admin_path.is_dir() && has_module_file(&admin_path) {
        modules.admin = true;
    }

    Ok(modules)
}

/// Check if directory has a mod.rs or routes.rs file
fn has_module_file(dir: &Path) -> bool {
    dir.join("mod.rs").exists() || dir.join("routes.rs").exists()
}

/// Generate main.rs content
fn generate_main_rs(project_name: &str, modules: &DetectedModules, args: &InitArgs) -> String {
    let mut imports = vec![
        format!("use {}::config::AppConfig;", project_name),
    ];

    if !args.no_database {
        imports.push("use sea_orm::Database;".to_string());
        if !args.no_migrations {
            imports.push("use migration::Migrator;".to_string());
            imports.push("use sea_orm_migration::MigratorTrait;".to_string());
        }
    }

    imports.push("use std::sync::Arc;".to_string());
    imports.push("use tideway::App;".to_string());

    if modules.auth || modules.admin {
        imports.push("use tideway::auth::{JwtIssuer, JwtIssuerConfig};".to_string());
    }

    if modules.auth {
        imports.push(format!("use {}::auth::AuthModule;", project_name));
    }

    if modules.organizations {
        imports.push(format!("use {}::organizations::OrganizationModule;", project_name));
    }

    if modules.admin {
        imports.push(format!("use {}::admin::AdminModule;", project_name));
    }

    // Note: billing is commented out for now as it needs manual setup

    let mut body = String::new();

    // Tracing init
    body.push_str("    // Initialize tracing\n");
    body.push_str("    tracing_subscriber::fmt::init();\n\n");

    // Config loading
    body.push_str("    // Load configuration from environment\n");
    body.push_str("    let config = AppConfig::from_env()?;\n\n");
    body.push_str("    tracing::info!(\"Starting {} on {}:{}\", config.app_name, config.host, config.port);\n\n");

    // Database connection
    if !args.no_database {
        body.push_str("    // Connect to database\n");
        body.push_str("    let db = Database::connect(&config.database_url)\n");
        body.push_str("        .await\n");
        body.push_str("        .expect(\"Failed to connect to database\");\n");
        body.push_str("    let db = Arc::new(db);\n\n");
        body.push_str("    tracing::info!(\"Connected to database\");\n\n");

        if !args.no_migrations {
            body.push_str("    // Run migrations\n");
            body.push_str("    tracing::info!(\"Running migrations...\");\n");
            body.push_str("    Migrator::up(&*db, None).await?;\n");
            body.push_str("    tracing::info!(\"Migrations complete\");\n\n");
        }
    }

    // JWT issuer
    if modules.auth || modules.admin {
        body.push_str("    // Create JWT issuer\n");
        body.push_str("    let jwt_config = JwtIssuerConfig::with_secret(&config.jwt_secret, &config.app_name);\n");
        body.push_str("    let jwt_issuer = Arc::new(JwtIssuer::new(jwt_config)?);\n\n");
    }

    // Module instantiation
    body.push_str("    // Create modules\n");

    if modules.auth {
        body.push_str("    let auth_module = AuthModule::new(\n");
        body.push_str("        db.clone(),\n");
        body.push_str("        jwt_issuer.clone(),\n");
        body.push_str("        config.jwt_secret.clone(),\n");
        body.push_str("        config.app_name.clone(),\n");
        body.push_str("    );\n\n");
    }

    if modules.organizations {
        body.push_str("    let org_module = OrganizationModule::new(\n");
        body.push_str("        db.clone(),\n");
        body.push_str("        config.jwt_secret.clone(),\n");
        body.push_str("    );\n\n");
    }

    if modules.admin {
        body.push_str("    let admin_module = AdminModule::new(\n");
        body.push_str("        db.clone(),\n");
        body.push_str("        config.jwt_secret.clone(),\n");
        body.push_str("        jwt_issuer.clone(),\n");
        body.push_str("    );\n\n");
    }

    // App builder
    body.push_str("    // Build application with modules\n");
    body.push_str("    let app = App::new()");

    if modules.auth {
        body.push_str("\n        .register_module(auth_module)");
    }

    if modules.organizations {
        body.push_str("\n        .register_module(org_module)");
    }

    if modules.admin {
        body.push_str("\n        .register_module(admin_module)");
    }

    body.push_str(";\n\n");

    // Billing note
    if modules.billing {
        body.push_str("    // TODO: Set up billing routes\n");
        body.push_str("    // let billing_router = billing::billing_routes();\n\n");
    }

    // Server binding
    body.push_str("    // Start server\n");
    body.push_str("    let addr = format!(\"{}:{}\", config.host, config.port);\n");
    body.push_str("    tracing::info!(\"Server running on http://{}\", addr);\n\n");
    body.push_str("    let listener = tokio::net::TcpListener::bind(&addr).await?;\n");
    body.push_str("    let router = app.into_router();\n");
    body.push_str("    axum::serve(listener, router).await?;\n\n");
    body.push_str("    Ok(())");

    format!(
        r#"//! Application entry point.
//!
//! Generated by `tideway init`

{}

#[tokio::main]
async fn main() -> anyhow::Result<()> {{
{}
}}
"#,
        imports.join("\n"),
        body
    )
}

/// Generate config.rs content
fn generate_config_rs(modules: &DetectedModules, args: &InitArgs) -> String {
    let mut fields = vec![
        ("app_name", "String", "APP_NAME"),
        ("host", "String", "HOST"),
        ("port", "u16", "PORT"),
    ];

    if !args.no_database {
        fields.push(("database_url", "String", "DATABASE_URL"));
    }

    if modules.auth || modules.admin {
        fields.push(("jwt_secret", "String", "JWT_SECRET"));
    }

    if modules.billing {
        fields.push(("stripe_secret_key", "String", "STRIPE_SECRET_KEY"));
        fields.push(("stripe_webhook_secret", "String", "STRIPE_WEBHOOK_SECRET"));
    }

    let field_defs: Vec<String> = fields
        .iter()
        .map(|(name, ty, _)| format!("    pub {}: {},", name, ty))
        .collect();

    let env_reads: Vec<String> = fields
        .iter()
        .map(|(name, ty, env)| {
            if *ty == "u16" {
                format!(
                    "            {}: std::env::var(\"{}\")?.parse()?,",
                    name, env
                )
            } else {
                format!("            {}: std::env::var(\"{}\")?,", name, env)
            }
        })
        .collect();

    format!(
        r#"//! Application configuration.
//!
//! Generated by `tideway init`

use anyhow::Result;

/// Application configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct AppConfig {{
{}
}}

impl AppConfig {{
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self> {{
        // Load .env file if present
        dotenvy::dotenv().ok();

        Ok(Self {{
{}
        }})
    }}
}}
"#,
        field_defs.join("\n"),
        env_reads.join("\n")
    )
}

/// Generate .env.example content
fn generate_env_example(modules: &DetectedModules, args: &InitArgs) -> String {
    let mut lines = vec![
        "# Application".to_string(),
        "APP_NAME=my_app".to_string(),
        "HOST=127.0.0.1".to_string(),
        "PORT=3000".to_string(),
        "".to_string(),
    ];

    if !args.no_database {
        lines.push("# Database".to_string());
        lines.push("DATABASE_URL=postgres://postgres:postgres@localhost:5432/my_app".to_string());
        lines.push("".to_string());
    }

    if modules.auth || modules.admin {
        lines.push("# Authentication".to_string());
        lines.push("JWT_SECRET=your-super-secret-jwt-key-change-in-production".to_string());
        lines.push("".to_string());
    }

    if modules.billing {
        lines.push("# Stripe".to_string());
        lines.push("STRIPE_SECRET_KEY=sk_test_...".to_string());
        lines.push("STRIPE_WEBHOOK_SECRET=whsec_...".to_string());
        lines.push("".to_string());
    }

    lines.join("\n")
}

/// Write file with optional force overwrite
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
