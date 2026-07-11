//! Init command - scans for modules and generates main.rs with proper wiring.

use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::InitArgs;
use crate::commands::file_ops::{
    INIT_FORCE_OVERWRITE_MESSAGE, to_pascal_case, write_file_with_force_with_message,
};
use crate::commands::messaging::{GREENFIELD_PRIMARY_PATH, NEW_APP_COMMAND};
use crate::{
    CommandRuntime, ExecutionPlan, PlanStep, TIDEWAY_VERSION, print_info, print_success,
    print_warning, write_file,
};

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
    run_with_runtime(args, CommandRuntime::from_process_state())
}

pub fn run_with_runtime(args: InitArgs, runtime: CommandRuntime) -> Result<()> {
    runtime.install();

    let src_path = Path::new(&args.src);
    let project_root = src_path.parent().unwrap_or(Path::new("."));

    if args.minimal {
        if runtime.plan_mode() {
            return run_minimal_plan(src_path, &args, runtime);
        }
        return run_minimal(src_path, &args, runtime);
    }

    if !runtime.json_output() {
        println!(
            "\n{} Scanning {} for modules...\n",
            "tideway".cyan().bold(),
            args.src.yellow()
        );
    }

    // Detect project name
    let project_name = detect_project_name(&args, project_root)?;
    let _project_name_pascal = to_pascal_case(&project_name);

    print_info(&format!("Project name: {}", project_name.green()));

    // Scan for modules
    let modules = scan_modules(src_path)?;

    if !modules.any() {
        print_warning(
            "No modules detected. Advanced fix: run `tideway backend` to generate modules.",
        );
        print_info(GREENFIELD_PRIMARY_PATH);
        return Ok(());
    }

    if runtime.plan_mode() {
        return emit_init_plan(src_path, project_root, &args, &modules, runtime);
    }

    // Print detected modules
    if !runtime.json_output() {
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
    }

    // Generate main.rs
    let main_rs = generate_main_rs(&project_name, &modules, &args);
    let main_path = src_path.join("main.rs");
    write_file_with_force_with_message(
        &main_path,
        &main_rs,
        args.force,
        INIT_FORCE_OVERWRITE_MESSAGE,
    )?;
    print_success("Generated main.rs");

    // Generate config.rs if it doesn't exist
    let config_path = src_path.join("config.rs");
    if !config_path.exists() || args.force {
        let config_rs = generate_config_rs(&modules, &args);
        write_file_with_force_with_message(
            &config_path,
            &config_rs,
            args.force,
            INIT_FORCE_OVERWRITE_MESSAGE,
        )?;
        print_success("Generated config.rs");
    } else {
        print_info("config.rs already exists, skipping (use --force to overwrite)");
    }

    // Generate .env.example
    if args.env_example {
        let env_example = generate_env_example(&project_name, &modules, &args);
        let env_path = project_root.join(".env.example");
        // Always overwrite .env.example
        write_file(&env_path, &env_example).context("Failed to write .env.example")?;
        print_success("Generated .env.example");
    }

    if !runtime.json_output() {
        println!("\n{} Initialization complete!\n", "✓".green().bold());
        print_info(&format!(
            "Note: `tideway init` is an advanced command for existing projects. For new projects, prefer {}.",
            NEW_APP_COMMAND,
        ));

        // Print next steps
        println!("{}", "Next steps:".yellow().bold());
        println!("  1. Copy .env.example to .env and fill in values:");
        println!("     cp .env.example .env");
        println!();
        println!("  2. Ensure dependencies in Cargo.toml:");
        println!(
            "     tideway = {{ version = \"{}\", features = [\"auth\", \"auth-mfa\", \"database\", \"billing\", \"billing-seaorm\"] }}",
            TIDEWAY_VERSION
        );
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
    }

    Ok(())
}

fn emit_init_plan(
    src_path: &Path,
    project_root: &Path,
    args: &InitArgs,
    modules: &DetectedModules,
    runtime: CommandRuntime,
) -> Result<()> {
    let mut created_dirs = BTreeSet::new();
    let mut steps = Vec::new();

    collect_write_steps(&src_path.join("main.rs"), &mut created_dirs, &mut steps);

    let config_path = src_path.join("config.rs");
    if !config_path.exists() || args.force {
        collect_write_steps(&config_path, &mut created_dirs, &mut steps);
    } else {
        steps.push(PlanStep::info(
            "Plan: keep existing config.rs (use --force to overwrite)",
        ));
    }

    if args.env_example {
        collect_write_steps(
            &project_root.join(".env.example"),
            &mut created_dirs,
            &mut steps,
        );
    }

    let mut plan = ExecutionPlan::new(plan_summary(src_path, modules));
    for step in steps {
        plan = plan.step(step);
    }
    plan.emit(runtime);
    print_info("Plan complete: no files were written");
    Ok(())
}

fn run_minimal(src_path: &Path, args: &InitArgs, runtime: CommandRuntime) -> Result<()> {
    if !runtime.json_output() {
        println!("\n{} Generating minimal app...\n", "tideway".cyan().bold());
    }

    let project_root = src_path.parent().unwrap_or(Path::new("."));
    let project_name = detect_project_name(args, project_root)?;
    let project_name_pascal = to_pascal_case(&project_name);

    print_info(&format!("Project name: {}", project_name.green()));

    let main_rs = generate_minimal_main_rs(&project_name_pascal);
    let routes_rs = generate_minimal_routes_rs();

    let main_path = src_path.join("main.rs");
    write_file_with_force_with_message(
        &main_path,
        &main_rs,
        args.force,
        INIT_FORCE_OVERWRITE_MESSAGE,
    )?;
    print_success("Generated main.rs");

    let routes_path = src_path.join("routes").join("mod.rs");
    write_file_with_force_with_message(
        &routes_path,
        &routes_rs,
        args.force,
        INIT_FORCE_OVERWRITE_MESSAGE,
    )?;
    print_success("Generated routes/mod.rs");

    if !runtime.json_output() {
        println!("\n{} Initialization complete!\n", "✓".green().bold());
        print_info(&format!(
            "Note: `tideway init` is advanced. For a new app, prefer {}.",
            NEW_APP_COMMAND
        ));

        println!("{}", "Next steps:".yellow().bold());
        println!("  1. cargo run");
        println!();
    }

    Ok(())
}

fn run_minimal_plan(src_path: &Path, args: &InitArgs, runtime: CommandRuntime) -> Result<()> {
    if !runtime.json_output() {
        println!("\n{} Planning minimal app...\n", "tideway".cyan().bold());
    }

    let project_root = src_path.parent().unwrap_or(Path::new("."));
    let project_name = detect_project_name(args, project_root)?;

    print_info(&format!("Project name: {}", project_name.green()));

    let mut created_dirs = BTreeSet::new();
    let mut steps = Vec::new();
    collect_write_steps(&src_path.join("main.rs"), &mut created_dirs, &mut steps);
    collect_write_steps(
        &src_path.join("routes").join("mod.rs"),
        &mut created_dirs,
        &mut steps,
    );

    let mut plan = ExecutionPlan::new(format!(
        "would generate minimal app in {}",
        src_path.display()
    ));
    for step in steps {
        plan = plan.step(step);
    }
    plan.emit(runtime);
    print_info("Plan complete: no files were written");
    Ok(())
}

fn plan_summary(src_path: &Path, modules: &DetectedModules) -> String {
    let mut detected = Vec::new();
    if modules.auth {
        detected.push("auth");
    }
    if modules.billing {
        detected.push("billing");
    }
    if modules.organizations {
        detected.push("organizations");
    }
    if modules.admin {
        detected.push("admin");
    }

    if detected.is_empty() {
        format!(
            "would initialize Tideway app wiring in {}",
            src_path.display()
        )
    } else {
        format!(
            "would initialize Tideway app wiring in {} ({})",
            src_path.display(),
            detected.join(", ")
        )
    }
}

fn collect_write_steps(
    path: &Path,
    created_dirs: &mut BTreeSet<PathBuf>,
    steps: &mut Vec<PlanStep>,
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
        steps.push(PlanStep::create_directory(dir.display().to_string()));
    }

    steps.push(PlanStep::write_file(path.display().to_string()));
}

/// Detect project name from Cargo.toml or directory name
fn detect_project_name(args: &InitArgs, project_root: &Path) -> Result<String> {
    if let Some(name) = &args.name {
        return Ok(name.clone());
    }

    // Try to read from Cargo.toml
    let cargo_toml = project_root.join("Cargo.toml");
    if cargo_toml.exists() {
        let content = fs::read_to_string(cargo_toml)?;
        if let Ok(doc) = content.parse::<toml_edit::DocumentMut>() {
            if let Some(name) = doc
                .get("package")
                .and_then(|pkg| pkg.get("name"))
                .and_then(|value| value.as_str())
            {
                return Ok(name.replace('-', "_"));
            }
        }
    }

    let cwd = std::env::current_dir()?;
    let dir_name = project_root
        .file_name()
        .or_else(|| cwd.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("my_app");

    Ok(dir_name.replace('-', "_"))
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
    let mut imports = vec![format!("use {}::config::AppConfig;", project_name)];

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
        imports.push(format!(
            "use {}::organizations::OrganizationModule;",
            project_name
        ));
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
        body.push_str("    let jwt_config = JwtIssuerConfig::with_secure_secret(&config.jwt_secret, &config.app_name)?.audience(env!(\"CARGO_PKG_NAME\"));\n");
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
    body.push_str("    // tideway:app-builder:start\n");
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

    body.push_str(";\n");
    body.push_str("    // tideway:app-builder:end\n\n");

    // Billing note
    if modules.billing {
        body.push_str("    // TODO: Set up billing routes\n");
        body.push_str("    // let billing_router = billing::authenticated_billing_routes();\n\n");
    }

    // Server binding
    body.push_str("    // Start server\n");
    body.push_str("    let addr = format!(\"{}:{}\", config.host, config.port);\n");
    body.push_str("    tracing::info!(\"Server running on http://{}\", addr);\n\n");
    body.push_str("    let listener = tokio::net::TcpListener::bind(&addr).await?;\n");
    body.push_str("    let router = app.into_router_with_middleware();\n");
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

fn generate_minimal_main_rs(project_name_pascal: &str) -> String {
    format!(
        "//! {} API server.\n\
\n\
use tideway::{{init_tracing, App}};\n\
\n\
mod routes;\n\
\n\
#[tokio::main]\n\
async fn main() -> Result<(), std::io::Error> {{\n\
    init_tracing();\n\
\n\
    // tideway:app-builder:start\n\
    let app = App::new()\n\
        .register_module(routes::ApiModule);\n\
    // tideway:app-builder:end\n\
\n\
    app.serve().await\n\
}}\n",
        project_name_pascal
    )
}

fn generate_minimal_routes_rs() -> String {
    "//! Minimal API routes.\n\
\n\
use axum::{routing::get, Router};\n\
use tideway::{AppContext, MessageResponse, RouteModule};\n\
\n\
pub struct ApiModule;\n\
\n\
impl RouteModule for ApiModule {\n\
    fn routes(&self) -> Router<AppContext> {\n\
        Router::new().route(\"/\", get(root))\n\
    }\n\
\n\
    fn prefix(&self) -> Option<&str> {\n\
        Some(\"/api\")\n\
    }\n\
}\n\
\n\
async fn root() -> MessageResponse {\n\
    MessageResponse::success(\"Tideway is running\")\n\
}\n"
    .to_string()
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
fn generate_env_example(project_name: &str, modules: &DetectedModules, args: &InitArgs) -> String {
    let mut lines = vec![
        "# Application".to_string(),
        format!("APP_NAME={}", project_name),
        "HOST=127.0.0.1".to_string(),
        "PORT=3000".to_string(),
        "".to_string(),
    ];

    if !args.no_database {
        lines.push("# Database".to_string());
        lines.push(format!(
            "DATABASE_URL=postgres://postgres:postgres@localhost:5432/{}",
            project_name
        ));
        lines.push("".to_string());
    }

    if modules.auth || modules.admin {
        lines.push("# Authentication".to_string());
        lines.push("JWT_SECRET=replace-with-at-least-32-random-bytes".to_string());
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
