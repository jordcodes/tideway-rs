//! CLI argument definitions using clap.

use crate::commands::messaging::CLI_HELP_TRAILER;
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "tideway")]
#[command(author = "JD")]
#[command(version)]
#[command(about = "Scaffold Tideway API apps and advanced helpers", long_about = None)]
#[command(after_help = CLI_HELP_TRAILER)]
pub struct Cli {
    /// Output machine-readable JSON lines
    #[arg(long, global = true, default_value = "false")]
    pub json: bool,

    /// Show planned changes without writing files
    #[arg(long, global = true, default_value = "false")]
    pub plan: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Primary: create a new Tideway starter app (use for greenfield projects)
    New(NewArgs),

    /// Primary: diagnose feature and project setup issues
    Doctor(DoctorArgs),

    /// Advanced: generate Vue frontend helpers for existing Vue apps (secondary to the API path)
    Generate(GenerateArgs),

    /// Advanced: generate backend scaffolding for existing/nonstandard projects (not for greenfield)
    Backend(BackendArgs),

    /// Advanced: add features/scaffolding to an existing project (not the default new-app path)
    Add(AddArgs),

    /// Advanced: initialize main.rs by scanning modules in existing projects (not for greenfield)
    Init(InitArgs),

    /// Primary: generate a CRUD resource module
    Resource(ResourceArgs),

    /// Advanced: set up Vue frontend dependencies for existing Vue apps (not required for API-only workflows)
    Setup(SetupArgs),

    /// Primary: run a Tideway app in dev mode (loads env, optional migrations)
    Dev(DevArgs),

    /// Primary: run database migrations
    Migrate(MigrateArgs),

    /// Advanced: list available templates (not needed for the primary API path)
    Templates,
}

#[derive(Parser, Debug)]
pub struct NewArgs {
    /// Project name (used for Cargo.toml)
    #[arg(value_name = "NAME")]
    pub name: Option<String>,

    /// Preset to apply (preselect features and scaffolding)
    #[arg(long, value_enum)]
    pub preset: Option<NewPreset>,

    /// Tideway features to enable (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub features: Vec<String>,

    /// Generate config.rs and error.rs starter files
    #[arg(long, default_value = "false")]
    pub with_config: bool,

    /// Generate docker-compose.yml for local Postgres
    #[arg(long, default_value = "false")]
    pub with_docker: bool,

    /// Generate GitHub Actions CI workflow
    #[arg(long, default_value = "false")]
    pub with_ci: bool,

    /// Skip interactive prompts (use flags instead)
    #[arg(long, default_value = "false")]
    pub no_prompt: bool,

    /// Print a summary of generated files
    #[arg(long, default_value = "true")]
    pub summary: bool,

    /// Always generate .env.example
    #[arg(long, default_value = "false")]
    pub with_env: bool,

    /// Omit organization invitations from SaaS/B2B scaffolds
    #[arg(long, default_value = "false")]
    pub without_invitations: bool,

    /// Output directory (defaults to the project name)
    #[arg(short, long)]
    pub path: Option<String>,

    /// Overwrite existing files without prompting
    #[arg(long, default_value = "false")]
    pub force: bool,
}

#[derive(ValueEnum, Debug, Copy, Clone, Eq, PartialEq)]
pub enum NewPreset {
    /// Minimal starter (no extra features)
    Minimal,
    /// API starter with auth, database, OpenAPI, and validation
    Api,
    /// SaaS starter with B2B backend modules and production defaults
    Saas,
    /// Worker starter focused on background jobs
    Worker,
    /// Print available presets
    List,
}

#[derive(Parser, Debug)]
pub struct AddArgs {
    /// Feature to add (auth, database, openapi, validation, cache, sessions, jobs, websocket, metrics, email, organizations)
    #[arg(value_enum)]
    pub feature: AddFeature,

    /// Project directory to update
    #[arg(short, long, default_value = ".")]
    pub path: String,

    /// Overwrite existing scaffold files
    #[arg(long, default_value = "false")]
    pub force: bool,

    /// Attempt to wire the new feature into src/main.rs
    #[arg(long, default_value = "false")]
    pub wire: bool,

    /// Generate database-backed organizations scaffolding
    #[arg(long, default_value = "false")]
    pub db: bool,
}

#[derive(ValueEnum, Debug, Copy, Clone, Eq, PartialEq)]
pub enum AddFeature {
    Auth,
    Database,
    Openapi,
    Validation,
    Cache,
    Sessions,
    Jobs,
    Websocket,
    Metrics,
    Email,
    Organizations,
}

#[derive(Parser, Debug)]
pub struct DoctorArgs {
    /// Project directory to analyze
    #[arg(short, long, default_value = ".")]
    pub path: String,

    /// Generate missing .env.example when possible
    #[arg(long, default_value = "false")]
    pub fix: bool,

    /// Check dependency alignment and source migrations for a Tideway upgrade
    #[arg(long, default_value = "false")]
    pub upgrade: bool,

    /// Exit with a non-zero status when doctor reports warnings
    #[arg(long, default_value = "false")]
    pub deny_warnings: bool,
}

#[derive(Parser, Debug)]
pub struct SetupArgs {
    /// Frontend framework to set up (current helper path is Vue-only)
    #[arg(value_enum, default_value = "vue")]
    pub framework: Framework,

    /// Styling approach for the Vue helper path
    #[arg(short, long, default_value = "shadcn")]
    pub style: Style,

    /// Skip Tailwind CSS setup
    #[arg(long, default_value = "false")]
    pub no_tailwind: bool,

    /// Skip shadcn component installation
    #[arg(long, default_value = "false")]
    pub no_components: bool,
}

#[derive(Parser, Debug)]
pub struct DevArgs {
    /// Project directory to run
    #[arg(short, long, default_value = ".")]
    pub path: String,

    /// Skip loading .env
    #[arg(long, default_value = "false")]
    pub no_env: bool,

    /// Legacy alias: eagerly create .env from .env.example when missing
    #[arg(long, default_value = "false")]
    pub fix_env: bool,

    /// Disable automatic migrations for this run
    #[arg(long, default_value = "false")]
    pub no_migrate: bool,

    /// Run once without watching for source changes
    #[arg(long, default_value = "false")]
    pub no_watch: bool,

    /// Extra Cargo args; use a second `--` before application args
    #[arg(trailing_var_arg = true)]
    pub args: Vec<String>,
}

#[derive(Parser, Debug)]
pub struct MigrateArgs {
    /// Action to run (up, down, status, reset, ...)
    #[arg(value_name = "ACTION", default_value = "up")]
    pub action: String,

    /// Project directory
    #[arg(short, long, default_value = ".")]
    pub path: String,

    /// Migration backend
    #[arg(long, value_enum, default_value = "auto")]
    pub backend: MigrateBackend,

    /// Skip loading .env
    #[arg(long, default_value = "false")]
    pub no_env: bool,

    /// Legacy alias: eagerly create .env from .env.example when missing
    #[arg(long, default_value = "false")]
    pub fix_env: bool,

    /// Extra args passed to the backend CLI (use `--` before them)
    #[arg(trailing_var_arg = true)]
    pub args: Vec<String>,
}

#[derive(ValueEnum, Debug, Copy, Clone, Eq, PartialEq)]
pub enum MigrateBackend {
    /// Auto-detect backend from Cargo.toml
    Auto,
    /// SeaORM migrations via sea-orm-cli
    SeaOrm,
}

#[derive(Parser, Debug)]
pub struct InitArgs {
    /// Source directory to scan for modules
    #[arg(short, long, default_value = "./src")]
    pub src: String,

    /// Project name (defaults to directory name or Cargo.toml package name)
    #[arg(short, long)]
    pub name: Option<String>,

    /// Overwrite existing main.rs without prompting
    #[arg(long, default_value = "false")]
    pub force: bool,

    /// Skip database setup
    #[arg(long, default_value = "false")]
    pub no_database: bool,

    /// Skip migration setup
    #[arg(long, default_value = "false")]
    pub no_migrations: bool,

    /// Generate .env.example file
    #[arg(long, default_value = "true")]
    pub env_example: bool,

    /// Generate a minimal app entrypoint and sample route
    #[arg(long, default_value = "false")]
    pub minimal: bool,
}

#[derive(Parser, Debug)]
pub struct ResourceArgs {
    /// Resource name (singular, e.g. user or invoice_item)
    #[arg(value_name = "NAME")]
    pub name: String,

    /// Project directory
    #[arg(short, long, default_value = ".")]
    pub path: String,

    /// Wire the module into routes/mod.rs and main.rs
    #[arg(long, default_value = "false")]
    pub wire: bool,

    /// Generate tests
    #[arg(long, default_value = "true")]
    pub with_tests: bool,

    /// Scaffold database entity + migration for the resource
    #[arg(long, default_value = "false")]
    pub db: bool,

    /// Generate a repository layer for DB-backed resources
    #[arg(long, default_value = "false")]
    pub repo: bool,

    /// Generate repository tests (requires --repo)
    #[arg(long, default_value = "false")]
    pub repo_tests: bool,

    /// Generate a service layer (requires --repo)
    #[arg(long, default_value = "false")]
    pub service: bool,

    /// ID type for DB scaffolding
    #[arg(long, value_enum, default_value = "int")]
    pub id_type: ResourceIdType,

    /// Auto-add uuid dependency when using --id-type uuid
    #[arg(long, default_value = "false")]
    pub add_uuid: bool,

    /// Add pagination (limit/offset) helpers for DB-backed resources
    #[arg(long, default_value = "false")]
    pub paginate: bool,

    /// Add simple search filter for list endpoints (requires --paginate)
    #[arg(long, default_value = "false")]
    pub search: bool,

    /// Database backend for scaffolding
    #[arg(long, value_enum, default_value = "auto")]
    pub db_backend: DbBackend,

    /// Scaffold profile: `api`, `tenant`, `owned`, `admin`, `event`, or `stub`
    #[arg(long, value_enum, default_value = "api")]
    pub profile: ResourceProfile,
}

#[derive(ValueEnum, Debug, Copy, Clone, Eq, PartialEq)]
pub enum ResourceIdType {
    /// Auto-incrementing integer IDs
    Int,
    /// UUID IDs
    Uuid,
}

#[derive(ValueEnum, Debug, Copy, Clone, Eq, PartialEq)]
pub enum DbBackend {
    /// Auto-detect backend from Cargo.toml
    Auto,
    /// SeaORM entities + migrations
    SeaOrm,
}

#[derive(ValueEnum, Debug, Copy, Clone, Eq, PartialEq)]
pub enum ResourceProfile {
    /// Full API path defaults (wire + db + repo + service + paginate + search)
    Api,
    /// SaaS tenant or organization resource defaults
    Tenant,
    /// Tenant-owned domain resource defaults
    Owned,
    /// Admin or operator-facing resource defaults
    Admin,
    /// Audit/event stream resource defaults
    Event,
    /// Lightweight route-only scaffold (legacy default style)
    Stub,
}

#[derive(Parser, Debug)]
pub struct BackendArgs {
    /// Preset: b2c (auth + billing + admin) or b2b (includes organizations)
    #[arg(value_enum)]
    pub preset: BackendPreset,

    /// Project name (used for module naming)
    #[arg(short, long, default_value = "my_app")]
    pub name: String,

    /// Output directory for generated source files
    #[arg(short, long, default_value = "./src")]
    pub output: String,

    /// Output directory for migrations
    #[arg(long, default_value = "./migration/src")]
    pub migrations_output: String,

    /// Overwrite existing files without prompting
    #[arg(long, default_value = "false")]
    pub force: bool,

    /// Database type
    #[arg(long, default_value = "postgres", value_parser = ["postgres", "sqlite"])]
    pub database: String,

    /// Omit organization invitation routes, entity, and migration
    #[arg(long, default_value = "false")]
    pub without_invitations: bool,
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum BackendPreset {
    /// B2C: Auth + Billing + Admin (no organizations)
    B2c,
    /// B2B: Auth + Billing + Organizations + Admin
    B2b,
}

#[derive(Parser, Debug)]
pub struct GenerateArgs {
    /// Vue frontend module to generate (auth, billing, organizations, admin, or all)
    #[arg(value_enum)]
    pub module: Module,

    /// Frontend framework to use (current helpers are Vue-only)
    #[arg(short, long, default_value = "vue")]
    pub framework: Framework,

    /// Styling approach
    #[arg(short, long, default_value = "shadcn")]
    pub style: Style,

    /// Output directory for generated files
    #[arg(short, long, default_value = "./src/components/tideway")]
    pub output: String,

    /// API base URL for fetch calls (fallback if VITE_API_URL env var not set)
    #[arg(long, default_value = "http://localhost:3000")]
    pub api_base: String,

    /// Overwrite existing files without prompting
    #[arg(long, default_value = "false")]
    pub force: bool,

    /// Skip generating shared files (useApi.ts, types/index.ts)
    #[arg(long, default_value = "false")]
    pub no_shared: bool,

    /// Also generate view files (e.g., AdminLayout.vue, AdminUsersView.vue)
    #[arg(long, default_value = "false")]
    pub with_views: bool,

    /// Output directory for view files (only used with --with-views)
    #[arg(long, default_value = "./src/views")]
    pub views_output: String,
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum Module {
    /// Authentication components (login, register, password reset, MFA)
    Auth,
    /// Billing components (subscription, checkout, portal, invoices)
    Billing,
    /// Organization components (switcher, settings, members, invites)
    Organizations,
    /// Admin components (dashboard, users, organizations, impersonation)
    Admin,
    /// Generate all modules
    All,
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum Framework {
    /// Vue 3 with Composition API
    Vue,
    // Future: React, Svelte
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum Style {
    /// shadcn-vue components (recommended)
    Shadcn,
    /// Plain Tailwind CSS
    Tailwind,
    /// Minimal HTML, no styling
    Unstyled,
}

impl std::fmt::Display for Module {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Module::Auth => write!(f, "auth"),
            Module::Billing => write!(f, "billing"),
            Module::Organizations => write!(f, "organizations"),
            Module::Admin => write!(f, "admin"),
            Module::All => write!(f, "all"),
        }
    }
}

impl std::fmt::Display for Framework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Framework::Vue => write!(f, "vue"),
        }
    }
}

impl std::fmt::Display for Style {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Style::Shadcn => write!(f, "shadcn"),
            Style::Tailwind => write!(f, "tailwind"),
            Style::Unstyled => write!(f, "unstyled"),
        }
    }
}

impl std::fmt::Display for BackendPreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendPreset::B2c => write!(f, "b2c"),
            BackendPreset::B2b => write!(f, "b2b"),
        }
    }
}

impl std::fmt::Display for AddFeature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            AddFeature::Auth => "auth",
            AddFeature::Database => "database",
            AddFeature::Openapi => "openapi",
            AddFeature::Validation => "validation",
            AddFeature::Cache => "cache",
            AddFeature::Sessions => "sessions",
            AddFeature::Jobs => "jobs",
            AddFeature::Websocket => "websocket",
            AddFeature::Metrics => "metrics",
            AddFeature::Email => "email",
            AddFeature::Organizations => "organizations",
        };
        write!(f, "{}", name)
    }
}
