//! CLI argument definitions using clap.

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "tideway")]
#[command(author = "JD")]
#[command(version)]
#[command(about = "Generate frontend components for tideway applications", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate frontend components
    Generate(GenerateArgs),

    /// Generate backend scaffolding (routes, entities, migrations)
    Backend(BackendArgs),

    /// List available templates
    Templates,
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
    /// Module to generate (auth, billing, organizations, or all)
    #[arg(value_enum)]
    pub module: Module,

    /// Frontend framework to use
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
