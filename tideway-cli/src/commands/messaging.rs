//! Shared user-facing messaging fragments for CLI commands.

pub const NEW_APP_COMMAND: &str = "`tideway new <app>`";
pub const NEW_APP_PRESET_API_COMMAND: &str = "`tideway new <app> --preset api`";
pub const DEV_FIX_ENV_COMMAND: &str = "`tideway dev --fix-env`";
pub const RESOURCE_WIRE_FLOW: &str =
    "`tideway resource <name> --wire --db --repo --service --paginate --search`";
pub const TIDEWAY_ADD_DATABASE_COMMAND: &str = "`tideway add database`";
pub const TIDEWAY_ADD_DATABASE_WIRE_COMMAND: &str = "`tideway add database --wire`";
pub const TIDEWAY_ADD_OPENAPI_COMMAND: &str = "`tideway add openapi`";
pub const TIDEWAY_ADD_OPENAPI_WIRE_COMMAND: &str = "`tideway add openapi --wire`";
pub const TIDEWAY_RESOURCE_WIRE_COMMAND: &str = "`tideway resource --wire`";
pub const TIDEWAY_BACKEND_COMMAND: &str = "`tideway backend`";
pub const SEA_ORM_MIGRATE_INIT_COMMAND: &str = "`sea-orm-cli migrate init`";
pub const TIDEWAY_DEV_COMMAND: &str = "`tideway dev`";

pub const GREENFIELD_NEW_APP_FIRST: &str = "For greenfield apps, run `tideway new <app>` first.";
pub const GREENFIELD_PRIMARY_PATH: &str = "For greenfield apps, use the primary path: tideway new <app> -> `tideway dev --fix-env` -> `tideway resource <name> --wire --db --repo --service --paginate --search`";
pub const GREENFIELD_NEW_APP_PRESET_API: &str =
    "For greenfield apps, run `tideway new <app> --preset api` first.";
pub const PRIMARY_PATH_REMINDER_CHAIN: &str = "Primary path reminder: tideway new <app> -> `tideway dev --fix-env` -> `tideway resource <name> --wire --db --repo --service --paginate --search`";
pub const PRIMARY_PATH: &str = "Primary path: tideway new <app> -> `tideway dev --fix-env` -> `tideway resource <name> --wire --db --repo --service --paginate --search`";

pub const PRIMARY_PATH_SEQUENCE_PLAIN: &str = "tideway new <app> -> tideway dev --fix-env -> tideway resource <name> --wire --db --repo --service --paginate --search -> tideway migrate";
pub const CLI_ADVANCED_NOTE: &str =
    "Advanced commands are for existing projects or nonstandard workflows.";
pub const CLI_HELP_TRAILER: &str = "Primary commands: new, dev, resource, doctor, migrate.\nAdvanced commands are for existing projects or nonstandard workflows.\nPrimary path (recommended): tideway new <app> -> tideway dev --fix-env -> tideway resource <name> --wire --db --repo --service --paginate --search -> tideway migrate";
