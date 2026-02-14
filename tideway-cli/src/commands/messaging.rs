//! Shared user-facing messaging fragments for CLI commands.

pub const NEW_APP_COMMAND: &str = "`tideway new <app>`";
pub const NEW_APP_PRESET_API_COMMAND: &str = "`tideway new <app> --preset api`";
pub const DEV_FIX_ENV_COMMAND: &str = "`tideway dev --fix-env`";
pub const RESOURCE_WIRE_FLOW: &str = "`tideway resource <name> --wire --db --repo --service --paginate --search`";

pub const GREENFIELD_NEW_APP_FIRST: &str = "For greenfield apps, run `tideway new <app>` first.";
pub const GREENFIELD_PRIMARY_PATH: &str =
    "For greenfield apps, use the primary path: tideway new <app> -> `tideway dev --fix-env` -> `tideway resource <name> --wire --db --repo --service --paginate --search`";
pub const GREENFIELD_NEW_APP_PRESET_API: &str =
    "For greenfield apps, run `tideway new <app> --preset api` first.";
pub const PRIMARY_PATH_REMINDER_CHAIN: &str =
    "Primary path reminder: tideway new <app> -> `tideway dev --fix-env` -> `tideway resource <name> --wire --db --repo --service --paginate --search`";
pub const PRIMARY_PATH: &str =
    "Primary path: tideway new <app> -> `tideway dev --fix-env` -> `tideway resource <name> --wire --db --repo --service --paginate --search`";
