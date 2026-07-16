use std::fs;
use std::path::Path;

use tideway_cli::cli::{AddArgs, AddFeature};

#[test]
fn test_add_auth_updates_cargo_and_scaffolds() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src")).expect("create src");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let args = AddArgs {
        feature: AddFeature::Auth,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: false,
        db: false,
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    assert_file_contains(&project_dir.join("Cargo.toml"), "\"auth\"");
    assert!(project_dir.join("src/auth/mod.rs").exists());
    assert!(project_dir.join("src/auth/routes.rs").exists());
    assert!(project_dir.join("src/auth/provider.rs").exists());
    assert!(project_dir.join(".env.example").exists());
}

#[test]
fn test_add_database_updates_cargo_and_env() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src")).expect("create src");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let args = AddArgs {
        feature: AddFeature::Database,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: false,
        db: false,
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    assert_file_contains(&project_dir.join("Cargo.toml"), "\"database\"");
    assert_file_contains(&project_dir.join("Cargo.toml"), "sea-orm");
    assert_file_contains(&project_dir.join(".env.example"), "DATABASE_URL=");
}

#[test]
fn test_add_organizations_scaffolds_without_billing_or_admin() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    write_organization_prerequisites(&project_dir, STANDARD_MIGRATION_LIB);

    let args = AddArgs {
        feature: AddFeature::Organizations,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: false,
        db: true,
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    assert_file_contains(&project_dir.join("Cargo.toml"), "\"organizations\"");
    assert_file_contains(&project_dir.join("Cargo.toml"), "\"organizations-seaorm\"");
    assert!(project_dir.join("src/organizations/mod.rs").exists());
    assert!(project_dir.join("src/organizations/routes.rs").exists());
    assert!(project_dir.join("src/entities/organization.rs").exists());
    assert!(
        project_dir
            .join("src/entities/organization_member.rs")
            .exists()
    );
    assert!(
        project_dir
            .join("migration/src/m005_create_organizations.rs")
            .exists()
    );
    assert!(
        project_dir
            .join("migration/src/m006_create_organization_members.rs")
            .exists()
    );
    assert!(!project_dir.join("src/billing/mod.rs").exists());
    assert!(!project_dir.join("src/admin/mod.rs").exists());
    assert_file_not_contains(
        &project_dir.join("src/entities/organization.rs"),
        "BillableEntity",
    );
}

#[test]
fn test_add_organizations_requires_db_backed_auth_contract() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src")).expect("create src");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let args = AddArgs {
        feature: AddFeature::Organizations,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: false,
        db: true,
    };

    let err = tideway_cli::commands::add::run(args).expect_err("expected missing contract error");
    let message = err.to_string();
    assert!(message.contains("DB-backed auth contract"));
    assert!(!project_dir.join("src/organizations/mod.rs").exists());
}

#[test]
fn test_add_organizations_rejects_non_org_aware_auth_contract() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src/auth")).expect("create auth");
    fs::create_dir_all(project_dir.join("src/entities")).expect("create entities");
    fs::create_dir_all(project_dir.join("migration/src")).expect("create migrations");
    write_basic_cargo(&project_dir);
    fs::write(
        project_dir.join("src/auth/actor.rs"),
        "pub struct RequestActor;\nimpl RequestActor { pub async fn from_headers() {} }\n",
    )
    .expect("write actor");
    fs::write(
        project_dir.join("src/entities/user.rs"),
        "pub struct Model { pub id: String }\n",
    )
    .expect("write user");
    fs::write(
        project_dir.join("migration/src/m001_create_users.rs"),
        "// users migration\n",
    )
    .expect("write users migration");
    fs::write(
        project_dir.join("migration/src/lib.rs"),
        STANDARD_MIGRATION_LIB,
    )
    .expect("write migration lib");

    let args = AddArgs {
        feature: AddFeature::Organizations,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: false,
        db: true,
    };

    let err =
        tideway_cli::commands::add::run(args).expect_err("expected non org-aware contract error");
    assert!(
        err.to_string()
            .contains("org-aware DB-backed auth contract")
    );
    assert!(!project_dir.join("src/organizations/mod.rs").exists());
}

#[test]
fn test_add_organizations_rejects_missing_migration_lib_registration() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src/auth")).expect("create auth");
    fs::create_dir_all(project_dir.join("src/entities")).expect("create entities");
    fs::create_dir_all(project_dir.join("migration/src")).expect("create migrations");
    write_basic_cargo(&project_dir);
    write_org_aware_contract_files(&project_dir);
    fs::write(
        project_dir.join("migration/src/m001_create_users.rs"),
        "// users migration\n",
    )
    .expect("write users migration");

    let args = AddArgs {
        feature: AddFeature::Organizations,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: false,
        db: true,
    };

    let err =
        tideway_cli::commands::add::run(args).expect_err("expected missing migration lib error");
    assert!(err.to_string().contains("migration/src/lib.rs"));
    assert!(!project_dir.join("src/organizations/mod.rs").exists());
}

#[test]
fn test_add_organizations_rejects_missing_user_organization_id_migration() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    write_organization_prerequisites(&project_dir, MIGRATION_LIB_WITHOUT_USER_ORG_COLUMN);
    fs::write(
        project_dir.join("migration/src/m007_add_admin_flag.rs"),
        r#"
enum Users {
    IsPlatformAdmin,
}
"#,
    )
    .expect("write migration without org column");

    let args = AddArgs {
        feature: AddFeature::Organizations,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: false,
        db: true,
    };

    let err = tideway_cli::commands::add::run(args)
        .expect_err("expected missing user organization_id migration error");
    assert!(err.to_string().contains("users.organization_id migration"));
    assert!(!project_dir.join("src/organizations/mod.rs").exists());
}

#[test]
fn test_add_organizations_rejects_commented_user_organization_id_migration() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    write_organization_prerequisites(&project_dir, STANDARD_MIGRATION_LIB);
    fs::write(
        project_dir.join("migration/src/m007_add_admin_flag.rs"),
        r#"
impl MigrationTrait for Migration {
    async fn up(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // Table::alter().table(Users::Table).add_column(ColumnDef::new(Users::OrganizationId));
        Ok(())
    }
}
"#,
    )
    .expect("write commented migration");

    let args = AddArgs {
        feature: AddFeature::Organizations,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: false,
        db: true,
    };

    let err = tideway_cli::commands::add::run(args)
        .expect_err("expected missing user organization_id migration error");
    assert!(err.to_string().contains("users.organization_id migration"));
    assert!(!project_dir.join("src/organizations/mod.rs").exists());
}

#[test]
fn test_add_rejects_db_flag_for_non_organization_features() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src")).expect("create src");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let args = AddArgs {
        feature: AddFeature::Auth,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: false,
        db: true,
    };

    let err = tideway_cli::commands::add::run(args).expect_err("expected unsupported flag error");
    assert!(err.to_string().contains("--db is only supported"));
    assert!(!project_dir.join("src/auth/mod.rs").exists());
}

#[test]
fn test_add_organizations_wires_custom_database_variable() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    write_organization_prerequisites(&project_dir, STANDARD_MIGRATION_LIB);

    let main_rs = r#"
use tideway::App;

mod routes;

#[tokio::main]
async fn main() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is not set");
    let conn = sea_orm::Database::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    let app = App::new()
        .register_module(routes::ApiModule);

    let _ = app;
    let _ = conn;
}
"#;
    fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    let args = AddArgs {
        feature: AddFeature::Organizations,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: true,
        db: true,
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated.contains("Arc::new(conn.clone())"));
    assert!(!updated.contains("Arc::new(db.clone())"));
    assert!(updated.contains("register_module(organization_module)"));
}

#[test]
fn test_add_organizations_wires_backend_fluent_app_builder() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    write_organization_prerequisites(&project_dir, STANDARD_MIGRATION_LIB);

    let main_rs = r#"
use std::sync::Arc;
use tideway::{App, AppContext, ConfigBuilder};

mod auth;
mod routes;

use crate::auth::AuthModule;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ConfigBuilder::new().build()?;
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is not set");
    let db = sea_orm::Database::connect(&database_url).await?;
    let auth_module = AuthModule::new();
    let context = AppContext::builder().build();

    App::with_config(config)
        .with_context(context)
        .register_module(auth_module)
        .serve()
        .await?;

    Ok(())
}

"#;
    fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    let args = AddArgs {
        feature: AddFeature::Organizations,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: true,
        db: true,
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated.contains("let organization_module = OrganizationModule::new("));
    assert!(updated.contains("Arc::new(db.clone())"));
    assert!(updated.contains(".register_module(organization_module)"));
    assert!(updated.contains(".serve()"));
}

#[test]
fn test_add_organizations_reuses_existing_paired_jwt_configuration() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    write_organization_prerequisites(&project_dir, STANDARD_MIGRATION_LIB);

    let main_rs = r#"
use tideway::App;

mod auth;

#[tokio::main]
async fn main() {
    let database_url = std::env::var("DATABASE_URL").unwrap();
    let db = sea_orm::Database::connect(&database_url).await.unwrap();
    let jwt = tideway::auth::JwtAuth::new(todo!()).unwrap();
    let app = App::new();
    let _ = app;
}
"#;
    fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    tideway_cli::commands::add::run(AddArgs {
        feature: AddFeature::Organizations,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: true,
        db: true,
    })
    .expect("run add command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated.contains("organization_jwt_verifier = jwt"));
    assert!(!updated.contains("organization_jwt_secret"));
    assert!(updated.contains("register_module(organization_module)"));
}

#[test]
fn test_add_organizations_skips_main_when_database_variable_is_unknown() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    write_organization_prerequisites(&project_dir, STANDARD_MIGRATION_LIB);

    let main_rs = r#"
use tideway::App;

mod routes;

#[tokio::main]
async fn main() {
    let app = App::new()
        .register_module(routes::ApiModule);

    let _ = app;
}
"#;
    fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    let args = AddArgs {
        feature: AddFeature::Organizations,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: true,
        db: true,
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(!updated.contains("OrganizationModule::new"));
    assert!(!updated.contains("register_module(organization_module)"));
    assert!(!updated.contains("mod organizations;"));
}

#[test]
fn test_add_organizations_registers_migrations_with_brackets_in_comments() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    write_organization_prerequisites(&project_dir, MIGRATION_LIB_WITH_BRACKET_COMMENT);

    let args = AddArgs {
        feature: AddFeature::Organizations,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: false,
        db: true,
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    let updated =
        fs::read_to_string(project_dir.join("migration/src/lib.rs")).expect("read migration lib");
    assert!(updated.contains("// comment with ] should not receive inserted migrations"));
    assert!(updated.contains("Box::new(m005_create_organizations::Migration),"));
    assert!(updated.contains("Box::new(m006_create_organization_members::Migration),"));
    assert!(updated.contains(
        "// comment with ] should not receive inserted migrations\n            Box::new(m001_create_users::Migration),"
    ));
}

#[test]
fn test_add_auth_wires_main_rs() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src")).expect("create src");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let main_rs = r#"
use tideway::App;

mod routes;

fn main() {
    let app = App::new()
        .register_module(routes::ApiModule);

    let _ = app;
}
"#;
    fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    let args = AddArgs {
        feature: AddFeature::Auth,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: true,
        db: false,
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated.contains("mod auth;"));
    assert!(updated.contains("AuthModule"));
    assert!(updated.contains("SimpleAuthProvider"));
    assert!(updated.contains("register_module(auth_module)"));
}

#[test]
fn test_add_auth_wires_main_rs_using_builder_markers() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src")).expect("create src");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let main_rs = r#"
use tideway::App;

mod routes;

#[tokio::main]
async fn main() {
    // tideway:app-builder:start
    let server = App::new()
        .register_module(routes::ApiModule);
    // tideway:app-builder:end

    let _ = server;
}
"#;
    fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    let args = AddArgs {
        feature: AddFeature::Auth,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: true,
        db: false,
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated.contains("mod auth;"));
    assert!(updated.contains("AuthModule"));
    assert!(updated.contains("SimpleAuthProvider"));
    assert!(updated.contains(".with_global_layer(Extension(auth_provider))"));
    assert!(updated.contains(".register_module(auth_module)"));
}

#[test]
fn test_add_auth_wire_is_idempotent() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src")).expect("create src");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let main_rs = r#"
use tideway::App;

mod routes;

#[tokio::main]
async fn main() {
    // tideway:app-builder:start
    let app = App::new()
        .register_module(routes::ApiModule);
    // tideway:app-builder:end

    let _ = app;
}
"#;
    fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    let args = AddArgs {
        feature: AddFeature::Auth,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: true,
        db: false,
    };
    tideway_cli::commands::add::run(args).expect("first run add command");
    let args = AddArgs {
        feature: AddFeature::Auth,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: true,
        db: false,
    };
    tideway_cli::commands::add::run(args).expect("second run add command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert_eq!(
        updated.matches("register_module(auth_module)").count(),
        1,
        "auth module registration should be inserted once"
    );
    assert_eq!(
        updated
            .matches(".with_global_layer(Extension(auth_provider))")
            .count(),
        1,
        "auth provider layer should be inserted once"
    );
}

#[test]
fn test_add_auth_wires_legacy_main_with_custom_builder_var() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src")).expect("create src");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let main_rs = r#"
use tideway::App;

mod routes;

#[tokio::main]
async fn main() {
    let boot = "ok";
    let server = App::new()
        .register_module(routes::ApiModule);

    let _ = boot;
    let _ = server;
}
"#;
    fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    let args = AddArgs {
        feature: AddFeature::Auth,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: true,
        db: false,
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated.contains("register_module(auth_module)"));
    assert!(updated.contains(".with_global_layer(Extension(auth_provider))"));
}

#[test]
fn test_add_auth_skips_fluent_main_without_partial_wiring() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src")).expect("create src");
    write_basic_cargo(&project_dir);

    let main_rs = r#"
use tideway::App;

mod routes;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    App::new()
        .register_module(routes::ApiModule)
        .serve()
        .await?;

    Ok(())
}
"#;
    fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    let args = AddArgs {
        feature: AddFeature::Auth,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: true,
        db: false,
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(!updated.contains("mod auth;"));
    assert!(!updated.contains("auth_module"));
    assert!(!updated.contains("auth_provider"));
}

#[test]
fn test_add_database_wires_main_rs() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src")).expect("create src");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let main_rs = r#"
use tideway::App;

mod routes;

#[tokio::main]
async fn main() {
    let app = App::new()
        .register_module(routes::ApiModule);

    let _ = app;
}
"#;
    fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    let args = AddArgs {
        feature: AddFeature::Database,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: true,
        db: false,
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated.contains("DATABASE_URL"));
    assert!(updated.contains("SeaOrmPool"));
    assert!(updated.contains("with_database"));
}

#[test]
fn test_add_database_wire_is_idempotent() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src")).expect("create src");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let main_rs = r#"
use tideway::App;

mod routes;

#[tokio::main]
async fn main() {
    // tideway:app-builder:start
    let app = App::new()
        .register_module(routes::ApiModule);
    // tideway:app-builder:end

    let _ = app;
}
"#;
    fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    let args = AddArgs {
        feature: AddFeature::Database,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: true,
        db: false,
    };
    tideway_cli::commands::add::run(args).expect("first run add command");
    let args = AddArgs {
        feature: AddFeature::Database,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: true,
        db: false,
    };
    tideway_cli::commands::add::run(args).expect("second run add command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert_eq!(
        updated
            .matches("let database_url = std::env::var(\"DATABASE_URL\")")
            .count(),
        1,
        "database url bootstrap should be inserted once"
    );
    assert_eq!(
        updated
            .matches(".with_database(Arc::new(SeaOrmPool::new(db, database_url)))")
            .count(),
        1,
        "database context wiring should be inserted once"
    );
}

#[test]
fn test_add_database_wires_legacy_main_with_custom_builder_var() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src")).expect("create src");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let main_rs = r#"
use tideway::App;

mod routes;

#[tokio::main]
async fn main() {
    let started = true;
    let server = App::new()
        .register_module(routes::ApiModule);

    let _ = started;
    let _ = server;
}
"#;
    fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    let args = AddArgs {
        feature: AddFeature::Database,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: true,
        db: false,
    };
    tideway_cli::commands::add::run(args).expect("run add command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated.contains("let database_url = std::env::var(\"DATABASE_URL\")"));
    assert!(updated.contains("server = App::new()") || updated.contains("let server = App::new()"));
    assert!(updated.contains(".with_database(Arc::new(SeaOrmPool::new(db, database_url)))"));
}

#[test]
fn test_add_database_skips_fluent_main_without_partial_wiring() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src")).expect("create src");
    write_basic_cargo(&project_dir);

    let main_rs = r#"
use tideway::{App, ConfigBuilder};

mod routes;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ConfigBuilder::new().build()?;

    App::with_config(config)
        .register_module(routes::ApiModule)
        .serve()
        .await?;

    Ok(())
}
"#;
    fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    let args = AddArgs {
        feature: AddFeature::Database,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: true,
        db: false,
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(!updated.contains("DATABASE_URL"));
    assert!(!updated.contains("SeaOrmPool"));
    assert!(!updated.contains("with_database"));
}

#[test]
fn test_add_openapi_wires_main_rs() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src")).expect("create src");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let main_rs = r#"
use tideway::{App, ConfigBuilder};

mod routes;
mod openapi_docs;

#[tokio::main]
async fn main() {
    let config = ConfigBuilder::new()
        .from_env()
        .build()
        .expect("Invalid TIDEWAY_* config");

    let app = App::new()
        .register_module(routes::ApiModule);

    let _ = app;
    let _ = config;
}
"#;
    fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    let args = AddArgs {
        feature: AddFeature::Openapi,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: true,
        db: false,
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated.contains("create_openapi_router"));
    assert!(updated.contains("openapi_merge_module"));
    assert!(!updated.contains("#[cfg(feature = \"openapi\")]"));
    assert!(project_dir.join("src/openapi_docs.rs").exists());
    assert_file_not_contains(
        &project_dir.join("src/openapi_docs.rs"),
        "#[cfg(feature = \"openapi\")]",
    );
}

#[test]
fn test_add_openapi_wires_main_rs_using_builder_markers_and_custom_var() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src")).expect("create src");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let main_rs = r#"
use tideway::{App, ConfigBuilder};

mod routes;

#[tokio::main]
async fn main() {
    let config = ConfigBuilder::new()
        .from_env()
        .build()
        .expect("Invalid TIDEWAY_* config");

    // tideway:app-builder:start
    let server = App::new()
        .register_module(routes::ApiModule);
    // tideway:app-builder:end

    let _ = server;
    let _ = config;
}
"#;
    fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    let args = AddArgs {
        feature: AddFeature::Openapi,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: true,
        db: false,
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated.contains("create_openapi_router"));
    assert!(updated.contains("openapi_merge_module"));
    assert!(updated.contains("server = server.merge_router(openapi_router);"));
    assert!(project_dir.join("src/openapi_docs.rs").exists());
    assert!(!updated.contains("#[cfg(feature = \"openapi\")]"));
}

#[test]
fn test_add_openapi_wire_is_idempotent() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src")).expect("create src");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let main_rs = r#"
use tideway::{App, ConfigBuilder};

mod routes;

#[tokio::main]
async fn main() {
    let config = ConfigBuilder::new()
        .from_env()
        .build()
        .expect("Invalid TIDEWAY_* config");

    // tideway:app-builder:start
    let app = App::new()
        .register_module(routes::ApiModule);
    // tideway:app-builder:end

    let _ = app;
    let _ = config;
}
"#;
    fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    let args = AddArgs {
        feature: AddFeature::Openapi,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: true,
        db: false,
    };
    tideway_cli::commands::add::run(args).expect("first run add command");
    let args = AddArgs {
        feature: AddFeature::Openapi,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: true,
        db: false,
    };
    tideway_cli::commands::add::run(args).expect("second run add command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert_eq!(
        updated.matches("create_openapi_router").count(),
        1,
        "openapi router wiring should be inserted once"
    );
    assert_eq!(
        updated
            .matches("openapi_merge_module!(openapi_docs, ApiDoc)")
            .count(),
        1,
        "openapi merge macro should be inserted once"
    );
}

#[test]
fn test_add_openapi_wires_legacy_main_with_custom_builder_var() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src")).expect("create src");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let main_rs = r#"
use tideway::{App, ConfigBuilder};

mod routes;

#[tokio::main]
async fn main() {
    let config = ConfigBuilder::new()
        .from_env()
        .build()
        .expect("Invalid TIDEWAY_* config");
    let server = App::new()
        .register_module(routes::ApiModule);

    let _ = server;
    let _ = config;
}
"#;
    fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    let args = AddArgs {
        feature: AddFeature::Openapi,
        path: project_dir.to_string_lossy().to_string(),
        force: false,
        wire: true,
        db: false,
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated.contains("server = server.merge_router(openapi_router);"));
    assert!(updated.contains("create_openapi_router"));
}

fn assert_file_contains(path: &Path, needle: &str) {
    let contents = fs::read_to_string(path).expect("read file");
    assert!(
        contents.contains(needle),
        "expected {} to contain {}, got:\n{}",
        path.display(),
        needle,
        contents
    );
}

fn assert_file_not_contains(path: &Path, needle: &str) {
    let contents = fs::read_to_string(path).expect("read file");
    assert!(
        !contents.contains(needle),
        "expected {} to not contain {}, got:\n{}",
        path.display(),
        needle,
        contents
    );
}

const STANDARD_MIGRATION_LIB: &str = r#"//! Database migrations.

pub use sea_orm_migration::prelude::*;

mod m001_create_users;
mod m007_add_admin_flag;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m001_create_users::Migration),
            Box::new(m007_add_admin_flag::Migration),
        ]
    }
}
"#;

const MIGRATION_LIB_WITH_BRACKET_COMMENT: &str = r#"//! Database migrations.

pub use sea_orm_migration::prelude::*;

mod m001_create_users;
mod m007_add_admin_flag;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        // vec![ignored] should not be treated as the migration list
        vec![
            // comment with ] should not receive inserted migrations
            Box::new(m001_create_users::Migration),
            Box::new(m007_add_admin_flag::Migration),
        ]
    }
}
"#;

const MIGRATION_LIB_WITHOUT_USER_ORG_COLUMN: &str = r#"//! Database migrations.

pub use sea_orm_migration::prelude::*;

mod m001_create_users;
mod m007_add_admin_flag;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m001_create_users::Migration),
            Box::new(m007_add_admin_flag::Migration),
        ]
    }
}
"#;

fn write_organization_prerequisites(project_dir: &Path, migration_lib: &str) {
    fs::create_dir_all(project_dir.join("src/auth")).expect("create auth");
    fs::create_dir_all(project_dir.join("src/entities")).expect("create entities");
    fs::create_dir_all(project_dir.join("migration/src")).expect("create migrations");

    write_basic_cargo(project_dir);
    write_org_aware_contract_files(project_dir);
    fs::write(project_dir.join("src/entities/mod.rs"), "pub mod user;\n").expect("write mod");
    fs::write(
        project_dir.join("migration/src/m001_create_users.rs"),
        "// users migration\n",
    )
    .expect("write users migration");
    fs::write(
        project_dir.join("migration/src/m007_add_admin_flag.rs"),
        r#"
enum Users {
    OrganizationId,
}

impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::OrganizationId).uuid().null())
                    .to_owned(),
            )
            .await
    }
}
"#,
    )
    .expect("write user org migration");
    fs::write(project_dir.join("migration/src/lib.rs"), migration_lib)
        .expect("write migration lib");
}

fn write_basic_cargo(project_dir: &Path) {
    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["auth", "database"] }
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");
}

fn write_org_aware_contract_files(project_dir: &Path) {
    fs::write(
        project_dir.join("src/auth/actor.rs"),
        r#"
pub struct RequestActor {
    pub membership: Option<String>,
}

impl RequestActor {
    pub async fn for_organization_with_verifier() {}
    pub fn require_org_role(&self, _allowed_roles: &[&str]) {}
}
"#,
    )
    .expect("write actor");
    fs::write(
        project_dir.join("src/entities/user.rs"),
        "pub struct Model { pub id: String, pub organization_id: Option<String> }\n",
    )
    .expect("write user");
}
