use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Mutex;

use tideway_cli::cli::{NewArgs, NewPreset, ResourceArgs};

#[test]
fn test_resource_command_generates_module_and_wires() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src/routes")).expect("create routes");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let routes_mod = r#"
use axum::{routing::get, Router};
use tideway::{AppContext, MessageResponse, RouteModule};

pub struct ApiModule;

impl RouteModule for ApiModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/", get(root))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

async fn root() -> MessageResponse {
    MessageResponse::success("Tideway is running")
}
"#;
    fs::write(project_dir.join("src/routes/mod.rs"), routes_mod).expect("write routes mod");

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

    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: true,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    assert!(project_dir.join("src/routes/user.rs").exists());
    assert_file_contains(&project_dir.join("src/routes/mod.rs"), "pub mod user;");
    assert_file_contains(
        &project_dir.join("src/main.rs"),
        ".register_module(routes::user::UserModule)",
    );
}

#[test]
fn test_resource_command_wires_main_rs_using_builder_markers() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src/routes")).expect("create routes");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let routes_mod = r#"
use axum::{routing::get, Router};
use tideway::{AppContext, MessageResponse, RouteModule};

pub struct ApiModule;

impl RouteModule for ApiModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/", get(root))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

async fn root() -> MessageResponse {
    MessageResponse::success("Tideway is running")
}
"#;
    fs::write(project_dir.join("src/routes/mod.rs"), routes_mod).expect("write routes mod");

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

    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated.contains(
        ".register_module(routes::ApiModule)\n        .register_module(routes::user::UserModule);"
    ));
}

#[test]
fn test_resource_wire_is_idempotent() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src/routes")).expect("create routes");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let routes_mod = r#"
use axum::{routing::get, Router};
use tideway::{AppContext, MessageResponse, RouteModule};

pub struct ApiModule;

impl RouteModule for ApiModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/", get(root))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

async fn root() -> MessageResponse {
    MessageResponse::success("Tideway is running")
}
"#;
    fs::write(project_dir.join("src/routes/mod.rs"), routes_mod).expect("write routes mod");

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

    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    };

    tideway_cli::commands::resource::run(args).expect("first run resource command");
    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    };
    tideway_cli::commands::resource::run(args).expect("second run resource command");

    let updated_main = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert_eq!(
        updated_main
            .matches(".register_module(routes::user::UserModule)")
            .count(),
        1,
        "resource module should be registered once"
    );

    let updated_routes_mod =
        fs::read_to_string(project_dir.join("src/routes/mod.rs")).expect("read routes mod");
    assert_eq!(
        updated_routes_mod.matches("pub mod user;").count(),
        1,
        "resource module declaration should be inserted once"
    );
}

#[test]
fn test_resource_wires_legacy_main_with_custom_builder_var() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src/routes")).expect("create routes");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let routes_mod = r#"
use axum::{routing::get, Router};
use tideway::{AppContext, MessageResponse, RouteModule};

pub struct ApiModule;

impl RouteModule for ApiModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/", get(root))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

async fn root() -> MessageResponse {
    MessageResponse::success("Tideway is running")
}
"#;
    fs::write(project_dir.join("src/routes/mod.rs"), routes_mod).expect("write routes mod");

    let main_rs = r#"
use tideway::App;

mod routes;

#[tokio::main]
async fn main() {
    let ready = true;
    let server = App::new()
        .register_module(routes::ApiModule);

    let _ = ready;
    let _ = server;
}
"#;
    fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(
        updated.contains(
            ".register_module(routes::ApiModule)\n        .register_module(routes::user::UserModule);"
        ),
        "expected resource registration to be appended to the app-builder chain"
    );
}

#[test]
fn test_resource_command_updates_openapi_docs() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src/routes")).expect("create routes");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["openapi"] }
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let routes_mod = r#"
use axum::{routing::get, Router};
use tideway::{AppContext, MessageResponse, RouteModule};

pub struct ApiModule;

impl RouteModule for ApiModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/", get(root))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

async fn root() -> MessageResponse {
    MessageResponse::success("Tideway is running")
}
"#;
    fs::write(project_dir.join("src/routes/mod.rs"), routes_mod).expect("write routes mod");

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

    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    let docs_path = project_dir.join("src/openapi_docs.rs");
    assert!(docs_path.exists());
    assert_file_contains(&docs_path, "crate::routes::user::list_users");
    assert_file_not_contains(&docs_path, "#[cfg(feature = \"openapi\")]");
    assert_file_not_contains(
        &project_dir.join("src/routes/user.rs"),
        "#[cfg_attr(feature = \"openapi\"",
    );
    assert_file_not_contains(
        &project_dir.join("src/routes/user.rs"),
        "mod openapi_docs {",
    );
}

#[test]
fn test_resource_command_generates_sea_orm_scaffold() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src/routes")).expect("create routes");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let routes_mod = r#"
use axum::{routing::get, Router};
use tideway::{AppContext, MessageResponse, RouteModule};

pub struct ApiModule;

impl RouteModule for ApiModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/", get(root))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

async fn root() -> MessageResponse {
    MessageResponse::success("Tideway is running")
}
"#;
    fs::write(project_dir.join("src/routes/mod.rs"), routes_mod).expect("write routes mod");

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

    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: false,
        db: true,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    assert!(project_dir.join("src/entities/user.rs").exists());
    assert_file_contains(&project_dir.join("src/entities/mod.rs"), "pub mod user;");

    let migration_lib = project_dir.join("migration/src/lib.rs");
    assert!(migration_lib.exists());
    assert_file_contains(&migration_lib, "create_users");

    let routes_path = project_dir.join("src/routes/user.rs");
    assert_file_contains(&routes_path, "State(ctx): State<AppContext>");
    assert_file_contains(&routes_path, "Entity::find");

    let updated_main = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated_main.contains("with_database("));
    assert!(updated_main.contains("mod entities;"));
}

#[test]
fn test_resource_command_skips_route_tests_for_db_scaffold() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src/routes")).expect("create routes");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let routes_mod = r#"
use axum::{routing::get, Router};
use tideway::{AppContext, MessageResponse, RouteModule};

pub struct ApiModule;

impl RouteModule for ApiModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/", get(root))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

async fn root() -> MessageResponse {
    MessageResponse::success("Tideway is running")
}
"#;
    fs::write(project_dir.join("src/routes/mod.rs"), routes_mod).expect("write routes mod");

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

    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: true,
        db: true,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    assert_file_not_contains(&project_dir.join("src/routes/user.rs"), "#[cfg(test)]");
}

#[test]
fn test_resource_command_generates_repository_layer() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src/routes")).expect("create routes");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let routes_mod = r#"
use axum::{routing::get, Router};
use tideway::{AppContext, MessageResponse, RouteModule};

pub struct ApiModule;

impl RouteModule for ApiModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/", get(root))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

async fn root() -> MessageResponse {
    MessageResponse::success("Tideway is running")
}
"#;
    fs::write(project_dir.join("src/routes/mod.rs"), routes_mod).expect("write routes mod");

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

    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: false,
        db: true,
        repo: true,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    assert!(project_dir.join("src/repositories/user.rs").exists());
    assert_file_contains(
        &project_dir.join("src/repositories/mod.rs"),
        "pub mod user;",
    );
    assert_file_contains(&project_dir.join("src/routes/user.rs"), "Repository");
    let updated_main = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated_main.contains("mod repositories;"));
}

#[test]
fn test_resource_command_updates_single_line_empty_migration_vector() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_resource_project_fixture(
        &project_dir,
        r#"
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#,
    );

    fs::create_dir_all(project_dir.join("migration/src")).expect("create migration src");
    fs::write(
        project_dir.join("migration/src/lib.rs"),
        r#"//! Database migrations.

pub use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![]
    }
}
"#,
    )
    .expect("write migration lib");

    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: false,
        with_tests: false,
        db: true,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    let migration_lib = project_dir.join("migration/src/lib.rs");
    assert_file_contains(&migration_lib, "mod m001_create_users;");
    assert_file_contains(&migration_lib, "Box::new(m001_create_users::Migration),");
    assert!(
        !fs::read_to_string(&migration_lib)
            .expect("read migration lib")
            .contains("vec![]"),
        "expected vec![] to be expanded into a multi-line migration list"
    );
}

#[test]
fn test_resource_command_preserves_timestamp_migration_convention() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_resource_project_fixture(
        &project_dir,
        r#"
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#,
    );
    fs::create_dir_all(project_dir.join("migration/src")).expect("create migration src");
    fs::write(
        project_dir.join("migration/src/m20990101_000000_application_change.rs"),
        "// application-owned migration\n",
    )
    .expect("write existing migration");
    fs::write(
        project_dir.join("migration/src/lib.rs"),
        r#"use sea_orm_migration::prelude::*;
mod m20990101_000000_application_change;
pub struct Migrator;
#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20990101_000000_application_change::Migration),
        ]
    }
}
"#,
    )
    .expect("write migration lib");

    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: false,
        with_tests: false,
        db: true,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    let migration = project_dir.join("migration/src/m20990101_000001_create_users.rs");
    assert_file_contains(&migration, "create_table");
    assert_file_contains(
        &project_dir.join("migration/src/lib.rs"),
        "Box::new(m20990101_000001_create_users::Migration)",
    );
}

#[test]
fn test_resource_ambiguous_migration_style_fails_before_writing() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_resource_project_fixture(
        &project_dir,
        r#"
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#,
    );
    fs::create_dir_all(project_dir.join("migration/src")).expect("create migration src");
    fs::write(
        project_dir.join("migration/src/m014_application_change.rs"),
        "// sequential application migration\n",
    )
    .expect("write sequential migration");
    fs::write(
        project_dir.join("migration/src/m20260717_120000_application_change.rs"),
        "// timestamp application migration\n",
    )
    .expect("write timestamp migration");
    fs::write(
        project_dir.join("migration/src/lib.rs"),
        r#"use sea_orm_migration::prelude::*;
pub struct Migrator;
#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![]
    }
}
"#,
    )
    .expect("write migration lib");
    let cargo_before = fs::read_to_string(project_dir.join("Cargo.toml")).expect("read Cargo");
    let main_before = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main");
    let routes_before =
        fs::read_to_string(project_dir.join("src/routes/mod.rs")).expect("read routes");

    let error = tideway_cli::commands::resource::run(ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: false,
        db: true,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    })
    .expect_err("ambiguous migration style should fail")
    .to_string();

    assert!(error.contains("Both sequential and timestamp migration names were found"));
    assert_eq!(
        fs::read_to_string(project_dir.join("Cargo.toml")).expect("read Cargo after"),
        cargo_before
    );
    assert_eq!(
        fs::read_to_string(project_dir.join("src/main.rs")).expect("read main after"),
        main_before
    );
    assert_eq!(
        fs::read_to_string(project_dir.join("src/routes/mod.rs")).expect("read routes after"),
        routes_before
    );
    assert!(!project_dir.join("src/routes/user.rs").exists());
    assert!(!project_dir.join("src/entities/user.rs").exists());
}

#[test]
fn test_resource_command_generates_repository_tests() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src/routes")).expect("create routes");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let routes_mod = r#"
use axum::{routing::get, Router};
use tideway::{AppContext, MessageResponse, RouteModule};

pub struct ApiModule;

impl RouteModule for ApiModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/", get(root))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

async fn root() -> MessageResponse {
    MessageResponse::success("Tideway is running")
}
"#;
    fs::write(project_dir.join("src/routes/mod.rs"), routes_mod).expect("write routes mod");

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

    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: false,
        db: true,
        repo: true,
        repo_tests: true,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    let test_path = project_dir.join("tests/repository_user.rs");
    assert!(test_path.exists());
    assert_file_contains(&test_path, "Repository");
    assert_file_contains(&test_path, "DATABASE_URL");
}

#[test]
fn test_resource_command_generates_pagination_helpers() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src/routes")).expect("create routes");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let routes_mod = r#"
use axum::{routing::get, Router};
use tideway::{AppContext, MessageResponse, RouteModule};

pub struct ApiModule;

impl RouteModule for ApiModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/", get(root))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

async fn root() -> MessageResponse {
    MessageResponse::success("Tideway is running")
}
"#;
    fs::write(project_dir.join("src/routes/mod.rs"), routes_mod).expect("write routes mod");

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

    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: false,
        db: true,
        repo: true,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: true,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    let routes_path = project_dir.join("src/routes/user.rs");
    assert_file_contains(&routes_path, "PaginationParams");
    assert_file_contains(&routes_path, "Query(params)");

    let repo_path = project_dir.join("src/repositories/user.rs");
    assert_file_contains(&repo_path, "limit: Option<u64>");
    assert_file_contains(
        &repo_path,
        "query = query.limit(limit.unwrap_or(20).clamp(1, 100));",
    );
}

#[test]
fn test_resource_command_generates_search_filter() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src/routes")).expect("create routes");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let routes_mod = r#"
use axum::{routing::get, Router};
use tideway::{AppContext, MessageResponse, RouteModule};

pub struct ApiModule;

impl RouteModule for ApiModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/", get(root))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

async fn root() -> MessageResponse {
    MessageResponse::success("Tideway is running")
}
"#;
    fs::write(project_dir.join("src/routes/mod.rs"), routes_mod).expect("write routes mod");

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

    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: false,
        db: true,
        repo: true,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: true,
        search: true,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    let routes_path = project_dir.join("src/routes/user.rs");
    assert_file_contains(&routes_path, "q: Option<String>");
    assert_file_contains(&routes_path, "params.q");

    let repo_path = project_dir.join("src/repositories/user.rs");
    assert_file_contains(&repo_path, "Column::Name.contains");
}

#[test]
fn test_resource_command_generates_service_layer() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src/routes")).expect("create routes");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let routes_mod = r#"
use axum::{routing::get, Router};
use tideway::{AppContext, MessageResponse, RouteModule};

pub struct ApiModule;

impl RouteModule for ApiModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/", get(root))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

async fn root() -> MessageResponse {
    MessageResponse::success("Tideway is running")
}
"#;
    fs::write(project_dir.join("src/routes/mod.rs"), routes_mod).expect("write routes mod");

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

    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: false,
        db: true,
        repo: true,
        repo_tests: false,
        service: true,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    assert!(project_dir.join("src/services/user.rs").exists());
    assert_file_contains(&project_dir.join("src/services/mod.rs"), "pub mod user;");
    assert_file_contains(&project_dir.join("src/routes/user.rs"), "Service");
    assert_file_contains(
        &project_dir.join("src/routes/user.rs"),
        "service.get_required(id).await?;",
    );
    assert_file_contains(
        &project_dir.join("src/services/user.rs"),
        "pub async fn get_required(&self, id: i32) -> Result<crate::entities::user::Model>",
    );
    assert_file_contains(
        &project_dir.join("src/services/user.rs"),
        "Self::normalize_required_string(\"name\", name)?",
    );
    assert_file_contains(
        &project_dir.join("src/services/user.rs"),
        "self.get_required(id).await?;",
    );
    let updated_main = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated_main.contains("mod services;"));
}

#[test]
fn test_resource_profile_api_defaults_to_full_stack_when_shape_flags_omitted() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_resource_project_fixture(
        &project_dir,
        r#"
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#,
    );

    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: false,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Api,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    assert!(project_dir.join("src/routes/user.rs").exists());
    assert!(project_dir.join("src/entities/user.rs").exists());
    assert!(project_dir.join("src/repositories/user.rs").exists());
    assert!(project_dir.join("src/services/user.rs").exists());
    assert!(project_dir.join("migration/src/lib.rs").exists());
    assert_file_contains(&project_dir.join("src/routes/user.rs"), "q: Option<String>");
    assert_file_contains(
        &project_dir.join("src/repositories/user.rs"),
        "Column::Name.contains",
    );
    let updated_main = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated_main.contains(".register_module(routes::user::UserModule)"));
    assert!(updated_main.contains("with_database("));
    assert!(updated_main.contains("mod entities;"));
    assert!(updated_main.contains("mod repositories;"));
    assert!(updated_main.contains("mod services;"));
}

#[test]
fn test_resource_profile_stub_defaults_to_route_only_when_shape_flags_omitted() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_resource_project_fixture(
        &project_dir,
        r#"
tideway = "0.7"
"#,
    );

    let main_before =
        fs::read_to_string(project_dir.join("src/main.rs")).expect("read main before");
    let routes_mod_before =
        fs::read_to_string(project_dir.join("src/routes/mod.rs")).expect("read routes mod before");

    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: false,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    assert!(project_dir.join("src/routes/user.rs").exists());
    assert!(!project_dir.join("src/entities/user.rs").exists());
    assert!(!project_dir.join("src/repositories/user.rs").exists());
    assert!(!project_dir.join("src/services/user.rs").exists());
    assert_eq!(
        fs::read_to_string(project_dir.join("src/main.rs")).expect("read main after"),
        main_before,
    );
    assert_eq!(
        fs::read_to_string(project_dir.join("src/routes/mod.rs")).expect("read routes mod after"),
        routes_mod_before,
    );
}

#[test]
fn test_resource_profile_api_respects_explicit_shape_flags() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_resource_project_fixture(
        &project_dir,
        r#"
tideway = "0.7"
"#,
    );

    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Api,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    assert!(project_dir.join("src/routes/user.rs").exists());
    assert!(!project_dir.join("src/entities/user.rs").exists());
    let updated_main = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated_main.contains(".register_module(routes::user::UserModule)"));
    assert!(!updated_main.contains("with_database("));
}

#[test]
fn test_resource_profile_tenant_generates_tenant_fields() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_resource_project_fixture(
        &project_dir,
        r#"
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#,
    );

    let args = ResourceArgs {
        name: "organization".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: false,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Tenant,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    assert_file_contains(
        &project_dir.join("src/routes/organization.rs"),
        "pub slug: String,",
    );
    assert_file_contains(
        &project_dir.join("src/routes/organization.rs"),
        "pub status: String,",
    );
    assert_file_contains(
        &project_dir.join("src/entities/organization.rs"),
        "pub created_at: i64,",
    );
    assert_file_contains(
        &project_dir.join("src/repositories/organization.rs"),
        "pub async fn create(&self, name: String, slug: String, status: String)",
    );
    assert_file_contains(
        &project_dir.join("src/repositories/organization.rs"),
        "current_timestamp()",
    );
    assert_file_contains(
        &project_dir.join("src/services/organization.rs"),
        "Self::normalize_slug(slug)?",
    );
    assert_file_contains(
        &project_dir.join("src/services/organization.rs"),
        "Self::normalize_lowercase_required(\"status\", status)?",
    );
}

#[test]
fn test_resource_profile_owned_respects_explicit_shape_flags() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_resource_project_fixture(
        &project_dir,
        r#"
tideway = "0.7"
"#,
    );

    let args = ResourceArgs {
        name: "subscription".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Owned,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    assert!(project_dir.join("src/routes/subscription.rs").exists());
    assert!(!project_dir.join("src/entities/subscription.rs").exists());
    assert!(
        !project_dir
            .join("src/repositories/subscription.rs")
            .exists()
    );
    assert!(!project_dir.join("src/services/subscription.rs").exists());
    assert_file_contains(
        &project_dir.join("src/routes/subscription.rs"),
        "pub organization_id: String,",
    );
    assert_file_contains(
        &project_dir.join("src/routes/subscription.rs"),
        "pub owner_id: String,",
    );
    assert_file_contains(
        &project_dir.join("src/routes/subscription.rs"),
        "pub status: String,",
    );
}

#[test]
fn test_resource_profile_owned_generates_saas_scoped_handlers_when_saas_scaffold_detected() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_resource_project_fixture(
        &project_dir,
        r#"
tideway = { version = "0.7", features = ["database", "auth", "organizations", "admin"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
uuid = { version = "1", features = ["v4", "serde"] }
"#,
    );
    create_saas_resource_markers(&project_dir, true, true, true);

    let args = ResourceArgs {
        name: "subscription".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: false,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Owned,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    assert_file_contains(
        &project_dir.join("src/routes/subscription.rs"),
        "use crate::auth::RequestActor;",
    );
    assert_file_contains(
        &project_dir.join("src/routes/subscription.rs"),
        "RequestActor::for_current_organization(&headers, &db).await?;",
    );
    assert_file_contains(
        &project_dir.join("src/routes/subscription.rs"),
        "service.create_for_actor(&actor, body.name, body.status).await?;",
    );
    assert_file_contains(
        &project_dir.join("src/routes/subscription.rs"),
        "let models = service.list_for_actor(&actor, params.limit, params.offset, params.q).await?;",
    );
    assert_file_not_contains(
        &project_dir.join("src/routes/subscription.rs"),
        "pub struct CreateRequest {\n    pub organization_id: String,",
    );
    assert_file_not_contains(
        &project_dir.join("src/routes/subscription.rs"),
        "pub struct UpdateRequest {\n    pub organization_id: Option<String>,",
    );
    assert_file_contains(
        &project_dir.join("src/repositories/subscription.rs"),
        "pub async fn list_owned(&self, organization_id: &str, owner_id: &str, limit: Option<u64>, offset: Option<u64>, search: Option<String>)",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "pub async fn get_required_owned(",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "fn ensure_owned_access(",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "pub async fn list_for_actor(&self, actor: &RequestActor, limit: Option<u64>, offset: Option<u64>, search: Option<String>)",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "pub struct SubscriptionAuditEvent {",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "pub action: &'static str,",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "pub actor_id: String,",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "pub organization_id: Option<String>,",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "pub resource: &'static str,",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "pub resource_id: String,",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "fn build_owned_audit_event(",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "resource: \"subscription\",",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "organization_id: Some(actor.organization_id()?.to_string()),",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "actor_id: actor.owner_id(),",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "async fn audit_owned_write(",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "Hook audit logging, events, or other side effects here.",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "let _ = (event, model);",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "fn policy_actor(actor: &RequestActor) -> Result<OrgActor> {",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "let event = Self::build_owned_audit_event(actor, \"create\", &model)?;",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "self.audit_owned_write(&event, &model).await?;",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "let event = Self::build_owned_audit_event(actor, \"update\", &model)?;",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "let event = Self::build_owned_audit_event(actor, \"delete\", &model)?;",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "self.audit_owned_write(&event, &model).await",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "let model = self",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "self.create_owned(&actor.organization_id, &actor.user_id, name, status)",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "self.update_owned(id, &actor.organization_id, &actor.user_id, name, status)",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        ".delete_authorized(&Self::policy_actor(actor)?, id)",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "TidewayError::forbidden(\"Subscription belongs to another user\")",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "let model = self.repo",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        ".get(id)",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "self.repo.list_owned(&organization_id, &owner_id, limit, offset, search).await",
    );
}

#[test]
fn test_resource_default_profile_generates_org_scoped_handlers_when_saas_scaffold_detected() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_resource_project_fixture(
        &project_dir,
        r#"
tideway = { version = "0.7", features = ["database", "auth", "organizations", "admin"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
uuid = { version = "1", features = ["v4", "serde"] }
"#,
    );
    create_saas_resource_markers(&project_dir, true, true, true);

    let args = ResourceArgs {
        name: "project".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: false,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Api,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    let route = project_dir.join("src/routes/project.rs");
    for handler in [
        "async fn list_projects(",
        "async fn get_project(",
        "async fn create_project(",
        "async fn update_project(",
        "async fn delete_project(",
    ] {
        let contents = fs::read_to_string(&route).expect("read route");
        let body = &contents[contents.find(handler).expect("handler exists")..];
        let body = &body[..body.find("\n}\n").expect("handler end")];
        assert!(
            body.contains("RequestActor::for_current_organization(&headers, &db).await?;"),
            "{handler} must authenticate and resolve organization membership:\n{body}"
        );
    }
    assert_file_contains(
        &route,
        "service.create_for_actor(&actor, body.name).await?;",
    );
    assert_file_not_contains(
        &route,
        "pub struct CreateRequest {\n    pub organization_id",
    );
    assert_file_not_contains(
        &route,
        "pub struct UpdateRequest {\n    pub organization_id",
    );
    assert_file_contains(
        &project_dir.join("src/entities/project.rs"),
        "pub organization_id: String,",
    );
    let repo = project_dir.join("src/repositories/project.rs");
    assert_file_contains(
        &repo,
        "pub async fn list_owned(&self, organization_id: &str, limit: Option<u64>, offset: Option<u64>, search: Option<String>)",
    );
    assert_file_contains(
        &repo,
        ".filter(project::Column::OrganizationId.eq(organization_id.to_string()))",
    );
    assert_file_not_contains(&repo, "OwnerId");
    let service = project_dir.join("src/services/project.rs");
    assert_file_contains(&service, "model.organization_id == organization_id");
    assert_file_contains(&service, "self.create_owned(&actor.organization_id, name)");
    assert_file_not_contains(&service, "owner_id: &str");
}

#[test]
fn test_resource_profile_tenant_generates_org_scoped_inline_handlers_when_saas_scaffold_detected() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_resource_project_fixture(
        &project_dir,
        r#"
tideway = { version = "0.7", features = ["database", "auth", "organizations", "admin"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
uuid = { version = "1", features = ["v4", "serde"] }
"#,
    );
    create_saas_resource_markers(&project_dir, true, true, false);

    let args = ResourceArgs {
        name: "workspace".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: false,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Tenant,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    let route = project_dir.join("src/routes/workspace.rs");
    assert_file_contains(
        &route,
        "async fn resolve_org_actor(headers: &HeaderMap, db: &DatabaseConnection) -> Result<OrgActor>",
    );
    assert_file_contains(
        &route,
        "let actor = resolve_org_actor(&headers, &db).await?;",
    );
    assert_file_contains(
        &route,
        ".create_authorized(&actor, body.name, body.slug, body.status)",
    );
    assert_file_not_contains(&route, "_owned(");
    assert_file_not_contains(&route, "owner_id");
    assert_file_contains(
        &project_dir.join("src/entities/workspace.rs"),
        "pub organization_id: String,",
    );
}

#[test]
fn test_resource_scoped_profiles_authorize_every_handler_through_a_policy() {
    for (profile, name, plural, shared_actor) in [
        (
            tideway_cli::cli::ResourceProfile::Tenant,
            "workspace",
            "workspaces",
            true,
        ),
        (
            tideway_cli::cli::ResourceProfile::Tenant,
            "workspace",
            "workspaces",
            false,
        ),
        (
            tideway_cli::cli::ResourceProfile::Owned,
            "note",
            "notes",
            true,
        ),
        (
            tideway_cli::cli::ResourceProfile::Owned,
            "note",
            "notes",
            false,
        ),
    ] {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let project_dir = temp_dir.path().join("my_app");
        create_resource_project_fixture(
            &project_dir,
            r#"
tideway = { version = "0.7", features = ["database", "auth", "organizations", "admin"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
uuid = { version = "1", features = ["v4", "serde"] }
"#,
        );
        create_saas_resource_markers(&project_dir, true, true, shared_actor);

        let args = ResourceArgs {
            name: name.to_string(),
            path: project_dir.to_string_lossy().to_string(),
            wire: false,
            with_tests: false,
            db: false,
            repo: false,
            repo_tests: false,
            service: false,
            id_type: tideway_cli::cli::ResourceIdType::Int,
            add_uuid: false,
            paginate: false,
            search: false,
            db_backend: tideway_cli::cli::DbBackend::Auto,
            profile,
            fields: Vec::new(),
        };
        tideway_cli::commands::resource::run(args).expect("run resource command");

        let context = format!("{profile:?} (shared actor: {shared_actor})");
        let pascal = if name == "note" { "Note" } else { "Workspace" };

        // A policy with role permission grants is generated and wired.
        let policy = project_dir.join(format!("src/policies/{name}.rs"));
        assert_file_contains(
            &policy,
            "use tideway::policy::{OrgActor, Policy, RolePermissions};",
        );
        assert_file_contains(
            &policy,
            &format!("impl Policy<OrgActor, {name}::Model> for {pascal}Policy {{"),
        );
        assert_file_contains(&policy, &format!(".grant(\"admin\", [\"{plural}.*\"])"));
        for action in ["view", "create", "update", "delete"] {
            assert_file_contains(
                &policy,
                &format!("actor.can(&self.permissions, \"{plural}.{action}\")"),
            );
        }
        assert_file_contains(
            &project_dir.join("src/policies/mod.rs"),
            &format!("pub mod {name};"),
        );
        assert_file_contains(&project_dir.join("src/main.rs"), "mod policies;");

        // Member delete rights and record checks follow the profile.
        if name == "note" {
            assert_file_contains(
                &policy,
                "actor.belongs_to(&model.organization_id)\n            && actor.is(&model.owner_id)",
            );
            assert_file_contains(
                &policy,
                ".grant(\"member\", [\"notes.view\", \"notes.create\", \"notes.update\", \"notes.delete\"])",
            );
        } else {
            assert_file_not_contains(&policy, "owner_id");
            assert_file_contains(
                &policy,
                ".grant(\"member\", [\"workspaces.view\", \"workspaces.create\", \"workspaces.update\"])",
            );
        }

        // The service holds the policy and checks it before every operation.
        let service = project_dir.join(format!("src/services/{name}.rs"));
        assert_file_contains(&service, &format!("    policy: {pascal}Policy,\n"));
        assert_file_contains(
            &service,
            &format!("pub fn with_policy(mut self, policy: {pascal}Policy) -> Self {{"),
        );
        for (method, check) in [
            ("list_authorized", "Action::ViewAny, None"),
            ("get_required_authorized", "Action::View, Some(&model)"),
            ("create_authorized", "Action::Create, None"),
            ("update_authorized", "Action::Update, Some(&model)"),
            ("delete_authorized", "Action::Delete, Some(&model)"),
        ] {
            let contents = fs::read_to_string(&service).expect("read service");
            let start = contents
                .find(&format!("pub async fn {method}("))
                .unwrap_or_else(|| panic!("{context}: {method} missing"));
            let body = &contents[start..];
            let body = &body[..body.find("\n    }\n").expect("method end")];
            assert!(
                body.contains(&format!("self.policy.authorize(actor, {check})?;")),
                "{context}: {method} must authorize through the policy:\n{body}"
            );
        }

        // Every route handler goes through an authorized service method.
        let route = project_dir.join(format!("src/routes/{name}.rs"));
        let contents = fs::read_to_string(&route).expect("read route");
        let suffix = if shared_actor {
            "_for_actor("
        } else {
            "_authorized("
        };
        for handler in [
            format!("async fn list_{plural}("),
            format!("async fn get_{name}("),
            format!("async fn create_{name}("),
            format!("async fn update_{name}("),
            format!("async fn delete_{name}("),
        ] {
            let body = &contents[contents.find(&handler).expect("handler exists")..];
            let body = &body[..body.find("\n}\n").expect("handler end")];
            assert!(
                body.contains(suffix) && !body.contains("_owned("),
                "{context}: {handler} must call an authorized service method:\n{body}"
            );
        }
        if shared_actor {
            for method in [
                "list_for_actor",
                "get_required_for_actor",
                "create_for_actor",
                "update_for_actor",
                "delete_for_actor",
            ] {
                let contents = fs::read_to_string(&service).expect("read service");
                let body = &contents[contents
                    .find(&format!("pub async fn {method}("))
                    .unwrap_or_else(|| panic!("{context}: {method} missing"))..];
                let body = &body[..body.find("\n    }\n").expect("method end")];
                assert!(
                    body.contains("_authorized(&Self::policy_actor(actor)?"),
                    "{context}: {method} must delegate to the authorized method:\n{body}"
                );
            }
        }
    }
}

#[test]
fn test_resource_unscoped_profiles_do_not_generate_policies() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_resource_project_fixture(
        &project_dir,
        r#"
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#,
    );

    let args = ResourceArgs {
        name: "workspace".to_string(),
        path: project_dir.to_string_lossy().to_string(),
        wire: false,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Tenant,
        fields: Vec::new(),
    };
    tideway_cli::commands::resource::run(args).expect("run resource command");

    assert!(!project_dir.join("src/policies").exists());
    assert_file_not_contains(&project_dir.join("src/main.rs"), "mod policies;");
    let service = project_dir.join("src/services/workspace.rs");
    assert_file_not_contains(&service, "policy");
    assert_file_contains(&service, "Self { repo }");
}

#[test]
fn test_resource_profile_admin_generates_saas_admin_guards_when_saas_scaffold_detected() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_resource_project_fixture(
        &project_dir,
        r#"
tideway = { version = "0.7", features = ["database", "auth", "admin"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
uuid = { version = "1", features = ["v4", "serde"] }
"#,
    );
    create_saas_resource_markers(&project_dir, false, true, true);

    let args = ResourceArgs {
        name: "admin_user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: false,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Admin,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    assert_file_contains(
        &project_dir.join("src/routes/admin_user.rs"),
        "use crate::auth::RequestActor;",
    );
    assert_file_contains(
        &project_dir.join("src/routes/admin_user.rs"),
        "RequestActor::from_headers(&headers, &db).await?;",
    );
    assert_file_contains(
        &project_dir.join("src/routes/admin_user.rs"),
        "let models = service.list_for_admin(&actor, params.limit, params.offset, params.q).await?;",
    );
    assert_file_not_contains(
        &project_dir.join("src/routes/admin_user.rs"),
        "actor.require_admin()?;",
    );
    assert_file_contains(
        &project_dir.join("src/services/admin_user.rs"),
        "pub async fn list_for_admin(&self, actor: &RequestActor, limit: Option<u64>, offset: Option<u64>, search: Option<String>) -> Result<Vec<crate::entities::admin_user::Model>>",
    );
    assert_file_contains(
        &project_dir.join("src/services/admin_user.rs"),
        "pub struct AdminUserAuditEvent {",
    );
    assert_file_contains(
        &project_dir.join("src/services/admin_user.rs"),
        "fn build_admin_audit_event(",
    );
    assert_file_contains(
        &project_dir.join("src/services/admin_user.rs"),
        "resource: \"admin_user\",",
    );
    assert_file_contains(
        &project_dir.join("src/services/admin_user.rs"),
        "organization_id: None,",
    );
    assert_file_contains(
        &project_dir.join("src/services/admin_user.rs"),
        "actor_id: actor.user.id.to_string(),",
    );
    assert_file_contains(
        &project_dir.join("src/services/admin_user.rs"),
        "async fn audit_admin_write(",
    );
    assert_file_contains(
        &project_dir.join("src/services/admin_user.rs"),
        "actor.require_admin()?;",
    );
    assert_file_contains(
        &project_dir.join("src/services/admin_user.rs"),
        "let event = Self::build_admin_audit_event(actor, \"create\", &model)?;",
    );
    assert_file_contains(
        &project_dir.join("src/services/admin_user.rs"),
        "self.audit_admin_write(&event, &model).await?;",
    );
    assert_file_contains(
        &project_dir.join("src/services/admin_user.rs"),
        "let event = Self::build_admin_audit_event(actor, \"update\", &model)?;",
    );
    assert_file_contains(
        &project_dir.join("src/services/admin_user.rs"),
        "let event = Self::build_admin_audit_event(actor, \"delete\", &model)?;",
    );
    assert_file_contains(
        &project_dir.join("src/services/admin_user.rs"),
        "self.audit_admin_write(&event, &model).await",
    );
    assert_file_contains(
        &project_dir.join("src/routes/admin_user.rs"),
        "pub email: String,",
    );
}

#[test]
fn test_resource_profile_owned_falls_back_to_inline_helpers_without_shared_actor_contract() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_resource_project_fixture(
        &project_dir,
        r#"
tideway = { version = "0.7", features = ["database", "auth", "organizations", "admin"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
uuid = { version = "1", features = ["v4", "serde"] }
"#,
    );
    create_saas_resource_markers(&project_dir, true, true, false);

    let args = ResourceArgs {
        name: "subscription".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: false,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Owned,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    assert_file_contains(
        &project_dir.join("src/routes/subscription.rs"),
        "async fn resolve_org_actor(headers: &HeaderMap, db: &DatabaseConnection) -> Result<OrgActor>",
    );
    assert_file_contains(
        &project_dir.join("src/routes/subscription.rs"),
        "Multiple organizations found; send x-organization-id",
    );
    assert_file_contains(
        &project_dir.join("src/routes/subscription.rs"),
        "jwt_verifier()?.verify_access_token(token).await?;",
    );
    assert_file_not_contains(
        &project_dir.join("src/routes/subscription.rs"),
        "jwt_verifier.verify(token).await?;",
    );
}

#[test]
fn test_resource_profile_admin_inline_guard_rejects_refresh_tokens() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_resource_project_fixture(
        &project_dir,
        r#"
tideway = { version = "0.7", features = ["database", "auth", "admin"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
uuid = { version = "1", features = ["v4", "serde"] }
"#,
    );
    create_saas_resource_markers(&project_dir, false, true, false);

    let args = ResourceArgs {
        name: "admin_user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: false,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Admin,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    let route = project_dir.join("src/routes/admin_user.rs");
    assert_file_contains(&route, "jwt_verifier()?.verify_access_token(token).await?;");
    assert_file_not_contains(&route, "jwt_verifier.verify(token).await?;");
}

#[test]
fn test_resource_profile_event_generates_event_search_and_service_shape() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_resource_project_fixture(
        &project_dir,
        r#"
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#,
    );

    let args = ResourceArgs {
        name: "audit_event".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: false,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Event,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    assert_file_contains(
        &project_dir.join("src/entities/audit_event.rs"),
        "pub payload_json: String,",
    );
    assert_file_contains(
        &project_dir.join("src/repositories/audit_event.rs"),
        "audit_event::Column::EventType.contains(search)",
    );
    assert_file_contains(
        &project_dir.join("src/services/audit_event.rs"),
        "pub async fn create(&self, event_type: String, actor_id: String, subject_id: String, payload_json: String)",
    );
    assert_file_contains(
        &project_dir.join("src/services/audit_event.rs"),
        "Self::normalize_lowercase_required(\"event_type\", event_type)?",
    );
}

#[test]
fn test_resource_profile_owned_compiles_against_saas_preset_workspace_scaffold() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let new_args = NewArgs {
        name: Some("my_app".to_string()),
        preset: Some(NewPreset::Saas),
        features: Vec::new(),
        with_config: false,
        with_docker: false,
        with_ci: false,
        no_prompt: true,
        summary: false,
        with_env: false,
        without_invitations: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };
    tideway_cli::commands::new::run(new_args).expect("run tideway new");

    let resource_args = ResourceArgs {
        name: "subscription".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: false,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Owned,
    };
    tideway_cli::commands::resource::run(resource_args).expect("run tideway resource");

    assert!(project_dir.join("src/routes/mod.rs").exists());
    assert_file_contains(&project_dir.join("src/lib.rs"), "pub mod routes;");
    assert_file_not_contains(&project_dir.join("src/main.rs"), "mod routes;");
    assert_file_contains(
        &project_dir.join("src/main.rs"),
        ".register_module(my_app::routes::subscription::SubscriptionModule)",
    );

    patch_scaffold_to_workspace(&project_dir);
    run_cargo_in_project(&project_dir, &["check"]);
    assert_generated_policy_tests_pass(&project_dir);
}

#[test]
fn test_resource_api_and_tenant_profiles_compile_against_saas_preset_workspace_scaffold() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let new_args = NewArgs {
        name: Some("my_app".to_string()),
        preset: Some(NewPreset::Saas),
        features: Vec::new(),
        with_config: false,
        with_docker: false,
        with_ci: false,
        no_prompt: true,
        summary: false,
        with_env: false,
        without_invitations: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };
    tideway_cli::commands::new::run(new_args).expect("run tideway new");

    for (name, fields, profile) in [
        ("project", vec![], tideway_cli::cli::ResourceProfile::Api),
        (
            "workspace",
            vec![],
            tideway_cli::cli::ResourceProfile::Tenant,
        ),
        (
            "ticket",
            vec!["subject:string", "body:text", "priority:int", "closed:bool"],
            tideway_cli::cli::ResourceProfile::Api,
        ),
        (
            "board",
            vec!["title:string", "archived:bool"],
            tideway_cli::cli::ResourceProfile::Tenant,
        ),
    ] {
        let resource_args = ResourceArgs {
            name: name.to_string(),
            fields: fields.iter().map(|field| field.to_string()).collect(),
            path: project_dir.to_string_lossy().to_string(),
            wire: false,
            with_tests: false,
            db: false,
            repo: false,
            repo_tests: false,
            service: false,
            id_type: tideway_cli::cli::ResourceIdType::Int,
            add_uuid: false,
            paginate: false,
            search: false,
            db_backend: tideway_cli::cli::DbBackend::Auto,
            profile,
        };
        tideway_cli::commands::resource::run(resource_args).expect("run tideway resource");
        assert_file_contains(
            &project_dir.join(format!("src/routes/{name}.rs")),
            "RequestActor::for_current_organization(&headers, &db).await?;",
        );
    }

    patch_scaffold_to_workspace(&project_dir);
    run_cargo_in_project(&project_dir, &["check"]);
    assert_generated_policy_tests_pass(&project_dir);
}

#[test]
fn test_resource_command_adds_uuid_dependency() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src/routes")).expect("create routes");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let routes_mod = r#"
use axum::{routing::get, Router};
use tideway::{AppContext, MessageResponse, RouteModule};

pub struct ApiModule;

impl RouteModule for ApiModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/", get(root))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

async fn root() -> MessageResponse {
    MessageResponse::success("Tideway is running")
}
"#;
    fs::write(project_dir.join("src/routes/mod.rs"), routes_mod).expect("write routes mod");

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

    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: false,
        db: true,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Uuid,
        add_uuid: true,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    let updated = fs::read_to_string(project_dir.join("Cargo.toml")).expect("read Cargo.toml");
    assert!(updated.contains("uuid"));
}

#[test]
fn test_resource_command_uuid_requires_dependency() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src/routes")).expect("create routes");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let routes_mod = r#"
use axum::{routing::get, Router};
use tideway::{AppContext, MessageResponse, RouteModule};

pub struct ApiModule;

impl RouteModule for ApiModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/", get(root))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

async fn root() -> MessageResponse {
    MessageResponse::success("Tideway is running")
}
"#;
    fs::write(project_dir.join("src/routes/mod.rs"), routes_mod).expect("write routes mod");

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

    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: false,
        db: true,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Uuid,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    };

    let err = tideway_cli::commands::resource::run(args).expect_err("expected error");
    assert!(
        err.to_string().contains("Problem:") && err.to_string().contains("Advanced fix:"),
        "unexpected error: {}",
        err
    );
}

#[test]
fn test_resource_command_invalid_db_combo_does_not_write_files() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src/routes")).expect("create routes");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let routes_mod = r#"
use axum::{routing::get, Router};
use tideway::{AppContext, MessageResponse, RouteModule};

pub struct ApiModule;

impl RouteModule for ApiModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/", get(root))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

async fn root() -> MessageResponse {
    MessageResponse::success("Tideway is running")
}
"#;
    fs::write(project_dir.join("src/routes/mod.rs"), routes_mod).expect("write routes mod");

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

    let before_main =
        fs::read_to_string(project_dir.join("src/main.rs")).expect("read main before");

    let args = ResourceArgs {
        name: "user".to_string(),
        fields: Vec::new(),
        path: project_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: false,
        db: false,
        repo: true,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    };

    let err = tideway_cli::commands::resource::run(args).expect_err("expected error");
    assert!(
        err.to_string()
            .contains("Repository scaffolding requires --db.")
    );
    assert!(!project_dir.join("src/routes/user.rs").exists());
    assert_eq!(
        fs::read_to_string(project_dir.join("src/main.rs")).expect("read main after"),
        before_main,
    );
}

#[test]
fn test_resource_cli_parses_inline_field_definitions() {
    use clap::Parser;

    let cli = tideway_cli::cli::Cli::try_parse_from([
        "tideway",
        "resource",
        "post",
        "title:string",
        "body:text",
        "published:bool",
        "--db",
    ])
    .expect("parse resource command");

    let tideway_cli::cli::Commands::Resource(args) = cli.command else {
        panic!("expected resource command");
    };
    assert_eq!(args.name, "post");
    assert_eq!(args.fields, ["title:string", "body:text", "published:bool"]);
    assert!(args.db);
}

#[test]
fn test_resource_inline_fields_drive_entity_migration_dto_and_validation() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_resource_project_fixture(
        &project_dir,
        r#"
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#,
    );

    let args = ResourceArgs {
        name: "post".to_string(),
        fields: [
            "title:string",
            "body:text",
            "published:bool",
            "views:int",
            "published_at:datetime",
        ]
        .map(String::from)
        .to_vec(),
        path: project_dir.to_string_lossy().to_string(),
        wire: false,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Api,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    let entity = fs::read_to_string(project_dir.join("src/entities/post.rs")).expect("entity");
    for line in [
        "pub title: String,",
        "pub body: String,",
        "pub published: bool,",
        "pub views: i32,",
        "pub published_at: i64,",
    ] {
        assert!(entity.contains(line), "entity missing `{line}`:\n{entity}");
    }
    assert!(
        !entity.contains("pub name: String"),
        "default field leaked:\n{entity}"
    );

    let migration = read_single_migration(&project_dir, "create_posts");
    for column in [
        "ColumnDef::new(Posts::Title).string().not_null()",
        "ColumnDef::new(Posts::Body).text().not_null()",
        "ColumnDef::new(Posts::Published).boolean().not_null()",
        "ColumnDef::new(Posts::Views).integer().not_null()",
        "ColumnDef::new(Posts::PublishedAt).big_integer().not_null()",
    ] {
        assert!(
            migration.contains(column),
            "migration missing `{column}`:\n{migration}"
        );
    }
    assert!(
        !migration.contains("Posts::Name"),
        "default column leaked:\n{migration}"
    );

    let routes = fs::read_to_string(project_dir.join("src/routes/post.rs")).expect("routes");
    for line in [
        "pub title: String,",
        "pub body: String,",
        "pub published: bool,",
        "pub views: i32,",
        "pub published_at: i64,",
        "pub title: Option<String>,",
        "pub published: Option<bool>,",
        "pub views: Option<i32>,",
    ] {
        assert!(routes.contains(line), "routes missing `{line}`:\n{routes}");
    }

    let service = fs::read_to_string(project_dir.join("src/services/post.rs")).expect("service");
    assert!(service.contains("Self::normalize_required_string(\"title\", title)?"));
    assert!(service.contains("Self::normalize_required_string(\"body\", body)?"));
    assert!(service.contains("Self::normalize_optional_string(\"title\", title)?"));
    assert!(!service.contains("\"published\", published"));

    assert_file_contains(
        &project_dir.join("src/repositories/post.rs"),
        "post::Column::Title.contains(search)",
    );
}

#[test]
fn test_resource_inline_fields_keep_profile_structural_fields() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_resource_project_fixture(
        &project_dir,
        r#"
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#,
    );

    let args = ResourceArgs {
        name: "task".to_string(),
        fields: vec!["title:string".to_string(), "done:bool".to_string()],
        path: project_dir.to_string_lossy().to_string(),
        wire: false,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Owned,
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    let entity = fs::read_to_string(project_dir.join("src/entities/task.rs")).expect("entity");
    let ordered = [
        "pub organization_id: String,",
        "pub owner_id: String,",
        "pub title: String,",
        "pub done: bool,",
        "pub created_at: i64,",
        "pub updated_at: i64,",
    ];
    let positions: Vec<usize> = ordered
        .iter()
        .map(|line| {
            entity
                .find(line)
                .unwrap_or_else(|| panic!("missing `{line}`:\n{entity}"))
        })
        .collect();
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "{entity}"
    );
    assert!(!entity.contains("pub name: String"));
    assert!(!entity.contains("pub status: String"));
}

#[test]
fn test_resource_invalid_inline_fields_fail_before_writing() {
    for (fields, expected) in [
        (vec!["title"], "expected `name:type`"),
        (vec!["title:uuid4"], "unknown type `uuid4`"),
        (vec!["Title:string"], "snake_case"),
        (vec!["type:string"], "Rust keyword"),
        (vec!["id:int"], "reserved"),
        (vec!["title:string", "title:text"], "more than once"),
    ] {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let project_dir = temp_dir.path().join("my_app");
        create_resource_project_fixture(
            &project_dir,
            r#"
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#,
        );

        let error = tideway_cli::commands::resource::run(ResourceArgs {
            name: "post".to_string(),
            fields: fields.iter().map(|field| field.to_string()).collect(),
            path: project_dir.to_string_lossy().to_string(),
            wire: false,
            with_tests: false,
            db: false,
            repo: false,
            repo_tests: false,
            service: false,
            id_type: tideway_cli::cli::ResourceIdType::Int,
            add_uuid: false,
            paginate: false,
            search: false,
            db_backend: tideway_cli::cli::DbBackend::Auto,
            profile: tideway_cli::cli::ResourceProfile::Api,
        })
        .expect_err("invalid field definitions should fail");

        assert!(
            error.to_string().contains(expected),
            "{fields:?}: expected `{expected}` in {error}"
        );
        assert!(!project_dir.join("src/routes/post.rs").exists());
        assert!(!project_dir.join("src/entities").exists());
    }

    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_resource_project_fixture(
        &project_dir,
        r#"
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#,
    );
    let error = tideway_cli::commands::resource::run(ResourceArgs {
        name: "task".to_string(),
        fields: vec!["created_at:datetime".to_string()],
        path: project_dir.to_string_lossy().to_string(),
        wire: false,
        with_tests: false,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Tenant,
    })
    .expect_err("duplicate structural field should fail");
    assert!(
        error
            .to_string()
            .contains("already generated by the `tenant` profile")
    );
    assert!(!project_dir.join("src/routes/task.rs").exists());
}

#[test]
fn test_resource_inline_fields_compile_against_api_preset_scaffold() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let new_args = NewArgs {
        name: Some("my_app".to_string()),
        preset: Some(NewPreset::Api),
        features: Vec::new(),
        with_config: false,
        with_docker: false,
        with_ci: false,
        no_prompt: true,
        summary: false,
        with_env: false,
        without_invitations: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };
    tideway_cli::commands::new::run(new_args).expect("run tideway new");

    for (name, fields, profile) in [
        (
            "post",
            vec![
                "title:string",
                "body:text",
                "published:bool",
                "views:int",
                "word_count:bigint",
                "published_at:datetime",
            ],
            tideway_cli::cli::ResourceProfile::Api,
        ),
        (
            "counter",
            vec!["hits:int", "enabled:bool"],
            tideway_cli::cli::ResourceProfile::Api,
        ),
        (
            "note",
            vec!["title:string", "pinned:bool"],
            tideway_cli::cli::ResourceProfile::Stub,
        ),
        (
            "tally",
            vec!["count:int"],
            tideway_cli::cli::ResourceProfile::Stub,
        ),
    ] {
        let resource_args = ResourceArgs {
            name: name.to_string(),
            fields: fields.iter().map(|field| field.to_string()).collect(),
            path: project_dir.to_string_lossy().to_string(),
            wire: matches!(profile, tideway_cli::cli::ResourceProfile::Stub),
            with_tests: true,
            db: false,
            repo: false,
            repo_tests: false,
            service: false,
            id_type: tideway_cli::cli::ResourceIdType::Int,
            add_uuid: false,
            paginate: false,
            search: false,
            db_backend: tideway_cli::cli::DbBackend::Auto,
            profile,
        };
        tideway_cli::commands::resource::run(resource_args).expect("run tideway resource");
    }

    patch_scaffold_to_workspace(&project_dir);
    run_cargo_in_project(&project_dir, &["check", "--all-targets"]);
}

fn read_single_migration(project_dir: &Path, suffix: &str) -> String {
    let migration_dir = project_dir.join("migration/src");
    let path = fs::read_dir(&migration_dir)
        .expect("read migration dir")
        .map(|entry| entry.expect("migration entry").path())
        .find(|path| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .is_some_and(|stem| stem.ends_with(suffix))
        })
        .unwrap_or_else(|| panic!("no migration ending in {suffix}"));
    fs::read_to_string(path).expect("read migration")
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

fn create_resource_project_fixture(project_dir: &Path, dependency_lines: &str) {
    fs::create_dir_all(project_dir.join("src/routes")).expect("create routes");
    fs::write(
        project_dir.join("Cargo.toml"),
        format!(
            r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
{}
"#,
            dependency_lines.trim()
        ),
    )
    .expect("write Cargo.toml");

    fs::write(
        project_dir.join("src/routes/mod.rs"),
        r#"
use axum::{routing::get, Router};
use tideway::{AppContext, MessageResponse, RouteModule};

pub struct ApiModule;

impl RouteModule for ApiModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/", get(root))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

async fn root() -> MessageResponse {
    MessageResponse::success("Tideway is running")
}
"#,
    )
    .expect("write routes mod");

    fs::write(
        project_dir.join("src/main.rs"),
        r#"
use tideway::App;

mod routes;

#[tokio::main]
async fn main() {
    let app = App::new()
        .register_module(routes::ApiModule);

    let _ = app;
}
"#,
    )
    .expect("write main.rs");
}

fn create_saas_resource_markers(
    project_dir: &Path,
    with_organizations: bool,
    with_admin: bool,
    with_shared_actor: bool,
) {
    fs::create_dir_all(project_dir.join("src/auth")).expect("create auth dir");
    fs::create_dir_all(project_dir.join("src/entities")).expect("create entities dir");
    let auth_mod = if with_shared_actor {
        "//! auth\n\npub use actor::RequestActor;\nmod actor;\n"
    } else {
        "//! auth\n"
    };
    fs::write(project_dir.join("src/auth/mod.rs"), auth_mod).expect("write auth mod");
    fs::write(project_dir.join("src/entities/user.rs"), "//! user\n").expect("write user entity");

    if with_organizations {
        fs::write(
            project_dir.join("src/entities/organization_member.rs"),
            "//! membership\n",
        )
        .expect("write organization member entity");
    }

    if with_admin {
        fs::create_dir_all(project_dir.join("src/admin")).expect("create admin dir");
        fs::write(project_dir.join("src/admin/mod.rs"), "//! admin\n").expect("write admin mod");
    }

    if with_shared_actor {
        fs::write(project_dir.join("src/auth/actor.rs"), "//! actor\n")
            .expect("write actor module");
    }
}

fn patch_scaffold_to_workspace(project_dir: &Path) {
    let cargo_path = project_dir.join("Cargo.toml");
    let mut contents = fs::read_to_string(&cargo_path).expect("read Cargo.toml");
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");
    let macros_root = workspace_root.join("tideway-macros");

    contents.push_str(&format!(
        "\n[patch.crates-io]\ntideway = {{ path = \"{}\" }}\ntideway-macros = {{ path = \"{}\" }}\n",
        escape_toml_path(workspace_root),
        escape_toml_path(&macros_root),
    ));

    fs::write(cargo_path, contents).expect("write Cargo.toml patch section");
}

fn run_cargo_in_project(project_dir: &Path, args: &[&str]) -> String {
    let mut command = Command::new("cargo");
    command
        .args(args)
        .current_dir(project_dir)
        .env("CARGO_TARGET_DIR", scaffold_target_dir(false));
    let output = output_serialized(&mut command, "run cargo");

    if !output.status.success() {
        panic!(
            "cargo {} failed.\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Serialises nested cargo builds within this test binary so parallel test
/// threads don't each spawn a full-core build at once.
static CARGO_LOCK: Mutex<()> = Mutex::new(());

/// Shared target dir for scaffold builds. Scaffolds are patched to the
/// workspace sources, so dependency artifacts are reused across tests and runs.
/// `-Dwarnings` builds get a sibling dir so the RUSTFLAGS change doesn't
/// invalidate the shared artifacts.
fn scaffold_target_dir(deny_warnings: bool) -> PathBuf {
    let name = if deny_warnings {
        "scaffold-tests-deny-warnings"
    } else {
        "scaffold-tests"
    };
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("target")
        .join(name)
}

fn output_serialized(command: &mut Command, context: &str) -> Output {
    let _guard = CARGO_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    command.output().expect(context)
}

/// Runs the generated policy unit tests against the real entity models.
fn assert_generated_policy_tests_pass(project_dir: &Path) {
    let stdout = run_cargo_in_project(project_dir, &["test", "--lib", "policies::"]);
    assert!(
        stdout.contains("policies::") && !stdout.contains(" 0 passed"),
        "expected generated policy tests to run:\n{stdout}"
    );
}

fn escape_toml_path(path: &Path) -> String {
    path_to_string(path).replace('\\', "\\\\")
}

fn path_to_string(path: &Path) -> String {
    PathBuf::from(path).to_string_lossy().into_owned()
}
