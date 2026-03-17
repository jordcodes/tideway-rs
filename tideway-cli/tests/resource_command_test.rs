use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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
        "let organization_id = actor.organization_id()?;",
    );
    assert_file_contains(
        &project_dir.join("src/services/subscription.rs"),
        "self.create_owned(organization_id, &owner_id, name, status).await",
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
        "actor.require_admin()?;",
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
        "async fn resolve_owned_actor(headers: &HeaderMap, db: &DatabaseConnection) -> Result<OwnedActor>",
    );
    assert_file_contains(
        &project_dir.join("src/routes/subscription.rs"),
        "Multiple organizations found; send x-organization-id",
    );
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
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };
    tideway_cli::commands::new::run(new_args).expect("run tideway new");

    let resource_args = ResourceArgs {
        name: "subscription".to_string(),
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
    assert_file_contains(&project_dir.join("src/main.rs"), "mod routes;");

    patch_scaffold_to_workspace(&project_dir);
    run_cargo_in_project(temp_dir.path(), &project_dir, &["check"]);
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

fn run_cargo_in_project(temp_root: &Path, project_dir: &Path, args: &[&str]) {
    let output = Command::new("cargo")
        .args(args)
        .current_dir(project_dir)
        .env("CARGO_TARGET_DIR", temp_root.join("cargo-target"))
        .output()
        .expect("run cargo");

    if !output.status.success() {
        panic!(
            "cargo {} failed.\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn escape_toml_path(path: &Path) -> String {
    path_to_string(path).replace('\\', "\\\\")
}

fn path_to_string(path: &Path) -> String {
    PathBuf::from(path).to_string_lossy().into_owned()
}
