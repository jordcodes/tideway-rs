use std::fs;
use std::path::Path;

use tideway_cli::cli::ResourceArgs;

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
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    let docs_path = project_dir.join("src/openapi_docs.rs");
    assert!(docs_path.exists());
    assert_file_contains(&docs_path, "crate::routes::user::list_users");
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
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    assert!(project_dir.join("src/services/user.rs").exists());
    assert_file_contains(&project_dir.join("src/services/mod.rs"), "pub mod user;");
    assert_file_contains(&project_dir.join("src/routes/user.rs"), "Service");
    let updated_main = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated_main.contains("mod services;"));
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
    };

    let err = tideway_cli::commands::resource::run(args).expect_err("expected error");
    assert!(
        err.to_string().contains("uuid dependency"),
        "unexpected error: {}",
        err
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
