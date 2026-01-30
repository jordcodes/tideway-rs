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
    };

    tideway_cli::commands::resource::run(args).expect("run resource command");

    let docs_path = project_dir.join("src/openapi_docs.rs");
    assert!(docs_path.exists());
    assert_file_contains(
        &docs_path,
        "crate::routes::user::list_users",
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
