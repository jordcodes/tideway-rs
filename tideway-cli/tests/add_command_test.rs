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
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    assert_file_contains(
        &project_dir.join("Cargo.toml"),
        "\"auth\"",
    );
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
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    assert_file_contains(
        &project_dir.join("Cargo.toml"),
        "\"database\"",
    );
    assert_file_contains(
        &project_dir.join("Cargo.toml"),
        "sea-orm",
    );
    assert_file_contains(
        &project_dir.join(".env.example"),
        "DATABASE_URL=",
    );
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
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated.contains("mod auth;"));
    assert!(updated.contains("AuthModule"));
    assert!(updated.contains("SimpleAuthProvider"));
    assert!(updated.contains("register_module(auth_module)"));
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
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated.contains("DATABASE_URL"));
    assert!(updated.contains("SeaOrmPool"));
    assert!(updated.contains("with_database"));
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
    };

    tideway_cli::commands::add::run(args).expect("run add command");

    let updated = fs::read_to_string(project_dir.join("src/main.rs")).expect("read main.rs");
    assert!(updated.contains("create_openapi_router"));
    assert!(updated.contains("openapi_merge_module"));
    assert!(project_dir.join("src/openapi_docs.rs").exists());
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
