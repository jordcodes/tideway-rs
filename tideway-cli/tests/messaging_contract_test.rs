use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn test_dev_plan_mentions_primary_command() {
    let output = run_tideway(&["--plan", "dev", "--path", "/tmp/nonexistent"]);
    assert_success(&output, "tideway dev --plan");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Plan: run command `cargo run` (cwd: /tmp/nonexistent)"),
        "expected explicit cargo run plan, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("Primary run command for local development."),
        "expected primary dev marker, got:\n{}",
        stdout
    );
}

#[test]
fn test_migrate_plan_mentions_backend_command() {
    let output = run_tideway(&[
        "--plan",
        "migrate",
        "status",
        "--backend",
        "sea-orm",
        "--path",
        "/tmp/nonexistent",
    ]);
    assert_success(&output, "tideway migrate --plan");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Plan: would run migrations (status)"),
        "expected migrate plan summary, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("Plan: run command `sea-orm-cli migrate status` (cwd: /tmp/nonexistent)"),
        "expected explicit sea-orm-cli plan, got:\n{}",
        stdout
    );
}

#[test]
fn test_root_help_mentions_primary_path_trailer() {
    let output = run_tideway(&["--help"]);
    assert_success(&output, "tideway --help");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Scaffold Tideway API apps and advanced helpers"),
        "expected narrowed root help summary, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("Primary path (recommended): tideway new <app>"),
        "expected canonical path trailer in root help, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("Advanced commands are for existing projects or nonstandard workflows."),
        "expected advanced-command note in root help, got:\n{}",
        stdout
    );
}

#[test]
fn test_generate_help_marks_vue_only_advanced_path() {
    let output = run_tideway(&["generate", "--help"]);
    assert_success(&output, "tideway generate --help");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Advanced: generate Vue frontend helpers for existing Vue apps"),
        "expected Vue-only advanced generate marker, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("current helpers are Vue-only"),
        "expected Vue-only framework note, got:\n{}",
        stdout
    );
}

#[test]
fn test_setup_help_marks_vue_only_advanced_path() {
    let output = run_tideway(&["setup", "--help"]);
    assert_success(&output, "tideway setup --help");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Advanced: set up Vue frontend dependencies for existing Vue apps"),
        "expected Vue-only advanced setup marker, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("current helper path is Vue-only"),
        "expected Vue-only setup note, got:\n{}",
        stdout
    );
}

#[test]
fn test_new_mentions_primary_path() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let output = run_tideway(&[
        "new",
        "my_app",
        "--no-prompt",
        "--path",
        project_dir.to_str().expect("utf8 path"),
    ]);
    assert_success(&output, "tideway new");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Primary path: tideway new <app>"),
        "expected primary path reminder, got:\n{}",
        stdout
    );
}

#[test]
fn test_new_keeps_dev_as_primary_next_step_and_doctor_optional() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let output = run_tideway(&[
        "new",
        "my_app",
        "--no-prompt",
        "--path",
        project_dir.to_str().expect("utf8 path"),
    ]);
    assert_success(&output, "tideway new");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("2. tideway dev"),
        "expected dev to stay in numbered next steps, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("Optional: run `tideway doctor`"),
        "expected optional doctor note, got:\n{}",
        stdout
    );
    assert!(
        !stdout.contains("2. tideway doctor --fix"),
        "doctor should not be shown as a required numbered next step, got:\n{}",
        stdout
    );
}

#[test]
fn test_resource_mentions_primary_path_reminder() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_minimal_resource_project(&project_dir);

    let output = run_tideway(&[
        "resource",
        "user",
        "--path",
        project_dir.to_str().expect("utf8 path"),
        "--wire",
    ]);
    assert_success(&output, "tideway resource");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Primary path reminder"),
        "expected primary resource reminder, got:\n{}",
        stdout
    );
}

#[test]
fn test_doctor_mentions_primary_path_reminder() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_minimal_project(&project_dir);

    let output = run_tideway(&["doctor", "--path", project_dir.to_str().expect("utf8 path")]);
    assert_success(&output, "tideway doctor");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Primary path reminder"),
        "expected primary doctor reminder, got:\n{}",
        stdout
    );
}

#[test]
fn test_init_no_modules_mentions_advanced_fix() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    fs::create_dir_all(project_dir.join("src")).expect("create src");
    fs::write(
        project_dir.join("Cargo.toml"),
        r#"[package]
name = "my_app"
version = "0.1.0"
edition = "2021"
"#,
    )
    .expect("write Cargo.toml");

    let output = Command::new(env!("CARGO_BIN_EXE_tideway"))
        .arg("init")
        .arg("--src")
        .arg(project_dir.join("src"))
        .current_dir(&project_dir)
        .output()
        .expect("run tideway init");
    assert_success(&output, "tideway init");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Advanced fix: run `tideway backend`"),
        "expected advanced init fix marker, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("For greenfield apps, use the primary path"),
        "expected greenfield guidance marker, got:\n{}",
        stdout
    );
}

#[test]
fn test_backend_skip_overwrite_mentions_advanced() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let src_dir = temp_dir.path().join("src");
    let migration_dir = temp_dir.path().join("migration/src");
    fs::create_dir_all(&src_dir).expect("create src");
    fs::create_dir_all(&migration_dir).expect("create migration/src");
    fs::write(src_dir.join("main.rs"), "fn main() {}\n").expect("write main.rs");

    let output = run_tideway(&[
        "backend",
        "b2c",
        "--name",
        "my_app",
        "--output",
        src_dir.to_str().expect("utf8 src"),
        "--migrations-output",
        migration_dir.to_str().expect("utf8 migration"),
    ]);
    assert_success(&output, "tideway backend b2c");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("`tideway backend` is an advanced command"),
        "expected advanced backend marker, got:\n{}",
        stdout
    );
}

fn run_tideway(args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tideway"));
    for arg in args {
        command.arg(arg);
    }
    command.output().expect("run tideway")
}

fn assert_success(output: &std::process::Output, label: &str) {
    assert!(
        output.status.success(),
        "{} failed.\nstdout:\n{}\nstderr:\n{}",
        label,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn create_minimal_project(project_dir: &Path) {
    fs::create_dir_all(project_dir.join("src")).expect("create src");
    fs::write(
        project_dir.join("Cargo.toml"),
        r#"[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#,
    )
    .expect("write Cargo.toml");
    fs::write(project_dir.join("src/main.rs"), "fn main() {}\n").expect("write src/main.rs");
}

fn create_minimal_resource_project(project_dir: &Path) {
    fs::create_dir_all(project_dir.join("src/routes")).expect("create routes");
    fs::write(
        project_dir.join("Cargo.toml"),
        r#"[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#,
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
