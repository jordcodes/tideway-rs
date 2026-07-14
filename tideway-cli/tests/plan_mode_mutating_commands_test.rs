use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn test_add_auth_wire_plan_mode_is_non_mutating() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_minimal_fixture(&project_dir);

    let tracked_files = vec![
        project_dir.join("Cargo.toml"),
        project_dir.join("src/main.rs"),
    ];
    let before = snapshot_files(&tracked_files);

    let output = Command::new(env!("CARGO_BIN_EXE_tideway"))
        .arg("--plan")
        .arg("add")
        .arg("auth")
        .arg("--wire")
        .arg("--path")
        .arg(&project_dir)
        .output()
        .expect("run tideway add --plan");

    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let after = snapshot_files(&tracked_files);
    assert_eq!(before, after, "expected add --plan to be non-mutating");

    assert!(!project_dir.join("src/auth").exists());
    assert!(!project_dir.join(".env.example").exists());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Plan: write file"),
        "expected plan output with file writes, got:\n{}",
        stdout
    );
}

#[test]
fn test_resource_wire_plan_mode_is_non_mutating() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_minimal_fixture(&project_dir);
    fs::create_dir_all(project_dir.join("src/routes")).expect("create routes dir");
    fs::write(
        project_dir.join("src/routes/mod.rs"),
        "use axum::Router;\n\npub fn router() -> Router { Router::new() }\n",
    )
    .expect("write routes mod");

    let tracked_files = vec![
        project_dir.join("Cargo.toml"),
        project_dir.join("src/main.rs"),
        project_dir.join("src/routes/mod.rs"),
    ];
    let before = snapshot_files(&tracked_files);

    let output = Command::new(env!("CARGO_BIN_EXE_tideway"))
        .arg("--plan")
        .arg("resource")
        .arg("todo")
        .arg("--wire")
        .arg("--path")
        .arg(&project_dir)
        .output()
        .expect("run tideway resource --plan");

    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let after = snapshot_files(&tracked_files);
    assert_eq!(before, after, "expected resource --plan to be non-mutating");

    assert!(!project_dir.join("src/routes/todo.rs").exists());
    assert!(!project_dir.join("src/repositories").exists());
    assert!(!project_dir.join("src/services").exists());
    assert!(!project_dir.join("migration").exists());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Plan: write file"),
        "expected plan output with file writes, got:\n{}",
        stdout
    );
}

#[test]
fn test_backend_plan_mode_is_non_mutating() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let output_dir = temp_dir.path().join("src");
    let migrations_dir = temp_dir.path().join("migration/src");

    let output = Command::new(env!("CARGO_BIN_EXE_tideway"))
        .arg("--plan")
        .arg("backend")
        .arg("b2c")
        .arg("--name")
        .arg("my_app")
        .arg("--output")
        .arg(&output_dir)
        .arg("--migrations-output")
        .arg(&migrations_dir)
        .output()
        .expect("run tideway backend --plan");

    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !output_dir.exists(),
        "expected backend --plan not to create output directory"
    );
    assert!(
        !migrations_dir.exists(),
        "expected backend --plan not to create migration directory"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Plan: write file"),
        "expected plan output with file writes, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("Plan complete: no files were written"),
        "expected explicit plan completion marker, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("m008_create_billing_plans.rs"),
        "expected plan output to include m008 migration, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("m009_create_webhook_processed_events.rs"),
        "expected plan output to include m009 migration, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("m010_create_billing_processed_events.rs"),
        "expected plan output to include m010 migration, got:\n{}",
        stdout
    );
}

#[test]
fn test_init_minimal_plan_mode_is_non_mutating() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let src_dir = temp_dir.path().join("src");

    let output = Command::new(env!("CARGO_BIN_EXE_tideway"))
        .arg("--plan")
        .arg("init")
        .arg("--minimal")
        .arg("--name")
        .arg("my_app")
        .arg("--src")
        .arg(&src_dir)
        .output()
        .expect("run tideway init --plan");

    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !src_dir.exists(),
        "expected init --plan not to create the source directory"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Plan: write file"),
        "expected plan output with file writes, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("Plan complete: no files were written"),
        "expected explicit plan completion marker, got:\n{}",
        stdout
    );
    assert!(
        !stdout.contains("Generated main.rs"),
        "expected init --plan not to claim files were generated, got:\n{}",
        stdout
    );
}

#[test]
fn test_new_api_plan_mode_is_non_mutating() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let output = Command::new(env!("CARGO_BIN_EXE_tideway"))
        .arg("--plan")
        .arg("new")
        .arg("my_app")
        .arg("--preset")
        .arg("api")
        .arg("--no-prompt")
        .arg("--path")
        .arg(&project_dir)
        .output()
        .expect("run tideway new --plan");

    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !project_dir.exists(),
        "expected new --plan not to create the project directory"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Plan: write file"),
        "expected plan output with file writes, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("src/routes/todo.rs"),
        "expected API preset resource route in plan output, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("migration/src/m004_create_todos.rs"),
        "expected API preset migration in plan output, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("Plan complete: no files were written"),
        "expected explicit plan completion marker, got:\n{}",
        stdout
    );
    assert!(
        !stdout.contains("starter app created"),
        "expected new --plan not to claim the starter app was created, got:\n{}",
        stdout
    );

    let root_dir_line = format!("→ Plan: create directory {}", project_dir.display());
    let root_dir_count = stdout.lines().filter(|line| *line == root_dir_line).count();
    assert_eq!(
        root_dir_count, 1,
        "expected root directory to be planned once, got:\n{}",
        stdout
    );
}

fn create_minimal_fixture(project_dir: &Path) {
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
    fs::write(
        project_dir.join("src/main.rs"),
        r#"use tideway::App;

mod routes;

#[tokio::main]
async fn main() {
    let app = App::new()
        .register_module(routes::ApiModule);

    let _ = app;
}
"#,
    )
    .expect("write src/main.rs");
}

fn snapshot_files(files: &[PathBuf]) -> BTreeMap<PathBuf, String> {
    files
        .iter()
        .map(|path| {
            let content = fs::read_to_string(path).expect("read tracked file");
            (path.clone(), content)
        })
        .collect()
}
