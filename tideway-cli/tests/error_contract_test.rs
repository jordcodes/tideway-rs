use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn test_new_missing_name_uses_error_contract() {
    let output = run_tideway(&["new", "--no-prompt"]);
    assert_failure(&output, "tideway new --no-prompt");
    assert_error_contract(&output);
}

#[test]
fn test_add_missing_cargo_uses_error_contract() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let output = run_tideway(&[
        "add",
        "auth",
        "--path",
        temp_dir.path().to_str().expect("utf8 path"),
    ]);
    assert_failure(&output, "tideway add auth");
    assert_error_contract(&output);
}

#[test]
fn test_resource_missing_src_uses_error_contract() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let output = run_tideway(&[
        "resource",
        "user",
        "--path",
        temp_dir.path().to_str().expect("utf8 path"),
    ]);
    assert_failure(&output, "tideway resource user");
    assert_error_contract(&output);
}

#[test]
fn test_resource_repo_without_db_uses_error_contract() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_basic_project(&project_dir);

    let output = run_tideway(&[
        "resource",
        "user",
        "--path",
        project_dir.to_str().expect("utf8 path"),
        "--repo",
    ]);
    assert_failure(&output, "tideway resource user --repo");
    assert_error_contract(&output);
}

#[test]
fn test_migrate_missing_database_url_uses_error_contract() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_basic_project(&project_dir);
    fs::create_dir_all(project_dir.join("migration/src")).expect("create migration/src");
    fs::write(
        project_dir.join("migration/src/lib.rs"),
        "// migration lib placeholder\n",
    )
    .expect("write migration lib");
    fs::write(
        project_dir.join("Cargo.toml"),
        r#"[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#,
    )
    .expect("write Cargo.toml");

    let output = run_tideway(&[
        "migrate",
        "status",
        "--path",
        project_dir.to_str().expect("utf8 path"),
    ]);
    assert_failure(&output, "tideway migrate status");
    assert_error_contract(&output);
}

#[test]
fn test_dev_unreachable_postgres_uses_error_contract() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_basic_project(&project_dir);
    fs::write(
        project_dir.join("Cargo.toml"),
        r#"[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#,
    )
    .expect("write Cargo.toml");
    fs::write(
        project_dir.join(".env"),
        "DATABASE_URL=postgres://postgres:postgres@127.0.0.1:1/my_app\n",
    )
    .expect("write .env");

    let output = run_tideway(&["dev", "--path", project_dir.to_str().expect("utf8 path")]);
    assert_failure(&output, "tideway dev");
    assert_error_contract(&output);
}

#[test]
fn test_json_mode_emits_structured_error_fields() {
    let output = run_tideway(&["--json", "new", "--no-prompt"]);
    assert_failure(&output, "tideway --json new --no-prompt");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"level\":\"error\""),
        "expected error level json, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("\"problem\":"),
        "expected `problem` field, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("\"primary_fix\":"),
        "expected `primary_fix` field, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("\"advanced_fix\":"),
        "expected `advanced_fix` field, got:\n{}",
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

fn assert_failure(output: &std::process::Output, label: &str) {
    assert!(
        !output.status.success(),
        "{} unexpectedly succeeded.\nstdout:\n{}\nstderr:\n{}",
        label,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_error_contract(output: &std::process::Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout, stderr);
    assert!(
        combined.contains("Problem:"),
        "expected `Problem:` in output, got:\n{}",
        combined
    );
    assert!(
        combined.contains("Primary fix:"),
        "expected `Primary fix:` in output, got:\n{}",
        combined
    );
    assert!(
        combined.contains("Advanced fix:"),
        "expected `Advanced fix:` in output, got:\n{}",
        combined
    );
}

fn create_basic_project(project_dir: &Path) {
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
    fs::write(project_dir.join("src/main.rs"), "fn main() {}\n").expect("write main.rs");
    fs::write(
        project_dir.join("src/routes/mod.rs"),
        "pub struct ApiModule;\n",
    )
    .expect("write routes mod");
}
