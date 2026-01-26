use std::fs;
use std::path::Path;

use tideway_cli::cli::NewArgs;

#[test]
fn test_new_command_generates_starter_files() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let args = NewArgs {
        name: "my_app".to_string(),
        features: Vec::new(),
        with_config: false,
        with_docker: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };

    tideway_cli::commands::new::run(args).expect("run new command");

    assert_file_contains(&project_dir.join("Cargo.toml"), "name = \"my_app\"");
    assert_file_contains(&project_dir.join("src/main.rs"), "App::new()");
    assert_file_contains(&project_dir.join("src/routes/mod.rs"), "Tideway is running");
    assert!(project_dir.join(".gitignore").exists());
    assert!(project_dir.join("tests/health.rs").exists());
}

#[test]
fn test_new_command_includes_features_and_env() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let args = NewArgs {
        name: "my_app".to_string(),
        features: vec!["auth".to_string(), "database".to_string()],
        with_config: false,
        with_docker: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };

    tideway_cli::commands::new::run(args).expect("run new command");

    assert_file_contains(
        &project_dir.join("Cargo.toml"),
        "features = [\"auth\", \"database\"]",
    );
    assert_file_contains(&project_dir.join("Cargo.toml"), "sea-orm");
    assert_file_contains(&project_dir.join(".env.example"), "DATABASE_URL=");
    assert_file_contains(&project_dir.join(".env.example"), "JWT_SECRET=");
    assert_file_contains(&project_dir.join("src/main.rs"), "DATABASE_URL");
    assert_file_contains(&project_dir.join("src/main.rs"), "JwtIssuer");
}

#[test]
fn test_new_command_compiles_with_features_smoke() {
    if std::env::var("TIDEWAY_CLI_SMOKE").is_err() {
        return;
    }

    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let args = NewArgs {
        name: "my_app".to_string(),
        features: vec!["auth".to_string(), "database".to_string()],
        with_config: false,
        with_docker: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };

    tideway_cli::commands::new::run(args).expect("run new command");

    let output = std::process::Command::new("cargo")
        .arg("check")
        .current_dir(&project_dir)
        .output()
        .expect("run cargo check");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("cargo check failed: {}", stderr);
    }
}

#[test]
fn test_new_command_with_config() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let args = NewArgs {
        name: "my_app".to_string(),
        features: Vec::new(),
        with_config: true,
        with_docker: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };

    tideway_cli::commands::new::run(args).expect("run new command");

    assert!(project_dir.join("src/config.rs").exists());
    assert!(project_dir.join("src/error.rs").exists());
    assert!(project_dir.join(".env.example").exists());
}

#[test]
fn test_new_command_with_docker() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let args = NewArgs {
        name: "my_app".to_string(),
        features: vec!["database".to_string()],
        with_config: false,
        with_docker: true,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };

    tideway_cli::commands::new::run(args).expect("run new command");

    assert!(project_dir.join("docker-compose.yml").exists());
}

fn assert_file_contains(path: &Path, needle: &str) {
    let contents = fs::read_to_string(path).expect("read file");
    assert!(
        contents.contains(needle),
        "expected {} to contain {}",
        path.display(),
        needle
    );
}
