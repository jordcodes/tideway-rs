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
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };

    tideway_cli::commands::new::run(args).expect("run new command");

    assert_file_contains(
        &project_dir.join("Cargo.toml"),
        "features = [\"auth\", \"database\"]",
    );
    assert_file_contains(&project_dir.join(".env.example"), "DATABASE_URL=");
    assert_file_contains(&project_dir.join(".env.example"), "JWT_SECRET=");
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
