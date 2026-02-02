use std::fs;
use std::path::Path;
use tideway_cli::cli::{NewArgs, NewPreset};

#[test]
fn test_new_command_generates_starter_files() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let args = NewArgs {
        name: Some("my_app".to_string()),
        preset: None,
        features: Vec::new(),
        with_config: false,
        with_docker: false,
        with_ci: false,
        no_prompt: true,
        summary: true,
        with_env: false,
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
        name: Some("my_app".to_string()),
        preset: None,
        features: vec!["auth".to_string(), "database".to_string()],
        with_config: false,
        with_docker: false,
        with_ci: false,
        no_prompt: true,
        summary: true,
        with_env: false,
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
    assert!(project_dir.join("src/auth/mod.rs").exists());
    assert!(project_dir.join("src/auth/routes.rs").exists());
    assert!(project_dir.join("src/auth/provider.rs").exists());
}

#[test]
fn test_new_command_compiles_with_features_smoke() {
    if std::env::var("TIDEWAY_CLI_SMOKE").is_err() {
        return;
    }

    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let args = NewArgs {
        name: Some("my_app".to_string()),
        preset: None,
        features: vec!["auth".to_string(), "database".to_string()],
        with_config: false,
        with_docker: false,
        with_ci: false,
        no_prompt: true,
        summary: true,
        with_env: false,
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
        name: Some("my_app".to_string()),
        preset: None,
        features: Vec::new(),
        with_config: true,
        with_docker: false,
        with_ci: false,
        no_prompt: true,
        summary: true,
        with_env: false,
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
        name: Some("my_app".to_string()),
        preset: None,
        features: vec!["database".to_string()],
        with_config: false,
        with_docker: true,
        with_ci: false,
        no_prompt: true,
        summary: true,
        with_env: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };

    tideway_cli::commands::new::run(args).expect("run new command");

    assert!(project_dir.join("docker-compose.yml").exists());
}

#[test]
fn test_new_command_with_ci() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let args = NewArgs {
        name: Some("my_app".to_string()),
        preset: None,
        features: Vec::new(),
        with_config: false,
        with_docker: false,
        with_ci: true,
        no_prompt: true,
        summary: true,
        with_env: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };

    tideway_cli::commands::new::run(args).expect("run new command");

    assert!(project_dir.join(".github/workflows/ci.yml").exists());
}

#[test]
fn test_new_command_prints_summary() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let args = NewArgs {
        name: Some("my_app".to_string()),
        preset: None,
        features: Vec::new(),
        with_config: false,
        with_docker: false,
        with_ci: false,
        no_prompt: true,
        summary: true,
        with_env: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };

    assert!(args.summary);

    let files = tideway_cli::commands::new::expected_files(&args);
    assert!(
        files.iter().any(|file| file == "src/main.rs"),
        "expected src/main.rs in file list, got {:?}",
        files
    );
}

#[test]
fn test_new_command_with_env() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let args = NewArgs {
        name: Some("my_app".to_string()),
        preset: None,
        features: Vec::new(),
        with_config: false,
        with_docker: false,
        with_ci: false,
        no_prompt: true,
        summary: true,
        with_env: true,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };

    tideway_cli::commands::new::run(args).expect("run new command");

    assert!(project_dir.join(".env.example").exists());
}

#[test]
fn test_new_command_with_preset_api() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let args = NewArgs {
        name: Some("my_app".to_string()),
        preset: Some(NewPreset::Api),
        features: Vec::new(),
        with_config: false,
        with_docker: false,
        with_ci: false,
        no_prompt: true,
        summary: true,
        with_env: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };

    tideway_cli::commands::new::run(args).expect("run new command");

    let cargo_toml = project_dir.join("Cargo.toml");
    assert_file_contains(&cargo_toml, "\"auth\"");
    assert_file_contains(&cargo_toml, "\"database\"");
    assert_file_contains(&cargo_toml, "\"openapi\"");
    assert_file_contains(&cargo_toml, "\"validation\"");
    assert!(project_dir.join("src/config.rs").exists());
    assert!(project_dir.join("docker-compose.yml").exists());
    assert!(project_dir.join(".github/workflows/ci.yml").exists());
    assert!(project_dir.join(".env.example").exists());
    assert!(project_dir.join("src/auth/mod.rs").exists());
    assert!(project_dir.join("migration/Cargo.toml").exists());
    assert!(project_dir.join("migration/src/lib.rs").exists());
    assert!(
        project_dir
            .join("migration/src/m001_create_todos.rs")
            .exists()
    );
    assert!(project_dir.join("src/entities/mod.rs").exists());
    assert!(project_dir.join("src/entities/todo.rs").exists());
    assert!(project_dir.join("src/routes/todo.rs").exists());
    assert!(project_dir.join("src/openapi_docs.rs").exists());
    assert_file_contains(&project_dir.join("src/main.rs"), "mod entities;");
}

#[test]
fn test_new_command_with_preset_list() {
    let args = NewArgs {
        name: None,
        preset: Some(NewPreset::List),
        features: Vec::new(),
        with_config: false,
        with_docker: false,
        with_ci: false,
        no_prompt: true,
        summary: true,
        with_env: false,
        path: None,
        force: false,
    };

    tideway_cli::commands::new::run(args).expect("run new command");
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
