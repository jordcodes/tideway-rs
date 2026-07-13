use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tideway_cli::cli::{NewArgs, NewPreset};

#[test]
fn test_new_command_generates_starter_files() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let args = NewArgs {
        name: Some("my_app".to_string()),
        preset: Some(NewPreset::Minimal),
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
    assert_file_contains(&project_dir.join("Cargo.toml"), "default-features = false");
    assert_file_contains(&project_dir.join("src/main.rs"), "App::new()");
    assert_file_contains(&project_dir.join("src/routes/mod.rs"), "Tideway is running");
    assert!(project_dir.join(".gitignore").exists());
    assert!(project_dir.join("tests/health.rs").exists());
}

#[test]
fn test_new_command_no_prompt_defaults_to_api_preset() {
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

    assert_file_contains(&project_dir.join("Cargo.toml"), "\"auth\"");
    assert_file_contains(&project_dir.join("Cargo.toml"), "\"database\"");
    assert_file_contains(&project_dir.join("Cargo.toml"), "default-features = false");
    assert!(project_dir.join("src/config.rs").exists());
    assert!(!project_dir.join("docker-compose.yml").exists());
    assert!(project_dir.join(".github/workflows/ci.yml").exists());
    assert!(project_dir.join(".github/dependabot.yml").exists());
    assert_file_contains(
        &project_dir.join(".github/workflows/ci.yml"),
        "rustsec/audit-check",
    );
    assert!(project_dir.join(".env.example").exists());
    assert_file_contains(
        &project_dir.join(".env.example"),
        "DATABASE_URL=sqlite:./my_app.db?mode=rwc",
    );
    assert!(project_dir.join("src/routes/todo.rs").exists());
    assert!(project_dir.join("src/repositories/todo.rs").exists());
    assert!(project_dir.join("src/services/todo.rs").exists());
    assert_file_contains(
        &project_dir.join("src/routes/todo.rs"),
        "Query(params): Query<PaginationParams>",
    );
    assert_file_contains(&project_dir.join("src/routes/todo.rs"), "params.q");
    assert!(
        project_dir
            .join("migration/src/m004_create_todos.rs")
            .exists()
    );
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
    assert_file_contains(&project_dir.join("Cargo.toml"), "default-features = false");
    assert_file_contains(&project_dir.join("Cargo.toml"), "sea-orm");
    assert_file_contains(&project_dir.join(".env.example"), "DATABASE_URL=");
    assert_file_contains(&project_dir.join(".env.example"), "JWT_SECRET=");
    assert_file_contains(&project_dir.join("src/main.rs"), "DATABASE_URL");
    assert_file_contains(&project_dir.join("src/main.rs"), "JwtIssuer");
    assert!(project_dir.join("src/auth/mod.rs").exists());
    assert!(project_dir.join("src/auth/routes.rs").exists());
    assert!(project_dir.join("src/auth/provider.rs").exists());
    assert!(project_dir.join("src/auth/store.rs").exists());
    assert!(project_dir.join("src/entities/user.rs").exists());
    assert!(
        project_dir
            .join("migration/src/m001_create_users.rs")
            .exists()
    );
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
fn test_new_command_api_preset_compiles_and_tests_against_workspace_source() {
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

    patch_scaffold_to_workspace(&project_dir);

    run_cargo_in_project(temp_dir.path(), &project_dir, &["check"]);
    run_cargo_in_project(temp_dir.path(), &project_dir, &["test"]);
}

#[test]
fn test_new_command_auth_mfa_scaffold_is_secure_and_compiles() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let args = NewArgs {
        name: Some("my_app".to_string()),
        preset: Some(NewPreset::Api),
        features: vec!["auth-mfa".to_string()],
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

    assert_file_contains(&project_dir.join(".env.example"), "MFA_ENCRYPTION_KEY=");
    assert_file_contains(&project_dir.join("src/auth/store.rs"), "MfaSecretCipher");
    assert_file_contains(
        &project_dir.join("src/auth/store.rs"),
        "consume_backup_code",
    );
    assert_file_contains(&project_dir.join("src/auth/store.rs"), "DbMfaTokenStore");
    assert_file_contains(
        &project_dir.join("migration/src/m004_create_mfa.rs"),
        "MfaTotpSecretEncrypted",
    );
    assert_file_contains(
        &project_dir.join("migration/src/m004_create_mfa.rs"),
        "MfaLastTotpStep",
    );
    assert!(project_dir.join("src/entities/mfa_backup_code.rs").exists());

    patch_scaffold_to_workspace(&project_dir);
    run_cargo_in_project(temp_dir.path(), &project_dir, &["test"]);
}

#[test]
fn test_new_command_minimal_compiles_against_workspace_source() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let args = NewArgs {
        name: Some("my_app".to_string()),
        preset: Some(NewPreset::Minimal),
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

    patch_scaffold_to_workspace(&project_dir);

    run_cargo_in_project(temp_dir.path(), &project_dir, &["check"]);
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
    assert_file_contains(&cargo_toml, "\"sqlx-sqlite\"");
    assert_file_not_contains(&cargo_toml, "\"sqlx-postgres\"");
    assert!(project_dir.join("src/config.rs").exists());
    assert!(!project_dir.join("docker-compose.yml").exists());
    assert!(project_dir.join(".github/workflows/ci.yml").exists());
    assert!(project_dir.join(".env.example").exists());
    assert_file_contains(
        &project_dir.join(".env.example"),
        "DATABASE_URL=sqlite:./my_app.db?mode=rwc",
    );
    assert!(project_dir.join("src/auth/mod.rs").exists());
    assert_file_contains(
        &project_dir.join("src/auth/routes.rs"),
        "RegistrationFlow::new",
    );
    assert_file_contains(
        &project_dir.join("src/auth/routes.rs"),
        ".with_rate_limiter(state.login_rate_limiter.clone())",
    );
    assert_file_contains(
        &project_dir.join("src/auth/store.rs"),
        "compare_and_swap_family_generation",
    );
    assert!(project_dir.join("src/entities/user.rs").exists());
    assert!(project_dir.join("src/entities/auth_token.rs").exists());
    assert!(project_dir.join("migration/Cargo.toml").exists());
    assert_file_contains(&project_dir.join("migration/Cargo.toml"), "\"sqlx-sqlite\"");
    assert!(project_dir.join("migration/src/lib.rs").exists());
    assert!(
        project_dir
            .join("migration/src/m004_create_todos.rs")
            .exists()
    );
    assert_file_contains(
        &project_dir.join("migration/src/lib.rs"),
        "Box::new(m004_create_todos::Migration)",
    );
    assert!(project_dir.join("src/entities/mod.rs").exists());
    assert!(project_dir.join("src/entities/todo.rs").exists());
    assert!(project_dir.join("src/repositories/mod.rs").exists());
    assert!(project_dir.join("src/repositories/todo.rs").exists());
    assert!(project_dir.join("src/services/mod.rs").exists());
    assert!(project_dir.join("src/services/todo.rs").exists());
    assert!(project_dir.join("src/routes/todo.rs").exists());
    assert!(project_dir.join("src/openapi_docs.rs").exists());
    assert_file_contains(&project_dir.join("src/main.rs"), "mod entities;");
    assert_file_contains(&project_dir.join("src/main.rs"), "mod repositories;");
    assert_file_contains(&project_dir.join("src/main.rs"), "mod services;");
    assert_file_contains(&project_dir.join("src/main.rs"), "mod openapi_docs;");
    assert_file_not_contains(
        &project_dir.join("src/main.rs"),
        "#[cfg(feature = \"openapi\")]",
    );
    assert_file_contains(
        &project_dir.join("src/main.rs"),
        "tideway::openapi::create_openapi_router",
    );
    assert_file_contains(
        &project_dir.join("src/main.rs"),
        "tideway::openapi_merge_module!(openapi_docs, ApiDoc)",
    );
    assert_file_not_contains(
        &project_dir.join("src/openapi_docs.rs"),
        "#[cfg(feature = \"openapi\")]",
    );
    assert_file_not_contains(
        &project_dir.join("src/routes/todo.rs"),
        "#[cfg_attr(feature = \"openapi\"",
    );
    assert_file_not_contains(&project_dir.join("src/routes/todo.rs"), ".with_json(");
    assert_file_not_contains(&project_dir.join("src/routes/todo.rs"), "#[cfg(test)]");
    assert_file_not_contains(
        &project_dir.join("src/routes/todo.rs"),
        "mod openapi_docs {",
    );
    assert_file_contains(
        &project_dir.join("src/routes/todo.rs"),
        "Query(params): Query<PaginationParams>",
    );
    assert_file_contains(&project_dir.join("src/routes/todo.rs"), "params.q");
    assert_file_contains(
        &project_dir.join("src/repositories/todo.rs"),
        "pub async fn list(&self, limit: Option<u64>, offset: Option<u64>, search: Option<String>)",
    );
    assert_file_contains(
        &project_dir.join("src/services/todo.rs"),
        "pub async fn list(&self, limit: Option<u64>, offset: Option<u64>, search: Option<String>)",
    );
    assert_file_contains(&project_dir.join(".env.example"), "OPENAPI_ENABLED=true");
    assert_file_contains(&project_dir.join(".gitignore"), "*.db");
}

#[test]
fn test_new_command_with_preset_api_and_docker_keeps_postgres_path() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let args = NewArgs {
        name: Some("my_app".to_string()),
        preset: Some(NewPreset::Api),
        features: Vec::new(),
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
    assert_file_contains(
        &project_dir.join(".env.example"),
        "DATABASE_URL=postgres://postgres:postgres@localhost:5432/my_app",
    );
    assert_file_contains(&project_dir.join("Cargo.toml"), "\"sqlx-postgres\"");
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

#[test]
fn test_new_command_with_preset_saas() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let args = NewArgs {
        name: Some("my_app".to_string()),
        preset: Some(NewPreset::Saas),
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
    assert_file_contains(&cargo_toml, "\"billing\"");
    assert_file_contains(&cargo_toml, "\"organizations\"");
    assert_file_contains(&cargo_toml, "\"admin\"");
    assert_file_not_contains(&cargo_toml, "\"openapi\"");
    assert!(project_dir.join(".env.example").exists());
    assert!(project_dir.join("docker-compose.yml").exists());
    assert!(project_dir.join(".github/workflows/ci.yml").exists());
    assert!(project_dir.join("src/auth/actor.rs").exists());
    assert!(project_dir.join("src/auth/mod.rs").exists());
    assert!(project_dir.join("src/billing/mod.rs").exists());
    assert!(project_dir.join("src/organizations/mod.rs").exists());
    assert!(project_dir.join("src/admin/mod.rs").exists());
    assert!(project_dir.join("src/lib.rs").exists());
    assert!(!project_dir.join("src/routes/mod.rs").exists());
    assert!(!project_dir.join("src/auth/provider.rs").exists());
    assert_file_contains(
        &project_dir.join(".env.example"),
        "STRIPE_SECRET_KEY=sk_test_replace_me",
    );
    assert_file_contains(
        &project_dir.join(".env.example"),
        "STRIPE_WEBHOOK_SECRET=whsec_replace_me",
    );
    assert_file_contains(
        &project_dir.join(".env.example"),
        "STRIPE_PRICE_ID=price_replace_me",
    );
    assert_file_contains(
        &project_dir.join(".env.example"),
        "APP_URL=http://localhost:8000",
    );
    assert_file_contains(&project_dir.join(".env.example"), "TIDEWAY_ENV=development");
    assert_file_contains(
        &project_dir.join(".env.example"),
        "TIDEWAY_CORS_ALLOWED_ORIGINS=http://localhost:5173",
    );
    assert_file_contains(
        &project_dir.join("src/main.rs"),
        "allowed_redirect_domains([app_host])",
    );
    assert_file_not_contains(&project_dir.join("src/main.rs"), "CorsConfig::permissive()");
    assert_file_not_contains(&project_dir.join(".env.example"), "OPENAPI_ENABLED");
}

#[test]
fn test_new_command_saas_preset_compiles_against_workspace_source() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let args = NewArgs {
        name: Some("my_app".to_string()),
        preset: Some(NewPreset::Saas),
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

    patch_scaffold_to_workspace(&project_dir);

    run_cargo_in_project(temp_dir.path(), &project_dir, &["check"]);
}

#[test]
fn test_new_command_with_preset_worker() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let args = NewArgs {
        name: Some("my_app".to_string()),
        preset: Some(NewPreset::Worker),
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
    assert_file_contains(&cargo_toml, "\"jobs\"");
    assert_file_contains(&cargo_toml, "\"jobs-redis\"");
    assert_file_contains(&cargo_toml, "\"metrics\"");
    assert_file_contains(&cargo_toml, "\"database\"");
    assert!(project_dir.join(".env.example").exists());
    assert!(project_dir.join("docker-compose.yml").exists());
    assert!(project_dir.join(".github/workflows/ci.yml").exists());
    assert!(project_dir.join("src/config.rs").exists());
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
