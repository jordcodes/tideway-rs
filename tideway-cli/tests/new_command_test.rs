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
        without_invitations: false,
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
        without_invitations: false,
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
    assert_file_contains(
        &project_dir.join(".env.example"),
        "ALLOW_PUBLIC_REGISTRATION=false",
    );
    assert_file_not_contains(
        &project_dir.join(".github/workflows/ci.yml"),
        "TEST_DATABASE_URL",
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
        without_invitations: false,
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
    assert_file_contains(&project_dir.join(".env.example"), "JWT_ISSUER=my_app");
    assert_file_contains(&project_dir.join(".env.example"), "JWT_AUDIENCE=my_app");
    assert_file_contains(&project_dir.join("src/main.rs"), "DATABASE_URL");
    assert_file_contains(&project_dir.join("src/main.rs"), "JwtAuth");
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
fn test_new_credits_seaorm_includes_database_and_ledger_schema() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    let args = NewArgs {
        name: Some("my_app".to_string()),
        preset: None,
        features: vec!["credits-seaorm".to_string()],
        with_config: false,
        with_docker: false,
        with_ci: false,
        no_prompt: true,
        summary: false,
        with_env: false,
        without_invitations: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };

    tideway_cli::commands::new::run(args).expect("create credits app");

    assert_file_contains(&project_dir.join("Cargo.toml"), "\"credits\"");
    assert_file_contains(&project_dir.join("Cargo.toml"), "\"credits-seaorm\"");
    assert_file_contains(&project_dir.join("Cargo.toml"), "\"database\"");
    assert_file_contains(&project_dir.join("migration/Cargo.toml"), "with-json");
    assert_file_contains(
        &project_dir.join("migration/src/m013_create_credit_ledger.rs"),
        "credit_buckets",
    );
    assert_file_contains(
        &project_dir.join("migration/src/lib.rs"),
        "Box::new(m013_create_credit_ledger::Migration)",
    );
    assert_file_contains(
        &project_dir.join("migration/src/m015_add_credit_revocation.rs"),
        "PendingRevocation",
    );
    assert_file_contains(
        &project_dir.join("migration/src/lib.rs"),
        "Box::new(m015_add_credit_revocation::Migration)",
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
        without_invitations: false,
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
        without_invitations: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };

    tideway_cli::commands::new::run(args).expect("run new command");

    assert_file_contains(
        &project_dir.join("src/auth/routes.rs"),
        "pub(crate) AuthApiDoc",
    );
    assert_file_contains(
        &project_dir.join("src/auth/routes.rs"),
        "security((\"bearer_auth\" = []))",
    );
    assert_file_contains(
        &project_dir.join("src/main.rs"),
        "auth::auth_openapi(allow_public_registration)",
    );
    assert_file_contains(
        &project_dir.join("src/main.rs"),
        ".run_migrations::<migration::Migrator>()",
    );
    assert_file_contains(
        &project_dir.join("migration/src/main.rs"),
        "cli::run_cli(migration::Migrator).await",
    );

    patch_scaffold_to_workspace(&project_dir);

    run_cargo_in_project(temp_dir.path(), &project_dir, &["check"]);
    run_cargo_in_project(temp_dir.path(), &project_dir, &["test"]);
    run_cargo_in_project(
        temp_dir.path(),
        &project_dir,
        &[
            "clippy",
            "--all-targets",
            "--no-deps",
            "--",
            "-D",
            "warnings",
        ],
    );
    run_cargo_in_project(
        temp_dir.path(),
        &project_dir,
        &[
            "check",
            "--manifest-path",
            "migration/Cargo.toml",
            "--all-targets",
        ],
    );
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
        without_invitations: false,
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
    assert_file_contains(
        &project_dir.join("src/auth/routes.rs"),
        "path = \"/auth/mfa/verify\"",
    );
    assert_file_contains(
        &project_dir.join("src/auth/routes.rs"),
        "path = \"/auth/mfa/setup\"",
    );
    assert_file_contains(
        &project_dir.join("src/main.rs"),
        "auth::auth_openapi(allow_public_registration)",
    );

    patch_scaffold_to_workspace(&project_dir);
    run_cargo_in_project(temp_dir.path(), &project_dir, &["test"]);
}

#[test]
fn test_new_command_mfa_alias_generates_auth_mfa_scaffold() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let args = NewArgs {
        name: Some("my_app".to_string()),
        preset: Some(NewPreset::Api),
        features: vec!["mfa".to_string()],
        with_config: false,
        with_docker: false,
        with_ci: false,
        no_prompt: true,
        summary: false,
        with_env: false,
        without_invitations: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };

    tideway_cli::commands::new::run(args).expect("run new command with mfa alias");

    assert_file_contains(&project_dir.join("Cargo.toml"), "\"auth-mfa\"");
    assert_file_not_contains(&project_dir.join("Cargo.toml"), "\"mfa\"");
    assert!(project_dir.join("src/entities/mfa_backup_code.rs").exists());
    assert!(
        project_dir
            .join("migration/src/m004_create_mfa.rs")
            .exists()
    );
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
        without_invitations: false,
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
        without_invitations: false,
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
        without_invitations: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };

    tideway_cli::commands::new::run(args).expect("run new command");

    assert!(project_dir.join("docker-compose.yml").exists());
}

#[test]
fn test_new_command_generates_production_dockerfile() {
    for (preset, with_docker) in [
        (NewPreset::Minimal, false),
        (NewPreset::Api, false),
        (NewPreset::Api, true),
    ] {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let project_dir = temp_dir.path().join("my_app");

        let args = NewArgs {
            name: Some("my_app".to_string()),
            preset: Some(preset),
            features: Vec::new(),
            with_config: false,
            with_docker,
            with_ci: false,
            no_prompt: true,
            summary: true,
            with_env: false,
            without_invitations: false,
            path: Some(project_dir.to_string_lossy().to_string()),
            force: false,
        };

        let files = tideway_cli::commands::new::expected_files(&args);
        assert!(files.contains(&"Dockerfile".to_string()));
        assert!(files.contains(&".dockerignore".to_string()));

        tideway_cli::commands::new::run(args).expect("run new command");

        let dockerfile = project_dir.join("Dockerfile");
        assert_file_contains(
            &dockerfile,
            "FROM lukemathwalker/cargo-chef:latest-rust-1-bookworm AS chef",
        );
        assert_file_contains(
            &dockerfile,
            "RUN cargo chef cook --release --locked --bin my_app --recipe-path recipe.json",
        );
        assert_file_contains(&dockerfile, "FROM debian:bookworm-slim AS runtime");
        assert_file_contains(&dockerfile, "cargo build --release --locked --bin my_app");
        assert_file_contains(
            &dockerfile,
            "COPY --from=builder /app/target/release/my_app /usr/local/bin/my_app",
        );
        assert_file_contains(&dockerfile, "USER app");
        assert_file_contains(&dockerfile, "PORT=8000");
        assert_file_contains(&dockerfile, "CMD [\"my_app\"]");
        assert_file_not_contains(&dockerfile, "{{");

        let sqlite = matches!(preset, NewPreset::Api) && !with_docker;
        if sqlite {
            assert_file_contains(
                &dockerfile,
                "ENV DATABASE_URL=sqlite:///app/data/my_app.db?mode=rwc",
            );
        } else {
            assert_file_not_contains(&dockerfile, "DATABASE_URL");
        }

        let dockerignore = project_dir.join(".dockerignore");
        assert_file_contains(&dockerignore, "target/");
        assert_file_contains(&dockerignore, ".env");
        assert_file_not_contains(&dockerignore, "Cargo.lock");
    }
}

/// Builds the generated production Dockerfile and checks the container serves /health.
/// Opt-in (slow, needs a Docker daemon): `TIDEWAY_DOCKER_SMOKE=1 cargo test -p tideway-cli
/// --test new_command_test production_dockerfile_builds -- --nocapture`.
#[test]
fn test_new_command_production_dockerfile_builds_and_serves_health_smoke() {
    if std::env::var("TIDEWAY_DOCKER_SMOKE").is_err() {
        return;
    }

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
        without_invitations: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };
    tideway_cli::commands::new::run(args).expect("run new command");

    // The scaffold pins the unreleased workspace version, so vendor the local crates into the
    // Docker build context and patch them in.
    vendor_workspace_crates(temp_dir.path(), &project_dir);

    let tag = format!("tideway-dockerfile-smoke-{}", std::process::id());
    run_checked(
        Command::new("docker")
            .args(["build", "-t", &tag, "."])
            .current_dir(&project_dir),
    );

    let container = run_checked(Command::new("docker").args([
        "run",
        "-d",
        "-p",
        "127.0.0.1::8000",
        "-e",
        "JWT_SECRET=smoke-test-secret-with-at-least-32-bytes",
        &tag,
    ]));
    let container = container.trim().to_string();

    let result = std::panic::catch_unwind(|| {
        let port_output = run_checked(Command::new("docker").args(["port", &container, "8000"]));
        let addr = port_output
            .lines()
            .next()
            .expect("published port")
            .trim()
            .to_string();
        wait_for_http_ok(&addr, "/health");
    });

    if result.is_err() {
        let logs = Command::new("docker")
            .args(["logs", &container])
            .output()
            .expect("docker logs");
        eprintln!(
            "container logs:\n{}{}",
            String::from_utf8_lossy(&logs.stdout),
            String::from_utf8_lossy(&logs.stderr)
        );
    }
    let _ = Command::new("docker")
        .args(["rm", "-f", &container])
        .output();
    let _ = Command::new("docker").args(["rmi", "-f", &tag]).output();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
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
        without_invitations: false,
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
        without_invitations: false,
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
        without_invitations: false,
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
        without_invitations: false,
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
        &project_dir.join("src/auth/routes.rs"),
        "if self.state.allow_public_registration",
    );
    assert_file_contains(
        &project_dir.join("src/auth/routes.rs"),
        "registration_rate_limiter",
    );
    assert_file_contains(
        &project_dir.join("src/auth/routes.rs"),
        "refresh_rate_limiter",
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
    assert!(project_dir.join("migration/src/main.rs").exists());
    assert_file_contains(
        &project_dir.join("migration/src/main.rs"),
        "cli::run_cli(migration::Migrator).await",
    );
    assert_file_contains(
        &project_dir.join("src/main.rs"),
        ".run_migrations::<migration::Migrator>()",
    );
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
        "auth::auth_openapi(allow_public_registration)",
    );
    assert_file_contains(
        &project_dir.join("src/auth/routes.rs"),
        "document.paths.paths.remove(\"/auth/register\")",
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
        without_invitations: false,
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
    assert_file_contains(
        &project_dir.join(".github/workflows/ci.yml"),
        "TEST_DATABASE_URL: postgres://postgres:postgres@localhost:5432/my_app_test",
    );
    assert_file_contains(
        &project_dir.join(".github/workflows/ci.yml"),
        "test -f Cargo.lock || cargo generate-lockfile",
    );
    assert_file_contains(
        &project_dir.join(".github/workflows/ci.yml"),
        "image: postgres:16",
    );
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
        without_invitations: false,
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
        without_invitations: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };

    tideway_cli::commands::new::run(args).expect("run new command");

    let cargo_toml = project_dir.join("Cargo.toml");
    assert_file_contains(&cargo_toml, "\"auth\"");
    assert_file_contains(&cargo_toml, "\"billing\"");
    assert_file_contains(&cargo_toml, "\"organizations\"");
    assert_file_contains(&cargo_toml, "\"admin\"");
    assert_file_contains(&cargo_toml, "\"email\"");
    assert_file_not_contains(&cargo_toml, "\"openapi\"");
    assert!(project_dir.join(".env.example").exists());
    assert!(project_dir.join("docker-compose.yml").exists());
    assert!(project_dir.join(".github/workflows/ci.yml").exists());
    assert_file_contains(
        &project_dir.join(".github/workflows/ci.yml"),
        "TEST_DATABASE_URL: postgres://postgres:postgres@localhost:5432/my_app_test",
    );
    assert_file_contains(
        &project_dir.join(".env.example"),
        "ALLOW_PUBLIC_REGISTRATION=false",
    );
    assert!(project_dir.join("src/auth/actor.rs").exists());
    assert!(project_dir.join("src/auth/mod.rs").exists());
    assert!(project_dir.join("src/auth/tests.rs").exists());
    assert_file_contains(&project_dir.join("src/auth/mod.rs"), "mod tests;");
    assert_file_not_contains(&project_dir.join("src/auth/tests.rs"), "SimpleAuthProvider");
    assert!(project_dir.join("src/billing/mod.rs").exists());
    assert!(project_dir.join("src/billing/events.rs").exists());
    assert_file_contains(
        &project_dir.join("src/billing/routes.rs"),
        ".with_event_sink(AppBillingEventSink)",
    );
    assert!(project_dir.join("src/organizations/mod.rs").exists());
    assert!(project_dir.join("src/admin/mod.rs").exists());
    assert!(project_dir.join("src/lib.rs").exists());
    assert!(project_dir.join("src/email.rs").exists());
    assert_file_contains(
        &project_dir.join("src/email.rs"),
        "pub fn new(\n        mailer: Arc<dyn Mailer>",
    );
    assert_file_contains(
        &project_dir.join("src/email.rs"),
        "APP_URL must use https outside development/test environments",
    );
    assert_file_contains(
        &project_dir.join("src/email.rs"),
        "fn transactional_email_html(",
    );
    assert_file_contains(&project_dir.join("src/email.rs"), ".html(html)");
    assert_file_contains(
        &project_dir.join("src/email.rs"),
        "transactional_html_is_accessible_and_escapes_application_values",
    );
    assert!(!project_dir.join("src/routes/mod.rs").exists());
    assert!(!project_dir.join("src/auth/provider.rs").exists());
    assert_file_contains(
        &project_dir.join(".env.example"),
        "STRIPE_SECRET_KEY=sk_test_tideway_local_only_000000",
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
        "APP_URL=http://localhost:5173",
    );
    assert_file_contains(&project_dir.join(".env.example"), "JWT_ISSUER=my_app");
    assert_file_contains(&project_dir.join(".env.example"), "JWT_AUDIENCE=my_app");
    assert_file_contains(&project_dir.join("src/config.rs"), "pub jwt_issuer: String");
    assert_file_contains(
        &project_dir.join("src/config.rs"),
        "pub jwt_audience: String",
    );
    assert_file_contains(&project_dir.join("src/main.rs"), "&app_config.jwt_issuer");
    assert_file_contains(
        &project_dir.join("src/main.rs"),
        "JwtAuthConfig::with_secure_secret(&app_config.jwt_secret, &app_config.jwt_issuer)",
    );
    assert_file_contains(
        &project_dir.join("src/main.rs"),
        ".audience(&app_config.jwt_audience)",
    );
    assert_file_not_contains(
        &project_dir.join("src/main.rs"),
        "&app_config.app_name,\n    )?.audience",
    );
    assert_file_contains(
        &project_dir.join("src/auth/tests.rs"),
        "display_name_does_not_change_jwt_identity",
    );
    assert_file_contains(
        &project_dir.join("src/auth/tests.rs"),
        "Method::GET, \"/organizations\"",
    );
    assert_file_contains(&project_dir.join(".env.example"), "TIDEWAY_ENV=development");
    assert_file_contains(&project_dir.join(".env.example"), "EMAIL_PROVIDER=console");
    assert_file_contains(
        &project_dir.join(".env.example"),
        "EMAIL_CONSOLE_SHOW_BODY=false",
    );
    assert_file_contains(&project_dir.join(".env.example"), "RESEND_API_KEY=");
    assert_file_contains(&project_dir.join(".env.example"), "SMTP_HOST=");
    assert_file_contains(&cargo_toml, "members = [\"migration\"]");
    assert_file_contains(&cargo_toml, "\"sqlx-sqlite\"");
    assert_file_contains(&cargo_toml, "tower = { version = \"0.5\"");
    assert_file_contains(&project_dir.join("migration/Cargo.toml"), "\"with-json\"");
    assert_file_contains(&project_dir.join("migration/Cargo.toml"), "\"sqlx-sqlite\"");
    assert_file_contains(
        &project_dir.join("migration/src/m008_create_billing_plans.rs"),
        "json!({",
    );
    assert_file_not_contains(
        &project_dir.join("migration/src/m008_create_billing_plans.rs"),
        ".default(\"{}\")",
    );
    assert_file_not_contains(&project_dir.join("docker-compose.yml"), "version:");
    assert_file_contains(
        &project_dir.join("src/main.rs"),
        "Replace the local-only STRIPE_SECRET_KEY before running outside development",
    );
    assert_file_contains(
        &project_dir.join(".env.example"),
        "TIDEWAY_CORS_ALLOWED_ORIGINS=http://localhost:5173",
    );
    assert_file_contains(
        &project_dir.join("src/main.rs"),
        "allowed_redirect_domains([app_host])",
    );
    assert_file_contains(
        &project_dir.join("src/main.rs"),
        ".with_email_delivery(email_service.clone())",
    );
    assert!(
        project_dir
            .join("src/entities/organization_invitation.rs")
            .exists()
    );
    assert!(
        project_dir
            .join("src/organizations/invitations.rs")
            .exists()
    );
    assert!(
        project_dir
            .join("migration/src/m011_create_organization_invitations.rs")
            .exists()
    );
    assert_file_contains(
        &project_dir.join("src/organizations/invitations.rs"),
        "Sha256::digest(token.as_bytes())",
    );
    assert_file_contains(
        &project_dir.join("src/organizations/invitations.rs"),
        "Column::Status.eq(\"pending\")",
    );
    assert_file_contains(
        &project_dir.join("src/organizations/invitations.rs"),
        "claim.rows_affected != 1",
    );
    assert_file_contains(
        &project_dir.join("src/organizations/invitations.rs"),
        ".lock_exclusive()",
    );
    assert_file_contains(
        &project_dir.join("src/organizations/invitations.rs"),
        "ensure_seat_available",
    );
    assert_file_contains(
        &project_dir.join("src/organizations/invitations.rs"),
        "Arc<dyn InvitationRateLimitProvider>",
    );
    assert_file_contains(
        &project_dir.join("src/organizations/invitations.rs"),
        "with_rate_limit_provider",
    );
    assert_file_contains(
        &project_dir.join("src/organizations/invitations.rs"),
        "concurrent_redemption_creates_one_membership",
    );
    assert_file_contains(
        &project_dir.join("src/organizations/invitations.rs"),
        "revocation_cannot_cross_organization_boundary",
    );
    assert_file_contains(
        &project_dir.join("src/organizations/invitations.rs"),
        "resend_delivery_failure_restores_previous_token",
    );
    assert_file_not_contains(
        &project_dir.join("src/entities/organization_invitation.rs"),
        "raw_token",
    );
    assert_file_not_contains(
        &project_dir.join("src/entities/organization_invitation.rs"),
        "Serialize",
    );
    assert_file_contains(
        &project_dir.join("src/auth/routes.rs"),
        ".route(\"/email/verify\", post(verify_email))",
    );
    assert_file_contains(
        &project_dir.join("src/auth/routes.rs"),
        "If an unverified account with that email exists",
    );
    assert_file_contains(
        &project_dir.join("src/auth/routes.rs"),
        "email_rate_limiter: AuthRateLimiter",
    );
    assert_file_contains(
        &project_dir.join("src/auth/routes.rs"),
        "format!(\"email:{}\"",
    );
    assert_file_not_contains(&project_dir.join("src/main.rs"), "CorsConfig::permissive()");
    assert_file_not_contains(&project_dir.join(".env.example"), "OPENAPI_ENABLED");
}

#[test]
fn test_new_saas_can_omit_optional_invitations() {
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
        without_invitations: true,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };

    tideway_cli::commands::new::run(args).expect("run new command");
    assert!(
        !project_dir
            .join("src/organizations/invitations.rs")
            .exists()
    );
    assert!(
        !project_dir
            .join("src/entities/organization_invitation.rs")
            .exists()
    );
    assert!(
        !project_dir
            .join("migration/src/m011_create_organization_invitations.rs")
            .exists()
    );
    assert_file_not_contains(&project_dir.join("Cargo.toml"), "sha2");
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
        without_invitations: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };

    tideway_cli::commands::new::run(args).expect("run new command");

    patch_scaffold_to_workspace(&project_dir);

    run_cargo_in_project_with_denied_warnings(
        temp_dir.path(),
        &project_dir,
        &["test", "--all-targets"],
    );
    assert!(project_dir.join("Cargo.lock").exists());
    assert!(
        !project_dir.join("migration/Cargo.lock").exists(),
        "workspace members should share the root Cargo.lock"
    );
}

#[test]
fn test_individual_auth_and_openapi_features_compile_without_warnings() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");

    for (name, feature) in [("auth_only", "auth"), ("openapi_only", "openapi")] {
        let project_dir = temp_dir.path().join(name);
        let args = NewArgs {
            name: Some(name.to_string()),
            preset: Some(NewPreset::Minimal),
            features: vec![feature.to_string()],
            with_config: false,
            with_docker: false,
            with_ci: false,
            no_prompt: true,
            summary: false,
            with_env: false,
            without_invitations: false,
            path: Some(project_dir.to_string_lossy().to_string()),
            force: false,
        };

        tideway_cli::commands::new::run(args).expect("run new command");
        patch_scaffold_to_workspace(&project_dir);
        run_cargo_in_project_with_denied_warnings(temp_dir.path(), &project_dir, &["check"]);
    }
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
        without_invitations: false,
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
    assert!(project_dir.join("src/entities/mod.rs").exists());
    assert!(project_dir.join("migration/src/main.rs").exists());
    assert_file_contains(
        &project_dir.join("src/main.rs"),
        ".run_migrations::<migration::Migrator>()",
    );
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
    run_cargo_in_project_inner(temp_root, project_dir, args, false);
}

fn run_cargo_in_project_with_denied_warnings(temp_root: &Path, project_dir: &Path, args: &[&str]) {
    run_cargo_in_project_inner(temp_root, project_dir, args, true);
}

fn run_cargo_in_project_inner(
    temp_root: &Path,
    project_dir: &Path,
    args: &[&str],
    deny_warnings: bool,
) {
    let mut command = Command::new("cargo");
    command
        .args(args)
        .current_dir(project_dir)
        .env("CARGO_TARGET_DIR", temp_root.join("cargo-target"));
    if deny_warnings {
        command.env("RUSTFLAGS", "-Dwarnings");
    }

    let output = command.output().expect("run cargo");

    if !output.status.success() {
        panic!(
            "cargo {} failed.\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn vendor_workspace_crates(temp_root: &Path, project_dir: &Path) {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");
    let package_target = temp_root.join("package-target");
    run_checked(
        Command::new("cargo")
            .args([
                "package",
                "-p",
                "tideway",
                "-p",
                "tideway-macros",
                "--no-verify",
                "--allow-dirty",
                "--target-dir",
            ])
            .arg(&package_target)
            .current_dir(workspace_root),
    );

    let vendor_dir = project_dir.join("vendor");
    fs::create_dir_all(&vendor_dir).expect("create vendor dir");
    let mut tideway_dir = None;
    let mut macros_dir = None;
    for entry in fs::read_dir(package_target.join("package")).expect("read package dir") {
        let path = entry.expect("package entry").path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(dir_name) = file_name.strip_suffix(".crate") else {
            continue;
        };
        run_checked(
            Command::new("tar")
                .arg("-xzf")
                .arg(&path)
                .arg("-C")
                .arg(&vendor_dir),
        );
        if dir_name.starts_with("tideway-macros-") {
            macros_dir = Some(dir_name.to_string());
        } else {
            tideway_dir = Some(dir_name.to_string());
        }
    }
    let tideway_dir = tideway_dir.expect("packaged tideway crate");
    let macros_dir = macros_dir.expect("packaged tideway-macros crate");

    // cargo-chef masks local crate versions in its dependency recipe, which breaks
    // `[patch.crates-io]` version matching, so use plain path dependencies instead. It also only
    // skeletonizes workspace members, so the vendored crates join the app's workspace.
    let tideway_manifest = vendor_dir.join(&tideway_dir).join("Cargo.toml");
    let manifest = fs::read_to_string(&tideway_manifest).expect("read vendored tideway manifest");
    let macros_version = macros_dir
        .strip_prefix("tideway-macros-")
        .expect("macros crate version");
    let macros_dep = format!("[dependencies.tideway-macros]\nversion = \"{macros_version}\"");
    assert!(
        manifest.contains(&macros_dep),
        "unexpected tideway-macros dependency in vendored manifest:\n{manifest}"
    );
    fs::write(
        &tideway_manifest,
        manifest.replace(
            &macros_dep,
            &format!("[dependencies.tideway-macros]\npath = \"../{macros_dir}\""),
        ),
    )
    .expect("write vendored tideway manifest");

    let cargo_path = project_dir.join("Cargo.toml");
    let mut contents = fs::read_to_string(&cargo_path).expect("read Cargo.toml");
    let tideway_dep = format!(
        "tideway = {{ version = \"{}\"",
        tideway_cli::TIDEWAY_VERSION
    );
    assert!(
        contents.contains(&tideway_dep),
        "unexpected tideway dependency:\n{contents}"
    );
    contents = contents.replace(
        &tideway_dep,
        &format!("tideway = {{ path = \"vendor/{tideway_dir}\""),
    );
    let members = format!("\"vendor/{tideway_dir}\", \"vendor/{macros_dir}\"");
    if contents.contains("members = [\"migration\"]") {
        contents = contents.replace(
            "members = [\"migration\"]",
            &format!("members = [\"migration\", {members}]"),
        );
    } else {
        contents.push_str(&format!("\n[workspace]\nmembers = [{members}]\n"));
    }
    fs::write(cargo_path, contents).expect("write Cargo.toml");
}

fn run_checked(command: &mut Command) -> String {
    let output = command.output().expect("spawn command");
    if !output.status.success() {
        panic!(
            "{:?} failed.\nstdout:\n{}\nstderr:\n{}",
            command,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn wait_for_http_ok(addr: &str, path: &str) {
    use std::io::{Read, Write};

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut last_response = String::new();
    while std::time::Instant::now() < deadline {
        if let Ok(mut stream) = std::net::TcpStream::connect(addr) {
            let request =
                format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
            if stream.write_all(request.as_bytes()).is_ok() {
                last_response.clear();
                let _ = stream.read_to_string(&mut last_response);
                if last_response.starts_with("HTTP/1.1 200") {
                    return;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    panic!("GET {path} on {addr} never returned 200; last response:\n{last_response}");
}

fn escape_toml_path(path: &Path) -> String {
    path_to_string(path).replace('\\', "\\\\")
}

fn path_to_string(path: &Path) -> String {
    PathBuf::from(path).to_string_lossy().into_owned()
}
