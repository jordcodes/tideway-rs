use std::fs;
use std::process::Command;

use tideway_cli::cli::{NewArgs, NewPreset};
use tideway_cli::commands::doctor::{analyze_project, analyze_project_with_upgrade};

#[test]
fn test_doctor_upgrade_reports_dependency_and_source_migrations() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();
    fs::create_dir_all(project_dir.join("src")).expect("create src");
    fs::write(
        project_dir.join("Cargo.toml"),
        r#"[package]
name = "upgrade_app"
version = "0.1.0"
edition = "2024"

[dependencies]
tideway = { version = "0.7.13", features = ["auth", "billing", "validation"] }
validator = { version = "0.18", features = ["derive"] }
stripe = { package = "async-stripe", version = "0.41", default-features = false, features = ["runtime-tokio-hyper-rustls-webpki", "billing"] }
"#,
    )
    .expect("write Cargo.toml");
    fs::write(
        project_dir.join("src/main.rs"),
        r#"fn migration_markers(context: tideway::AppContext, secret: &str) {
    let _ = context.database.is_some();
    let _ = tideway::auth::JwtIssuerConfig::with_secret(secret, "upgrade_app");
    let _ = tideway::auth::JwtVerifier::from_secret(secret.as_bytes());
}
"#,
    )
    .expect("write main.rs");

    let report = analyze_project_with_upgrade(project_dir, false, true).expect("analyze upgrade");
    let warnings = report.warnings();

    for expected in [
        "declares Tideway 0.7.13",
        "validator 0.20",
        "only one TLS implementation",
        "with_secure_secret",
        "from_secret_checked",
        "database_opt()",
    ] {
        assert!(
            warnings.iter().any(|warning| warning.contains(expected)),
            "expected upgrade warning containing {expected:?}, got {warnings:?}"
        );
    }
}

#[test]
fn test_doctor_upgrade_accepts_aligned_dependencies_and_current_apis() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();
    fs::create_dir_all(project_dir.join("src")).expect("create src");
    fs::write(
        project_dir.join("Cargo.toml"),
        format!(
            r#"[package]
name = "upgrade_app"
version = "0.1.0"
edition = "2024"

[dependencies]
tideway = {{ version = "{}", features = ["billing", "validation"] }}
validator = {{ version = "0.20", features = ["derive"] }}
stripe = {{ package = "async-stripe", version = "0.41", default-features = false, features = ["runtime-tokio-hyper", "billing"] }}
"#,
            tideway_cli::TIDEWAY_VERSION
        ),
    )
    .expect("write Cargo.toml");
    fs::write(project_dir.join("src/main.rs"), "fn main() {}\n").expect("write main.rs");

    let report = analyze_project_with_upgrade(project_dir, false, true).expect("analyze upgrade");
    let warnings = report.warnings();
    assert!(
        !warnings.iter().any(|warning| warning.contains("validator"))
            && !warnings
                .iter()
                .any(|warning| warning.contains("TLS implementation"))
            && !warnings
                .iter()
                .any(|warning| warning.contains("Deprecated")),
        "expected aligned upgrade dependencies, got {warnings:?}"
    );
}

#[test]
fn test_doctor_upgrade_rejects_fix_mode() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    fs::write(
        temp_dir.path().join("Cargo.toml"),
        r#"[package]
name = "upgrade_app"
version = "0.1.0"
edition = "2024"

[dependencies]
tideway = "0.7.23"
"#,
    )
    .expect("write Cargo.toml");

    let output = Command::new(env!("CARGO_BIN_EXE_tideway"))
        .arg("doctor")
        .arg("--upgrade")
        .arg("--fix")
        .arg("--path")
        .arg(temp_dir.path())
        .output()
        .expect("run tideway doctor");

    assert!(!output.status.success(), "combined modes should fail");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("cannot be combined"),
        "expected read-only mode error, got: {combined}"
    );
}

#[test]
fn test_doctor_detects_missing_feature() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    fs::create_dir_all(project_dir.join("src/auth")).expect("create src/auth");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;

    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let report = analyze_project(project_dir, false).expect("analyze project");
    assert!(
        report.warnings().iter().any(|w| w.contains("auth")),
        "expected auth warning, got {:?}",
        report.warnings()
    );
}

#[test]
fn test_doctor_no_warning_when_feature_present() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    fs::create_dir_all(project_dir.join("src/auth")).expect("create src/auth");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["auth"] }
"#;

    fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");
    fs::write(
        project_dir.join(".env"),
        "JWT_SECRET=0123456789abcdef0123456789abcdef\n",
    )
    .expect("write env");

    let report = analyze_project(project_dir, false).expect("analyze project");
    assert!(
        report.warnings().is_empty(),
        "expected no warnings, got {:?}",
        report.warnings()
    );
}

#[test]
fn test_doctor_warns_for_placeholder_and_short_jwt_secrets() {
    for secret in [
        "replace-with-at-least-32-random-bytes",
        "short-development-secret",
    ] {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let project_dir = temp_dir.path();
        fs::create_dir_all(project_dir.join("src/auth")).expect("create auth module");
        fs::write(
            project_dir.join("Cargo.toml"),
            r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["auth"] }
"#,
        )
        .expect("write Cargo.toml");
        fs::write(project_dir.join(".env"), format!("JWT_SECRET={secret}\n")).expect("write env");

        let report = analyze_project(project_dir, false).expect("analyze project");
        assert!(
            report
                .warnings()
                .iter()
                .any(|warning| warning.contains("JWT_SECRET")),
            "expected weak JWT warning for {secret}, got {:?}",
            report.warnings()
        );
    }
}

#[test]
fn test_doctor_warns_when_email_verification_has_no_delivery() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();
    fs::create_dir_all(project_dir.join("src/auth")).expect("create auth module");
    fs::write(
        project_dir.join("Cargo.toml"),
        r#"[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["auth"] }
"#,
    )
    .expect("write Cargo.toml");
    fs::write(
        project_dir.join(".env"),
        "JWT_SECRET=0123456789abcdef0123456789abcdef\nREQUIRE_EMAIL_VERIFICATION=true\n",
    )
    .expect("write env");
    fs::write(project_dir.join("src/main.rs"), "fn main() {}\n").expect("write main");

    let report = analyze_project(project_dir, false).expect("analyze project");
    assert!(
        report
            .warnings()
            .iter()
            .any(|warning| warning.contains("with_email_delivery")),
        "expected delivery warning, got {:?}",
        report.warnings()
    );
}

#[test]
fn test_doctor_warns_when_mfa_storage_is_still_a_stub() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();
    fs::create_dir_all(project_dir.join("src/auth")).expect("create auth module");
    fs::write(
        project_dir.join("Cargo.toml"),
        r#"[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["auth", "auth-mfa"] }
"#,
    )
    .expect("write Cargo.toml");
    fs::write(
        project_dir.join(".env"),
        "JWT_SECRET=0123456789abcdef0123456789abcdef\n",
    )
    .expect("write env");
    fs::write(
        project_dir.join("src/auth/store.rs"),
        "async fn has_mfa_enabled() { Ok(false) }\n",
    )
    .expect("write store");

    let report = analyze_project(project_dir, false).expect("analyze project");
    assert!(
        report
            .warnings()
            .iter()
            .any(|warning| warning.contains("MFA")),
        "expected MFA persistence warning, got {:?}",
        report.warnings()
    );
}

#[test]
fn test_doctor_requires_a_valid_mfa_encryption_key() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();
    fs::create_dir_all(project_dir.join("src/auth")).expect("create auth module");
    fs::write(
        project_dir.join("Cargo.toml"),
        r#"[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["auth", "auth-mfa"] }
"#,
    )
    .expect("write Cargo.toml");
    fs::write(
        project_dir.join(".env"),
        "JWT_SECRET=0123456789abcdef0123456789abcdef\nMFA_ENCRYPTION_KEY=not-a-production-key\n",
    )
    .expect("write env");

    let report = analyze_project(project_dir, false).expect("analyze project");
    assert!(
        report
            .warnings()
            .iter()
            .any(|warning| warning.contains("exactly 32 random bytes")),
        "expected invalid MFA key warning, got {:?}",
        report.warnings()
    );
}

#[test]
fn test_doctor_accepts_a_32_byte_base64_mfa_encryption_key() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();
    fs::create_dir_all(project_dir.join("src/auth")).expect("create auth module");
    fs::write(
        project_dir.join("Cargo.toml"),
        r#"[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["auth", "auth-mfa"] }
"#,
    )
    .expect("write Cargo.toml");
    fs::write(
        project_dir.join(".env"),
        concat!(
            "JWT_SECRET=0123456789abcdef0123456789abcdef\n",
            "MFA_ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        ),
    )
    .expect("write env");

    let report = analyze_project(project_dir, false).expect("analyze project");
    assert!(
        report
            .warnings()
            .iter()
            .all(|warning| !warning.contains("MFA_ENCRYPTION_KEY")),
        "expected valid MFA key to pass, got {:?}",
        report.warnings()
    );
}

#[test]
fn test_doctor_env_checks() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    std::fs::create_dir_all(project_dir.join("src/auth")).expect("create src/auth");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["auth", "database"] }
"#;
    std::fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    std::fs::write(
        project_dir.join(".env.example"),
        "DATABASE_URL=postgres://localhost/my_app\n",
    )
    .expect("write env example");

    let report = analyze_project(project_dir, false).expect("analyze project");
    assert!(
        report.warnings().iter().any(|w| w.contains("JWT_SECRET")),
        "expected JWT_SECRET warning, got {:?}",
        report.warnings()
    );
    assert!(
        report.warnings().iter().any(|w| w.contains("DATABASE_URL")),
        "expected DATABASE_URL warning, got {:?}",
        report.warnings()
    );
}

#[test]
fn test_doctor_warns_when_saas_billing_env_missing() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    tideway_cli::commands::new::run(NewArgs {
        name: Some("my_app".to_string()),
        preset: Some(NewPreset::Saas),
        features: Vec::new(),
        with_config: false,
        with_docker: false,
        with_ci: false,
        no_prompt: true,
        summary: false,
        with_env: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    })
    .expect("run tideway new");

    let report = analyze_project(&project_dir, false).expect("analyze project");
    for key in [
        "STRIPE_SECRET_KEY",
        "STRIPE_WEBHOOK_SECRET",
        "STRIPE_PRICE_ID",
    ] {
        assert!(
            report
                .warnings()
                .iter()
                .any(|warning| warning.contains(key)),
            "expected {key} warning, got {:?}",
            report.warnings()
        );
    }
}

#[test]
fn test_doctor_invalid_database_url_format() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    std::fs::create_dir_all(project_dir.join("src/database")).expect("create src/database");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
"#;
    std::fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");
    std::fs::write(project_dir.join(".env"), "DATABASE_URL=not-a-url\n").expect("write env");

    let report = analyze_project(project_dir, false).expect("analyze project");
    assert!(
        report
            .warnings()
            .iter()
            .any(|w| w.contains("DATABASE_URL looks invalid")),
        "expected DATABASE_URL invalid warning, got {:?}",
        report.warnings()
    );
}

#[test]
fn test_doctor_accepts_sqlite_database_url_format() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    std::fs::create_dir_all(project_dir.join("src/database")).expect("create src/database");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
"#;
    std::fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");
    std::fs::write(
        project_dir.join(".env"),
        "DATABASE_URL=sqlite:./my_app.db?mode=rwc\n",
    )
    .expect("write env");

    let report = analyze_project(project_dir, false).expect("analyze project");
    assert!(
        !report
            .warnings()
            .iter()
            .any(|w| w.contains("DATABASE_URL format")),
        "expected no DATABASE_URL format warning, got {:?}",
        report.warnings()
    );
}

#[test]
fn test_doctor_fix_updates_env_example_with_billing_keys() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    std::fs::create_dir_all(project_dir.join("src/billing")).expect("create src/billing");
    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["billing"] }
"#;
    std::fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");
    std::fs::write(
        project_dir.join(".env.example"),
        "# Server\nTIDEWAY_HOST=0.0.0.0\nTIDEWAY_PORT=8000\n",
    )
    .expect("write env example");

    let report = analyze_project(project_dir, true).expect("analyze project");
    let env_example =
        fs::read_to_string(project_dir.join(".env.example")).expect("read env example");

    assert!(
        env_example.contains("APP_URL=http://localhost:8000"),
        "expected APP_URL to be added, got:\n{}",
        env_example
    );
    assert!(
        env_example.contains("STRIPE_SECRET_KEY=sk_test_replace_me"),
        "expected STRIPE_SECRET_KEY to be added, got:\n{}",
        env_example
    );
    assert!(
        env_example.contains("STRIPE_WEBHOOK_SECRET=whsec_replace_me"),
        "expected STRIPE_WEBHOOK_SECRET to be added, got:\n{}",
        env_example
    );
    assert!(
        env_example.contains("STRIPE_PRICE_ID=price_replace_me"),
        "expected STRIPE_PRICE_ID to be added, got:\n{}",
        env_example
    );
    assert!(
        report
            .fixes()
            .iter()
            .any(|line| line.contains("Updated .env.example with missing keys")),
        "expected env example update fix, got {:?}",
        report.fixes()
    );
}

#[test]
fn test_doctor_log_level_info() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    std::fs::create_dir_all(project_dir.join("src")).expect("create src");
    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    std::fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let report = analyze_project(project_dir, false).expect("analyze project");
    assert!(
        report
            .info()
            .iter()
            .any(|line| line.contains("TIDEWAY_LOG_LEVEL")),
        "expected log level info, got {:?}",
        report.info()
    );
}

#[test]
fn test_doctor_package_metadata_info() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    std::fs::create_dir_all(project_dir.join("src")).expect("create src");
    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    std::fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let report = analyze_project(project_dir, false).expect("analyze project");
    assert!(
        report
            .info()
            .iter()
            .any(|line| line.contains("Package metadata missing")),
        "expected metadata info, got {:?}",
        report.info()
    );
}

#[test]
fn test_doctor_port_info() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    std::fs::create_dir_all(project_dir.join("src")).expect("create src");
    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = "0.7"
"#;
    std::fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let report = analyze_project(project_dir, false).expect("analyze project");
    assert!(
        report
            .info()
            .iter()
            .any(|line| line.contains("TIDEWAY_PORT")),
        "expected port info, got {:?}",
        report.info()
    );
}

#[test]
fn test_doctor_fix_creates_env_example() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    std::fs::create_dir_all(project_dir.join("src/database")).expect("create src/database");
    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
"#;
    std::fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let report = analyze_project(project_dir, true).expect("analyze project");
    assert!(
        project_dir.join(".env.example").exists(),
        "expected .env.example to be created"
    );
    assert!(
        report
            .fixes()
            .iter()
            .any(|line| line.contains("Created .env.example")),
        "expected creation fix, got {:?}",
        report.fixes()
    );
}

#[test]
fn test_doctor_fix_creates_env_from_env_example() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    std::fs::create_dir_all(project_dir.join("src/database")).expect("create src/database");
    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
"#;
    std::fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");
    std::fs::write(
        project_dir.join(".env.example"),
        "DATABASE_URL=postgres://localhost/my_app\n",
    )
    .expect("write env example");

    let report = analyze_project(project_dir, true).expect("analyze project");
    assert!(
        project_dir.join(".env").exists(),
        "expected .env to be created"
    );
    assert!(
        report
            .fixes()
            .iter()
            .any(|line| line.contains("Created .env from .env.example")),
        "expected env copy fix, got {:?}",
        report.fixes()
    );
    assert!(
        !report
            .warnings()
            .iter()
            .any(|line| line.contains("DATABASE_URL missing in .env")),
        "expected no stale DATABASE_URL warning after fix, got {:?}",
        report.warnings()
    );
}

#[test]
fn test_doctor_no_openapi_warning_for_api_preset_scaffold() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    tideway_cli::commands::new::run(NewArgs {
        name: Some("my_app".to_string()),
        preset: Some(NewPreset::Api),
        features: Vec::new(),
        with_config: false,
        with_docker: false,
        with_ci: false,
        no_prompt: true,
        summary: false,
        with_env: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    })
    .expect("run tideway new");

    let env_example =
        fs::read_to_string(project_dir.join(".env.example")).expect("read env example");
    fs::write(project_dir.join(".env"), env_example).expect("write env");

    let report = analyze_project(&project_dir, false).expect("analyze project");
    assert!(
        !report
            .warnings()
            .iter()
            .any(|warning| warning.contains("OpenAPI")),
        "expected no OpenAPI warnings, got {:?}",
        report.warnings()
    );
}

#[test]
fn test_doctor_no_openapi_warning_for_saas_preset_scaffold() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    tideway_cli::commands::new::run(NewArgs {
        name: Some("my_app".to_string()),
        preset: Some(NewPreset::Saas),
        features: Vec::new(),
        with_config: false,
        with_docker: false,
        with_ci: false,
        no_prompt: true,
        summary: false,
        with_env: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    })
    .expect("run tideway new");

    let env_example =
        fs::read_to_string(project_dir.join(".env.example")).expect("read env example");
    fs::write(project_dir.join(".env"), env_example).expect("write env");

    let report = analyze_project(&project_dir, false).expect("analyze project");
    assert!(
        !report
            .warnings()
            .iter()
            .any(|warning| warning.contains("OpenAPI")),
        "expected no OpenAPI warnings, got {:?}",
        report.warnings()
    );
}

#[test]
fn test_doctor_fix_recreates_sqlite_env_for_api_preset_scaffold() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    tideway_cli::commands::new::run(NewArgs {
        name: Some("my_app".to_string()),
        preset: Some(NewPreset::Api),
        features: Vec::new(),
        with_config: false,
        with_docker: false,
        with_ci: false,
        no_prompt: true,
        summary: false,
        with_env: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    })
    .expect("run tideway new");

    fs::remove_file(project_dir.join(".env")).ok();
    fs::remove_file(project_dir.join(".env.example")).expect("remove env example");

    let report = analyze_project(&project_dir, true).expect("analyze project");
    let env_example =
        fs::read_to_string(project_dir.join(".env.example")).expect("read env example");

    assert!(
        env_example.contains("DATABASE_URL=sqlite:./my_app.db?mode=rwc"),
        "expected sqlite env example, got:\n{}",
        env_example
    );
    assert!(
        report
            .fixes()
            .iter()
            .any(|line| line.contains("Created .env.example")),
        "expected env example creation fix, got {:?}",
        report.fixes()
    );
}

#[test]
fn test_doctor_fix_updates_env_example_with_missing_keys() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    std::fs::create_dir_all(project_dir.join("src/auth")).expect("create src/auth");
    std::fs::create_dir_all(project_dir.join("src/database")).expect("create src/database");
    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database", "auth"] }
"#;
    std::fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");
    std::fs::write(
        project_dir.join(".env.example"),
        "DATABASE_URL=postgres://localhost/my_app\n",
    )
    .expect("write env example");

    let report = analyze_project(project_dir, true).expect("analyze project");
    let env_example = std::fs::read_to_string(project_dir.join(".env.example")).expect("read env");
    assert!(
        env_example.contains("JWT_SECRET="),
        "expected JWT_SECRET to be added, got:\n{}",
        env_example
    );
    assert!(
        env_example.contains("TIDEWAY_HOST="),
        "expected server keys to be added, got:\n{}",
        env_example
    );
    assert!(
        report
            .fixes()
            .iter()
            .any(|line| line.contains("Updated .env.example with missing keys")),
        "expected env example update fix, got {:?}",
        report.fixes()
    );
    assert!(
        !report
            .warnings()
            .iter()
            .any(|line| line.contains("DATABASE_URL missing in .env")
                || line.contains("JWT_SECRET missing in .env")),
        "expected no stale env warnings after fix, got {:?}",
        report.warnings()
    );
}

#[test]
fn test_doctor_json_includes_summary_line() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    std::fs::create_dir_all(project_dir.join("src/database")).expect("create src/database");
    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
"#;
    std::fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let output = Command::new(env!("CARGO_BIN_EXE_tideway"))
        .arg("--json")
        .arg("doctor")
        .arg("--fix")
        .arg("--path")
        .arg(project_dir.to_str().expect("utf8 path"))
        .output()
        .expect("run tideway doctor");

    assert!(
        output.status.success(),
        "doctor command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Doctor summary:"),
        "expected summary line in JSON output, got:\n{}",
        stdout
    );
}

#[test]
fn test_doctor_openapi_missing_docs_warning() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    std::fs::create_dir_all(project_dir.join("src")).expect("create src");
    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["openapi"] }
"#;
    std::fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

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
    std::fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    let report = analyze_project(project_dir, false).expect("analyze project");
    assert!(
        report
            .warnings()
            .iter()
            .any(|line| line.contains("openapi_docs.rs")),
        "expected openapi_docs warning, got {:?}",
        report.warnings()
    );
}

#[test]
fn test_doctor_missing_migration_lib_warning() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    std::fs::create_dir_all(project_dir.join("src/database")).expect("create src/database");
    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
"#;
    std::fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");
    std::fs::write(
        project_dir.join(".env"),
        "DATABASE_URL=postgres://localhost/my_app\n",
    )
    .expect("write env");

    let report = analyze_project(project_dir, false).expect("analyze project");
    assert!(
        report
            .warnings()
            .iter()
            .any(|line| line.contains("migration/src/lib.rs")),
        "expected migration lib warning, got {:?}",
        report.warnings()
    );
}

#[test]
fn test_doctor_warns_when_db_routes_unwired() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    std::fs::create_dir_all(project_dir.join("src/routes")).expect("create src/routes");
    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#;
    std::fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");
    std::fs::write(
        project_dir.join(".env"),
        "DATABASE_URL=postgres://localhost/my_app\n",
    )
    .expect("write env");

    let routes = r#"
use axum::extract::State;
use tideway::{AppContext, Result};

async fn list(State(ctx): State<AppContext>) -> Result<()> {
    let _ = ctx.sea_orm_connection()?;
    Ok(())
}
"#;
    std::fs::write(project_dir.join("src/routes/todo.rs"), routes).expect("write route");

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
    std::fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    let report = analyze_project(project_dir, false).expect("analyze project");
    assert!(
        report
            .warnings()
            .iter()
            .any(|line| line.contains("AppContext is not wired")),
        "expected wiring warning, got {:?}",
        report.warnings()
    );
}

#[test]
fn test_doctor_reports_missing_migration_autorun() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    std::fs::create_dir_all(project_dir.join("src")).expect("create src");
    std::fs::create_dir_all(project_dir.join("migration/src")).expect("create migration");
    std::fs::write(project_dir.join("migration/src/lib.rs"), "// migration lib")
        .expect("write lib");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
"#;
    std::fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

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
    std::fs::write(project_dir.join("src/main.rs"), main_rs).expect("write main.rs");

    let report = analyze_project(project_dir, false).expect("analyze project");
    assert!(
        report
            .info()
            .iter()
            .any(|line| line.contains("Migrations detected")),
        "expected migration hint, got {:?}",
        report.info()
    );
}

#[test]
fn test_doctor_warns_when_openapi_docs_missing_routes() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    std::fs::create_dir_all(project_dir.join("src/routes")).expect("create src/routes");
    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["openapi"] }
"#;
    std::fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");

    let openapi_docs = r#"
#[cfg(feature = "openapi")]
tideway::openapi_doc!(
    pub(crate) ApiDoc,
    paths(
        crate::routes::users::list_users,
    )
);
"#;
    std::fs::write(project_dir.join("src/openapi_docs.rs"), openapi_docs)
        .expect("write openapi docs");

    let route = r#"
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/todos",
    responses((status = 200))
))]
async fn list_todos() {}
"#;
    std::fs::write(project_dir.join("src/routes/todos.rs"), route).expect("write route");

    let report = analyze_project(project_dir, false).expect("analyze project");
    assert!(
        report
            .warnings()
            .iter()
            .any(|line| line.contains("OpenAPI docs missing routes")),
        "expected openapi coverage warning, got {:?}",
        report.warnings()
    );
}

#[test]
fn test_doctor_warns_when_webhook_db_idempotency_migration_missing() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    std::fs::create_dir_all(project_dir.join("src")).expect("create src");
    std::fs::create_dir_all(project_dir.join("migration/src")).expect("create migration src");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
"#;
    std::fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");
    std::fs::write(
        project_dir.join("src/webhooks.rs"),
        r#"use tideway::webhooks::DatabaseIdempotencyStore;

fn build(db: sea_orm::DatabaseConnection) -> DatabaseIdempotencyStore {
    DatabaseIdempotencyStore::new(db)
}
"#,
    )
    .expect("write webhook src");
    std::fs::write(
        project_dir.join("migration/src/lib.rs"),
        "// no webhook migration yet",
    )
    .expect("write migration lib");

    let report = analyze_project(project_dir, false).expect("analyze project");
    assert!(
        report
            .warnings()
            .iter()
            .any(|line| line.contains("webhook_processed_events")),
        "expected webhook idempotency migration warning, got {:?}",
        report.warnings()
    );
}

#[test]
fn test_doctor_webhook_db_idempotency_no_warning_when_marker_present() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    std::fs::create_dir_all(project_dir.join("src")).expect("create src");
    std::fs::create_dir_all(project_dir.join("migration/src")).expect("create migration src");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
"#;
    std::fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");
    std::fs::write(
        project_dir.join("src/webhooks.rs"),
        r#"use tideway::webhooks::DatabaseIdempotencyStore;

fn build(db: sea_orm::DatabaseConnection) -> DatabaseIdempotencyStore {
    DatabaseIdempotencyStore::new(db)
}
"#,
    )
    .expect("write webhook src");
    std::fs::write(
        project_dir.join("migration/src/lib.rs"),
        "mod m009_create_webhook_processed_events;\n",
    )
    .expect("write migration lib");
    std::fs::write(
        project_dir.join("migration/src/m009_create_webhook_processed_events.rs"),
        "// creates webhook_processed_events table",
    )
    .expect("write migration");

    let report = analyze_project(project_dir, false).expect("analyze project");
    assert!(
        !report
            .warnings()
            .iter()
            .any(|line| line.contains("webhook_processed_events")),
        "did not expect webhook idempotency warning, got {:?}",
        report.warnings()
    );
}

#[test]
fn test_doctor_json_reports_webhook_db_idempotency_warning() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    std::fs::create_dir_all(project_dir.join("src")).expect("create src");
    std::fs::create_dir_all(project_dir.join("migration/src")).expect("create migration src");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
"#;
    std::fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");
    std::fs::write(
        project_dir.join("src/webhooks.rs"),
        "use tideway::webhooks::DatabaseIdempotencyStore;\n",
    )
    .expect("write webhook src");
    std::fs::write(
        project_dir.join("migration/src/lib.rs"),
        "// no webhook marker",
    )
    .expect("write migration lib");

    let output = Command::new(env!("CARGO_BIN_EXE_tideway"))
        .arg("--json")
        .arg("doctor")
        .arg("--path")
        .arg(project_dir.to_str().expect("utf8 path"))
        .output()
        .expect("run tideway doctor");

    assert!(
        output.status.success(),
        "doctor command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("webhook_processed_events"),
        "expected webhook idempotency warning in json output, got:\n{}",
        stdout
    );
}

#[test]
fn test_doctor_fix_includes_webhook_db_idempotency_todo_snippet() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path();

    std::fs::create_dir_all(project_dir.join("src")).expect("create src");
    std::fs::create_dir_all(project_dir.join("migration/src")).expect("create migration src");

    let cargo = r#"
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
"#;
    std::fs::write(project_dir.join("Cargo.toml"), cargo).expect("write Cargo.toml");
    std::fs::write(
        project_dir.join("src/webhooks.rs"),
        "use tideway::webhooks::DatabaseIdempotencyStore;\n",
    )
    .expect("write webhook src");
    std::fs::write(
        project_dir.join("migration/src/lib.rs"),
        "// no webhook marker",
    )
    .expect("write migration lib");

    let report = analyze_project(project_dir, true).expect("analyze project");
    assert!(
        report
            .fixes()
            .iter()
            .any(|line| line.contains("Webhook idempotency migration TODO")),
        "expected webhook idempotency TODO fix, got {:?}",
        report.fixes()
    );
}
