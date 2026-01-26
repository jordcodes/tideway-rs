use std::fs;

use tideway_cli::commands::doctor::analyze_project;

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

    let report = analyze_project(project_dir).expect("analyze project");
    assert!(
        report.warnings.iter().any(|w| w.contains("auth")),
        "expected auth warning, got {:?}",
        report.warnings
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
        "JWT_SECRET=dev-secret\n",
    )
    .expect("write env");

    let report = analyze_project(project_dir).expect("analyze project");
    assert!(
        report.warnings.is_empty(),
        "expected no warnings, got {:?}",
        report.warnings
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

    let report = analyze_project(project_dir).expect("analyze project");
    assert!(
        report.warnings.iter().any(|w| w.contains("JWT_SECRET")),
        "expected JWT_SECRET warning, got {:?}",
        report.warnings
    );
    assert!(
        report.warnings.iter().any(|w| w.contains("DATABASE_URL")),
        "expected DATABASE_URL warning, got {:?}",
        report.warnings
    );
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
    std::fs::write(project_dir.join(".env"), "DATABASE_URL=not-a-url\n")
        .expect("write env");

    let report = analyze_project(project_dir).expect("analyze project");
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("DATABASE_URL format")),
        "expected DATABASE_URL format warning, got {:?}",
        report.warnings
    );
}
