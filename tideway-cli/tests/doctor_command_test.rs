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

    let report = analyze_project(project_dir).expect("analyze project");
    assert!(
        report.warnings.is_empty(),
        "expected no warnings, got {:?}",
        report.warnings
    );
}
