use std::fs;
use std::process::Command;

use tideway_cli::cli::{NewArgs, NewPreset};
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

    let report = analyze_project(project_dir, false).expect("analyze project");
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
    fs::write(project_dir.join(".env"), "JWT_SECRET=dev-secret\n").expect("write env");

    let report = analyze_project(project_dir, false).expect("analyze project");
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

    let report = analyze_project(project_dir, false).expect("analyze project");
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
    std::fs::write(project_dir.join(".env"), "DATABASE_URL=not-a-url\n").expect("write env");

    let report = analyze_project(project_dir, false).expect("analyze project");
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("DATABASE_URL format")),
        "expected DATABASE_URL format warning, got {:?}",
        report.warnings
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
            .info
            .iter()
            .any(|line| line.contains("TIDEWAY_LOG_LEVEL")),
        "expected log level info, got {:?}",
        report.info
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
            .info
            .iter()
            .any(|line| line.contains("Package metadata missing")),
        "expected metadata info, got {:?}",
        report.info
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
        report.info.iter().any(|line| line.contains("TIDEWAY_PORT")),
        "expected port info, got {:?}",
        report.info
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
            .fixes
            .iter()
            .any(|line| line.contains("Created .env.example")),
        "expected creation fix, got {:?}",
        report.fixes
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
            .fixes
            .iter()
            .any(|line| line.contains("Created .env from .env.example")),
        "expected env copy fix, got {:?}",
        report.fixes
    );
    assert!(
        !report
            .warnings
            .iter()
            .any(|line| line.contains("DATABASE_URL missing in .env")),
        "expected no stale DATABASE_URL warning after fix, got {:?}",
        report.warnings
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
            .warnings
            .iter()
            .any(|warning| warning.contains("OpenAPI")),
        "expected no OpenAPI warnings, got {:?}",
        report.warnings
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
            .fixes
            .iter()
            .any(|line| line.contains("Updated .env.example with missing keys")),
        "expected env example update fix, got {:?}",
        report.fixes
    );
    assert!(
        !report
            .warnings
            .iter()
            .any(|line| line.contains("DATABASE_URL missing in .env")
                || line.contains("JWT_SECRET missing in .env")),
        "expected no stale env warnings after fix, got {:?}",
        report.warnings
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
            .warnings
            .iter()
            .any(|line| line.contains("openapi_docs.rs")),
        "expected openapi_docs warning, got {:?}",
        report.warnings
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
            .warnings
            .iter()
            .any(|line| line.contains("migration/src/lib.rs")),
        "expected migration lib warning, got {:?}",
        report.warnings
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
            .warnings
            .iter()
            .any(|line| line.contains("AppContext is not wired")),
        "expected wiring warning, got {:?}",
        report.warnings
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
            .info
            .iter()
            .any(|line| line.contains("Migrations detected")),
        "expected migration hint, got {:?}",
        report.info
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
            .warnings
            .iter()
            .any(|line| line.contains("OpenAPI docs missing routes")),
        "expected openapi coverage warning, got {:?}",
        report.warnings
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
            .warnings
            .iter()
            .any(|line| line.contains("webhook_processed_events")),
        "expected webhook idempotency migration warning, got {:?}",
        report.warnings
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
            .warnings
            .iter()
            .any(|line| line.contains("webhook_processed_events")),
        "did not expect webhook idempotency warning, got {:?}",
        report.warnings
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
            .fixes
            .iter()
            .any(|line| line.contains("Webhook idempotency migration TODO")),
        "expected webhook idempotency TODO fix, got {:?}",
        report.fixes
    );
}
