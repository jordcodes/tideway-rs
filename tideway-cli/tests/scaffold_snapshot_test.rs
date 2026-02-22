use std::fs;
use std::path::Path;

use tideway_cli::cli::{NewArgs, ResourceArgs};
use tideway_cli::commands;

#[test]
fn test_new_minimal_scaffold_snapshots() {
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
        summary: false,
        with_env: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };
    commands::new::run(args).expect("run tideway new");

    assert_file_snapshot(
        &project_dir.join("Cargo.toml"),
        "new_minimal__Cargo.toml.snap",
    );
    assert_file_snapshot(
        &project_dir.join("src/main.rs"),
        "new_minimal__src_main.rs.snap",
    );
    assert_file_snapshot(
        &project_dir.join("src/routes/mod.rs"),
        "new_minimal__src_routes_mod.rs.snap",
    );
    assert_file_snapshot(
        &project_dir.join("tests/health.rs"),
        "new_minimal__tests_health.rs.snap",
    );
}

#[test]
fn test_resource_wire_scaffold_snapshots() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let new_args = NewArgs {
        name: Some("my_app".to_string()),
        preset: None,
        features: Vec::new(),
        with_config: false,
        with_docker: false,
        with_ci: false,
        no_prompt: true,
        summary: false,
        with_env: false,
        path: Some(project_dir.to_string_lossy().to_string()),
        force: false,
    };
    commands::new::run(new_args).expect("run tideway new");

    let resource_args = ResourceArgs {
        name: "todo".to_string(),
        path: project_dir.to_string_lossy().to_string(),
        wire: true,
        with_tests: true,
        db: false,
        repo: false,
        repo_tests: false,
        service: false,
        id_type: tideway_cli::cli::ResourceIdType::Int,
        add_uuid: false,
        paginate: false,
        search: false,
        db_backend: tideway_cli::cli::DbBackend::Auto,
        profile: tideway_cli::cli::ResourceProfile::Stub,
    };
    commands::resource::run(resource_args).expect("run tideway resource");

    assert_file_snapshot(
        &project_dir.join("src/main.rs"),
        "resource_wire__src_main.rs.snap",
    );
    assert_file_snapshot(
        &project_dir.join("src/routes/mod.rs"),
        "resource_wire__src_routes_mod.rs.snap",
    );
    assert_file_snapshot(
        &project_dir.join("src/routes/todo.rs"),
        "resource_wire__src_routes_todo.rs.snap",
    );
}

fn assert_file_snapshot(actual_path: &Path, snapshot_name: &str) {
    let actual = fs::read_to_string(actual_path).expect("read generated file");
    let snapshot_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots")
        .join(snapshot_name);
    let expected = fs::read_to_string(&snapshot_path).expect("read snapshot");

    assert_eq!(
        expected,
        actual,
        "snapshot mismatch for {}.\nIf intentional, update {}",
        actual_path.display(),
        snapshot_path.display()
    );
}
