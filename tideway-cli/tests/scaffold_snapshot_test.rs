use std::fs;
use std::path::Path;

use tideway_cli::cli::{NewArgs, NewPreset, ResourceArgs};
use tideway_cli::commands;

#[test]
fn test_new_minimal_scaffold_snapshots() {
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
        summary: false,
        with_env: false,
        without_invitations: false,
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
        preset: Some(NewPreset::Minimal),
        features: Vec::new(),
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
    let actual = normalize_snapshot(&fs::read_to_string(actual_path).expect("read generated file"));
    let snapshot_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots")
        .join(snapshot_name);
    let expected = normalize_snapshot(&fs::read_to_string(&snapshot_path).expect("read snapshot"));

    assert_eq!(
        expected,
        actual,
        "snapshot mismatch for {}.\nIf intentional, update {}",
        actual_path.display(),
        snapshot_path.display()
    );
}

fn normalize_snapshot(contents: &str) -> String {
    let mut normalized_lines = Vec::new();
    let mut previous_blank = false;

    for line in contents.lines() {
        let line = line.trim_end();
        let is_blank = line.is_empty();

        if is_blank && previous_blank {
            continue;
        }

        normalized_lines.push(line);
        previous_blank = is_blank;
    }

    while normalized_lines.last().is_some_and(|line| line.is_empty()) {
        normalized_lines.pop();
    }

    normalized_lines.join("\n")
}
