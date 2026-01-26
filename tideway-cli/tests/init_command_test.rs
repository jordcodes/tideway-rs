use std::path::PathBuf;

use tideway_cli::cli::InitArgs;

#[test]
fn test_init_minimal_generates_files() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let src_dir = temp_dir.path().join("src");

    let args = InitArgs {
        src: src_dir.to_string_lossy().to_string(),
        name: Some("my_app".to_string()),
        minimal: true,
        force: true,
        no_database: false,
        no_migrations: false,
        env_example: false,
    };

    tideway_cli::commands::init::run(args).expect("run init");

    assert_contains(src_dir.join("main.rs"), "App::new()");
    assert_contains(src_dir.join("routes/mod.rs"), "Tideway is running");
}

fn assert_contains(path: PathBuf, needle: &str) {
    let contents = std::fs::read_to_string(&path).expect("read file");
    assert!(
        contents.contains(needle),
        "expected {} to contain {}",
        path.display(),
        needle
    );
}
