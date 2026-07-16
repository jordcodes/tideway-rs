use std::{fs, path::PathBuf};

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
    assert_contains(src_dir.join("main.rs"), "tideway:app-builder:start");
    assert_contains(src_dir.join("main.rs"), "tideway:app-builder:end");
    assert_contains(src_dir.join("routes/mod.rs"), "Tideway is running");
}

#[test]
fn test_init_auth_only_generates_only_the_jwt_values_it_uses() {
    let main = generate_for_modules(&["auth"]);

    assert!(main.contains("use tideway::auth::{JwtAuth, JwtAuthConfig};"));
    assert!(!main.contains("AccessTokenClaims"));
    assert!(main.contains("let jwt_issuer = jwt.issuer();"));
    assert!(!main.contains("let jwt_verifier ="));
}

#[test]
fn test_init_organizations_only_generates_only_the_jwt_values_it_uses() {
    let main = generate_for_modules(&["organizations"]);

    assert!(main.contains("AccessTokenClaims, JwtAuth, JwtAuthConfig"));
    assert!(!main.contains("let jwt_issuer = jwt.issuer();"));
    assert!(main.contains("let jwt_verifier = jwt.verifier::<AccessTokenClaims>()?;"));
}

#[test]
fn test_init_admin_generates_paired_issuer_and_verifier() {
    let main = generate_for_modules(&["admin"]);

    assert!(main.contains("let jwt_issuer = jwt.issuer();"));
    assert!(main.contains("let jwt_verifier = jwt.verifier::<AccessTokenClaims>()?;"));
}

fn generate_for_modules(modules: &[&str]) -> String {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let src_dir = temp_dir.path().join("src");
    for module in modules {
        let module_dir = src_dir.join(module);
        fs::create_dir_all(&module_dir).expect("create module dir");
        fs::write(module_dir.join("mod.rs"), "// detected module\n").expect("write module");
    }

    tideway_cli::commands::init::run(InitArgs {
        src: src_dir.to_string_lossy().to_string(),
        name: Some("my_app".to_string()),
        minimal: false,
        force: true,
        no_database: false,
        no_migrations: false,
        env_example: true,
    })
    .expect("run init");

    fs::read_to_string(src_dir.join("main.rs")).expect("read generated main")
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
