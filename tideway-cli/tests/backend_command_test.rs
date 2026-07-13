use std::fs;
use std::process::Command;

#[test]
fn test_backend_generates_webhook_processed_events_migration() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let output_dir = temp_dir.path().join("src");
    let migrations_dir = temp_dir.path().join("migration/src");

    let output = run_tideway(&[
        "backend",
        "b2c",
        "--name",
        "my_app",
        "--output",
        output_dir.to_str().expect("output dir utf8"),
        "--migrations-output",
        migrations_dir.to_str().expect("migrations dir utf8"),
    ]);
    assert_success(&output, "tideway backend b2c");

    assert!(
        migrations_dir.join("m008_create_billing_plans.rs").exists(),
        "expected m008_create_billing_plans.rs to be generated"
    );
    assert!(
        migrations_dir
            .join("m009_create_webhook_processed_events.rs")
            .exists(),
        "expected m009_create_webhook_processed_events.rs to be generated"
    );

    let lib_rs = fs::read_to_string(migrations_dir.join("lib.rs")).expect("read migration lib");
    assert!(
        lib_rs.contains("mod m009_create_webhook_processed_events;"),
        "expected m009 module declaration in lib.rs"
    );
    assert!(
        lib_rs.contains("Box::new(m009_create_webhook_processed_events::Migration),"),
        "expected m009 migration registration in lib.rs"
    );
}

#[test]
fn test_backend_migration_lib_matches_generated_files_for_b2c_and_b2b() {
    assert_migration_lib_matches_generated_files("b2c");
    assert_migration_lib_matches_generated_files("b2b");
}

#[test]
fn test_backend_billing_routes_are_mounted_with_explicit_access_boundaries() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let output_dir = temp_dir.path().join("src");
    let migrations_dir = temp_dir.path().join("migration/src");

    let output = run_tideway(&[
        "backend",
        "b2b",
        "--name",
        "my_app",
        "--output",
        output_dir.to_str().expect("output dir utf8"),
        "--migrations-output",
        migrations_dir.to_str().expect("migrations dir utf8"),
    ]);
    assert_success(&output, "tideway backend b2b");

    let main_rs = fs::read_to_string(output_dir.join("main.rs")).expect("read main.rs");
    assert!(main_rs.contains(".nest(\"/billing/public\", public_billing_routes())"));
    assert!(main_rs.contains(".nest(\"/billing\", authenticated_billing_routes())"));
    assert!(main_rs.contains(".nest(\"/billing/webhook\", billing_webhook_routes())"));
    assert!(main_rs.contains(".nest(\"/admin/billing\", admin_billing_routes())"));
    assert!(!main_rs.contains(".nest(\"/billing\", billing_routes())"));

    let billing_routes =
        fs::read_to_string(output_dir.join("billing/routes.rs")).expect("read billing routes");
    assert!(billing_routes.contains("pub fn public_billing_routes()"));
    assert!(billing_routes.contains("pub fn authenticated_billing_routes()"));
    assert!(billing_routes.contains("pub fn billing_webhook_routes()"));
    assert!(billing_routes.contains("pub fn admin_billing_routes()"));
    assert!(billing_routes.contains("authorize_billing_owner"));
    assert!(billing_routes.contains("authorize_billing_member"));
    assert!(billing_routes.contains("require_platform_admin"));
    assert!(billing_routes.contains("billing_store.claim_event(&event.id)"));
    assert!(billing_routes.contains("billing_store.release_event_claim(&event.id)"));
    assert!(billing_routes.contains("deactivate_plans_with_price(state, price_id).await?"));
}

#[test]
fn test_backend_auth_uses_shared_guards_and_atomic_token_updates() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let output_dir = temp_dir.path().join("src");
    let migrations_dir = temp_dir.path().join("migration/src");

    let output = run_tideway(&[
        "backend",
        "b2b",
        "--name",
        "my_app",
        "--output",
        output_dir.to_str().expect("output dir utf8"),
        "--migrations-output",
        migrations_dir.to_str().expect("migrations dir utf8"),
    ]);
    assert_success(&output, "tideway backend b2b");

    let routes = fs::read_to_string(output_dir.join("auth/routes.rs")).expect("read auth routes");
    assert!(routes.contains("login_rate_limiter: LoginRateLimiter"));
    assert!(routes.contains("state.mfa_tokens.clone()"));
    assert!(routes.contains("login_with_ip(request, Some(address.ip().to_string()))"));
    assert!(routes.contains("DbUserStore::from_transaction(transaction.clone())"));
    assert!(routes.contains("Arc::try_unwrap(transaction)"));

    let store = fs::read_to_string(output_dir.join("auth/store.rs")).expect("read auth store");
    assert!(store.contains("compare_and_swap_family_generation"));
    assert!(store.contains("update.rows_affected == 1"));
    assert!(store.contains("revoke_all_for_user(user_id)"));
}

fn run_tideway(args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tideway"));
    for arg in args {
        command.arg(arg);
    }
    command.output().expect("run tideway")
}

fn assert_success(output: &std::process::Output, label: &str) {
    assert!(
        output.status.success(),
        "{} failed.\nstdout:\n{}\nstderr:\n{}",
        label,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_migration_lib_matches_generated_files(preset: &str) {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let output_dir = temp_dir.path().join("src");
    let migrations_dir = temp_dir.path().join("migration/src");

    let output = run_tideway(&[
        "backend",
        preset,
        "--name",
        "my_app",
        "--output",
        output_dir.to_str().expect("output dir utf8"),
        "--migrations-output",
        migrations_dir.to_str().expect("migrations dir utf8"),
    ]);
    assert_success(&output, &format!("tideway backend {}", preset));

    let lib_rs = fs::read_to_string(migrations_dir.join("lib.rs")).expect("read migration lib");
    let migration_mods = parse_migration_mods(&lib_rs);
    assert!(
        !migration_mods.is_empty(),
        "expected migration modules in lib.rs for {}",
        preset
    );

    for module in migration_mods {
        let file_path = migrations_dir.join(format!("{}.rs", module));
        assert!(
            file_path.exists(),
            "missing migration file for module '{}' at {}",
            module,
            file_path.display()
        );
    }
}

fn parse_migration_mods(lib_rs: &str) -> Vec<String> {
    lib_rs
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("mod m") && line.ends_with(';'))
        .map(|line| {
            line.strip_prefix("mod ")
                .and_then(|rest| rest.strip_suffix(';'))
                .expect("valid mod line")
                .to_string()
        })
        .collect()
}
