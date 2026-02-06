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
