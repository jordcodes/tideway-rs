use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn test_golden_path_new_then_doctor_then_dev_plan() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let new_output = run_tideway(&[
        "new",
        "my_app",
        "--no-prompt",
        "--path",
        project_dir.to_str().expect("project path utf8"),
    ]);
    assert_success(&new_output, "tideway new");

    assert!(project_dir.join("Cargo.toml").exists());
    assert!(project_dir.join("src/main.rs").exists());
    assert!(project_dir.join("src/routes/mod.rs").exists());
    assert!(project_dir.join("tests/health.rs").exists());

    let doctor_output = run_tideway(&[
        "--json",
        "doctor",
        "--path",
        project_dir.to_str().expect("project path utf8"),
    ]);
    assert_success(&doctor_output, "tideway doctor");

    let doctor_stdout = String::from_utf8_lossy(&doctor_output.stdout);
    assert!(
        doctor_stdout.contains("\"level\":\"info\"")
            || doctor_stdout.contains("\"level\":\"warning\""),
        "expected doctor report output, got:\n{}",
        doctor_stdout
    );

    let dev_output = run_tideway(&[
        "--plan",
        "dev",
        "--path",
        project_dir.to_str().expect("project path utf8"),
    ]);
    assert_success(&dev_output, "tideway dev --plan");

    let dev_stdout = String::from_utf8_lossy(&dev_output.stdout);
    assert!(
        dev_stdout.contains("Plan: would run tideway dev (cargo run) with env + migrations"),
        "expected dev plan marker, got:\n{}",
        dev_stdout
    );
}

#[test]
fn test_golden_path_no_prompt_scaffold_accepts_primary_resource_flow() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let new_output = run_tideway(&[
        "new",
        "my_app",
        "--no-prompt",
        "--path",
        project_dir.to_str().expect("project path utf8"),
    ]);
    assert_success(&new_output, "tideway new");

    let resource_output = run_tideway(&[
        "resource",
        "user",
        "--wire",
        "--db",
        "--repo",
        "--service",
        "--paginate",
        "--search",
        "--path",
        project_dir.to_str().expect("project path utf8"),
    ]);
    assert_success(&resource_output, "tideway resource");

    assert!(project_dir.join("src/routes/user.rs").exists());
    assert!(project_dir.join("src/repositories/user.rs").exists());
    assert!(project_dir.join("src/services/user.rs").exists());
}

#[test]
fn test_dev_fix_env_copies_env_example_and_passes_env_to_cargo() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_minimal_project(&project_dir);
    fs::write(
        project_dir.join(".env.example"),
        "JWT_SECRET=dev-secret\nDATABASE_URL=sqlite://dev.db\n",
    )
    .expect("write .env.example");

    let fake_cargo_dir = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_cargo_dir).expect("create fake bin dir");
    let invocation_log = temp_dir.path().join("cargo-invocation.log");
    write_fake_cargo(&fake_cargo_dir, &invocation_log);

    let output = run_tideway_with_path(
        &[
            "dev",
            "--path",
            project_dir.to_str().expect("project path utf8"),
            "--fix-env",
        ],
        &fake_cargo_dir,
    );
    assert_success(&output, "tideway dev --fix-env");

    assert!(
        project_dir.join(".env").exists(),
        "expected .env to be created"
    );
    let env_contents = fs::read_to_string(project_dir.join(".env")).expect("read .env");
    assert!(
        env_contents.contains("JWT_SECRET=dev-secret"),
        "expected copied JWT_SECRET, got:\n{}",
        env_contents
    );

    let invocation = fs::read_to_string(&invocation_log).expect("read invocation log");
    assert!(
        invocation.contains("ARG:run"),
        "expected `cargo run` invocation, got:\n{}",
        invocation
    );
    assert!(
        invocation.contains("ENV:DATABASE_AUTO_MIGRATE=true"),
        "expected DATABASE_AUTO_MIGRATE env, got:\n{}",
        invocation
    );
    assert!(
        invocation.contains("ENV:JWT_SECRET=dev-secret"),
        "expected JWT_SECRET to be loaded from .env, got:\n{}",
        invocation
    );
}

#[test]
fn test_dev_warns_when_env_missing_without_fix() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_minimal_project(&project_dir);
    fs::write(project_dir.join(".env.example"), "JWT_SECRET=dev-secret\n").expect("write env");

    let fake_cargo_dir = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_cargo_dir).expect("create fake bin dir");
    let invocation_log = temp_dir.path().join("cargo-invocation.log");
    write_fake_cargo(&fake_cargo_dir, &invocation_log);

    let output = run_tideway_with_path(
        &[
            "dev",
            "--path",
            project_dir.to_str().expect("project path utf8"),
        ],
        &fake_cargo_dir,
    );
    assert_success(&output, "tideway dev");

    assert!(
        !project_dir.join(".env").exists(),
        "expected .env to remain absent without --fix-env"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Missing .env"),
        "expected missing env warning, got:\n{}",
        stdout
    );
}

fn run_tideway(args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tideway"));
    for arg in args {
        command.arg(arg);
    }
    command.output().expect("run tideway")
}

fn run_tideway_with_path(args: &[&str], fake_cargo_dir: &Path) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tideway"));
    for arg in args {
        command.arg(arg);
    }
    let current_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{}", fake_cargo_dir.display(), current_path);
    command.env("PATH", new_path);
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

fn create_minimal_project(project_dir: &Path) {
    fs::create_dir_all(project_dir.join("src")).expect("create src");
    fs::write(
        project_dir.join("Cargo.toml"),
        r#"[package]
name = "my_app"
version = "0.1.0"
edition = "2021"
"#,
    )
    .expect("write Cargo.toml");
    fs::write(project_dir.join("src/main.rs"), "fn main() {}\n").expect("write src/main.rs");
}

fn write_fake_cargo(fake_cargo_dir: &Path, invocation_log: &Path) {
    let fake_cargo = fake_cargo_dir.join("cargo");
    let script = format!(
        "#!/usr/bin/env bash\n\
set -euo pipefail\n\
log=\"{}\"\n\
echo \"ARG:$1\" > \"$log\"\n\
echo \"ENV:DATABASE_AUTO_MIGRATE=${{DATABASE_AUTO_MIGRATE:-}}\" >> \"$log\"\n\
echo \"ENV:JWT_SECRET=${{JWT_SECRET:-}}\" >> \"$log\"\n\
echo \"ENV:DATABASE_URL=${{DATABASE_URL:-}}\" >> \"$log\"\n\
exit 0\n",
        invocation_log.display()
    );
    fs::write(&fake_cargo, script).expect("write fake cargo script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&fake_cargo).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&fake_cargo, perms).expect("set executable bit");
    }
}
