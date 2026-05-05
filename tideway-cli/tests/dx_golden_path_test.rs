use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

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
fn test_golden_path_default_api_boots_and_serves_health() {
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

    patch_scaffold_to_workspace(&project_dir);

    let port = reserve_local_port();
    configure_env_example_for_boot(&project_dir, port);

    let log_path = temp_dir.path().join("tideway-dev.log");
    let stdout_log = File::create(&log_path).expect("create dev log");
    let stderr_log = stdout_log.try_clone().expect("clone dev log handle");
    let target_dir = temp_dir.path().join("cargo-target");

    let mut command = Command::new(env!("CARGO_BIN_EXE_tideway"));
    command
        .arg("dev")
        .arg("--path")
        .arg(project_dir.to_str().expect("project path utf8"))
        .env("CARGO_TARGET_DIR", &target_dir)
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log));
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command.spawn().expect("run tideway dev");

    wait_for_health(&mut child, port, Duration::from_secs(120), &log_path);

    terminate_process_tree(&mut child);
}

#[test]
fn test_golden_path_saas_scaffold_supports_doctor_and_dev_plan() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let new_output = run_tideway(&[
        "new",
        "my_app",
        "--preset",
        "saas",
        "--no-prompt",
        "--path",
        project_dir.to_str().expect("project path utf8"),
    ]);
    assert_success(&new_output, "tideway new --preset saas");
    let new_stdout = String::from_utf8_lossy(&new_output.stdout);
    assert!(
        !new_stdout.contains("`tideway backend` is advanced"),
        "expected saas preset to stay on the new-command path, got:\n{}",
        new_stdout
    );
    assert!(
        !new_stdout.contains("Add dependencies to Cargo.toml"),
        "expected saas preset to avoid backend-manual dependency guidance, got:\n{}",
        new_stdout
    );
    assert!(
        new_stdout.contains("curl http://localhost:8000/billing/public/plans"),
        "expected saas smoke check in output, got:\n{}",
        new_stdout
    );

    let doctor_output = run_tideway(&[
        "--json",
        "doctor",
        "--path",
        project_dir.to_str().expect("project path utf8"),
    ]);
    assert_success(&doctor_output, "tideway doctor");
    let doctor_stdout = String::from_utf8_lossy(&doctor_output.stdout);
    assert!(
        !doctor_stdout.contains("OpenAPI"),
        "expected saas doctor output to stay free of stale openapi warnings, got:\n{}",
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
fn test_dev_bootstraps_env_example_and_passes_env_to_cargo() {
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
        ],
        &fake_cargo_dir,
    );
    assert_success(&output, "tideway dev");

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
fn test_dev_fails_fast_when_postgres_server_is_unreachable() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");

    let new_output = run_tideway(&[
        "new",
        "my_app",
        "--no-prompt",
        "--preset",
        "api",
        "--with-docker",
        "--path",
        project_dir.to_str().expect("project path utf8"),
    ]);
    assert_success(&new_output, "tideway new --preset api --with-docker");

    let unreachable_port = reserve_local_port();
    configure_env_example_database_url(
        &project_dir,
        &format!(
            "postgres://postgres:postgres@127.0.0.1:{}/my_app",
            unreachable_port
        ),
    );

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
    assert!(
        !output.status.success(),
        "expected tideway dev to fail fast.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Problem: Postgres is not reachable"),
        "expected fail-fast Postgres problem, got:\n{}",
        combined
    );
    assert!(
        combined.contains("docker compose up -d"),
        "expected docker compose guidance, got:\n{}",
        combined
    );
    assert!(
        !invocation_log.exists(),
        "expected cargo run to be skipped when preflight fails"
    );
}

#[test]
fn test_dev_bootstraps_env_when_example_exists() {
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
        project_dir.join(".env").exists(),
        "expected .env to be created automatically"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Created .env from .env.example"),
        "expected env bootstrap message, got:\n{}",
        stdout
    );
}

#[test]
fn test_dev_ignores_dev_only_database_dependencies() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_minimal_project(&project_dir);
    fs::write(
        project_dir.join("Cargo.toml"),
        r#"[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dev-dependencies]
sea-orm = { version = "1.1", features = ["sqlx-sqlite", "runtime-tokio-rustls"] }
"#,
    )
    .expect("write Cargo.toml");

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

    let invocation = fs::read_to_string(&invocation_log).expect("read invocation log");
    assert!(
        invocation.contains("ARG:run"),
        "expected cargo run invocation, got:\n{}",
        invocation
    );
}

#[test]
fn test_migrate_accepts_sqlite_database_url() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_minimal_database_project(&project_dir);
    fs::write(
        project_dir.join(".env"),
        "DATABASE_URL=sqlite:./my_app.db?mode=rwc\n",
    )
    .expect("write .env");

    let fake_bin_dir = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin_dir).expect("create fake bin dir");
    let invocation_log = temp_dir.path().join("sea-orm-cli.log");
    write_fake_sea_orm_cli(&fake_bin_dir, &invocation_log);

    let output = run_tideway_with_path(
        &[
            "migrate",
            "status",
            "--path",
            project_dir.to_str().expect("project path utf8"),
        ],
        &fake_bin_dir,
    );
    assert_success(&output, "tideway migrate status");

    let invocation = fs::read_to_string(&invocation_log).expect("read invocation log");
    assert!(
        invocation.contains("ARG:migrate"),
        "expected sea-orm-cli migrate invocation, got:\n{}",
        invocation
    );
    assert!(
        invocation.contains("ARG:status"),
        "expected sea-orm-cli status invocation, got:\n{}",
        invocation
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

fn create_minimal_database_project(project_dir: &Path) {
    create_minimal_project(project_dir);
    fs::create_dir_all(project_dir.join("migration/src")).expect("create migration/src");
    fs::write(
        project_dir.join("Cargo.toml"),
        r#"[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[dependencies]
tideway = { version = "0.7", features = ["database"] }
sea-orm = { version = "1.1", features = ["sqlx-sqlite", "runtime-tokio-rustls"] }
"#,
    )
    .expect("write Cargo.toml");
    fs::write(
        project_dir.join("migration/src/lib.rs"),
        "// migration lib placeholder\n",
    )
    .expect("write migration lib");
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

fn write_fake_sea_orm_cli(fake_bin_dir: &Path, invocation_log: &Path) {
    let fake_sea_orm_cli = fake_bin_dir.join("sea-orm-cli");
    let script = format!(
        "#!/usr/bin/env bash\n\
set -euo pipefail\n\
log=\"{}\"\n\
echo \"ARG:$1\" > \"$log\"\n\
echo \"ARG:$2\" >> \"$log\"\n\
exit 0\n",
        invocation_log.display()
    );
    fs::write(&fake_sea_orm_cli, script).expect("write fake sea-orm-cli script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&fake_sea_orm_cli)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&fake_sea_orm_cli, perms).expect("set executable bit");
    }
}

fn patch_scaffold_to_workspace(project_dir: &Path) {
    let cargo_path = project_dir.join("Cargo.toml");
    let mut contents = fs::read_to_string(&cargo_path).expect("read Cargo.toml");
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");
    let macros_root = workspace_root.join("tideway-macros");
    contents.push_str(&format!(
        "\n[patch.crates-io]\n\
tideway = {{ path = \"{}\" }}\n\
tideway-macros = {{ path = \"{}\" }}\n",
        workspace_root.display(),
        macros_root.display()
    ));
    fs::write(cargo_path, contents).expect("write patched Cargo.toml");
}

fn configure_env_example_for_boot(project_dir: &Path, port: u16) {
    let env_example_path = project_dir.join(".env.example");
    let contents = fs::read_to_string(&env_example_path).expect("read .env.example");
    let mut updated = Vec::new();

    for line in contents.lines() {
        if line.starts_with("TIDEWAY_HOST=") {
            updated.push("TIDEWAY_HOST=127.0.0.1".to_string());
        } else if line.starts_with("TIDEWAY_PORT=") {
            updated.push(format!("TIDEWAY_PORT={}", port));
        } else {
            updated.push(line.to_string());
        }
    }

    fs::write(env_example_path, updated.join("\n") + "\n").expect("write .env.example");
}

fn configure_env_example_database_url(project_dir: &Path, database_url: &str) {
    let env_example_path = project_dir.join(".env.example");
    let contents = fs::read_to_string(&env_example_path).expect("read .env.example");
    let mut updated = Vec::new();

    for line in contents.lines() {
        if line.starts_with("DATABASE_URL=") {
            updated.push(format!("DATABASE_URL={}", database_url));
        } else {
            updated.push(line.to_string());
        }
    }

    fs::write(env_example_path, updated.join("\n") + "\n").expect("write .env.example");
}

fn reserve_local_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

fn wait_for_health(child: &mut std::process::Child, port: u16, timeout: Duration, log_path: &Path) {
    let start = Instant::now();

    loop {
        if health_check(port) {
            return;
        }

        if let Some(status) = child.try_wait().expect("poll tideway dev") {
            let log = fs::read_to_string(log_path).unwrap_or_default();
            panic!(
                "tideway dev exited before health check.\nstatus: {}\nlog:\n{}",
                status, log
            );
        }

        if start.elapsed() > timeout {
            terminate_process_tree(child);
            let log = fs::read_to_string(log_path).unwrap_or_default();
            panic!(
                "timed out waiting for /health on port {}.\nlog:\n{}",
                port, log
            );
        }

        thread::sleep(Duration::from_millis(200));
    }
}

fn health_check(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };

    if stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }

    let mut response = String::new();
    if stream.read_to_string(&mut response).is_err() {
        return false;
    }

    response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200")
}

fn terminate_process_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg("--")
            .arg(format!("-{}", child.id()))
            .status();
    }

    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }

    let _ = child.wait();
}
