use std::fs;
use std::process::Command;

#[test]
fn test_new_then_backend_warns_and_preserves_main_without_force() {
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

    let main_path = project_dir.join("src/main.rs");
    let main_before = fs::read_to_string(&main_path).expect("read scaffolded main.rs");

    let backend_output = run_tideway(&[
        "backend",
        "b2c",
        "--name",
        "my_app",
        "--output",
        project_dir
            .join("src")
            .to_str()
            .expect("project src path utf8"),
        "--migrations-output",
        project_dir
            .join("migration/src")
            .to_str()
            .expect("project migration path utf8"),
    ]);
    assert_success(&backend_output, "tideway backend b2c");

    let stdout = String::from_utf8_lossy(&backend_output.stdout);
    assert!(
        stdout.contains("`tideway backend` is advanced. For greenfield apps, prefer `tideway new <app>`."),
        "expected advanced backend warning in mixed flow, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("`tideway backend` is an advanced command; use --force to overwrite"),
        "expected overwrite guidance for mixed flow, got:\n{}",
        stdout
    );

    let main_after = fs::read_to_string(&main_path).expect("read main.rs after backend");
    assert_eq!(
        main_before, main_after,
        "expected backend to avoid overwriting scaffolded main.rs without --force"
    );
}

#[test]
fn test_new_then_init_surfaces_primary_path_guidance() {
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

    let main_path = project_dir.join("src/main.rs");
    let main_before = fs::read_to_string(&main_path).expect("read scaffolded main.rs");

    let init_output = Command::new(env!("CARGO_BIN_EXE_tideway"))
        .arg("init")
        .arg("--src")
        .arg(project_dir.join("src"))
        .current_dir(&project_dir)
        .output()
        .expect("run tideway init");
    assert_success(&init_output, "tideway init");

    let stdout = String::from_utf8_lossy(&init_output.stdout);
    assert!(
        stdout.contains("No modules detected. Advanced fix: run `tideway backend`"),
        "expected no-modules advanced guidance in mixed flow, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("For greenfield apps, use the primary path"),
        "expected primary path reminder in mixed flow, got:\n{}",
        stdout
    );

    let main_after = fs::read_to_string(&main_path).expect("read main.rs after init");
    assert_eq!(
        main_before, main_after,
        "expected init mixed flow to keep scaffolded main.rs unchanged"
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
