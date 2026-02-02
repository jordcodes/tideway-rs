use std::process::Command;

#[test]
fn feature_gate_errors_provide_actionable_messages() {
    let output = Command::new("cargo")
        .args([
            "check",
            "-p",
            "tideway",
            "--no-default-features",
            "--features",
            "feature-gate-errors",
        ])
        .output()
        .expect("run cargo check with feature-gate-errors");

    assert!(
        !output.status.success(),
        "expected check to fail.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    for expected in [
        "Enable the `auth` feature to use tideway::auth",
        "Enable the `database` feature to use tideway::database",
        "Enable the `openapi` feature to use tideway::openapi",
    ] {
        assert!(
            stderr.contains(expected),
            "missing expected compile guidance: {expected}\nstderr:\n{stderr}"
        );
    }
}

#[test]
fn feature_gate_warnings_mode_still_compiles() {
    let output = Command::new("cargo")
        .args([
            "check",
            "-p",
            "tideway",
            "--no-default-features",
            "--features",
            "feature-gate-warnings",
        ])
        .output()
        .expect("run cargo check with feature-gate-warnings");

    assert!(
        output.status.success(),
        "expected check to succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
