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
        "Enable the `billing` feature to use tideway::billing",
        "Enable the `organizations` feature to use tideway::organizations",
        "Enable the `admin` feature to use tideway::admin",
        "Enable the `cache` feature to use tideway::cache",
        "Enable the `database` feature to use tideway::database",
        "Enable the `metrics` feature to use tideway::metrics",
        "Enable the `openapi` feature to use tideway::openapi",
        "Enable the `sessions` feature to use tideway::session",
        "Enable the `jobs` feature to use tideway::jobs",
        "Enable the `email` feature to use tideway::email",
        "Enable the `validation` feature to use tideway::validation",
        "Enable the `websocket` feature to use tideway::websocket",
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

#[test]
fn isolated_feature_builds_stay_warning_free() {
    for feature in ["billing", "database-sqlx", "openapi"] {
        let output = Command::new("cargo")
            .args([
                "check",
                "-p",
                "tideway",
                "--no-default-features",
                "--features",
                feature,
            ])
            .output()
            .unwrap_or_else(|_| panic!("run cargo check for isolated feature {feature}"));

        assert!(
            output.status.success(),
            "expected isolated feature build to succeed for {feature}.\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("unused import: `error::TidewayError`"),
            "isolated feature build leaked the core warning for {feature}.\nstderr:\n{stderr}"
        );
    }
}
