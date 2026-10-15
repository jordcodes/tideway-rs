//! Keeps plain `cargo test` at the repo root running every first-party test suite.
//!
//! The root `Cargo.toml` is both the workspace and the `tideway` package, so without
//! `workspace.default-members` a bare `cargo test` only selects `tideway` and silently skips the
//! CLI and macro suites.

use std::path::Path;
use std::process::Command;

#[test]
fn plain_cargo_test_at_root_selects_cli_and_macros() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(cargo)
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(&root)
        .output()
        .expect("failed to run `cargo metadata`");
    assert!(
        output.status.success(),
        "`cargo metadata` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("`cargo metadata` emitted invalid JSON");
    let default_ids: Vec<&str> = metadata["workspace_default_members"]
        .as_array()
        .expect("missing `workspace_default_members`")
        .iter()
        .filter_map(|id| id.as_str())
        .collect();
    let default_names: Vec<&str> = metadata["packages"]
        .as_array()
        .expect("missing `packages`")
        .iter()
        .filter(|pkg| default_ids.contains(&pkg["id"].as_str().unwrap_or_default()))
        .filter_map(|pkg| pkg["name"].as_str())
        .collect();

    for name in ["tideway", "tideway-cli", "tideway-macros"] {
        assert!(
            default_names.contains(&name),
            "plain `cargo test` at the repo root must include `{name}`; \
             add it to `workspace.default-members` (selected: {default_names:?})"
        );
    }
}
