//! Keeps the Tideway version scaffolded by the CLI in sync with the framework release.
//!
//! Workspace builds read the framework version from the root `Cargo.toml`, while the published
//! CLI falls back to `package.metadata.tideway_version`. If they drift, the published CLI
//! scaffolds apps against a different (possibly semver-incompatible) Tideway release.

use std::path::Path;

fn read_manifest(path: &Path) -> toml::Value {
    std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
        .parse()
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn str_at<'a>(value: &'a toml::Value, keys: &[&str]) -> &'a str {
    keys.iter()
        .try_fold(value, |value, key| value.get(key))
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("missing `{}`", keys.join(".")))
}

#[test]
fn cli_metadata_tideway_version_matches_framework_version() {
    let cli_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let framework = read_manifest(&cli_dir.join("../Cargo.toml"));
    let cli = read_manifest(&cli_dir.join("Cargo.toml"));

    let framework_version = str_at(&framework, &["package", "version"]);
    let metadata_version = str_at(&cli, &["package", "metadata", "tideway_version"]);

    assert_eq!(
        metadata_version, framework_version,
        "tideway-cli `package.metadata.tideway_version` must match the framework version"
    );
    assert_eq!(tideway_cli::TIDEWAY_VERSION, framework_version);
}
