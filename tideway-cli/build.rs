use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=../Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.toml");

    let version = read_workspace_version("../Cargo.toml")
        .or_else(|| read_cli_metadata_version("Cargo.toml"))
        .unwrap_or_else(|| "0.7".to_string());

    println!("cargo:rustc-env=TIDEWAY_VERSION={}", version);
}

fn read_workspace_version(path: &str) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    let value: toml::Value = contents.parse().ok()?;
    value
        .get("package")
        .and_then(|pkg| pkg.get("version"))
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
}

fn read_cli_metadata_version(path: &str) -> Option<String> {
    let contents = fs::read_to_string(Path::new(path)).ok()?;
    let value: toml::Value = contents.parse().ok()?;
    value
        .get("package")
        .and_then(|pkg| pkg.get("metadata"))
        .and_then(|meta| meta.get("tideway_version"))
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
}
