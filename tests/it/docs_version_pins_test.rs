//! Guards against documentation pinning an outdated tideway version.
//!
//! `docs/upgrading.md` and `CHANGELOG.md` are excluded because they intentionally reference
//! historical versions (migration steps, rollback instructions).

use std::fs;
use std::path::{Path, PathBuf};

const EXCLUDED: &[&str] = &["upgrading.md"];

/// Extracts the version from a `tideway = "x"` or `tideway = { version = "x", ... }` line.
fn pinned_version(line: &str) -> Option<&str> {
    let rest = line.trim().strip_prefix("tideway")?.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let rest = match rest.strip_prefix('{') {
        Some(table) => {
            let idx = table.find("version")?;
            let after = table[idx + "version".len()..].trim_start();
            after.strip_prefix('=')?.trim_start()
        }
        None => rest,
    };
    let rest = rest.strip_prefix('"')?;
    rest.split('"').next()
}

fn doc_files(root: &Path) -> Vec<PathBuf> {
    let mut files = vec![root.join("README.md")];
    for entry in fs::read_dir(root.join("docs")).expect("read docs dir") {
        let path = entry.expect("docs entry").path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if path.extension().is_some_and(|ext| ext == "md") && !EXCLUDED.contains(&name.as_str()) {
            files.push(path);
        }
    }
    files
}

#[test]
fn pinned_version_parses_supported_forms() {
    assert_eq!(pinned_version(r#"tideway = "0.9.0""#), Some("0.9.0"));
    assert_eq!(
        pinned_version(r#"tideway = { version = "0.2", features = ["billing"] }"#),
        Some("0.2")
    );
    assert_eq!(
        pinned_version(r#"tideway = { path = "../tideway", features = ["websocket"] }"#),
        None
    );
    assert_eq!(pinned_version(r#"tideway-cli = "0.1""#), None);
}

#[test]
fn docs_pin_current_tideway_version() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected = env!("CARGO_PKG_VERSION");
    let mut stale = Vec::new();

    for path in doc_files(root) {
        let contents = fs::read_to_string(&path).expect("read doc");
        for (idx, line) in contents.lines().enumerate() {
            if let Some(version) = pinned_version(line)
                && version != expected
            {
                stale.push(format!(
                    "{}:{}: tideway pinned to \"{}\"",
                    path.strip_prefix(root).unwrap().display(),
                    idx + 1,
                    version
                ));
            }
        }
    }

    assert!(
        stale.is_empty(),
        "docs should pin tideway to \"{expected}\":\n{}",
        stale.join("\n")
    );
}
