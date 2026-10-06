//! Guards against public macro docs being attached to hidden helpers.
//!
//! rustdoc attaches `///` comments to the next item, so docs written above a
//! `#[doc(hidden)]` helper silently disappear from the public API docs.

const SOURCES: &[(&str, &str)] = &[
    ("src/lib.rs", include_str!("../../src/lib.rs")),
    (
        "src/openapi/mod.rs",
        include_str!("../../src/openapi/mod.rs"),
    ),
    (
        "src/testing/database.rs",
        include_str!("../../src/testing/database.rs"),
    ),
    (
        "src/utils/ensure.rs",
        include_str!("../../src/utils/ensure.rs"),
    ),
];

/// Returns `(macro_name, has_doc_comment, is_hidden)` for each exported macro.
fn exported_macros(source: &str) -> Vec<(String, bool, bool)> {
    let lines: Vec<&str> = source.lines().map(str::trim).collect();
    let mut macros = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        let Some(rest) = line.strip_prefix("macro_rules!") else {
            continue;
        };
        let name = rest.trim().trim_end_matches('{').trim().to_string();

        let mut exported = false;
        let mut hidden = false;
        let mut documented = false;
        for prev in lines[..i].iter().rev() {
            if prev.starts_with("#[") {
                exported |= prev.contains("macro_export");
                hidden |= prev.contains("doc(hidden)");
            } else if prev.starts_with("///") {
                documented = true;
            } else {
                break;
            }
        }

        if exported {
            macros.push((name, documented, hidden));
        }
    }

    macros
}

#[test]
fn public_macros_are_documented_and_hidden_helpers_are_not() {
    let mut problems = Vec::new();

    for (path, source) in SOURCES {
        for (name, documented, hidden) in exported_macros(source) {
            if hidden && documented {
                problems.push(format!(
                    "{path}: hidden macro `{name}!` has doc comments (meant for a public macro?)"
                ));
            }
            if !hidden && !documented {
                problems.push(format!(
                    "{path}: public macro `{name}!` has no doc comments"
                ));
            }
        }
    }

    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn module_macro_is_documented() {
    let macros = exported_macros(include_str!("../../src/lib.rs"));
    let module = macros
        .iter()
        .find(|(name, _, _)| name == "module")
        .expect("module! should be exported from src/lib.rs");
    assert!(module.1, "module! should carry its public documentation");
    assert!(!module.2, "module! should not be doc(hidden)");
}
