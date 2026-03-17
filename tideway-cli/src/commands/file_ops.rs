use anyhow::{Context, Result, anyhow};
use std::path::Path;

use crate::{ensure_dir, print_warning, write_file};

pub const FORCE_OVERWRITE_MESSAGE: &str = "use --force to overwrite";
pub const BACKEND_FORCE_OVERWRITE_MESSAGE: &str =
    "`tideway backend` is an advanced command; use --force to overwrite";
pub const INIT_FORCE_OVERWRITE_MESSAGE: &str =
    "use --force to overwrite; `tideway init` is advanced for existing projects";

pub fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .filter(|part| !part.is_empty())
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().chain(chars).collect(),
            }
        })
        .collect()
}

pub fn write_file_with_force(path: &Path, contents: &str, force: bool) -> Result<()> {
    write_file_with_force_with_message(path, contents, force, FORCE_OVERWRITE_MESSAGE)
}

pub fn write_file_with_force_with_message(
    path: &Path,
    contents: &str,
    force: bool,
    skip_message: &str,
) -> Result<()> {
    if path.exists() && !force {
        print_warning(&format!("Skipping {} ({})", path.display(), skip_message));
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        ensure_dir(parent).with_context(|| format!("Failed to create {}", parent.display()))?;
    }

    write_file(path, contents).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

pub fn write_file_with_force_or_error(
    path: &Path,
    contents: &str,
    force: bool,
    skip_message: &str,
) -> Result<()> {
    if path.exists() && !force {
        return Err(anyhow!(
            "File already exists: {} ({})",
            path.display(),
            skip_message
        ));
    }

    write_file_with_force_with_message(path, contents, true, skip_message)
}

pub fn write_file_with_force_or_error_default(
    path: &Path,
    contents: &str,
    force: bool,
) -> Result<()> {
    write_file_with_force_or_error(path, contents, force, FORCE_OVERWRITE_MESSAGE)
}

pub fn ensure_module_decl(contents: &str, module_name: &str) -> String {
    let declaration = format!("mod {};", module_name);

    if contents.contains(declaration.as_str()) {
        return contents.to_string();
    }

    let module_decl = format!("{}\n", declaration);
    if contents.contains("mod routes;\n") {
        contents.replace("mod routes;\n", &format!("mod routes;\n{}", module_decl))
    } else {
        let mut insert_at = 0usize;

        for line in contents.split_inclusive('\n') {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//!") || trimmed.starts_with("#![") || trimmed.trim().is_empty()
            {
                insert_at += line.len();
                continue;
            }
            break;
        }

        if insert_at == 0 {
            format!("{}{}", module_decl, contents)
        } else {
            format!(
                "{}{}{}",
                &contents[..insert_at],
                module_decl,
                &contents[insert_at..]
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn ensure_module_decl_inserts_before_routes_when_routes_exists() {
        let input = "mod config;\nmod routes;\nmod handlers;\n";
        assert_eq!(
            ensure_module_decl(input, "services"),
            "mod config;\nmod routes;\nmod services;\nmod handlers;\n"
        );
    }

    #[test]
    fn ensure_module_decl_inserts_at_top_when_routes_missing() {
        let input = "mod config;\nmod handlers;\n";
        assert_eq!(
            ensure_module_decl(input, "entities"),
            "mod entities;\nmod config;\nmod handlers;\n"
        );
    }

    #[test]
    fn ensure_module_decl_inserts_after_inner_doc_comments() {
        let input = "//! app docs\n\nuse tideway::App;\n";
        assert_eq!(
            ensure_module_decl(input, "routes"),
            "//! app docs\n\nmod routes;\nuse tideway::App;\n"
        );
    }

    #[test]
    fn ensure_module_decl_is_idempotent() {
        let input = "mod config;\nmod services;\nmod routes;\n";
        assert_eq!(ensure_module_decl(input, "services"), input);
    }

    #[test]
    fn to_pascal_case_handles_underscores() {
        assert_eq!(to_pascal_case("hello_world"), "HelloWorld");
    }

    #[test]
    fn to_pascal_case_skips_empty_segments() {
        assert_eq!(to_pascal_case("hello__world"), "HelloWorld");
    }

    #[test]
    fn write_file_with_force_does_not_overwrite_without_force() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("skipped.rs");
        crate::write_file(&path, "original").unwrap();

        write_file_with_force(&path, "updated", false).unwrap();
        let contents = fs::read_to_string(&path).unwrap();

        assert_eq!(contents, "original");
    }

    #[test]
    fn write_file_with_force_or_error_blocks_existing_without_force() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blocked.rs");
        crate::write_file(&path, "original").unwrap();

        let err =
            write_file_with_force_or_error(&path, "updated", false, "must force").unwrap_err();
        assert!(err.to_string().contains("File already exists"));
        assert!(err.to_string().contains("must force"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "original");
    }
}
