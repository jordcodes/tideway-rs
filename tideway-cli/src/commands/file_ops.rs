use anyhow::{anyhow, Context, Result};
use std::path::Path;

use crate::{ensure_dir, print_warning, write_file};

pub fn write_file_with_force(path: &Path, contents: &str, force: bool) -> Result<()> {
    write_file_with_force_with_message(path, contents, force, "use --force to overwrite")
}

pub fn write_file_with_force_with_message(
    path: &Path,
    contents: &str,
    force: bool,
    skip_message: &str,
) -> Result<()> {
    if path.exists() && !force {
        print_warning(&format!(
            "Skipping {} ({})",
            path.display(),
            skip_message
        ));
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

pub fn ensure_module_decl(contents: &str, module_name: &str) -> String {
    let declaration = format!("mod {};", module_name);

    if contents.contains(declaration.as_str()) {
        return contents.to_string();
    }

    let module_decl = format!("{}\n", declaration);
    if contents.contains("mod routes;\n") {
        contents.replace("mod routes;\n", &format!("mod routes;\n{}", module_decl))
    } else {
        format!("{}{}", module_decl, contents)
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
    fn ensure_module_decl_is_idempotent() {
        let input = "mod config;\nmod services;\nmod routes;\n";
        assert_eq!(ensure_module_decl(input, "services"), input);
    }

    #[test]
    fn write_file_with_force_does_not_overwrite_without_force() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("skipped.rs");
        fs::write(&path, "original").unwrap();

        write_file_with_force(&path, "updated", false).unwrap();
        let contents = fs::read_to_string(&path).unwrap();

        assert_eq!(contents, "original");
    }

    #[test]
    fn write_file_with_force_or_error_blocks_existing_without_force() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blocked.rs");
        fs::write(&path, "original").unwrap();

        let err = write_file_with_force_or_error(&path, "updated", false, "must force").unwrap_err();
        assert!(err.to_string().contains("File already exists"));
        assert!(err.to_string().contains("must force"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "original");
    }
}
