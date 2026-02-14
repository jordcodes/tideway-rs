use anyhow::{Context, Result};
use std::path::Path;

use crate::{ensure_dir, print_warning, write_file};

pub fn write_file_with_force(path: &Path, contents: &str, force: bool) -> Result<()> {
    if path.exists() && !force {
        print_warning(&format!(
            "Skipping {} (use --force to overwrite)",
            path.display()
        ));
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        ensure_dir(parent).with_context(|| format!("Failed to create {}", parent.display()))?;
    }

    write_file(path, contents).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
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
