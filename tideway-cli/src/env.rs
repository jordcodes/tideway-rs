//! Shared environment helpers for CLI commands.

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::RngCore;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::{error_contract, print_success, print_warning, write_file};

const JWT_SECRET_PLACEHOLDERS: [&str; 2] = [
    "your-super-secret-jwt-key-change-in-production",
    "replace-with-at-least-32-random-bytes",
];

pub fn ensure_project_dir(project_dir: &Path) -> Result<()> {
    let cargo_toml = project_dir.join("Cargo.toml");
    if !cargo_toml.exists() {
        return Err(anyhow::anyhow!(error_contract(
            &format!("Cargo.toml not found in {}", project_dir.display()),
            "Run this command in a Rust project root.",
            "For a new app, run `tideway new <app>` first."
        )));
    }

    let main_rs = project_dir.join("src").join("main.rs");
    if !main_rs.exists() {
        print_warning(
            "src/main.rs not found (advanced: run `tideway init` for existing projects; for greenfield apps use `tideway new <app>`)",
        );
    }

    Ok(())
}

pub fn ensure_env(project_dir: &Path, fix_env: bool) -> Result<()> {
    let env_path = project_dir.join(".env");
    if env_path.exists() {
        if fix_env {
            replace_local_secret_placeholders(&env_path)?;
        }
        return Ok(());
    }

    let env_example_path = project_dir.join(".env.example");
    if !env_example_path.exists() {
        print_warning(".env not found and .env.example is missing");
        return Ok(());
    }

    let contents = fs::read_to_string(&env_example_path)
        .with_context(|| format!("Failed to read {}", env_example_path.display()))?;
    write_file(
        &env_path,
        &replace_local_secret_placeholders_in_contents(&contents),
    )
    .with_context(|| format!("Failed to create {}", env_path.display()))?;
    print_success("Created .env from .env.example");
    Ok(())
}

fn replace_local_secret_placeholders(path: &Path) -> Result<()> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let replaced_jwt = contains_jwt_placeholder(&contents);
    let replaced_mfa = contains_empty_mfa_key(&contents);
    let updated = replace_local_secret_placeholders_in_contents(&contents);
    if updated != contents {
        write_file(path, &updated)
            .with_context(|| format!("Failed to update {}", path.display()))?;
    }
    if replaced_jwt {
        print_success("Replaced placeholder JWT_SECRET with a random local secret");
    }
    if replaced_mfa {
        print_success("Generated a random local MFA_ENCRYPTION_KEY");
    }
    Ok(())
}

fn contains_jwt_placeholder(contents: &str) -> bool {
    contents.lines().any(|line| {
        let Some((key, value)) = line.trim().split_once('=') else {
            return false;
        };
        key.trim() == "JWT_SECRET"
            && JWT_SECRET_PLACEHOLDERS.contains(&value.trim().trim_matches(['\"', '\'']))
    })
}

fn contains_empty_mfa_key(contents: &str) -> bool {
    contents.lines().any(|line| {
        let Some((key, value)) = line.trim().split_once('=') else {
            return false;
        };
        key.trim() == "MFA_ENCRYPTION_KEY" && value.trim().trim_matches(['\"', '\'']).is_empty()
    })
}

fn replace_local_secret_placeholders_in_contents(contents: &str) -> String {
    let jwt_secret = contains_jwt_placeholder(contents).then(generate_jwt_secret);
    let mfa_key = contains_empty_mfa_key(contents).then(generate_mfa_encryption_key);
    contents
        .lines()
        .map(|line| {
            let Some((key, value)) = line.trim().split_once('=') else {
                return line.to_string();
            };
            if key.trim() == "JWT_SECRET"
                && JWT_SECRET_PLACEHOLDERS.contains(&value.trim().trim_matches(['\"', '\'']))
            {
                format!(
                    "JWT_SECRET={}",
                    jwt_secret.as_deref().expect("generated above")
                )
            } else if key.trim() == "MFA_ENCRYPTION_KEY"
                && value.trim().trim_matches(['\"', '\'']).is_empty()
            {
                format!(
                    "MFA_ENCRYPTION_KEY={}",
                    mfa_key.as_deref().expect("generated above")
                )
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + if contents.ends_with('\n') { "\n" } else { "" }
}

fn generate_jwt_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn generate_mfa_encryption_key() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    STANDARD.encode(bytes)
}

pub fn read_env_map(path: &Path) -> Option<BTreeMap<String, String>> {
    let contents = fs::read_to_string(path).ok()?;
    Some(parse_env_map(&contents))
}

fn parse_env_map(contents: &str) -> BTreeMap<String, String> {
    let mut vars = BTreeMap::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim();
            if !key.is_empty() {
                let value = value.trim().trim_matches('"').trim_matches('\'');
                vars.insert(key.to_string(), value.to_string());
            }
        }
    }
    vars
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_secret_bootstrap_generates_independent_valid_values() {
        let updated = replace_local_secret_placeholders_in_contents(
            "JWT_SECRET=replace-with-at-least-32-random-bytes\nMFA_ENCRYPTION_KEY=\n",
        );
        let env = parse_env_map(&updated);
        let jwt = env.get("JWT_SECRET").expect("JWT secret");
        let mfa = env.get("MFA_ENCRYPTION_KEY").expect("MFA key");

        assert_eq!(jwt.len(), 64);
        assert_eq!(STANDARD.decode(mfa).expect("base64 MFA key").len(), 32);
        assert_ne!(jwt, mfa);
    }

    #[test]
    fn local_secret_bootstrap_preserves_user_supplied_values() {
        let contents = "JWT_SECRET=user-supplied-secret-with-at-least-32-bytes\nMFA_ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n";
        assert_eq!(
            replace_local_secret_placeholders_in_contents(contents),
            contents
        );
    }
}
