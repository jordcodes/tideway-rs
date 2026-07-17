use anyhow::{Context, Result};
use chrono::{Duration, NaiveDateTime, Utc};
use std::fs;
use std::path::Path;

use crate::error_contract;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MigrationName {
    pub module: String,
    pub file: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MigrationStyle {
    Sequential,
    Timestamp,
}

#[derive(Clone, Debug)]
struct ExistingMigration {
    module: String,
    style: MigrationStyle,
    sequential: Option<(u64, usize)>,
    timestamp: Option<NaiveDateTime>,
}

pub(crate) fn next_migration_name(
    migrations_dir: &Path,
    description: &str,
    first_sequential_number: u64,
) -> Result<MigrationName> {
    next_migration_name_at(
        migrations_dir,
        description,
        first_sequential_number,
        Utc::now().naive_utc(),
    )
}

pub(crate) fn is_migration_module(module: &str) -> bool {
    parse_migration(module).is_some()
}

fn next_migration_name_at(
    migrations_dir: &Path,
    description: &str,
    first_sequential_number: u64,
    now: NaiveDateTime,
) -> Result<MigrationName> {
    let migrations = read_migrations(migrations_dir)?;
    let style = detect_style(migrations_dir, &migrations)?;

    let module = match style {
        MigrationStyle::Sequential => {
            let mut max_number = first_sequential_number.saturating_sub(1);
            let mut width = 3usize;
            for migration in &migrations {
                if let Some((number, number_width)) = migration.sequential {
                    max_number = max_number.max(number);
                    width = width.max(number_width);
                }
            }
            let next = max_number
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("Migration number overflow"))?;
            format!("m{next:0width$}_{description}", width = width)
        }
        MigrationStyle::Timestamp => {
            let latest = migrations
                .iter()
                .filter_map(|migration| migration.timestamp)
                .max();
            let candidate = match latest {
                Some(latest) if now <= latest => latest
                    .checked_add_signed(Duration::seconds(1))
                    .ok_or_else(|| anyhow::anyhow!("Migration timestamp overflow"))?,
                _ => now,
            };
            format!("m{}_{description}", candidate.format("%Y%m%d_%H%M%S"))
        }
    };

    let file = format!("{module}.rs");
    if migrations_dir.join(&file).exists() {
        return Err(anyhow::anyhow!(error_contract(
            &format!(
                "Migration {} already exists",
                migrations_dir.join(&file).display()
            ),
            "Choose a different resource name or wait one second before retrying.",
            "Create and register an application-owned migration manually.",
        )));
    }

    Ok(MigrationName { module, file })
}

fn read_migrations(migrations_dir: &Path) -> Result<Vec<ExistingMigration>> {
    if !migrations_dir.exists() {
        return Ok(Vec::new());
    }

    let mut migrations = Vec::new();
    for entry in fs::read_dir(migrations_dir)
        .with_context(|| format!("Failed to read {}", migrations_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }
        let Some(module) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if let Some(migration) = parse_migration(module) {
            migrations.push(migration);
        }
    }
    Ok(migrations)
}

fn parse_migration(module: &str) -> Option<ExistingMigration> {
    let remainder = module.strip_prefix('m')?;
    let mut parts = remainder.split('_');
    let first = parts.next()?;
    if first.len() == 8 && first.bytes().all(|byte| byte.is_ascii_digit()) {
        let second = parts.next()?;
        if second.len() == 6 && second.bytes().all(|byte| byte.is_ascii_digit()) {
            let timestamp =
                NaiveDateTime::parse_from_str(&format!("{first}_{second}"), "%Y%m%d_%H%M%S")
                    .ok()?;
            return Some(ExistingMigration {
                module: module.to_string(),
                style: MigrationStyle::Timestamp,
                sequential: None,
                timestamp: Some(timestamp),
            });
        }
    }

    if first.is_empty() || !first.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(ExistingMigration {
        module: module.to_string(),
        style: MigrationStyle::Sequential,
        sequential: Some((first.parse().ok()?, first.len())),
        timestamp: None,
    })
}

fn detect_style(migrations_dir: &Path, migrations: &[ExistingMigration]) -> Result<MigrationStyle> {
    let has_sequential = migrations
        .iter()
        .any(|migration| migration.style == MigrationStyle::Sequential);
    let has_timestamp = migrations
        .iter()
        .any(|migration| migration.style == MigrationStyle::Timestamp);

    match (has_sequential, has_timestamp) {
        (false, false) | (true, false) => Ok(MigrationStyle::Sequential),
        (false, true) => Ok(MigrationStyle::Timestamp),
        (true, true) => registered_style(migrations_dir, migrations)?.ok_or_else(|| {
            anyhow::anyhow!(error_contract(
                "Both sequential and timestamp migration names were found, but the active convention could not be determined from migration/src/lib.rs.",
                "Register the most recent application migration in Migrator::migrations(), then retry.",
                "Create and register the new application-owned migration manually using the convention you intend to keep.",
            ))
        }),
    }
}

fn registered_style(
    migrations_dir: &Path,
    migrations: &[ExistingMigration],
) -> Result<Option<MigrationStyle>> {
    let lib_path = migrations_dir.join("lib.rs");
    if !lib_path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(&lib_path)
        .with_context(|| format!("Failed to read {}", lib_path.display()))?;
    let contents = strip_rust_comments(&contents);
    let Some(migrations_vector) = migrations_vector(&contents) else {
        return Ok(None);
    };

    let mut last_registered = None;
    for migration in migrations {
        let marker = format!("Box::new({}::Migration)", migration.module);
        if let Some(position) = migrations_vector.rfind(&marker)
            && last_registered.is_none_or(|(last_position, _)| position > last_position)
        {
            last_registered = Some((position, migration.style));
        }
    }
    Ok(last_registered.map(|(_, style)| style))
}

fn migrations_vector(contents: &str) -> Option<&str> {
    let function_start = contents.find("fn migrations")?;
    let after_function = &contents[function_start..];
    let vector_start = after_function.find("vec![")? + "vec!".len();
    let vector = &after_function[vector_start..];
    let mut depth = 0usize;
    for (index, character) in vector.char_indices() {
        match character {
            '[' => depth = depth.checked_add(1)?,
            ']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(&vector[..=index]);
                }
            }
            _ => {}
        }
    }
    None
}

fn strip_rust_comments(contents: &str) -> String {
    #[derive(Clone, Copy)]
    enum State {
        Normal,
        LineComment,
        BlockComment,
        String,
    }

    let mut output = String::with_capacity(contents.len());
    let mut characters = contents.chars().peekable();
    let mut state = State::Normal;
    let mut escaped = false;

    while let Some(character) = characters.next() {
        match state {
            State::Normal => match character {
                '/' if characters.peek() == Some(&'/') => {
                    characters.next();
                    state = State::LineComment;
                    output.push(' ');
                }
                '/' if characters.peek() == Some(&'*') => {
                    characters.next();
                    state = State::BlockComment;
                    output.push(' ');
                }
                '"' => {
                    state = State::String;
                    escaped = false;
                    output.push(character);
                }
                _ => output.push(character),
            },
            State::LineComment => {
                if character == '\n' {
                    state = State::Normal;
                    output.push('\n');
                }
            }
            State::BlockComment => {
                if character == '*' && characters.peek() == Some(&'/') {
                    characters.next();
                    state = State::Normal;
                    output.push(' ');
                } else if character == '\n' {
                    output.push('\n');
                }
            }
            State::String => {
                output.push(character);
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    state = State::Normal;
                }
            }
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::write_file;

    fn fixed_time() -> NaiveDateTime {
        NaiveDateTime::parse_from_str("20260717_143012", "%Y%m%d_%H%M%S").unwrap()
    }

    #[test]
    fn sequential_names_preserve_width_and_increment() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("m014_existing.rs"), "").unwrap();
        let name = next_migration_name_at(dir.path(), "create_widgets", 1, fixed_time()).unwrap();
        assert_eq!(name.module, "m015_create_widgets");
        assert_eq!(name.file, "m015_create_widgets.rs");
    }

    #[test]
    fn timestamp_names_preserve_seaorm_convention() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("m20260716_120000_existing.rs"), "").unwrap();
        let name = next_migration_name_at(dir.path(), "create_widgets", 1, fixed_time()).unwrap();
        assert_eq!(name.module, "m20260717_143012_create_widgets");
    }

    #[test]
    fn timestamp_names_stay_monotonic_when_clock_is_not_ahead() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("m20260718_090000_existing.rs"), "").unwrap();
        let name = next_migration_name_at(dir.path(), "create_widgets", 1, fixed_time()).unwrap();
        assert_eq!(name.module, "m20260718_090001_create_widgets");
    }

    #[test]
    fn mixed_history_uses_last_registered_convention() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("m014_existing.rs"), "").unwrap();
        write_file(&dir.path().join("m20260716_120000_newer.rs"), "").unwrap();
        write_file(
            &dir.path().join("lib.rs"),
            "fn migrations() {\nvec![\nBox::new(m014_existing::Migration),\nBox::new(m20260716_120000_newer::Migration),\n]\n}\n",
        )
        .unwrap();
        let name = next_migration_name_at(dir.path(), "create_widgets", 1, fixed_time()).unwrap();
        assert_eq!(name.module, "m20260717_143012_create_widgets");
    }

    #[test]
    fn ambiguous_mixed_history_fails_instead_of_guessing() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("m014_existing.rs"), "").unwrap();
        write_file(&dir.path().join("m20260716_120000_newer.rs"), "").unwrap();
        let error = next_migration_name_at(dir.path(), "create_widgets", 1, fixed_time())
            .unwrap_err()
            .to_string();
        assert!(error.contains("Both sequential and timestamp migration names were found"));
    }

    #[test]
    fn commented_registration_does_not_change_mixed_history_style() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("m014_existing.rs"), "").unwrap();
        write_file(&dir.path().join("m20260716_120000_newer.rs"), "").unwrap();
        write_file(
            &dir.path().join("lib.rs"),
            "fn migrations() {\nvec![\nBox::new(m014_existing::Migration),\n// Box::new(m20260716_120000_newer::Migration),\n]\n}\n",
        )
        .unwrap();

        let name = next_migration_name_at(dir.path(), "create_widgets", 1, fixed_time()).unwrap();

        assert_eq!(name.module, "m015_create_widgets");
    }

    #[test]
    fn registration_text_outside_migrations_vector_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("m014_existing.rs"), "").unwrap();
        write_file(&dir.path().join("m20260716_120000_newer.rs"), "").unwrap();
        write_file(
            &dir.path().join("lib.rs"),
            "fn migrations() {\nvec![\nBox::new(m014_existing::Migration),\n]\n}\nconst EXAMPLE: &str = \"Box::new(m20260716_120000_newer::Migration)\";\n",
        )
        .unwrap();

        let name = next_migration_name_at(dir.path(), "create_widgets", 1, fixed_time()).unwrap();

        assert_eq!(name.module, "m015_create_widgets");
    }
}
