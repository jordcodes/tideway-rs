//! Shared database URL helpers for CLI commands.

use anyhow::{Result, anyhow};
use std::collections::BTreeMap;
use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseUrlKind {
    Postgres,
    Sqlite,
}

pub fn resolve_database_url(env_map: &Option<BTreeMap<String, String>>) -> Option<String> {
    match std::env::var("DATABASE_URL") {
        Ok(value) => return non_empty_trimmed(value),
        Err(std::env::VarError::NotPresent) => {}
        Err(std::env::VarError::NotUnicode(_)) => return None,
    }

    env_map
        .as_ref()
        .and_then(|map| map.get("DATABASE_URL"))
        .cloned()
        .and_then(non_empty_trimmed)
}

fn non_empty_trimmed(value: String) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

pub fn validate_database_url(value: &str) -> Result<DatabaseUrlKind> {
    let trimmed = value.trim();
    let lower = trimmed.to_lowercase();

    if lower.starts_with("sqlite:") {
        return Ok(DatabaseUrlKind::Sqlite);
    }

    if lower.starts_with("postgres://") || lower.starts_with("postgresql://") {
        return Ok(DatabaseUrlKind::Postgres);
    }

    // Never echo the full URL: it may contain credentials. Only a well-formed
    // scheme (letters, digits, `+`, `-`, `.`) is safe to show.
    if let Some((scheme, _)) = trimmed.split_once("://") {
        let is_plain_scheme = !scheme.is_empty()
            && scheme
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'));
        if is_plain_scheme {
            return Err(anyhow!(format!(
                "DATABASE_URL scheme looks invalid: {}://",
                scheme
            )));
        }
        return Err(anyhow!("DATABASE_URL scheme looks invalid"));
    }

    Err(anyhow!(
        "DATABASE_URL looks invalid (missing scheme); expected postgres://, postgresql://, or sqlite:"
    ))
}

pub fn redact_database_url(database_url: &str) -> String {
    if let Ok(mut parsed) = Url::parse(database_url) {
        if parsed.password().is_some() {
            let _ = parsed.set_password(Some("[REDACTED]"));
        }
        return parsed.to_string();
    }

    if let Some(at_pos) = database_url.find('@')
        && let Some(colon_pos) = database_url[..at_pos].rfind(':')
        && let Some(scheme_end) = database_url.find("://")
        && colon_pos > scheme_end + 3
    {
        return format!(
            "{}[REDACTED]{}",
            &database_url[..colon_pos + 1],
            &database_url[at_pos..]
        );
    }

    database_url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_database_url_accepts_sqlite_without_slashes() {
        let kind = validate_database_url("sqlite:./my_app.db?mode=rwc").expect("sqlite url");
        assert_eq!(kind, DatabaseUrlKind::Sqlite);
    }

    #[test]
    fn test_validate_database_url_errors_do_not_leak_credentials() {
        let invalid_scheme = validate_database_url("mysql://root:hunter2@db/app")
            .expect_err("mysql url should be rejected")
            .to_string();
        assert!(!invalid_scheme.contains("hunter2"), "{}", invalid_scheme);
        assert!(invalid_scheme.contains("mysql://"), "{}", invalid_scheme);

        let missing_scheme = validate_database_url("user:hunter2@host/db")
            .expect_err("missing scheme should be rejected")
            .to_string();
        assert!(!missing_scheme.contains("hunter2"), "{}", missing_scheme);
        assert!(
            missing_scheme.contains("missing scheme"),
            "{}",
            missing_scheme
        );

        let odd_scheme = validate_database_url("user:hunter2@host://db")
            .expect_err("malformed scheme should be rejected")
            .to_string();
        assert!(!odd_scheme.contains("hunter2"), "{}", odd_scheme);
    }

    #[test]
    fn test_redact_database_url_hides_password() {
        let redacted = redact_database_url("postgres://postgres:secret@localhost:5432/my_app");
        assert!(
            redacted.contains("[REDACTED]") || redacted.contains("%5BREDACTED%5D"),
            "expected redaction marker, got {}",
            redacted
        );
        assert!(
            !redacted.contains("secret"),
            "password leaked in {}",
            redacted
        );
    }
}
