//! Internal utilities for the organizations module.

use std::time::{SystemTime, UNIX_EPOCH};

/// Get current Unix timestamp in seconds.
#[inline]
pub(crate) fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

/// Basic email format validation.
///
/// Checks that the email:
/// - Contains exactly one `@` symbol
/// - Has at least one character before `@`
/// - Has at least one `.` after `@`
/// - Has at least one character after the last `.`
///
/// This is not RFC 5322 compliant but catches obvious formatting errors.
#[inline]
pub(crate) fn is_valid_email(email: &str) -> bool {
    let email = email.trim();

    // Must contain exactly one @
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let local = parts[0];
    let domain = parts[1];

    // Local part must not be empty
    if local.is_empty() {
        return false;
    }

    // Domain must contain at least one dot
    if !domain.contains('.') {
        return false;
    }

    // Domain must not start or end with a dot
    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }

    // Must have something after the last dot (TLD)
    if let Some(tld) = domain.rsplit('.').next() {
        if tld.is_empty() {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_emails() {
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("user.name@example.com"));
        assert!(is_valid_email("user@sub.example.com"));
        assert!(is_valid_email("user+tag@example.com"));
    }

    #[test]
    fn test_invalid_emails() {
        assert!(!is_valid_email(""));
        assert!(!is_valid_email("user"));
        assert!(!is_valid_email("@example.com"));
        assert!(!is_valid_email("user@"));
        assert!(!is_valid_email("user@example"));
        assert!(!is_valid_email("user@@example.com"));
        assert!(!is_valid_email("user@.example.com"));
        assert!(!is_valid_email("user@example."));
    }
}
