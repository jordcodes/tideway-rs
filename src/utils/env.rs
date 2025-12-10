/// Get environment variable with TIDEWAY_ prefix, falling back to unprefixed version
///
/// This helper function checks for `TIDEWAY_{key}` first, then falls back to `{key}`
/// for compatibility with standard environment variable naming.
///
/// # Examples
///
/// ```rust
/// use tideway::utils::get_env_with_prefix;
///
/// // Checks TIDEWAY_PORT first, then PORT
/// let port = get_env_with_prefix("PORT");
///
/// // Checks TIDEWAY_LOG_LEVEL first, then LOG_LEVEL
/// let level = get_env_with_prefix("LOG_LEVEL");
/// ```
pub fn get_env_with_prefix(key: &str) -> Option<String> {
    std::env::var(format!("TIDEWAY_{}", key))
        .or_else(|_| std::env::var(key))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_env_with_prefix() {
        // Test with TIDEWAY_ prefix
        unsafe {
            std::env::set_var("TIDEWAY_TEST_VAR", "prefixed_value");
        }
        assert_eq!(get_env_with_prefix("TEST_VAR"), Some("prefixed_value".to_string()));
        unsafe {
            std::env::remove_var("TIDEWAY_TEST_VAR");
        }

        // Test with unprefixed fallback
        unsafe {
            std::env::set_var("FALLBACK_VAR", "unprefixed_value");
        }
        assert_eq!(get_env_with_prefix("FALLBACK_VAR"), Some("unprefixed_value".to_string()));
        unsafe {
            std::env::remove_var("FALLBACK_VAR");
        }

        // Test non-existent variable
        assert_eq!(get_env_with_prefix("NON_EXISTENT_VAR"), None);
    }
}
