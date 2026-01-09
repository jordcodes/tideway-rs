//! Password breach checking via HaveIBeenPwned API.
//!
//! This module provides functionality to check if passwords have appeared in
//! known data breaches using the HaveIBeenPwned Pwned Passwords API.
//!
//! # Privacy
//!
//! Uses k-anonymity: only the first 5 characters of the SHA-1 hash are sent
//! to the API. The full password hash never leaves your server.
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::auth::breach::BreachChecker;
//!
//! let checker = BreachChecker::hibp();
//!
//! // Check if password has been breached
//! let result = checker.check("password123").await?;
//! if let Some(count) = result {
//!     println!("Password found in {} breaches!", count);
//! }
//! ```

use crate::error::{Result, TidewayError};
use sha1::{Digest, Sha1};
use std::time::Duration;

/// Default timeout for HIBP API requests.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

/// Default minimum breach count to consider a password compromised.
const DEFAULT_MIN_BREACH_COUNT: u32 = 1;

/// HaveIBeenPwned API endpoint for Pwned Passwords.
const HIBP_API_URL: &str = "https://api.pwnedpasswords.com/range/";

/// Configuration for breach checking.
#[derive(Clone, Debug)]
pub struct BreachCheckConfig {
    /// Timeout for API requests (default: 3 seconds).
    pub timeout: Duration,
    /// Minimum number of breaches to consider password compromised (default: 1).
    pub min_breach_count: u32,
    /// If true, API failures won't block password validation (default: true).
    pub fail_open: bool,
    /// Custom API URL (default: HaveIBeenPwned).
    pub api_url: String,
}

impl Default for BreachCheckConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            min_breach_count: DEFAULT_MIN_BREACH_COUNT,
            fail_open: true,
            api_url: HIBP_API_URL.to_string(),
        }
    }
}

impl BreachCheckConfig {
    /// Create a new config with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the request timeout.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the minimum breach count threshold.
    ///
    /// Passwords appearing in fewer breaches than this will be allowed.
    /// Set to 1 to block any breached password (default).
    #[must_use]
    pub fn min_breach_count(mut self, count: u32) -> Self {
        self.min_breach_count = count;
        self
    }

    /// Set whether to fail open (allow password) on API errors.
    ///
    /// When `true` (default), API timeouts or errors won't block registration.
    /// When `false`, API errors will reject the password.
    #[must_use]
    pub fn fail_open(mut self, fail_open: bool) -> Self {
        self.fail_open = fail_open;
        self
    }

    /// Set a custom API URL (for testing or self-hosted instances).
    #[must_use]
    pub fn api_url(mut self, url: impl Into<String>) -> Self {
        self.api_url = url.into();
        self
    }
}

/// Password breach checker using HaveIBeenPwned API.
///
/// Uses k-anonymity to check passwords without revealing them:
/// 1. SHA-1 hash the password
/// 2. Send first 5 chars of hash to API
/// 3. API returns all matching hash suffixes
/// 4. Check locally if full hash is in the list
///
/// # Example
///
/// ```rust,ignore
/// use tideway::auth::breach::BreachChecker;
/// use std::time::Duration;
///
/// // Default HIBP checker
/// let checker = BreachChecker::hibp();
///
/// // With custom configuration
/// let checker = BreachChecker::hibp()
///     .with_timeout(Duration::from_secs(5))
///     .with_min_breach_count(10)  // Only block if seen 10+ times
///     .with_fail_open(true);      // Don't block on API errors
///
/// // Check a password
/// match checker.check("password123").await? {
///     Some(count) => println!("Breached {} times!", count),
///     None => println!("Password not found in breaches"),
/// }
/// ```
#[derive(Clone, Debug)]
pub struct BreachChecker {
    config: BreachCheckConfig,
    client: reqwest::Client,
}

impl BreachChecker {
    /// Create a new breach checker with HaveIBeenPwned API.
    #[must_use]
    pub fn hibp() -> Self {
        Self::with_config(BreachCheckConfig::default())
    }

    /// Create a breach checker with custom configuration.
    #[must_use]
    pub fn with_config(config: BreachCheckConfig) -> Self {
        let client = Self::build_client(config.timeout);
        Self { config, client }
    }

    /// Set the request timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self.client = Self::build_client(timeout);
        self
    }

    /// Build HTTP client with given timeout.
    fn build_client(timeout: Duration) -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(timeout)
            .user_agent("tideway-auth")
            .build()
            .unwrap_or_default()
    }

    /// Set the minimum breach count threshold.
    #[must_use]
    pub fn with_min_breach_count(mut self, count: u32) -> Self {
        self.config.min_breach_count = count;
        self
    }

    /// Set whether to fail open on API errors.
    #[must_use]
    pub fn with_fail_open(mut self, fail_open: bool) -> Self {
        self.config.fail_open = fail_open;
        self
    }

    /// Check if a password has been seen in data breaches.
    ///
    /// Returns `Some(count)` if the password was found, where `count` is the
    /// number of times it appeared in breaches. Returns `None` if not found.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails and `fail_open` is `false`.
    /// If `fail_open` is `true` (default), API errors return `Ok(None)`.
    pub async fn check(&self, password: &str) -> Result<Option<u32>> {
        let (prefix, suffix) = self.hash_password(password);

        match self.query_api(&prefix).await {
            Ok(response) => Ok(self.find_in_response(&suffix, &response)),
            Err(e) => {
                tracing::warn!(
                    target: "auth.breach.api_error",
                    error = %e,
                    "Breach check API request failed"
                );

                if self.config.fail_open {
                    Ok(None)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Check if a password is considered breached based on configuration.
    ///
    /// Returns `true` if the password appears in breaches at least
    /// `min_breach_count` times.
    pub async fn is_breached(&self, password: &str) -> Result<bool> {
        match self.check(password).await? {
            Some(count) => Ok(count >= self.config.min_breach_count),
            None => Ok(false),
        }
    }

    /// Validate a password, returning an error if it's breached.
    ///
    /// This is a convenience method for use in registration flows.
    pub async fn validate(&self, password: &str) -> Result<()> {
        if self.is_breached(password).await? {
            tracing::info!(
                target: "auth.breach.password_blocked",
                "Password rejected: found in breach database"
            );

            Err(TidewayError::BadRequest(
                "This password has appeared in a data breach and cannot be used. \
                 Please choose a different password."
                    .to_string(),
            ))
        } else {
            Ok(())
        }
    }

    /// Hash the password and split into prefix (5 chars) and suffix.
    fn hash_password(&self, password: &str) -> (String, String) {
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        let hex = format!("{:X}", hash);

        let prefix = hex[..5].to_string();
        let suffix = hex[5..].to_string();

        (prefix, suffix)
    }

    /// Query the HIBP API with the hash prefix.
    async fn query_api(&self, prefix: &str) -> Result<String> {
        let url = format!("{}{}", self.config.api_url, prefix);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| TidewayError::Internal(format!("Breach check request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(TidewayError::Internal(format!(
                "Breach check API returned status: {}",
                response.status()
            )));
        }

        response
            .text()
            .await
            .map_err(|e| TidewayError::Internal(format!("Failed to read breach check response: {}", e)))
    }

    /// Find the hash suffix in the API response.
    ///
    /// Response format: "SUFFIX:COUNT\r\n" per line
    fn find_in_response(&self, suffix: &str, response: &str) -> Option<u32> {
        for line in response.lines() {
            if let Some((hash_suffix, count_str)) = line.split_once(':') {
                if hash_suffix.eq_ignore_ascii_case(suffix) {
                    return count_str.trim().parse().ok();
                }
            }
        }
        None
    }

    /// Get the current configuration.
    pub fn config(&self) -> &BreachCheckConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_password_format() {
        let checker = BreachChecker::hibp();
        let (prefix, suffix) = checker.hash_password("password");

        // SHA1 of "password" is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        assert_eq!(prefix.len(), 5);
        assert_eq!(suffix.len(), 35);
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn test_find_in_response() {
        let checker = BreachChecker::hibp();

        let response = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                        1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n\
                        1E4FA36A26C8D85B3F1FA8C382D1C94E682:2";

        // Should find "password" hash suffix
        let result = checker.find_in_response("1E4C9B93F3F0682250B6CF8331B7EE68FD8", response);
        assert_eq!(result, Some(9659365));

        // Should not find non-existent hash
        let result = checker.find_in_response("NOTFOUND", response);
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_in_response_case_insensitive() {
        let checker = BreachChecker::hibp();

        let response = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:100";

        // Lowercase should match uppercase
        let result = checker.find_in_response("1e4c9b93f3f0682250b6cf8331b7ee68fd8", response);
        assert_eq!(result, Some(100));
    }

    #[test]
    fn test_config_builder() {
        let config = BreachCheckConfig::new()
            .timeout(Duration::from_secs(10))
            .min_breach_count(5)
            .fail_open(false);

        assert_eq!(config.timeout, Duration::from_secs(10));
        assert_eq!(config.min_breach_count, 5);
        assert!(!config.fail_open);
    }

    #[test]
    fn test_checker_builder() {
        let checker = BreachChecker::hibp()
            .with_timeout(Duration::from_secs(10))
            .with_min_breach_count(5)
            .with_fail_open(false);

        assert_eq!(checker.config.timeout, Duration::from_secs(10));
        assert_eq!(checker.config.min_breach_count, 5);
        assert!(!checker.config.fail_open);
    }

    // Integration tests - require network access
    // Run with: cargo test --features auth-breach -- --ignored

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_hibp_api_known_breached_password() {
        let checker = BreachChecker::hibp();

        // "password" is definitely in the breach database
        let result = checker.check("password").await.unwrap();
        assert!(result.is_some());
        let count = result.unwrap();
        assert!(count > 1000, "Expected 'password' to be in many breaches, got {}", count);

        // Verify is_breached returns true
        assert!(checker.is_breached("password").await.unwrap());
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_hibp_api_likely_unique_password() {
        let checker = BreachChecker::hibp();

        // Generate a random password that's unlikely to be breached
        let unique_password = format!(
            "tideway-test-{}-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            rand::random::<u64>(),
            rand::random::<u64>()
        );

        let result = checker.check(&unique_password).await.unwrap();
        assert!(result.is_none(), "Random password should not be in breach database");
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_validate_blocks_breached_password() {
        let checker = BreachChecker::hibp();

        let result = checker.validate("password123").await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.to_string().contains("data breach"));
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_min_breach_count_threshold() {
        let checker = BreachChecker::hibp()
            .with_min_breach_count(999_999_999); // Set threshold very high

        // "password" is breached but below threshold
        let result = checker.is_breached("password").await.unwrap();
        assert!(!result, "Should not be considered breached when below threshold");
    }
}
