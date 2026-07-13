//! TOTP (Time-based One-Time Password) support.

use crate::error::{Result, TidewayError};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use totp_rs::{Algorithm, Secret, TOTP};

/// Configuration for TOTP generation.
#[derive(Clone)]
pub struct TotpConfig {
    /// Issuer name shown in authenticator apps (e.g., "MyApp").
    pub issuer: String,
    /// Number of digits in the code (default: 6).
    pub digits: usize,
    /// Time step in seconds (default: 30).
    pub step: u64,
    /// Algorithm (default: SHA1 for compatibility).
    pub algorithm: Algorithm,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            issuer: "App".to_string(),
            digits: 6,
            step: 30,
            algorithm: Algorithm::SHA1,
        }
    }
}

impl TotpConfig {
    /// Create a new TOTP config with the given issuer name.
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            ..Default::default()
        }
    }

    /// Set the number of digits.
    pub fn digits(mut self, digits: usize) -> Self {
        self.digits = digits;
        self
    }

    /// Set the time step in seconds.
    pub fn step(mut self, step: u64) -> Self {
        self.step = step;
        self
    }
}

/// Data returned when setting up TOTP for a user.
pub struct TotpSetup {
    /// Base32-encoded secret to store in database.
    pub secret: String,
    /// URI for QR code (otpauth://...).
    pub uri: String,
    /// QR code as base64-encoded PNG (for embedding in img src).
    pub qr_code_base64: String,
}

/// Manages TOTP operations.
#[derive(Clone)]
pub struct TotpManager {
    config: TotpConfig,
}

impl TotpManager {
    /// Create a new TOTP manager with the given configuration.
    pub fn new(config: TotpConfig) -> Self {
        Self { config }
    }

    /// Generate a new TOTP setup for a user.
    ///
    /// Returns the secret, URI, and QR code for the user to scan.
    pub fn generate_setup(&self, account_name: &str) -> Result<TotpSetup> {
        let secret = Secret::generate_secret();
        let secret_base32 = secret.to_encoded().to_string();

        let totp = self.build_totp(&secret_base32, account_name)?;
        let uri = totp.get_url();

        let qr_code = totp
            .get_qr_base64()
            .map_err(|e| TidewayError::Internal(format!("Failed to generate QR code: {}", e)))?;

        Ok(TotpSetup {
            secret: secret_base32,
            uri,
            qr_code_base64: qr_code,
        })
    }

    /// Verify a TOTP code against a stored secret.
    ///
    /// Uses a window of ±1 time step to account for clock drift.
    pub fn verify(&self, secret: &str, code: &str, account_name: &str) -> Result<bool> {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(now) => Ok(self
                .verify_step_at(secret, code, account_name, now.as_secs())?
                .is_some()),
            Err(e) => {
                tracing::warn!(error = %e, "TOTP verification error (system time issue?)");
                // Return false rather than error - this is likely a clock issue
                // but we don't want to leak information about why verification failed
                Ok(false)
            }
        }
    }

    /// Verify a TOTP code and return the matched time-step counter.
    ///
    /// Persist and atomically consume this counter to prevent a valid code from
    /// being replayed during its acceptance window.
    pub fn verify_step(&self, secret: &str, code: &str, account_name: &str) -> Result<Option<u64>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                TidewayError::internal(format!("Unable to read system time for TOTP: {error}"))
            })?;
        self.verify_step_at(secret, code, account_name, now.as_secs())
    }

    /// Verify a TOTP code at a timestamp and return the matched step counter.
    pub fn verify_step_at(
        &self,
        secret: &str,
        code: &str,
        account_name: &str,
        time: u64,
    ) -> Result<Option<u64>> {
        let totp = self.build_totp(secret, account_name)?;
        let code = code.replace([' ', '-'], "");
        let current_step = time / self.config.step;
        let mut matched = None;
        for step in current_step.saturating_sub(1)..=current_step.saturating_add(1) {
            let expected = totp.generate(step.saturating_mul(self.config.step));
            if bool::from(expected.as_bytes().ct_eq(code.as_bytes())) {
                matched = Some(step);
            }
        }
        Ok(matched)
    }

    /// Verify with a specific timestamp (useful for testing).
    pub fn verify_at(
        &self,
        secret: &str,
        code: &str,
        account_name: &str,
        time: u64,
    ) -> Result<bool> {
        let totp = self.build_totp(secret, account_name)?;
        let code = code.replace([' ', '-'], "");
        Ok(totp.check(&code, time))
    }

    /// Generate the current TOTP code.
    ///
    /// This is useful for integration tests and trusted administrative tooling.
    /// Never return generated codes from an API response.
    pub fn generate_current(&self, secret: &str, account_name: &str) -> Result<String> {
        let totp = self.build_totp(secret, account_name)?;
        totp.generate_current()
            .map_err(|e| TidewayError::Internal(format!("Failed to generate TOTP: {}", e)))
    }

    fn build_totp(&self, secret: &str, account_name: &str) -> Result<TOTP> {
        TOTP::new(
            self.config.algorithm,
            self.config.digits,
            1, // 1 step skew tolerance
            self.config.step,
            Secret::Encoded(secret.to_string())
                .to_bytes()
                .map_err(|e| TidewayError::Internal(format!("Invalid TOTP secret: {}", e)))?,
            Some(self.config.issuer.clone()),
            account_name.to_string(),
        )
        .map_err(|e| TidewayError::Internal(format!("Failed to create TOTP: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_verify() {
        let manager = TotpManager::new(TotpConfig::new("TestApp"));
        let setup = manager.generate_setup("user@example.com").unwrap();

        // Generate a code and verify it
        let code = manager
            .generate_current(&setup.secret, "user@example.com")
            .unwrap();
        assert!(
            manager
                .verify(&setup.secret, &code, "user@example.com")
                .unwrap()
        );
    }

    #[test]
    fn test_verify_step_returns_exact_counter_with_skew() {
        let manager = TotpManager::new(TotpConfig::new("TestApp"));
        let setup = manager.generate_setup("user@example.com").unwrap();
        let time = 1_700_000_000;
        let previous_step = time / manager.config.step - 1;
        let code = manager
            .build_totp(&setup.secret, "user@example.com")
            .unwrap()
            .generate(previous_step * manager.config.step);

        assert_eq!(
            manager
                .verify_step_at(&setup.secret, &code, "user@example.com", time)
                .unwrap(),
            Some(previous_step)
        );
    }

    #[test]
    fn test_code_with_spaces() {
        let manager = TotpManager::new(TotpConfig::new("TestApp"));
        let setup = manager.generate_setup("user@example.com").unwrap();

        let code = manager
            .generate_current(&setup.secret, "user@example.com")
            .unwrap();
        // Add spaces like some users might copy
        let code_with_spaces = format!("{} {}", &code[..3], &code[3..]);
        assert!(
            manager
                .verify(&setup.secret, &code_with_spaces, "user@example.com")
                .unwrap()
        );
    }

    #[test]
    fn test_invalid_code() {
        let manager = TotpManager::new(TotpConfig::new("TestApp"));
        let setup = manager.generate_setup("user@example.com").unwrap();

        assert!(
            !manager
                .verify(&setup.secret, "000000", "user@example.com")
                .unwrap()
        );
    }

    #[test]
    fn test_setup_contains_qr_code() {
        let manager = TotpManager::new(TotpConfig::new("TestApp"));
        let setup = manager.generate_setup("user@example.com").unwrap();

        assert!(!setup.secret.is_empty());
        assert!(setup.uri.starts_with("otpauth://totp/"));
        assert!(!setup.qr_code_base64.is_empty());
    }
}
