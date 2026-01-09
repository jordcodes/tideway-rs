//! Password hashing and validation.
//!
//! Provides secure password hashing with Argon2id and configurable password policies.
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::auth::{PasswordHasher, PasswordPolicy};
//!
//! // Hash a password
//! let hasher = PasswordHasher::default();
//! let hash = hasher.hash("my-secure-password")?;
//!
//! // Verify a password
//! let valid = hasher.verify("my-secure-password", &hash)?;
//!
//! // Validate password strength
//! let policy = PasswordPolicy::modern();
//! policy.check("weak")?; // Returns error if too weak
//! ```

use crate::error::{Result, TidewayError};

#[cfg(feature = "auth")]
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher as Argon2Hasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};

/// Configuration for password hashing.
#[derive(Clone, Debug)]
pub struct PasswordConfig {
    /// Memory cost in KiB (default: 19456 = 19MB)
    pub memory_cost: u32,
    /// Time cost / iterations (default: 2)
    pub time_cost: u32,
    /// Parallelism (default: 1)
    pub parallelism: u32,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        // OWASP recommended minimum for Argon2id
        Self {
            memory_cost: 19 * 1024, // 19 MiB
            time_cost: 2,
            parallelism: 1,
        }
    }
}

impl PasswordConfig {
    /// Create a new password config with custom settings.
    pub fn new(memory_cost: u32, time_cost: u32, parallelism: u32) -> Self {
        Self {
            memory_cost,
            time_cost,
            parallelism,
        }
    }

    /// Faster settings for development/testing (NOT for production).
    #[cfg(any(test, debug_assertions))]
    pub fn fast() -> Self {
        Self {
            memory_cost: 1024,
            time_cost: 1,
            parallelism: 1,
        }
    }
}

/// Handles password hashing and verification using Argon2id.
#[derive(Clone)]
pub struct PasswordHasher {
    config: PasswordConfig,
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self::new(PasswordConfig::default())
    }
}

impl PasswordHasher {
    /// Create a new password hasher with the given configuration.
    pub fn new(config: PasswordConfig) -> Self {
        Self { config }
    }

    /// Hash a password using Argon2id.
    ///
    /// Returns the PHC-formatted hash string (includes algorithm, params, salt, and hash).
    #[cfg(feature = "auth")]
    pub fn hash(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = self.build_argon2()?;

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| TidewayError::Internal(format!("Password hashing failed: {}", e)))
    }

    /// Verify a password against a stored hash.
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    #[cfg(feature = "auth")]
    pub fn verify(&self, password: &str, hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| TidewayError::Internal(format!("Invalid password hash format: {}", e)))?;

        // Argon2 verify is already constant-time
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    /// Check if a hash needs to be rehashed (params changed).
    ///
    /// Call this on successful login to transparently upgrade old hashes.
    #[cfg(feature = "auth")]
    pub fn needs_rehash(&self, hash: &str) -> Result<bool> {
        let parsed = PasswordHash::new(hash)
            .map_err(|e| TidewayError::Internal(format!("Invalid hash format: {}", e)))?;

        // Check if algorithm is Argon2id
        if parsed.algorithm != argon2::ARGON2ID_IDENT {
            return Ok(true);
        }

        // Check params match current config
        if let (Some(m), Some(t), Some(p)) = (
            parsed.params.get("m"),
            parsed.params.get("t"),
            parsed.params.get("p"),
        ) {
            let m: u32 = m.decimal().unwrap_or(0);
            let t: u32 = t.decimal().unwrap_or(0);
            let p: u32 = p.decimal().unwrap_or(0);

            Ok(m != self.config.memory_cost
                || t != self.config.time_cost
                || p != self.config.parallelism)
        } else {
            Ok(true)
        }
    }

    #[cfg(feature = "auth")]
    fn build_argon2(&self) -> Result<Argon2<'static>> {
        let params = Params::new(
            self.config.memory_cost,
            self.config.time_cost,
            self.config.parallelism,
            None, // Default output length (32 bytes)
        )
        .map_err(|e| TidewayError::Internal(format!("Invalid Argon2 params: {}", e)))?;

        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }

    // Stub implementations when auth feature is not enabled
    #[cfg(not(feature = "auth"))]
    pub fn hash(&self, _password: &str) -> Result<String> {
        Err(TidewayError::Internal("auth feature not enabled".into()))
    }

    #[cfg(not(feature = "auth"))]
    pub fn verify(&self, _password: &str, _hash: &str) -> Result<bool> {
        Err(TidewayError::Internal("auth feature not enabled".into()))
    }

    #[cfg(not(feature = "auth"))]
    pub fn needs_rehash(&self, _hash: &str) -> Result<bool> {
        Err(TidewayError::Internal("auth feature not enabled".into()))
    }
}

/// Password strength validation policy.
#[derive(Clone, Debug)]
pub struct PasswordPolicy {
    /// Minimum length (default: 8)
    pub min_length: usize,
    /// Require at least one uppercase letter
    pub require_uppercase: bool,
    /// Require at least one lowercase letter
    pub require_lowercase: bool,
    /// Require at least one digit
    pub require_digit: bool,
    /// Require at least one special character
    pub require_special: bool,
    /// Maximum length (default: 128, prevents DoS)
    pub max_length: usize,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordPolicy {
    /// Create a basic password policy (8+ characters).
    pub fn new() -> Self {
        Self {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            max_length: 128,
        }
    }

    /// Strict policy requiring mixed character types.
    pub fn strict() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            max_length: 128,
        }
    }

    /// Modern policy: just require length (NIST SP 800-63B recommendation).
    pub fn modern() -> Self {
        Self {
            min_length: 12,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            max_length: 128,
        }
    }

    /// Set minimum password length.
    pub fn min_length(mut self, len: usize) -> Self {
        self.min_length = len;
        self
    }

    /// Set maximum password length.
    pub fn max_length(mut self, len: usize) -> Self {
        self.max_length = len;
        self
    }

    /// Require at least one uppercase letter.
    pub fn require_uppercase(mut self) -> Self {
        self.require_uppercase = true;
        self
    }

    /// Require at least one lowercase letter.
    pub fn require_lowercase(mut self) -> Self {
        self.require_lowercase = true;
        self
    }

    /// Require at least one digit.
    pub fn require_digit(mut self) -> Self {
        self.require_digit = true;
        self
    }

    /// Require at least one special character.
    pub fn require_special(mut self) -> Self {
        self.require_special = true;
        self
    }

    /// Validate a password against the policy.
    ///
    /// Returns a list of validation errors (empty if valid).
    pub fn validate(&self, password: &str) -> Vec<PasswordError> {
        let mut errors = Vec::new();

        if password.len() < self.min_length {
            errors.push(PasswordError::TooShort {
                min: self.min_length,
            });
        }

        if password.len() > self.max_length {
            errors.push(PasswordError::TooLong {
                max: self.max_length,
            });
        }

        if self.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            errors.push(PasswordError::MissingUppercase);
        }

        if self.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            errors.push(PasswordError::MissingLowercase);
        }

        if self.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            errors.push(PasswordError::MissingDigit);
        }

        if self.require_special && !password.chars().any(is_special_char) {
            errors.push(PasswordError::MissingSpecial);
        }

        errors
    }

    /// Check if password is valid (no errors).
    pub fn is_valid(&self, password: &str) -> bool {
        self.validate(password).is_empty()
    }

    /// Validate and return Result for easy use in handlers.
    pub fn check(&self, password: &str) -> Result<()> {
        let errors = self.validate(password);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(TidewayError::BadRequest(format!(
                "Password requirements not met: {}",
                errors
                    .iter()
                    .map(|e| e.message())
                    .collect::<Vec<_>>()
                    .join(", ")
            )))
        }
    }
}

/// Password validation error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordError {
    /// Password is too short.
    TooShort { min: usize },
    /// Password is too long.
    TooLong { max: usize },
    /// Password is missing an uppercase letter.
    MissingUppercase,
    /// Password is missing a lowercase letter.
    MissingLowercase,
    /// Password is missing a digit.
    MissingDigit,
    /// Password is missing a special character.
    MissingSpecial,
}

impl PasswordError {
    /// Get a human-readable error message.
    pub fn message(&self) -> String {
        match self {
            Self::TooShort { min } => format!("must be at least {} characters", min),
            Self::TooLong { max } => format!("must be at most {} characters", max),
            Self::MissingUppercase => "must contain an uppercase letter".to_string(),
            Self::MissingLowercase => "must contain a lowercase letter".to_string(),
            Self::MissingDigit => "must contain a digit".to_string(),
            Self::MissingSpecial => "must contain a special character".to_string(),
        }
    }
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for PasswordError {}

fn is_special_char(c: char) -> bool {
    matches!(
        c,
        '!' | '@'
            | '#'
            | '$'
            | '%'
            | '^'
            | '&'
            | '*'
            | '('
            | ')'
            | '-'
            | '_'
            | '='
            | '+'
            | '['
            | ']'
            | '{'
            | '}'
            | '|'
            | '\\'
            | ';'
            | ':'
            | '\''
            | '"'
            | ','
            | '.'
            | '<'
            | '>'
            | '/'
            | '?'
            | '`'
            | '~'
    )
}

#[cfg(all(test, feature = "auth"))]
mod tests {
    use super::*;

    fn fast_hasher() -> PasswordHasher {
        PasswordHasher::new(PasswordConfig::fast())
    }

    #[test]
    fn test_hash_and_verify() {
        let hasher = fast_hasher();
        let hash = hasher.hash("correct-horse-battery-staple").unwrap();

        assert!(hasher.verify("correct-horse-battery-staple", &hash).unwrap());
        assert!(!hasher.verify("wrong-password", &hash).unwrap());
    }

    #[test]
    fn test_hash_is_unique() {
        let hasher = fast_hasher();
        let hash1 = hasher.hash("same-password").unwrap();
        let hash2 = hasher.hash("same-password").unwrap();

        // Same password should produce different hashes (different salts)
        assert_ne!(hash1, hash2);

        // But both should verify
        assert!(hasher.verify("same-password", &hash1).unwrap());
        assert!(hasher.verify("same-password", &hash2).unwrap());
    }

    #[test]
    fn test_needs_rehash() {
        let hasher = fast_hasher();
        let hash = hasher.hash("password").unwrap();

        // Same config shouldn't need rehash
        assert!(!hasher.needs_rehash(&hash).unwrap());

        // Different config should need rehash
        let different = PasswordHasher::new(PasswordConfig {
            memory_cost: 2048,
            time_cost: 3,
            parallelism: 1,
        });
        assert!(different.needs_rehash(&hash).unwrap());
    }

    #[test]
    fn test_policy_min_length() {
        let policy = PasswordPolicy::new().min_length(10);

        assert!(!policy.is_valid("short"));
        assert!(policy.is_valid("longenough!"));
    }

    #[test]
    fn test_policy_strict() {
        let policy = PasswordPolicy::strict();

        // Missing requirements
        assert!(!policy.is_valid("alllowercase"));
        assert!(!policy.is_valid("ALLUPPERCASE"));
        assert!(!policy.is_valid("NoDigitsHere!"));
        assert!(!policy.is_valid("NoSpecial123"));

        // Valid
        assert!(policy.is_valid("ValidPass123!"));
    }

    #[test]
    fn test_policy_modern() {
        let policy = PasswordPolicy::modern();

        // Just needs length
        assert!(!policy.is_valid("short"));
        assert!(policy.is_valid("this is a long passphrase with spaces"));
    }

    #[test]
    fn test_max_length_dos_protection() {
        let policy = PasswordPolicy::new();
        let long_password = "a".repeat(200);

        let errors = policy.validate(&long_password);
        assert!(errors.contains(&PasswordError::TooLong { max: 128 }));
    }

    #[test]
    fn test_error_messages() {
        let policy = PasswordPolicy::strict();
        let errors = policy.validate("weak");

        assert!(errors.iter().any(|e| matches!(e, PasswordError::TooShort { .. })));
    }

    #[test]
    fn test_check_returns_result() {
        let policy = PasswordPolicy::modern();

        assert!(policy.check("this is a long password").is_ok());
        assert!(policy.check("short").is_err());
    }
}
