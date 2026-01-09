//! Backup codes for account recovery.

/// A set of backup codes for account recovery.
#[derive(Clone, Debug)]
pub struct BackupCodes {
    /// The codes (store hashed in production).
    pub codes: Vec<String>,
}

impl BackupCodes {
    /// Format codes for display to user (grouped for readability).
    pub fn display_codes(&self) -> Vec<String> {
        self.codes
            .iter()
            .map(|c| {
                if c.len() >= 8 {
                    format!("{}-{}", &c[..4], &c[4..])
                } else {
                    c.clone()
                }
            })
            .collect()
    }
}

/// Generates cryptographically secure backup codes.
#[derive(Clone, Debug)]
pub struct BackupCodeGenerator {
    /// Number of codes to generate (default: 10).
    pub count: usize,
    /// Length of each code (default: 8).
    pub length: usize,
}

impl Default for BackupCodeGenerator {
    fn default() -> Self {
        Self {
            count: 10,
            length: 8,
        }
    }
}

impl BackupCodeGenerator {
    /// Create a new backup code generator with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the number of codes to generate.
    pub fn with_count(mut self, count: usize) -> Self {
        self.count = count;
        self
    }

    /// Set the length of each code.
    pub fn with_length(mut self, length: usize) -> Self {
        self.length = length;
        self
    }

    /// Generate a new set of backup codes.
    pub fn generate(&self) -> BackupCodes {
        use rand::Rng;

        // No 0, O, 1, I to avoid confusion
        const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

        let mut rng = rand::rngs::OsRng;
        let codes = (0..self.count)
            .map(|_| {
                (0..self.length)
                    .map(|_| {
                        let idx = rng.gen_range(0..CHARSET.len());
                        CHARSET[idx] as char
                    })
                    .collect()
            })
            .collect();

        BackupCodes { codes }
    }

    /// Verify a backup code against a list of valid codes.
    ///
    /// Returns the index of the matched code (so it can be removed), or None.
    pub fn verify(code: &str, valid_codes: &[String]) -> Option<usize> {
        // Normalize: remove dashes, uppercase
        let normalized = code.replace('-', "").to_uppercase();

        valid_codes
            .iter()
            .position(|c| constant_time_compare(c, &normalized))
    }
}

/// Constant-time string comparison to prevent timing attacks.
///
/// Uses the `subtle` crate for proper constant-time comparison that
/// doesn't leak length information through timing.
fn constant_time_compare(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_codes() {
        let generator = BackupCodeGenerator::new();
        let codes = generator.generate();

        assert_eq!(codes.codes.len(), 10);
        assert!(codes.codes.iter().all(|c| c.len() == 8));
    }

    #[test]
    fn test_verify_code() {
        let generator = BackupCodeGenerator::new();
        let codes = generator.generate();

        // Should find the first code
        let result = BackupCodeGenerator::verify(&codes.codes[0], &codes.codes);
        assert_eq!(result, Some(0));

        // Should work with dashes
        let with_dash = format!("{}-{}", &codes.codes[0][..4], &codes.codes[0][4..]);
        let result = BackupCodeGenerator::verify(&with_dash, &codes.codes);
        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_invalid_code() {
        let generator = BackupCodeGenerator::new();
        let codes = generator.generate();

        let result = BackupCodeGenerator::verify("INVALID1", &codes.codes);
        assert_eq!(result, None);
    }

    #[test]
    fn test_display_codes() {
        let codes = BackupCodes {
            codes: vec!["ABCD1234".to_string()],
        };

        assert_eq!(codes.display_codes(), vec!["ABCD-1234"]);
    }

    #[test]
    fn test_case_insensitive() {
        let generator = BackupCodeGenerator::new();
        let codes = generator.generate();

        // Lowercase should also work
        let lowercase = codes.codes[0].to_lowercase();
        let result = BackupCodeGenerator::verify(&lowercase, &codes.codes);
        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_custom_settings() {
        let generator = BackupCodeGenerator::new().with_count(5).with_length(10);

        let codes = generator.generate();

        assert_eq!(codes.codes.len(), 5);
        assert!(codes.codes.iter().all(|c| c.len() == 10));
    }
}
