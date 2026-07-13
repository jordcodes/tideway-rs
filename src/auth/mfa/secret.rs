//! Authenticated encryption for TOTP secrets.

use crate::{Result, TidewayError};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng, Payload, rand_core::RngCore},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::fmt;

const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;
const FORMAT_PREFIX: &str = "v1.";

/// Encrypts TOTP secrets with AES-256-GCM and binds ciphertext to a user ID.
#[derive(Clone)]
pub struct MfaSecretCipher {
    cipher: Aes256Gcm,
}

impl MfaSecretCipher {
    /// Construct a cipher from a base64-encoded 32-byte key.
    pub fn from_base64(key: &str) -> Result<Self> {
        let mut decoded = STANDARD
            .decode(key.trim())
            .map_err(|_| TidewayError::bad_request("MFA encryption key must be valid base64"))?;
        if decoded.len() != KEY_LENGTH {
            decoded.fill(0);
            return Err(TidewayError::bad_request(
                "MFA encryption key must decode to exactly 32 bytes",
            ));
        }
        let cipher = Aes256Gcm::new_from_slice(&decoded)
            .map_err(|_| TidewayError::internal("Unable to initialize MFA encryption"))?;
        decoded.fill(0);

        Ok(Self { cipher })
    }

    /// Construct a cipher from a required environment variable.
    pub fn from_env(name: &str) -> Result<Self> {
        let key = std::env::var(name).map_err(|_| {
            TidewayError::bad_request(format!(
                "{name} is required when the auth-mfa feature is enabled"
            ))
        })?;
        Self::from_base64(&key)
    }

    /// Encrypt a TOTP secret, using the user ID as authenticated associated data.
    pub fn encrypt(&self, user_id: &str, secret: &str) -> Result<String> {
        let mut nonce_bytes = [0_u8; NONCE_LENGTH];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: secret.as_bytes(),
                    aad: user_id.as_bytes(),
                },
            )
            .map_err(|_| TidewayError::internal("Unable to encrypt MFA secret"))?;

        let mut encoded = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
        encoded.extend_from_slice(&nonce_bytes);
        encoded.extend_from_slice(&ciphertext);
        Ok(format!("{FORMAT_PREFIX}{}", STANDARD.encode(encoded)))
    }

    /// Decrypt a TOTP secret for the expected user ID.
    pub fn decrypt(&self, user_id: &str, encrypted: &str) -> Result<String> {
        let encoded = encrypted
            .strip_prefix(FORMAT_PREFIX)
            .ok_or_else(|| TidewayError::internal("Unsupported MFA secret encryption format"))?;
        let payload = STANDARD
            .decode(encoded)
            .map_err(|_| TidewayError::internal("Invalid MFA secret ciphertext"))?;
        if payload.len() <= NONCE_LENGTH {
            return Err(TidewayError::internal("Invalid MFA secret ciphertext"));
        }

        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(&payload[..NONCE_LENGTH]),
                Payload {
                    msg: &payload[NONCE_LENGTH..],
                    aad: user_id.as_bytes(),
                },
            )
            .map_err(|_| TidewayError::internal("Unable to decrypt MFA secret"))?;
        String::from_utf8(plaintext)
            .map_err(|_| TidewayError::internal("Decrypted MFA secret is not valid UTF-8"))
    }
}

impl fmt::Debug for MfaSecretCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MfaSecretCipher")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher() -> MfaSecretCipher {
        MfaSecretCipher::from_base64(&STANDARD.encode([7_u8; KEY_LENGTH])).unwrap()
    }

    #[test]
    fn round_trips_secret_for_same_user() {
        let cipher = cipher();
        let encrypted = cipher.encrypt("user-1", "JBSWY3DPEHPK3PXP").unwrap();

        assert_ne!(encrypted, "JBSWY3DPEHPK3PXP");
        assert_eq!(
            cipher.decrypt("user-1", &encrypted).unwrap(),
            "JBSWY3DPEHPK3PXP"
        );
    }

    #[test]
    fn ciphertext_is_bound_to_user() {
        let cipher = cipher();
        let encrypted = cipher.encrypt("user-1", "JBSWY3DPEHPK3PXP").unwrap();

        assert!(cipher.decrypt("user-2", &encrypted).is_err());
    }

    #[test]
    fn encryption_uses_unique_nonces() {
        let cipher = cipher();
        let first = cipher.encrypt("user-1", "JBSWY3DPEHPK3PXP").unwrap();
        let second = cipher.encrypt("user-1", "JBSWY3DPEHPK3PXP").unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn rejects_wrong_sized_keys() {
        let key = STANDARD.encode([7_u8; KEY_LENGTH - 1]);
        assert!(MfaSecretCipher::from_base64(&key).is_err());
    }
}
