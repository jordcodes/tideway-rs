//! Authenticated encryption for stored provider tokens.

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

/// Encrypts provider access/refresh tokens with AES-256-GCM before they are persisted.
///
/// Ciphertext is bound to the identity (`provider` + `subject`) through associated data,
/// so a token copied onto another identity row fails to decrypt.
///
/// Only persist provider tokens if the application calls the provider's API on the
/// user's behalf; sign-in itself does not need them.
#[derive(Clone)]
pub struct OAuthTokenCipher {
    cipher: Aes256Gcm,
}

impl OAuthTokenCipher {
    /// Construct a cipher from a base64-encoded 32-byte key.
    pub fn from_base64(key: &str) -> Result<Self> {
        let mut decoded = STANDARD
            .decode(key.trim())
            .map_err(|_| TidewayError::bad_request("OAuth token key must be valid base64"))?;
        if decoded.len() != KEY_LENGTH {
            decoded.fill(0);
            return Err(TidewayError::bad_request(
                "OAuth token key must decode to exactly 32 bytes",
            ));
        }
        let cipher = Aes256Gcm::new_from_slice(&decoded)
            .map_err(|_| TidewayError::internal("Unable to initialize OAuth token encryption"))?;
        decoded.fill(0);
        Ok(Self { cipher })
    }

    /// Construct a cipher from a required environment variable.
    pub fn from_env(name: &str) -> Result<Self> {
        let key = std::env::var(name)
            .map_err(|_| TidewayError::bad_request(format!("{name} must be set")))?;
        Self::from_base64(&key)
    }

    /// Encrypt a token for the given identity.
    pub fn encrypt(&self, provider: &str, subject: &str, token: &str) -> Result<String> {
        let aad = associated_data(provider, subject);
        let mut nonce_bytes = [0_u8; NONCE_LENGTH];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: token.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| TidewayError::internal("Unable to encrypt OAuth token"))?;

        let mut encoded = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
        encoded.extend_from_slice(&nonce_bytes);
        encoded.extend_from_slice(&ciphertext);
        Ok(format!("{FORMAT_PREFIX}{}", STANDARD.encode(encoded)))
    }

    /// Decrypt a token previously encrypted for the same identity.
    pub fn decrypt(&self, provider: &str, subject: &str, encrypted: &str) -> Result<String> {
        let encoded = encrypted
            .strip_prefix(FORMAT_PREFIX)
            .ok_or_else(|| TidewayError::internal("Unsupported OAuth token encryption format"))?;
        let payload = STANDARD
            .decode(encoded)
            .map_err(|_| TidewayError::internal("Invalid OAuth token ciphertext"))?;
        if payload.len() <= NONCE_LENGTH {
            return Err(TidewayError::internal("Invalid OAuth token ciphertext"));
        }
        let aad = associated_data(provider, subject);
        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(&payload[..NONCE_LENGTH]),
                Payload {
                    msg: &payload[NONCE_LENGTH..],
                    aad: &aad,
                },
            )
            .map_err(|_| TidewayError::internal("Unable to decrypt OAuth token"))?;
        String::from_utf8(plaintext)
            .map_err(|_| TidewayError::internal("Decrypted OAuth token is not valid UTF-8"))
    }
}

/// Length-prefix the provider so `("a:b", "c")` and `("a", "b:c")` differ.
fn associated_data(provider: &str, subject: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + provider.len() + subject.len());
    aad.extend_from_slice(&(provider.len() as u64).to_be_bytes());
    aad.extend_from_slice(provider.as_bytes());
    aad.extend_from_slice(subject.as_bytes());
    aad
}

impl fmt::Debug for OAuthTokenCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthTokenCipher")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher() -> OAuthTokenCipher {
        OAuthTokenCipher::from_base64(&STANDARD.encode([9_u8; KEY_LENGTH])).unwrap()
    }

    #[test]
    fn round_trips_for_same_identity() {
        let cipher = cipher();
        let encrypted = cipher.encrypt("github", "42", "gho_token").unwrap();
        assert!(!encrypted.contains("gho_token"));
        assert_eq!(
            cipher.decrypt("github", "42", &encrypted).unwrap(),
            "gho_token"
        );
    }

    #[test]
    fn rejects_other_identity() {
        let cipher = cipher();
        let encrypted = cipher.encrypt("github", "42", "gho_token").unwrap();
        assert!(cipher.decrypt("github", "43", &encrypted).is_err());
        assert!(cipher.decrypt("google", "42", &encrypted).is_err());
    }

    #[test]
    fn rejects_wrong_key_length() {
        assert!(OAuthTokenCipher::from_base64(&STANDARD.encode([1_u8; 16])).is_err());
    }
}
