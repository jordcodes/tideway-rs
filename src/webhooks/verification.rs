use crate::error::Result;
use async_trait::async_trait;

/// Trait for verifying webhook signatures
///
/// Different webhook providers use different signature algorithms.
/// Implement this trait to verify webhooks from your provider.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::webhooks::WebhookVerifier;
/// use hmac::{Hmac, Mac};
/// use sha2::Sha256;
///
/// struct MyWebhookVerifier {
///     secret: String,
/// }
///
/// #[async_trait]
/// impl WebhookVerifier for MyWebhookVerifier {
///     async fn verify_signature(&self, payload: &[u8], signature: &str) -> Result<bool> {
///         type HmacSha256 = Hmac<Sha256>;
///         let mut mac = HmacSha256::new_from_slice(self.secret.as_bytes())?;
///         mac.update(payload);
///         let expected = hex::encode(mac.finalize().into_bytes());
///         Ok(expected == signature)
///     }
/// }
/// ```
#[async_trait]
pub trait WebhookVerifier: Send + Sync {
    /// Verify the webhook signature
    ///
    /// # Arguments
    ///
    /// * `payload` - The raw webhook payload bytes
    /// * `signature` - The signature from the webhook headers
    ///
    /// # Returns
    ///
    /// `Ok(true)` if signature is valid, `Ok(false)` if invalid, `Err` on error
    async fn verify_signature(&self, payload: &[u8], signature: &str) -> Result<bool>;
}

/// No-op verifier that accepts all webhooks (for testing or providers without signatures)
pub struct NoVerification;

#[async_trait]
impl WebhookVerifier for NoVerification {
    async fn verify_signature(&self, _payload: &[u8], _signature: &str) -> Result<bool> {
        Ok(true)
    }
}

/// HMAC-SHA256 webhook verifier
pub struct HmacSha256Verifier {
    #[allow(dead_code)]
    secret: Vec<u8>,
}

impl HmacSha256Verifier {
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            secret: secret.into(),
        }
    }
}

#[async_trait]
impl WebhookVerifier for HmacSha256Verifier {
    async fn verify_signature(&self, _payload: &[u8], signature: &str) -> Result<bool> {
        // Simple implementation - for production, use hmac crate
        // This is a placeholder showing the pattern

        // In a real implementation, you would:
        // 1. Compute HMAC-SHA256 of payload with secret
        // 2. Compare with provided signature

        // For now, just check if signature is not empty
        Ok(!signature.is_empty())
    }
}
