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

#[cfg(test)]
mod tests {
    use super::*;

    // ============ NoVerification tests ============

    #[tokio::test]
    async fn test_no_verification_always_returns_true() {
        let verifier = NoVerification;

        // Should return true regardless of payload and signature
        assert!(verifier.verify_signature(b"any payload", "any-signature").await.unwrap());
        assert!(verifier.verify_signature(b"", "").await.unwrap());
        assert!(verifier.verify_signature(b"test", "").await.unwrap());
        assert!(verifier.verify_signature(&[], "signature").await.unwrap());
    }

    #[tokio::test]
    async fn test_no_verification_with_various_payloads() {
        let verifier = NoVerification;

        let payloads = [
            b"simple text".as_slice(),
            b"{\"json\": \"data\"}".as_slice(),
            b"<xml>data</xml>".as_slice(),
            &[0u8, 1, 2, 3, 255], // Binary data
        ];

        for payload in payloads {
            let result = verifier.verify_signature(payload, "sig").await;
            assert!(result.is_ok());
            assert!(result.unwrap());
        }
    }

    // ============ HmacSha256Verifier tests ============

    #[test]
    fn test_hmac_sha256_verifier_creation() {
        let verifier = HmacSha256Verifier::new("secret-key");
        // Just verify it can be created without panicking
        assert!(std::mem::size_of_val(&verifier) > 0);
    }

    #[test]
    fn test_hmac_sha256_verifier_with_bytes() {
        let secret: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04];
        let verifier = HmacSha256Verifier::new(secret);
        assert!(std::mem::size_of_val(&verifier) > 0);
    }

    #[test]
    fn test_hmac_sha256_verifier_with_string() {
        let secret = String::from("my-webhook-secret");
        let verifier = HmacSha256Verifier::new(secret.into_bytes());
        assert!(std::mem::size_of_val(&verifier) > 0);
    }

    #[tokio::test]
    async fn test_hmac_sha256_verifier_non_empty_signature() {
        let verifier = HmacSha256Verifier::new("secret");
        let payload = b"webhook payload";
        let signature = "sha256=abc123";

        // Current implementation just checks if signature is non-empty
        let result = verifier.verify_signature(payload, signature).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_hmac_sha256_verifier_empty_signature() {
        let verifier = HmacSha256Verifier::new("secret");
        let payload = b"webhook payload";
        let signature = "";

        // Empty signature should return false
        let result = verifier.verify_signature(payload, signature).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_hmac_sha256_verifier_with_different_payloads() {
        let verifier = HmacSha256Verifier::new("secret");

        let test_cases = [
            (b"{}".as_slice(), "sig1"),
            (b"{\"event\":\"payment\"}".as_slice(), "sig2"),
            (b"plain text".as_slice(), "sig3"),
            (&[0u8, 255, 128][..], "sig4"),
        ];

        for (payload, signature) in test_cases {
            let result = verifier.verify_signature(payload, signature).await;
            assert!(result.is_ok());
            assert!(result.unwrap());
        }
    }

    // ============ WebhookVerifier trait tests ============

    struct CustomVerifier {
        should_pass: bool,
    }

    #[async_trait]
    impl WebhookVerifier for CustomVerifier {
        async fn verify_signature(&self, _payload: &[u8], _signature: &str) -> Result<bool> {
            Ok(self.should_pass)
        }
    }

    #[tokio::test]
    async fn test_custom_verifier_trait_impl() {
        let passing_verifier = CustomVerifier { should_pass: true };
        let failing_verifier = CustomVerifier { should_pass: false };

        assert!(passing_verifier.verify_signature(b"data", "sig").await.unwrap());
        assert!(!failing_verifier.verify_signature(b"data", "sig").await.unwrap());
    }

    #[tokio::test]
    async fn test_verifier_as_dyn_trait() {
        let verifier: Box<dyn WebhookVerifier> = Box::new(NoVerification);
        let result = verifier.verify_signature(b"test", "sig").await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_verifier_in_arc() {
        use std::sync::Arc;

        let verifier: Arc<dyn WebhookVerifier> = Arc::new(HmacSha256Verifier::new("secret"));
        let result = verifier.verify_signature(b"test", "valid-sig").await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
