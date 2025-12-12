use crate::error::Result;
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Trait for verifying webhook signatures
///
/// Different webhook providers use different signature algorithms.
/// Implement this trait to verify webhooks from your provider.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::webhooks::{WebhookVerifier, HmacSha256Verifier};
///
/// // Create verifier with your webhook secret
/// let verifier = HmacSha256Verifier::new("whsec_your_secret_here");
///
/// // Verify incoming webhook
/// let payload = br#"{"event": "payment.completed"}"#;
/// let signature = "abc123..."; // From X-Signature header
/// let is_valid = verifier.verify_signature(payload, signature).await?;
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

/// No-op verifier that accepts all webhooks
///
/// **WARNING:** This verifier accepts ALL webhooks without verification.
/// Only use this for:
/// - Testing/development environments
/// - Webhook providers that don't support signatures
///
/// **NEVER use in production** for providers that support signatures.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoVerification;

#[async_trait]
impl WebhookVerifier for NoVerification {
    async fn verify_signature(&self, _payload: &[u8], _signature: &str) -> Result<bool> {
        tracing::warn!("NoVerification webhook verifier used - all webhooks accepted without verification");
        Ok(true)
    }
}

/// HMAC-SHA256 webhook verifier with timing-safe comparison
///
/// This is the standard verification method used by most webhook providers
/// including Stripe, GitHub, Shopify, and others.
///
/// # Signature Formats
///
/// Different providers use different signature formats:
/// - **Hex encoded**: `a1b2c3d4...` (most common)
/// - **Hex with prefix**: `sha256=a1b2c3d4...` (GitHub style)
/// - **Base64 encoded**: `oWvD1A==...`
///
/// Use the appropriate constructor for your provider's format.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::webhooks::HmacSha256Verifier;
///
/// // For hex-encoded signatures (default)
/// let verifier = HmacSha256Verifier::new("your_webhook_secret");
///
/// // For signatures with "sha256=" prefix (GitHub, etc.)
/// let verifier = HmacSha256Verifier::new_with_prefix("your_secret", "sha256=");
/// ```
pub struct HmacSha256Verifier {
    secret: Vec<u8>,
    /// Optional prefix to strip from signatures (e.g., "sha256=")
    signature_prefix: Option<String>,
    /// Whether signatures are base64 encoded (vs hex encoded)
    base64_encoded: bool,
}

impl HmacSha256Verifier {
    /// Create a new verifier with hex-encoded signatures (most common)
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            secret: secret.into(),
            signature_prefix: None,
            base64_encoded: false,
        }
    }

    /// Create a verifier that strips a prefix from signatures
    ///
    /// Use this for providers like GitHub that send signatures as `sha256=abc123...`
    pub fn new_with_prefix(secret: impl Into<Vec<u8>>, prefix: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            signature_prefix: Some(prefix.into()),
            base64_encoded: false,
        }
    }

    /// Create a verifier for base64-encoded signatures
    pub fn new_base64(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            secret: secret.into(),
            signature_prefix: None,
            base64_encoded: true,
        }
    }

    /// Compute the expected HMAC-SHA256 signature for a payload
    fn compute_signature(&self, payload: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .expect("HMAC can take key of any size");
        mac.update(payload);
        mac.finalize().into_bytes().to_vec()
    }

    /// Decode the provided signature from hex or base64
    fn decode_signature(&self, signature: &str) -> Option<Vec<u8>> {
        // Strip prefix if configured
        let sig = if let Some(ref prefix) = self.signature_prefix {
            signature.strip_prefix(prefix.as_str()).unwrap_or(signature)
        } else {
            signature
        };

        if self.base64_encoded {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig).ok()
        } else {
            hex_decode(sig)
        }
    }
}

/// Decode a hex string to bytes
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }

    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Constant-time comparison to prevent timing attacks
///
/// Uses the `subtle` crate which provides compiler-optimization-resistant
/// constant-time operations. This prevents attackers from using timing
/// information to guess valid signatures byte-by-byte.
///
/// Unlike a naive XOR-and-fold implementation, the `subtle` crate uses
/// optimization barriers to prevent LLVM from converting bitwise operations
/// back into timing-leaking branches.
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // Use subtle's ConstantTimeEq which is resistant to compiler optimizations
    a.ct_eq(b).into()
}

#[async_trait]
impl WebhookVerifier for HmacSha256Verifier {
    async fn verify_signature(&self, payload: &[u8], signature: &str) -> Result<bool> {
        // Decode the provided signature
        let provided = match self.decode_signature(signature) {
            Some(bytes) => bytes,
            None => {
                tracing::debug!("Failed to decode webhook signature");
                return Ok(false);
            }
        };

        // Compute expected signature
        let expected = self.compute_signature(payload);

        // Use constant-time comparison to prevent timing attacks
        let is_valid = constant_time_compare(&expected, &provided);

        if !is_valid {
            tracing::debug!("Webhook signature verification failed");
        }

        Ok(is_valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============ Helper functions ============

    /// Compute a valid HMAC-SHA256 signature for testing
    fn compute_test_signature(secret: &[u8], payload: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret)
            .expect("HMAC can take key of any size");
        mac.update(payload);
        let result = mac.finalize().into_bytes();
        // Convert to hex string
        result.iter().map(|b| format!("{:02x}", b)).collect()
    }

    // ============ hex_decode tests ============

    #[test]
    fn test_hex_decode_valid() {
        assert_eq!(hex_decode(""), Some(vec![]));
        assert_eq!(hex_decode("00"), Some(vec![0x00]));
        assert_eq!(hex_decode("ff"), Some(vec![0xff]));
        assert_eq!(hex_decode("0a1b2c"), Some(vec![0x0a, 0x1b, 0x2c]));
        assert_eq!(hex_decode("AABB"), Some(vec![0xaa, 0xbb])); // uppercase
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert_eq!(hex_decode("0"), None); // odd length
        assert_eq!(hex_decode("0g"), None); // invalid char
        assert_eq!(hex_decode("xyz"), None); // invalid chars, odd length
    }

    // ============ constant_time_compare tests ============

    #[test]
    fn test_constant_time_compare_equal() {
        assert!(constant_time_compare(&[], &[]));
        assert!(constant_time_compare(&[1, 2, 3], &[1, 2, 3]));
        assert!(constant_time_compare(&[0xff; 32], &[0xff; 32]));
    }

    #[test]
    fn test_constant_time_compare_not_equal() {
        assert!(!constant_time_compare(&[1], &[2]));
        assert!(!constant_time_compare(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_compare(&[0; 32], &[0xff; 32]));
    }

    #[test]
    fn test_constant_time_compare_different_lengths() {
        assert!(!constant_time_compare(&[1, 2], &[1, 2, 3]));
        assert!(!constant_time_compare(&[1, 2, 3], &[1, 2]));
        assert!(!constant_time_compare(&[], &[1]));
    }

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

    // ============ HmacSha256Verifier creation tests ============

    #[test]
    fn test_hmac_sha256_verifier_creation() {
        let verifier = HmacSha256Verifier::new("secret-key");
        assert!(!verifier.base64_encoded);
        assert!(verifier.signature_prefix.is_none());
    }

    #[test]
    fn test_hmac_sha256_verifier_with_bytes() {
        let secret: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04];
        let verifier = HmacSha256Verifier::new(secret);
        assert_eq!(verifier.secret, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_hmac_sha256_verifier_with_prefix() {
        let verifier = HmacSha256Verifier::new_with_prefix("secret", "sha256=");
        assert_eq!(verifier.signature_prefix, Some("sha256=".to_string()));
        assert!(!verifier.base64_encoded);
    }

    #[test]
    fn test_hmac_sha256_verifier_base64() {
        let verifier = HmacSha256Verifier::new_base64("secret");
        assert!(verifier.base64_encoded);
        assert!(verifier.signature_prefix.is_none());
    }

    // ============ HmacSha256Verifier verification tests ============

    #[tokio::test]
    async fn test_hmac_sha256_verifier_valid_signature() {
        let secret = b"my-webhook-secret";
        let payload = b"test payload";
        let verifier = HmacSha256Verifier::new(secret.to_vec());

        // Compute the correct signature
        let signature = compute_test_signature(secret, payload);

        let result = verifier.verify_signature(payload, &signature).await;
        assert!(result.is_ok());
        assert!(result.unwrap(), "Valid signature should pass verification");
    }

    #[tokio::test]
    async fn test_hmac_sha256_verifier_invalid_signature() {
        let secret = b"my-webhook-secret";
        let payload = b"test payload";
        let verifier = HmacSha256Verifier::new(secret.to_vec());

        // Use a completely wrong signature
        let wrong_signature = "0000000000000000000000000000000000000000000000000000000000000000";

        let result = verifier.verify_signature(payload, wrong_signature).await;
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Invalid signature should fail verification");
    }

    #[tokio::test]
    async fn test_hmac_sha256_verifier_wrong_secret() {
        let payload = b"test payload";

        // Create signature with one secret
        let signature = compute_test_signature(b"secret1", payload);

        // Verify with different secret
        let verifier = HmacSha256Verifier::new("secret2");
        let result = verifier.verify_signature(payload, &signature).await;
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Signature with wrong secret should fail");
    }

    #[tokio::test]
    async fn test_hmac_sha256_verifier_modified_payload() {
        let secret = b"my-secret";
        let original_payload = b"original payload";
        let modified_payload = b"modified payload";

        // Create signature for original payload
        let signature = compute_test_signature(secret, original_payload);

        // Try to verify with modified payload
        let verifier = HmacSha256Verifier::new(secret.to_vec());
        let result = verifier.verify_signature(modified_payload, &signature).await;
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Modified payload should fail verification");
    }

    #[tokio::test]
    async fn test_hmac_sha256_verifier_empty_signature() {
        let verifier = HmacSha256Verifier::new("secret");
        let payload = b"webhook payload";
        let signature = "";

        let result = verifier.verify_signature(payload, signature).await;
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Empty signature should fail");
    }

    #[tokio::test]
    async fn test_hmac_sha256_verifier_malformed_signature() {
        let verifier = HmacSha256Verifier::new("secret");
        let payload = b"webhook payload";

        // Test various malformed signatures
        let malformed = ["not-hex", "abc", "xyz123", "0g0g0g"];

        for sig in malformed {
            let result = verifier.verify_signature(payload, sig).await;
            assert!(result.is_ok());
            assert!(!result.unwrap(), "Malformed signature '{}' should fail", sig);
        }
    }

    #[tokio::test]
    async fn test_hmac_sha256_verifier_with_prefix_valid() {
        let secret = b"github-secret";
        let payload = b"{\"action\": \"push\"}";
        let verifier = HmacSha256Verifier::new_with_prefix(secret.to_vec(), "sha256=");

        // Compute signature and add prefix
        let signature = format!("sha256={}", compute_test_signature(secret, payload));

        let result = verifier.verify_signature(payload, &signature).await;
        assert!(result.is_ok());
        assert!(result.unwrap(), "Prefixed signature should pass");
    }

    #[tokio::test]
    async fn test_hmac_sha256_verifier_with_prefix_missing_prefix() {
        let secret = b"github-secret";
        let payload = b"{\"action\": \"push\"}";
        let verifier = HmacSha256Verifier::new_with_prefix(secret.to_vec(), "sha256=");

        // Signature WITHOUT prefix - should still work because we strip prefix if present
        let signature = compute_test_signature(secret, payload);

        let result = verifier.verify_signature(payload, &signature).await;
        assert!(result.is_ok());
        assert!(result.unwrap(), "Signature without prefix should also work");
    }

    #[tokio::test]
    async fn test_hmac_sha256_verifier_json_payload() {
        let secret = b"webhook-secret";
        let payload = br#"{"event":"payment.completed","data":{"id":"pay_123","amount":1000}}"#;
        let verifier = HmacSha256Verifier::new(secret.to_vec());

        let signature = compute_test_signature(secret, payload);

        let result = verifier.verify_signature(payload, &signature).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_hmac_sha256_verifier_empty_payload() {
        let secret = b"secret";
        let payload = b"";
        let verifier = HmacSha256Verifier::new(secret.to_vec());

        let signature = compute_test_signature(secret, payload);

        let result = verifier.verify_signature(payload, &signature).await;
        assert!(result.is_ok());
        assert!(result.unwrap(), "Empty payload with valid signature should pass");
    }

    #[tokio::test]
    async fn test_hmac_sha256_verifier_binary_payload() {
        let secret = b"secret";
        let payload: &[u8] = &[0x00, 0x01, 0xff, 0xfe, 0x80];
        let verifier = HmacSha256Verifier::new(secret.to_vec());

        let signature = compute_test_signature(secret, payload);

        let result = verifier.verify_signature(payload, &signature).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
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

        let secret = b"arc-secret";
        let payload = b"arc-test";
        let signature = compute_test_signature(secret, payload);

        let verifier: Arc<dyn WebhookVerifier> = Arc::new(HmacSha256Verifier::new(secret.to_vec()));
        let result = verifier.verify_signature(payload, &signature).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
