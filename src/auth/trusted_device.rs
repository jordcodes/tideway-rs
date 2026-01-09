//! Trusted device management for MFA bypass.
//!
//! Allows users to mark devices as "trusted" after completing MFA,
//! enabling them to skip MFA on subsequent logins from the same device.
//!
//! # Security
//!
//! - Trust tokens are hashed before storage (SHA-256)
//! - Tokens have configurable expiry (default: 30 days)
//! - Tokens can be revoked individually or all at once
//! - Optional fingerprint validation (IP/user agent)
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::auth::trusted_device::{TrustedDeviceManager, TrustedDeviceConfig};
//!
//! let manager = TrustedDeviceManager::new(store, TrustedDeviceConfig::default());
//!
//! // After MFA success, trust the device
//! let token = manager.trust_device("user-123", fingerprint).await?;
//! // Return token to client as a cookie
//!
//! // On next login, check if device is trusted
//! if manager.is_trusted("user-123", &token, fingerprint).await? {
//!     // Skip MFA
//! }
//! ```

use crate::error::Result;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime};

/// Default trust duration (30 days).
const DEFAULT_TRUST_DURATION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Length of generated trust tokens (32 bytes = 256 bits).
const TOKEN_LENGTH: usize = 32;

/// Maximum length for IP address strings (prevent DoS).
const MAX_IP_LENGTH: usize = 45; // IPv6 max length

/// Maximum length for user agent strings (prevent DoS).
const MAX_USER_AGENT_LENGTH: usize = 512;

/// Configuration for trusted devices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedDeviceConfig {
    /// How long a device stays trusted (default: 30 days).
    pub trust_duration: Duration,
    /// Maximum trusted devices per user (default: 10).
    pub max_devices_per_user: usize,
    /// Whether to validate fingerprint on verification (default: false).
    /// When true, IP and user agent must match for trust to be valid.
    pub validate_fingerprint: bool,
}

impl Default for TrustedDeviceConfig {
    fn default() -> Self {
        Self {
            trust_duration: DEFAULT_TRUST_DURATION,
            max_devices_per_user: 10,
            validate_fingerprint: false,
        }
    }
}

impl TrustedDeviceConfig {
    /// Create a new config with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the trust duration.
    #[must_use]
    pub fn trust_duration(mut self, duration: Duration) -> Self {
        self.trust_duration = duration;
        self
    }

    /// Set the maximum devices per user.
    #[must_use]
    pub fn max_devices_per_user(mut self, max: usize) -> Self {
        self.max_devices_per_user = max;
        self
    }

    /// Enable fingerprint validation.
    ///
    /// When enabled, the IP and user agent must match for trust to be valid.
    /// This provides extra security but may cause issues with dynamic IPs.
    #[must_use]
    pub fn validate_fingerprint(mut self, validate: bool) -> Self {
        self.validate_fingerprint = validate;
        self
    }
}

/// Device fingerprint for identification.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceFingerprint {
    /// Client IP address.
    pub ip_address: Option<String>,
    /// User agent string.
    pub user_agent: Option<String>,
}

impl DeviceFingerprint {
    /// Create an empty fingerprint.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the IP address.
    #[must_use]
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Set the user agent.
    #[must_use]
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Check if this fingerprint matches another (for validation).
    #[must_use]
    pub fn matches(&self, other: &DeviceFingerprint) -> bool {
        // IP must match if both are present
        let ip_matches = match (&self.ip_address, &other.ip_address) {
            (Some(a), Some(b)) => a == b,
            _ => true, // If either is missing, don't fail
        };

        // User agent must match if both are present
        let ua_matches = match (&self.user_agent, &other.user_agent) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        };

        ip_matches && ua_matches
    }
}

/// Information about a trusted device.
#[derive(Clone, Debug)]
pub struct TrustedDevice {
    /// Unique device ID.
    pub id: String,
    /// User ID this device belongs to.
    pub user_id: String,
    /// Hashed trust token.
    pub token_hash: String,
    /// Device name/description (from user agent).
    pub device_name: Option<String>,
    /// IP address when trusted.
    pub ip_address: Option<String>,
    /// User agent when trusted.
    pub user_agent: Option<String>,
    /// When the device was trusted.
    pub trusted_at: SystemTime,
    /// When the trust expires.
    pub expires_at: SystemTime,
    /// Last time the trust was used.
    pub last_used_at: Option<SystemTime>,
}

impl TrustedDevice {
    /// Check if this trust has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }
}

/// Trait for trusted device storage.
#[async_trait]
pub trait TrustedDeviceStore: Send + Sync {
    /// Store a new trusted device.
    async fn store_trusted_device(&self, device: &TrustedDevice) -> Result<()>;

    /// Find a trusted device by user ID and token hash.
    async fn find_by_token_hash(
        &self,
        user_id: &str,
        token_hash: &str,
    ) -> Result<Option<TrustedDevice>>;

    /// List all trusted devices for a user.
    async fn list_trusted_devices(&self, user_id: &str) -> Result<Vec<TrustedDevice>>;

    /// Update the last_used_at timestamp.
    async fn touch_trusted_device(&self, device_id: &str) -> Result<()>;

    /// Revoke a specific trusted device.
    async fn revoke_trusted_device(&self, device_id: &str) -> Result<bool>;

    /// Revoke all trusted devices for a user.
    async fn revoke_all_trusted_devices(&self, user_id: &str) -> Result<usize>;

    /// Remove expired trusted devices.
    async fn cleanup_expired(&self) -> Result<usize>;

    /// Count trusted devices for a user.
    async fn count_trusted_devices(&self, user_id: &str) -> Result<usize> {
        Ok(self.list_trusted_devices(user_id).await?.len())
    }
}

/// Manager for trusted device operations.
pub struct TrustedDeviceManager<S: TrustedDeviceStore> {
    store: S,
    config: TrustedDeviceConfig,
}

impl<S: TrustedDeviceStore> TrustedDeviceManager<S> {
    /// Create a new trusted device manager.
    #[must_use]
    pub fn new(store: S, config: TrustedDeviceConfig) -> Self {
        Self { store, config }
    }

    /// Trust a device after successful MFA.
    ///
    /// Returns the trust token to be stored on the client (e.g., as a cookie).
    /// The token is hashed before storage.
    pub async fn trust_device(
        &self,
        user_id: &str,
        fingerprint: DeviceFingerprint,
    ) -> Result<String> {
        // Check device limit
        let current_count = self.store.count_trusted_devices(user_id).await?;
        if current_count >= self.config.max_devices_per_user {
            // Revoke oldest device to make room
            let devices = self.store.list_trusted_devices(user_id).await?;
            if let Some(oldest) = devices.last() {
                self.store.revoke_trusted_device(&oldest.id).await?;
                tracing::info!(
                    target: "auth.trusted_device.evicted",
                    user_id = %user_id,
                    device_id = %oldest.id,
                    "Evicted oldest trusted device due to limit"
                );
            }
        }

        // Generate token
        let token = self.generate_token();
        let token_hash = self.hash_token(&token);
        let device_id = self.generate_device_id();

        let now = SystemTime::now();
        let expires_at = now + self.config.trust_duration;

        // Truncate inputs to prevent DoS
        let ip_address = fingerprint
            .ip_address
            .map(|ip| truncate_string(&ip, MAX_IP_LENGTH));
        let user_agent = fingerprint
            .user_agent
            .map(|ua| truncate_string(&ua, MAX_USER_AGENT_LENGTH));

        let device = TrustedDevice {
            id: device_id.clone(),
            user_id: user_id.to_string(),
            token_hash,
            device_name: user_agent.as_ref().map(|ua| parse_device_name(ua)),
            ip_address,
            user_agent,
            trusted_at: now,
            expires_at,
            last_used_at: None,
        };

        self.store.store_trusted_device(&device).await?;

        tracing::info!(
            target: "auth.trusted_device.created",
            user_id = %user_id,
            device_id = %device_id,
            expires_in_days = self.config.trust_duration.as_secs() / 86400,
            "Device trusted"
        );

        Ok(token)
    }

    /// Check if a device is trusted.
    ///
    /// Returns true if the token is valid and not expired.
    pub async fn is_trusted(
        &self,
        user_id: &str,
        token: &str,
        fingerprint: Option<DeviceFingerprint>,
    ) -> Result<bool> {
        let token_hash = self.hash_token(token);

        let device = match self.store.find_by_token_hash(user_id, &token_hash).await? {
            Some(d) => d,
            None => return Ok(false),
        };

        // Check expiration
        if device.is_expired() {
            tracing::debug!(
                target: "auth.trusted_device.expired",
                user_id = %user_id,
                device_id = %device.id,
                "Trust token expired"
            );
            return Ok(false);
        }

        // Optionally validate fingerprint
        if self.config.validate_fingerprint {
            if let Some(ref fp) = fingerprint {
                let stored_fp = DeviceFingerprint {
                    ip_address: device.ip_address.clone(),
                    user_agent: device.user_agent.clone(),
                };
                if !stored_fp.matches(fp) {
                    tracing::warn!(
                        target: "auth.trusted_device.fingerprint_mismatch",
                        user_id = %user_id,
                        device_id = %device.id,
                        "Trust token fingerprint mismatch"
                    );
                    return Ok(false);
                }
            }
        }

        // Update last used
        let _ = self.store.touch_trusted_device(&device.id).await;

        tracing::debug!(
            target: "auth.trusted_device.verified",
            user_id = %user_id,
            device_id = %device.id,
            "Device trust verified"
        );

        Ok(true)
    }

    /// Verify and consume a trust token, returning device info if valid.
    ///
    /// Unlike `is_trusted`, this returns the device info for display purposes.
    pub async fn verify_trust(
        &self,
        user_id: &str,
        token: &str,
        fingerprint: Option<DeviceFingerprint>,
    ) -> Result<Option<TrustedDevice>> {
        let token_hash = self.hash_token(token);

        let device = match self.store.find_by_token_hash(user_id, &token_hash).await? {
            Some(d) => d,
            None => return Ok(None),
        };

        if device.is_expired() {
            return Ok(None);
        }

        if self.config.validate_fingerprint {
            if let Some(ref fp) = fingerprint {
                let stored_fp = DeviceFingerprint {
                    ip_address: device.ip_address.clone(),
                    user_agent: device.user_agent.clone(),
                };
                if !stored_fp.matches(fp) {
                    return Ok(None);
                }
            }
        }

        let _ = self.store.touch_trusted_device(&device.id).await;
        Ok(Some(device))
    }

    /// List all trusted devices for a user.
    pub async fn list_devices(&self, user_id: &str) -> Result<Vec<TrustedDevice>> {
        self.store.list_trusted_devices(user_id).await
    }

    /// Revoke trust for a specific device.
    pub async fn revoke_device(&self, user_id: &str, device_id: &str) -> Result<bool> {
        // Verify ownership first
        let devices = self.store.list_trusted_devices(user_id).await?;
        if !devices.iter().any(|d| d.id == device_id) {
            return Ok(false);
        }

        let revoked = self.store.revoke_trusted_device(device_id).await?;

        if revoked {
            tracing::info!(
                target: "auth.trusted_device.revoked",
                user_id = %user_id,
                device_id = %device_id,
                "Trusted device revoked"
            );
        }

        Ok(revoked)
    }

    /// Revoke all trusted devices for a user.
    pub async fn revoke_all_devices(&self, user_id: &str) -> Result<usize> {
        let count = self.store.revoke_all_trusted_devices(user_id).await?;

        tracing::warn!(
            target: "auth.trusted_device.revoke_all",
            user_id = %user_id,
            count = count,
            "All trusted devices revoked"
        );

        Ok(count)
    }

    /// Clean up expired trusted devices.
    pub async fn cleanup_expired(&self) -> Result<usize> {
        let count = self.store.cleanup_expired().await?;

        if count > 0 {
            tracing::info!(
                target: "auth.trusted_device.cleanup",
                count = count,
                "Expired trusted devices cleaned up"
            );
        }

        Ok(count)
    }

    /// Get the current configuration.
    #[must_use]
    pub fn config(&self) -> &TrustedDeviceConfig {
        &self.config
    }

    /// Get a reference to the underlying store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Generate a secure random token.
    fn generate_token(&self) -> String {
        use rand::Rng;
        let bytes: [u8; TOKEN_LENGTH] = rand::thread_rng().r#gen();
        base64_encode(&bytes)
    }

    /// Generate a unique device ID.
    fn generate_device_id(&self) -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Hash a token for storage.
    fn hash_token(&self, token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let result = hasher.finalize();
        format!("{:x}", result)
    }
}

/// Parse a user agent string into a friendly device name.
fn parse_device_name(ua: &str) -> String {
    // Simple parsing - extract browser and OS
    let browser = if ua.contains("Chrome") && !ua.contains("Edg") {
        "Chrome"
    } else if ua.contains("Firefox") {
        "Firefox"
    } else if ua.contains("Safari") && !ua.contains("Chrome") {
        "Safari"
    } else if ua.contains("Edg") {
        "Edge"
    } else {
        "Browser"
    };

    // Check iOS first (iPhone/iPad) before macOS checks
    let os = if ua.contains("iPhone") || ua.contains("iPad") || ua.contains("iPhone OS") {
        "iOS"
    } else if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("Mac OS X") || ua.contains("macOS") || ua.contains("Macintosh") {
        "macOS"
    } else if ua.contains("Android") {
        "Android"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "Unknown"
    };

    format!("{} on {}", browser, os)
}

/// Base64 encode bytes (URL-safe, no padding).
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Truncate a string to a maximum length (UTF-8 safe).
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        // Find a valid UTF-8 boundary at or before max_len
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_string()
    }
}

/// In-memory store for testing.
#[cfg(any(test, feature = "test-auth-bypass"))]
pub mod test {
    use super::*;
    use std::collections::HashMap;
    use std::sync::RwLock;

    /// In-memory trusted device store for testing.
    #[derive(Default)]
    pub struct InMemoryTrustedDeviceStore {
        devices: RwLock<HashMap<String, TrustedDevice>>,
    }

    impl InMemoryTrustedDeviceStore {
        /// Create a new in-memory store.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }
    }

    #[async_trait]
    impl TrustedDeviceStore for InMemoryTrustedDeviceStore {
        async fn store_trusted_device(&self, device: &TrustedDevice) -> Result<()> {
            self.devices
                .write()
                .unwrap()
                .insert(device.id.clone(), device.clone());
            Ok(())
        }

        async fn find_by_token_hash(
            &self,
            user_id: &str,
            token_hash: &str,
        ) -> Result<Option<TrustedDevice>> {
            let devices = self.devices.read().unwrap();
            Ok(devices
                .values()
                .find(|d| d.user_id == user_id && d.token_hash == token_hash)
                .cloned())
        }

        async fn list_trusted_devices(&self, user_id: &str) -> Result<Vec<TrustedDevice>> {
            let devices = self.devices.read().unwrap();
            let mut result: Vec<_> = devices
                .values()
                .filter(|d| d.user_id == user_id && !d.is_expired())
                .cloned()
                .collect();
            // Sort by trusted_at descending (newest first)
            result.sort_by(|a, b| b.trusted_at.cmp(&a.trusted_at));
            Ok(result)
        }

        async fn touch_trusted_device(&self, device_id: &str) -> Result<()> {
            let mut devices = self.devices.write().unwrap();
            if let Some(device) = devices.get_mut(device_id) {
                device.last_used_at = Some(SystemTime::now());
            }
            Ok(())
        }

        async fn revoke_trusted_device(&self, device_id: &str) -> Result<bool> {
            let mut devices = self.devices.write().unwrap();
            Ok(devices.remove(device_id).is_some())
        }

        async fn revoke_all_trusted_devices(&self, user_id: &str) -> Result<usize> {
            let mut devices = self.devices.write().unwrap();
            let to_remove: Vec<_> = devices
                .iter()
                .filter(|(_, d)| d.user_id == user_id)
                .map(|(k, _)| k.clone())
                .collect();
            let count = to_remove.len();
            for id in to_remove {
                devices.remove(&id);
            }
            Ok(count)
        }

        async fn cleanup_expired(&self) -> Result<usize> {
            let mut devices = self.devices.write().unwrap();
            let now = SystemTime::now();
            let to_remove: Vec<_> = devices
                .iter()
                .filter(|(_, d)| d.expires_at < now)
                .map(|(k, _)| k.clone())
                .collect();
            let count = to_remove.len();
            for id in to_remove {
                devices.remove(&id);
            }
            Ok(count)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::InMemoryTrustedDeviceStore;

    #[tokio::test]
    async fn test_trust_and_verify_device() {
        let store = InMemoryTrustedDeviceStore::new();
        let manager = TrustedDeviceManager::new(store, TrustedDeviceConfig::default());

        let fingerprint = DeviceFingerprint::new()
            .with_ip("192.168.1.1")
            .with_user_agent("Mozilla/5.0 Chrome/120");

        // Trust the device
        let token = manager.trust_device("user-1", fingerprint.clone()).await.unwrap();
        assert!(!token.is_empty());

        // Verify trust
        let is_trusted = manager.is_trusted("user-1", &token, Some(fingerprint)).await.unwrap();
        assert!(is_trusted);

        // Wrong token should fail
        let is_trusted = manager.is_trusted("user-1", "wrong-token", None).await.unwrap();
        assert!(!is_trusted);

        // Wrong user should fail
        let is_trusted = manager.is_trusted("user-2", &token, None).await.unwrap();
        assert!(!is_trusted);
    }

    #[tokio::test]
    async fn test_fingerprint_validation() {
        let store = InMemoryTrustedDeviceStore::new();
        let config = TrustedDeviceConfig::default().validate_fingerprint(true);
        let manager = TrustedDeviceManager::new(store, config);

        let fingerprint = DeviceFingerprint::new()
            .with_ip("192.168.1.1")
            .with_user_agent("Mozilla/5.0 Chrome/120");

        let token = manager.trust_device("user-1", fingerprint.clone()).await.unwrap();

        // Same fingerprint should work
        let is_trusted = manager
            .is_trusted("user-1", &token, Some(fingerprint.clone()))
            .await
            .unwrap();
        assert!(is_trusted);

        // Different IP should fail
        let different_ip = DeviceFingerprint::new()
            .with_ip("10.0.0.1")
            .with_user_agent("Mozilla/5.0 Chrome/120");
        let is_trusted = manager
            .is_trusted("user-1", &token, Some(different_ip))
            .await
            .unwrap();
        assert!(!is_trusted);
    }

    #[tokio::test]
    async fn test_device_limit() {
        let store = InMemoryTrustedDeviceStore::new();
        let config = TrustedDeviceConfig::default().max_devices_per_user(2);
        let manager = TrustedDeviceManager::new(store, config);

        // Trust 3 devices
        let token1 = manager
            .trust_device("user-1", DeviceFingerprint::new())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let token2 = manager
            .trust_device("user-1", DeviceFingerprint::new())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let token3 = manager
            .trust_device("user-1", DeviceFingerprint::new())
            .await
            .unwrap();

        // Token 1 should be evicted (oldest)
        let is_trusted = manager.is_trusted("user-1", &token1, None).await.unwrap();
        assert!(!is_trusted);

        // Tokens 2 and 3 should still work
        let is_trusted = manager.is_trusted("user-1", &token2, None).await.unwrap();
        assert!(is_trusted);
        let is_trusted = manager.is_trusted("user-1", &token3, None).await.unwrap();
        assert!(is_trusted);

        // Should have exactly 2 devices
        let devices = manager.list_devices("user-1").await.unwrap();
        assert_eq!(devices.len(), 2);
    }

    #[tokio::test]
    async fn test_revoke_device() {
        let store = InMemoryTrustedDeviceStore::new();
        let manager = TrustedDeviceManager::new(store, TrustedDeviceConfig::default());

        let token = manager
            .trust_device("user-1", DeviceFingerprint::new())
            .await
            .unwrap();

        // Get device ID
        let devices = manager.list_devices("user-1").await.unwrap();
        let device_id = &devices[0].id;

        // Revoke
        let revoked = manager.revoke_device("user-1", device_id).await.unwrap();
        assert!(revoked);

        // Token should no longer work
        let is_trusted = manager.is_trusted("user-1", &token, None).await.unwrap();
        assert!(!is_trusted);
    }

    #[tokio::test]
    async fn test_revoke_all_devices() {
        let store = InMemoryTrustedDeviceStore::new();
        let manager = TrustedDeviceManager::new(store, TrustedDeviceConfig::default());

        // Trust multiple devices
        manager
            .trust_device("user-1", DeviceFingerprint::new())
            .await
            .unwrap();
        manager
            .trust_device("user-1", DeviceFingerprint::new())
            .await
            .unwrap();
        manager
            .trust_device("user-2", DeviceFingerprint::new())
            .await
            .unwrap();

        // Revoke all for user-1
        let count = manager.revoke_all_devices("user-1").await.unwrap();
        assert_eq!(count, 2);

        // User-1 should have no devices
        let devices = manager.list_devices("user-1").await.unwrap();
        assert_eq!(devices.len(), 0);

        // User-2 should still have their device
        let devices = manager.list_devices("user-2").await.unwrap();
        assert_eq!(devices.len(), 1);
    }

    #[tokio::test]
    async fn test_expired_device() {
        let store = InMemoryTrustedDeviceStore::new();
        let config = TrustedDeviceConfig::default()
            .trust_duration(Duration::from_millis(50)); // Very short for testing
        let manager = TrustedDeviceManager::new(store, config);

        let token = manager
            .trust_device("user-1", DeviceFingerprint::new())
            .await
            .unwrap();

        // Should work immediately
        let is_trusted = manager.is_trusted("user-1", &token, None).await.unwrap();
        assert!(is_trusted);

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should be expired
        let is_trusted = manager.is_trusted("user-1", &token, None).await.unwrap();
        assert!(!is_trusted);
    }

    #[tokio::test]
    async fn test_verify_trust_returns_device() {
        let store = InMemoryTrustedDeviceStore::new();
        let manager = TrustedDeviceManager::new(store, TrustedDeviceConfig::default());

        let fingerprint = DeviceFingerprint::new()
            .with_ip("192.168.1.1")
            .with_user_agent("Mozilla/5.0 (Macintosh) Chrome/120");

        let token = manager.trust_device("user-1", fingerprint).await.unwrap();

        let device = manager.verify_trust("user-1", &token, None).await.unwrap();
        assert!(device.is_some());

        let device = device.unwrap();
        assert_eq!(device.user_id, "user-1");
        assert_eq!(device.device_name, Some("Chrome on macOS".to_string()));
    }

    #[test]
    fn test_config_builder() {
        let config = TrustedDeviceConfig::new()
            .trust_duration(Duration::from_secs(7 * 24 * 60 * 60)) // 7 days
            .max_devices_per_user(5)
            .validate_fingerprint(true);

        assert_eq!(config.trust_duration, Duration::from_secs(7 * 24 * 60 * 60));
        assert_eq!(config.max_devices_per_user, 5);
        assert!(config.validate_fingerprint);
    }

    #[test]
    fn test_fingerprint_matching() {
        let fp1 = DeviceFingerprint::new()
            .with_ip("192.168.1.1")
            .with_user_agent("Chrome");

        let fp2 = DeviceFingerprint::new()
            .with_ip("192.168.1.1")
            .with_user_agent("Chrome");

        let fp3 = DeviceFingerprint::new()
            .with_ip("10.0.0.1")
            .with_user_agent("Chrome");

        assert!(fp1.matches(&fp2));
        assert!(!fp1.matches(&fp3));

        // Partial fingerprints should match
        let partial = DeviceFingerprint::new().with_ip("192.168.1.1");
        assert!(fp1.matches(&partial));
    }

    #[test]
    fn test_parse_device_name() {
        assert_eq!(
            parse_device_name("Mozilla/5.0 (Macintosh; Intel Mac OS X) Chrome/120"),
            "Chrome on macOS"
        );
        assert_eq!(
            parse_device_name("Mozilla/5.0 (Windows NT 10.0) Firefox/121"),
            "Firefox on Windows"
        );
        assert_eq!(
            parse_device_name("Mozilla/5.0 (iPhone; CPU iPhone OS 17) Safari/605"),
            "Safari on iOS"
        );
    }
}
