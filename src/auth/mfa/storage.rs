//! MFA storage trait.

use crate::error::Result;
use async_trait::async_trait;

/// MFA status for a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MfaStatus {
    /// MFA not enabled.
    Disabled,
    /// MFA setup started but not verified.
    Pending,
    /// MFA fully enabled and verified.
    Enabled,
}

/// Trait for storing MFA data.
///
/// Implement this for your database layer.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::auth::mfa::MfaStore;
/// use async_trait::async_trait;
///
/// struct MyMfaStore {
///     db: DatabaseConnection,
/// }
///
/// #[async_trait]
/// impl MfaStore for MyMfaStore {
///     async fn get_totp_secret(&self, user_id: &str) -> Result<Option<String>> {
///         // Query your database
///         Ok(self.db.get_mfa_secret(user_id).await?)
///     }
///
///     // ... implement other methods
/// }
/// ```
#[async_trait]
pub trait MfaStore: Send + Sync {
    /// Get the TOTP secret for a user (None if MFA not set up).
    async fn get_totp_secret(&self, user_id: &str) -> Result<Option<String>>;

    /// Store a TOTP secret (during setup, before verification).
    async fn set_totp_secret(&self, user_id: &str, secret: &str) -> Result<()>;

    /// Mark TOTP as verified/enabled.
    async fn enable_totp(&self, user_id: &str) -> Result<()>;

    /// Disable TOTP (removes secret).
    async fn disable_totp(&self, user_id: &str) -> Result<()>;

    /// Get MFA status for a user.
    async fn get_mfa_status(&self, user_id: &str) -> Result<MfaStatus>;

    /// Get backup codes (should be stored hashed).
    async fn get_backup_codes(&self, user_id: &str) -> Result<Vec<String>>;

    /// Store backup codes (should be hashed before storage).
    async fn set_backup_codes(&self, user_id: &str, codes: &[String]) -> Result<()>;

    /// Remove a used backup code by index.
    async fn remove_backup_code(&self, user_id: &str, index: usize) -> Result<()>;

    /// Get count of remaining backup codes.
    async fn backup_codes_remaining(&self, user_id: &str) -> Result<usize> {
        Ok(self.get_backup_codes(user_id).await?.len())
    }
}
