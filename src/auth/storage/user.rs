//! User storage trait for authentication.

use crate::error::Result;
use async_trait::async_trait;
use std::time::SystemTime;

/// Trait for user storage operations required by auth flows.
///
/// Implement this trait for your database layer to use the authentication flows.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::auth::storage::UserStore;
/// use async_trait::async_trait;
///
/// struct MyUserStore {
///     db: DatabaseConnection,
/// }
///
/// #[async_trait]
/// impl UserStore for MyUserStore {
///     type User = MyUser;
///
///     async fn find_by_email(&self, email: &str) -> Result<Option<Self::User>> {
///         // Query your database
///         Ok(self.db.find_user_by_email(email).await?)
///     }
///
///     // ... implement other methods
/// }
/// ```
#[async_trait]
pub trait UserStore: Send + Sync {
    /// The user type returned by this store.
    type User: Send + Sync + Clone;

    /// Find a user by email address (case-insensitive).
    async fn find_by_email(&self, email: &str) -> Result<Option<Self::User>>;

    /// Find a user by their unique ID.
    async fn find_by_id(&self, id: &str) -> Result<Option<Self::User>>;

    /// Get the user's ID as a string.
    fn user_id(&self, user: &Self::User) -> String;

    /// Get the user's email address.
    fn user_email(&self, user: &Self::User) -> String;

    /// Get the user's name (if available).
    fn user_name(&self, _user: &Self::User) -> Option<String> {
        None
    }

    /// Get the user's password hash.
    async fn get_password_hash(&self, user: &Self::User) -> Result<String>;

    /// Update the user's password hash.
    async fn update_password_hash(&self, user: &Self::User, hash: &str) -> Result<()>;

    /// Check if the user's email has been verified.
    async fn is_verified(&self, user: &Self::User) -> Result<bool>;

    /// Mark the user's email as verified.
    async fn mark_verified(&self, user: &Self::User) -> Result<()>;

    /// Check if the account is locked and return unlock time if so.
    async fn is_locked(&self, user: &Self::User) -> Result<Option<SystemTime>>;

    /// Record a failed login attempt (password failure).
    ///
    /// Implementations should track failed attempts and optionally lock
    /// the account after too many failures.
    async fn record_failed_attempt(&self, user: &Self::User) -> Result<()>;

    /// Record a failed MFA attempt.
    ///
    /// By default, this calls `record_failed_attempt`. Override to track
    /// MFA failures separately with different lockout policies.
    async fn record_failed_mfa_attempt(&self, user: &Self::User) -> Result<()> {
        self.record_failed_attempt(user).await
    }

    /// Clear failed login attempts (call on successful login).
    async fn clear_failed_attempts(&self, user: &Self::User) -> Result<()>;

    /// Check if the user has MFA enabled.
    async fn has_mfa_enabled(&self, user: &Self::User) -> Result<bool>;

    /// Get the user's TOTP secret (if MFA is enabled).
    #[cfg(feature = "auth-mfa")]
    async fn get_totp_secret(&self, user: &Self::User) -> Result<Option<String>>;

    /// Get the user's backup codes.
    #[cfg(feature = "auth-mfa")]
    async fn get_backup_codes(&self, user: &Self::User) -> Result<Vec<String>>;

    /// Remove a used backup code by index.
    #[cfg(feature = "auth-mfa")]
    async fn remove_backup_code(&self, user: &Self::User, index: usize) -> Result<()>;
}

/// Trait for creating new users during registration.
#[async_trait]
pub trait UserCreator: Send + Sync {
    /// The user type created by this store.
    type User: Send + Sync;

    /// Check if an email address is already registered.
    async fn email_exists(&self, email: &str) -> Result<bool>;

    /// Create a new user with the given credentials.
    ///
    /// Returns the created user.
    async fn create_user(
        &self,
        email: &str,
        password_hash: &str,
        name: Option<&str>,
    ) -> Result<Self::User>;

    /// Send a verification email to the user.
    async fn send_verification_email(&self, user: &Self::User) -> Result<()>;
}

/// Trait for password reset token storage.
#[async_trait]
pub trait PasswordResetStore: Send + Sync {
    /// The user type.
    type User: Send + Sync;

    /// Find a user by email.
    async fn find_by_email(&self, email: &str) -> Result<Option<Self::User>>;

    /// Get the user's ID.
    fn user_id(&self, user: &Self::User) -> String;

    /// Store a password reset token with expiration.
    async fn store_reset_token(
        &self,
        user_id: &str,
        token_hash: &str,
        expires: SystemTime,
    ) -> Result<()>;

    /// Consume a reset token, returning the user ID if valid.
    ///
    /// This should delete or mark the token as used.
    async fn consume_reset_token(&self, token_hash: &str) -> Result<Option<String>>;

    /// Update a user's password hash.
    async fn update_password(&self, user_id: &str, hash: &str) -> Result<()>;

    /// Invalidate all sessions for a user (force re-login after password change).
    async fn invalidate_sessions(&self, user_id: &str) -> Result<()>;

    /// Send a password reset email.
    async fn send_reset_email(
        &self,
        user: &Self::User,
        token: &str,
        expires_in: std::time::Duration,
    ) -> Result<()>;
}

/// Trait for email verification token storage.
#[async_trait]
pub trait VerificationStore: Send + Sync {
    /// Store an email verification token.
    async fn store_verification_token(
        &self,
        user_id: &str,
        token_hash: &str,
        expires: SystemTime,
    ) -> Result<()>;

    /// Consume a verification token, returning the user ID if valid.
    async fn consume_verification_token(&self, token_hash: &str) -> Result<Option<String>>;

    /// Mark a user as verified.
    async fn mark_user_verified(&self, user_id: &str) -> Result<()>;

    /// Send a verification email.
    async fn send_verification_email(
        &self,
        user_id: &str,
        email: &str,
        token: &str,
        expires_in: std::time::Duration,
    ) -> Result<()>;
}
