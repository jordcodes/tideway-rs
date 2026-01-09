//! Registration flow.

use crate::auth::password::{PasswordHasher, PasswordPolicy};
use crate::auth::storage::UserCreator;
use crate::error::{Result, TidewayError};

use super::types::RegisterRequest;

/// Handles user registration.
pub struct RegistrationFlow<C: UserCreator> {
    user_creator: C,
    password_hasher: PasswordHasher,
    password_policy: PasswordPolicy,
}

impl<C: UserCreator> RegistrationFlow<C> {
    /// Create a new registration flow.
    pub fn new(user_creator: C) -> Self {
        Self {
            user_creator,
            password_hasher: PasswordHasher::default(),
            password_policy: PasswordPolicy::modern(),
        }
    }

    /// Set a custom password policy.
    pub fn with_policy(mut self, policy: PasswordPolicy) -> Self {
        self.password_policy = policy;
        self
    }

    /// Set a custom password hasher.
    pub fn with_hasher(mut self, hasher: PasswordHasher) -> Self {
        self.password_hasher = hasher;
        self
    }

    /// Register a new user.
    #[cfg(feature = "auth")]
    pub async fn register(&self, req: RegisterRequest) -> Result<C::User> {
        let email = req.email.trim().to_lowercase();

        // Validate email format
        if !is_valid_email(&email) {
            return Err(TidewayError::BadRequest("Invalid email format".into()));
        }

        // Validate password
        self.password_policy.check(&req.password)?;

        // Check if already registered
        if self.user_creator.email_exists(&email).await? {
            return Err(TidewayError::BadRequest("Email already registered".into()));
        }

        // Hash password
        let hash = self.password_hasher.hash(&req.password)?;

        // Create user
        let user = self
            .user_creator
            .create_user(&email, &hash, req.name.as_deref())
            .await?;

        // Send verification email (fire and forget, don't fail registration)
        if let Err(e) = self.user_creator.send_verification_email(&user).await {
            tracing::warn!("Failed to send verification email: {}", e);
        }

        Ok(user)
    }

    #[cfg(not(feature = "auth"))]
    pub async fn register(&self, _req: RegisterRequest) -> Result<C::User> {
        Err(TidewayError::Internal("auth feature not enabled".into()))
    }
}

/// Basic email validation.
fn is_valid_email(email: &str) -> bool {
    // Basic validation - has @ and domain
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let local = parts[0];
    let domain = parts[1];

    !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_emails() {
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("user.name@example.com"));
        assert!(is_valid_email("user+tag@example.co.uk"));
    }

    #[test]
    fn test_invalid_emails() {
        assert!(!is_valid_email("userexample.com"));
        assert!(!is_valid_email("user@"));
        assert!(!is_valid_email("@example.com"));
        assert!(!is_valid_email("user@.com"));
        assert!(!is_valid_email("user@example."));
        assert!(!is_valid_email("user@@example.com"));
    }
}
