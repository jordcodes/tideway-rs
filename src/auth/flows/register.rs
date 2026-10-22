//! Registration flow.
//!
//! This module emits tracing events for security monitoring:
//! - `auth.register.success` - User registered successfully
//! - `auth.register.failed` - Registration failed (validation, duplicate)
//! - `auth.register.verification_email_failed` - Failed to send verification email
//! - `auth.register.existing_account_notice_failed` - Failed to notify an existing account owner

use crate::auth::password::{PasswordHasher, PasswordPolicy};
use crate::auth::storage::UserCreator;
use crate::error::{Result, TidewayError};

use super::types::RegisterRequest;

/// Handles user registration.
///
/// [`Self::register`] returns the created user, so a caller can tell a new email from an
/// existing one. Use [`Self::register_without_enumeration`] when registration must not reveal
/// which emails have accounts.
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
    ///
    /// An email that is already registered returns `BadRequest("Registration failed")` without
    /// hashing, so callers can tell it apart from a successful registration. Use
    /// [`Self::register_without_enumeration`] if that matters.
    #[cfg(feature = "auth")]
    pub async fn register(&self, req: RegisterRequest) -> Result<C::User> {
        let email = self.validate(&req)?;

        if self.user_creator.email_exists(&email).await? {
            tracing::info!(
                target: "auth.register.failed",
                email = %email,
                reason = "email_exists",
                "Registration failed: email already registered"
            );
            return Err(TidewayError::BadRequest("Registration failed".into()));
        }

        self.create(&email, &req).await
    }

    /// Register without revealing whether the email already has an account.
    ///
    /// New and existing emails both return `Ok(())` after hashing the password. A new email
    /// creates the user and sends the verification email; an existing one calls
    /// [`UserCreator::notify_existing_account`] instead. Respond with the same "check your email"
    /// message either way, and do not log the user in from this response. Invalid emails and
    /// weak passwords still return errors, since they reveal nothing about other accounts.
    #[cfg(feature = "auth")]
    pub async fn register_without_enumeration(&self, req: RegisterRequest) -> Result<()> {
        let email = self.validate(&req)?;

        if self.user_creator.email_exists(&email).await? {
            // Match the new-account path's hashing cost.
            let _ = self.password_hasher.hash_async(&req.password).await?;
            tracing::info!(
                target: "auth.register.failed",
                email = %email,
                reason = "email_exists",
                "Registration skipped: email already registered"
            );
            if let Err(e) = self.user_creator.notify_existing_account(&email).await {
                tracing::warn!(
                    target: "auth.register.existing_account_notice_failed",
                    email = %email,
                    error = %e,
                    "Failed to notify existing account owner"
                );
            }
            return Ok(());
        }

        self.create(&email, &req).await.map(|_| ())
    }

    #[cfg(feature = "auth")]
    fn validate(&self, req: &RegisterRequest) -> Result<String> {
        let email = req.email.trim().to_lowercase();

        // Validate email format
        if !is_valid_email(&email) {
            tracing::info!(
                target: "auth.register.failed",
                email = %email,
                reason = "invalid_email_format",
                "Registration failed: invalid email format"
            );
            return Err(TidewayError::BadRequest("Invalid email format".into()));
        }

        // Validate password
        if let Err(e) = self.password_policy.check(&req.password) {
            tracing::info!(
                target: "auth.register.failed",
                email = %email,
                reason = "weak_password",
                "Registration failed: password policy violation"
            );
            return Err(e);
        }

        Ok(email)
    }

    #[cfg(feature = "auth")]
    async fn create(&self, email: &str, req: &RegisterRequest) -> Result<C::User> {
        let hash = self.password_hasher.hash_async(&req.password).await?;
        let user = self
            .user_creator
            .create_user(email, &hash, req.name.as_deref())
            .await?;

        let user_id = self.user_creator.user_id(&user);

        tracing::info!(
            target: "auth.register.success",
            user_id = %user_id,
            email = %email,
            "User registered successfully"
        );

        // Send verification email (fire and forget, don't fail registration)
        if let Err(e) = self.user_creator.send_verification_email(&user).await {
            tracing::warn!(
                target: "auth.register.verification_email_failed",
                user_id = %user_id,
                email = %email,
                error = %e,
                "Failed to send verification email"
            );
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

    #[derive(Default)]
    struct TestCreator {
        users: std::sync::Mutex<Vec<String>>,
        notified: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl UserCreator for TestCreator {
        type User = String;

        fn user_id(&self, user: &String) -> String {
            user.clone()
        }

        async fn email_exists(&self, email: &str) -> Result<bool> {
            Ok(self.users.lock().unwrap().iter().any(|u| u == email))
        }

        async fn create_user(
            &self,
            email: &str,
            _hash: &str,
            _name: Option<&str>,
        ) -> Result<String> {
            self.users.lock().unwrap().push(email.to_string());
            Ok(email.to_string())
        }

        async fn send_verification_email(&self, _user: &String) -> Result<()> {
            Ok(())
        }

        async fn notify_existing_account(&self, email: &str) -> Result<()> {
            self.notified.lock().unwrap().push(email.to_string());
            Ok(())
        }
    }

    fn request(email: &str) -> RegisterRequest {
        RegisterRequest {
            email: email.to_string(),
            password: "Correct-Horse-Battery-9".to_string(),
            name: None,
        }
    }

    #[cfg(feature = "auth")]
    #[tokio::test]
    async fn register_without_enumeration_answers_existing_and_new_emails_alike() {
        use crate::auth::password::PasswordConfig;

        let flow = RegistrationFlow::new(TestCreator::default())
            .with_hasher(PasswordHasher::new(PasswordConfig::fast()));
        flow.register(request("taken@example.com")).await.unwrap();

        let existing = flow
            .register_without_enumeration(request("Taken@example.com"))
            .await;
        let new = flow
            .register_without_enumeration(request("new@example.com"))
            .await;

        assert!(existing.is_ok());
        assert!(new.is_ok());
        assert_eq!(
            *flow.user_creator.users.lock().unwrap(),
            ["taken@example.com", "new@example.com"]
        );
        assert_eq!(
            *flow.user_creator.notified.lock().unwrap(),
            ["taken@example.com"]
        );

        // The original method still reports the duplicate.
        assert!(matches!(
            flow.register(request("taken@example.com")).await,
            Err(TidewayError::BadRequest(_))
        ));
    }

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
