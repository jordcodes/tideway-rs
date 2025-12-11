//! Test fixtures and factory pattern for generating test data
//!
//! This module provides helpers for creating test data in a consistent way.

use uuid::Uuid;

/// Trait for factories that can create test data
pub trait TestFactory<T> {
    /// Create a new instance with default test values
    fn build() -> T;

    /// Create a new instance using a builder pattern
    fn builder() -> T;
}

/// Helper functions for generating fake test data
pub mod fake {
    use super::*;

    /// Generate a fake email address
    pub fn email() -> String {
        format!("test-{}@example.com", Uuid::new_v4().simple())
    }

    /// Generate a fake UUID as a string
    pub fn uuid() -> String {
        Uuid::new_v4().to_string()
    }

    /// Generate a fake name
    pub fn name() -> String {
        format!("Test User {}", &Uuid::new_v4().simple().to_string()[..8])
    }

    /// Generate a fake username
    pub fn username() -> String {
        format!("user_{}", &Uuid::new_v4().simple().to_string()[..8])
    }

    /// Generate a fake phone number (US format)
    pub fn phone() -> String {
        format!("+1555{:07}", fastrand::u32(0..9999999))
    }

    /// Generate a random integer between min and max
    pub fn int(min: i32, max: i32) -> i32 {
        fastrand::i32(min..=max)
    }

    /// Generate a random string of the given length
    pub fn string(length: usize) -> String {
        (0..length)
            .map(|_| fastrand::alphabetic())
            .collect()
    }
}

/// Builder for creating test user data
#[derive(Debug, Clone)]
pub struct TestUser {
    pub id: String,
    pub email: String,
    pub name: String,
    pub username: String,
}

impl TestUser {
    /// Create a new TestUser builder
    pub fn builder() -> TestUserBuilder {
        TestUserBuilder::default()
    }

    /// Create a TestUser with generated values
    pub fn generate() -> Self {
        Self::builder().build()
    }
}

/// Builder for TestUser
pub struct TestUserBuilder {
    id: Option<String>,
    email: Option<String>,
    name: Option<String>,
    username: Option<String>,
}

impl Default for TestUserBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TestUserBuilder {
    /// Create a new TestUserBuilder
    pub fn new() -> Self {
        Self {
            id: None,
            email: None,
            name: None,
            username: None,
        }
    }

    /// Set the user ID
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set the email
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Set the name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the username
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Build the TestUser
    pub fn build(self) -> TestUser {
        TestUser {
            id: self.id.unwrap_or_else(fake::uuid),
            email: self.email.unwrap_or_else(fake::email),
            name: self.name.unwrap_or_else(fake::name),
            username: self.username.unwrap_or_else(fake::username),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fake_email() {
        let email = fake::email();
        assert!(email.contains("@example.com"));
        assert!(email.starts_with("test-"));
    }

    #[test]
    fn test_fake_uuid() {
        let uuid1 = fake::uuid();
        let uuid2 = fake::uuid();
        assert_ne!(uuid1, uuid2);
        assert_eq!(uuid1.len(), 36); // Standard UUID format
    }

    #[test]
    fn test_test_user_builder() {
        let user = TestUser::builder()
            .with_email("custom@example.com")
            .with_name("Custom Name")
            .build();

        assert_eq!(user.email, "custom@example.com");
        assert_eq!(user.name, "Custom Name");
        assert!(!user.id.is_empty());
        assert!(!user.username.is_empty());
    }

    #[test]
    fn test_test_user_generate() {
        let user = TestUser::generate();
        assert!(!user.id.is_empty());
        assert!(!user.email.is_empty());
        assert!(!user.name.is_empty());
        assert!(!user.username.is_empty());
    }
}

