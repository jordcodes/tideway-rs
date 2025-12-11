//! Console mailer for development
//!
//! Prints emails to stdout instead of sending them, useful for local development.

use crate::error::Result;
use crate::traits::mailer::{Email, Mailer};
use async_trait::async_trait;

/// A mailer that prints emails to stdout instead of sending them
///
/// Useful for development and testing when you want to see what emails
/// would be sent without actually sending them.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::email::ConsoleMailer;
/// use tideway::traits::mailer::{Mailer, Email};
///
/// let mailer = ConsoleMailer::new();
///
/// let email = Email::new("from@example.com", "to@example.com", "Test")
///     .text("Hello!");
///
/// mailer.send(&email).await?; // Prints to stdout
/// ```
#[derive(Debug, Clone, Default)]
pub struct ConsoleMailer {
    /// Optional prefix for log output
    prefix: String,
}

impl ConsoleMailer {
    /// Create a new console mailer
    pub fn new() -> Self {
        Self {
            prefix: "[EMAIL]".to_string(),
        }
    }

    /// Create a console mailer with a custom prefix
    pub fn with_prefix(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }
}

#[async_trait]
impl Mailer for ConsoleMailer {
    async fn send(&self, email: &Email) -> Result<()> {
        email.validate()?;

        println!("{} ════════════════════════════════════════", self.prefix);
        println!("{} From:    {}", self.prefix, email.from);
        println!("{} To:      {}", self.prefix, email.to.join(", "));
        if !email.cc.is_empty() {
            println!("{} CC:      {}", self.prefix, email.cc.join(", "));
        }
        if !email.bcc.is_empty() {
            println!("{} BCC:     {}", self.prefix, email.bcc.join(", "));
        }
        if let Some(ref reply_to) = email.reply_to {
            println!("{} Reply-To: {}", self.prefix, reply_to);
        }
        println!("{} Subject: {}", self.prefix, email.subject);
        println!("{} ────────────────────────────────────────", self.prefix);
        if let Some(ref text) = email.text {
            println!("{} [TEXT]", self.prefix);
            for line in text.lines() {
                println!("{} {}", self.prefix, line);
            }
        }
        if let Some(ref html) = email.html {
            println!("{} [HTML]", self.prefix);
            for line in html.lines() {
                println!("{} {}", self.prefix, line);
            }
        }
        println!("{} ════════════════════════════════════════", self.prefix);

        Ok(())
    }

    fn is_healthy(&self) -> bool {
        true // Console is always available
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_console_mailer_sends_without_error() {
        let mailer = ConsoleMailer::new();
        let email = Email::new("from@test.com", "to@test.com", "Test Subject")
            .text("Test body");

        let result = mailer.send(&email).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_console_mailer_validates_email() {
        let mailer = ConsoleMailer::new();
        let email = Email::new("from@test.com", "to@test.com", "Test Subject");
        // No body - should fail validation

        let result = mailer.send(&email).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_console_mailer_is_healthy() {
        let mailer = ConsoleMailer::new();
        assert!(mailer.is_healthy());
    }
}
