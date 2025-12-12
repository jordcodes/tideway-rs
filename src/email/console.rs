//! Console mailer for development
//!
//! Prints emails to stdout instead of sending them, useful for local development.
//!
//! # Security Warning
//!
//! This mailer outputs email content to stdout/stderr which may be captured by
//! logging systems in containerized environments. **Do not use in production**
//! as email content may contain sensitive information (tokens, PII, etc.).
//!
//! For production, use a real email provider (SMTP, SendGrid, etc.).

use crate::error::Result;
use crate::traits::mailer::{Email, Mailer};
use async_trait::async_trait;

/// A mailer that prints emails to stdout instead of sending them
///
/// Useful for development and testing when you want to see what emails
/// would be sent without actually sending them.
///
/// # Security Warning
///
/// **FOR DEVELOPMENT USE ONLY.** This mailer outputs email content including
/// potentially sensitive information (email addresses, body content, tokens)
/// to stdout. In containerized environments, stdout is often captured by
/// logging systems, which could expose sensitive data.
///
/// By default, email body content is redacted. Use `with_full_output(true)`
/// to see full content in development.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::email::ConsoleMailer;
/// use tideway::traits::mailer::{Mailer, Email};
///
/// // Default: redacts body content for safety
/// let mailer = ConsoleMailer::new();
///
/// // Development only: show full email content
/// let mailer = ConsoleMailer::new().with_full_output(true);
///
/// let email = Email::new("from@example.com", "to@example.com", "Test")
///     .text("Hello!");
///
/// mailer.send(&email).await?; // Prints to stdout
/// ```
#[derive(Debug, Clone)]
pub struct ConsoleMailer {
    /// Optional prefix for log output
    prefix: String,
    /// Whether to show full email content (default: false for security)
    show_full_content: bool,
}

impl ConsoleMailer {
    /// Create a new console mailer
    ///
    /// By default, email body content is redacted for security.
    /// Use `with_full_output(true)` to see full content.
    pub fn new() -> Self {
        Self {
            prefix: "[EMAIL]".to_string(),
            show_full_content: false,
        }
    }

    /// Create a console mailer with a custom prefix
    pub fn with_prefix(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            show_full_content: false,
        }
    }

    /// Enable or disable full email content output
    ///
    /// # Security Warning
    ///
    /// When enabled, full email body content will be printed to stdout.
    /// Only enable this in secure development environments where stdout
    /// is not captured by logging systems.
    ///
    /// Default: `false` (body content is redacted)
    pub fn with_full_output(mut self, enabled: bool) -> Self {
        if enabled {
            tracing::warn!(
                "ConsoleMailer: full output enabled - email content will be visible in logs. \
                 Do not use in production!"
            );
        }
        self.show_full_content = enabled;
        self
    }
}

impl Default for ConsoleMailer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Mailer for ConsoleMailer {
    async fn send(&self, email: &Email) -> Result<()> {
        email.validate()?;

        println!("{} ════════════════════════════════════════", self.prefix);
        println!("{} From:    {}", self.prefix, email.from);
        println!("{} To:      {} recipient(s)", self.prefix, email.to.len());
        if !email.cc.is_empty() {
            println!("{} CC:      {} recipient(s)", self.prefix, email.cc.len());
        }
        if !email.bcc.is_empty() {
            println!("{} BCC:     {} recipient(s)", self.prefix, email.bcc.len());
        }
        if email.reply_to.is_some() {
            println!("{} Reply-To: [set]", self.prefix);
        }
        println!("{} Subject: {}", self.prefix, email.subject);
        println!("{} ────────────────────────────────────────", self.prefix);

        if self.show_full_content {
            // Full output mode - show everything (development only)
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
        } else {
            // Redacted mode (default) - show metadata only
            if let Some(ref text) = email.text {
                println!("{} [TEXT] {} bytes [REDACTED]", self.prefix, text.len());
            }
            if let Some(ref html) = email.html {
                println!("{} [HTML] {} bytes [REDACTED]", self.prefix, html.len());
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
