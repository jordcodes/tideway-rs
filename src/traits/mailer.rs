//! Mailer trait for sending emails
//!
//! This trait abstracts email sending backends, allowing users to swap between
//! SMTP, third-party services (Resend, SendGrid), or console output for development.

use crate::error::Result;
use async_trait::async_trait;

/// An email message to be sent
#[derive(Debug, Clone)]
pub struct Email {
    /// Sender email address (e.g., "noreply@example.com")
    pub from: String,
    /// Recipient email addresses
    pub to: Vec<String>,
    /// CC recipients
    pub cc: Vec<String>,
    /// BCC recipients
    pub bcc: Vec<String>,
    /// Email subject line
    pub subject: String,
    /// Plain text body (optional if html is provided)
    pub text: Option<String>,
    /// HTML body (optional if text is provided)
    pub html: Option<String>,
    /// Reply-to address (optional)
    pub reply_to: Option<String>,
}

impl Email {
    /// Create a new email with the required fields
    pub fn new(from: impl Into<String>, to: impl Into<String>, subject: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: vec![to.into()],
            cc: Vec::new(),
            bcc: Vec::new(),
            subject: subject.into(),
            text: None,
            html: None,
            reply_to: None,
        }
    }

    /// Add a recipient
    pub fn to(mut self, recipient: impl Into<String>) -> Self {
        self.to.push(recipient.into());
        self
    }

    /// Add multiple recipients
    pub fn to_many(mut self, recipients: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.to.extend(recipients.into_iter().map(|r| r.into()));
        self
    }

    /// Add a CC recipient
    pub fn cc(mut self, recipient: impl Into<String>) -> Self {
        self.cc.push(recipient.into());
        self
    }

    /// Add a BCC recipient
    pub fn bcc(mut self, recipient: impl Into<String>) -> Self {
        self.bcc.push(recipient.into());
        self
    }

    /// Set the plain text body
    pub fn text(mut self, body: impl Into<String>) -> Self {
        self.text = Some(body.into());
        self
    }

    /// Set the HTML body
    pub fn html(mut self, body: impl Into<String>) -> Self {
        self.html = Some(body.into());
        self
    }

    /// Set the reply-to address
    pub fn reply_to(mut self, address: impl Into<String>) -> Self {
        self.reply_to = Some(address.into());
        self
    }

    /// Validate the email has required fields
    pub fn validate(&self) -> Result<()> {
        if self.from.is_empty() {
            return Err(crate::error::TidewayError::bad_request("Email 'from' is required"));
        }
        if self.to.is_empty() {
            return Err(crate::error::TidewayError::bad_request("Email 'to' is required"));
        }
        if self.subject.is_empty() {
            return Err(crate::error::TidewayError::bad_request("Email 'subject' is required"));
        }
        if self.text.is_none() && self.html.is_none() {
            return Err(crate::error::TidewayError::bad_request("Email must have either 'text' or 'html' body"));
        }
        Ok(())
    }
}

/// Mailer trait for sending emails
///
/// Implement this trait to create custom email backends.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::traits::mailer::{Mailer, Email};
/// use tideway::error::Result;
/// use async_trait::async_trait;
///
/// struct MyMailer;
///
/// #[async_trait]
/// impl Mailer for MyMailer {
///     async fn send(&self, email: &Email) -> Result<()> {
///         // Send via your preferred service
///         Ok(())
///     }
///
///     fn is_healthy(&self) -> bool {
///         true
///     }
/// }
/// ```
#[async_trait]
pub trait Mailer: Send + Sync {
    /// Send an email
    ///
    /// Returns `Ok(())` if the email was sent successfully.
    /// Returns an error if sending failed.
    async fn send(&self, email: &Email) -> Result<()>;

    /// Check if the mailer backend is healthy/connected
    fn is_healthy(&self) -> bool;
}
