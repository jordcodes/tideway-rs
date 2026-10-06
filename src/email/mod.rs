//! Email sending functionality
//!
//! This module provides email sending capabilities with multiple backend options:
//! - `ConsoleMailer` - Prints emails to stdout (for development)
//! - `SmtpMailer` - Sends emails via SMTP using lettre
//! - `ResendMailer` - Sends emails through Resend's HTTPS API
//!
//! It also ships default, overridable lifecycle emails (verification, password
//! reset, invitation, trial ending, payment failed, receipt) rendered by
//! [`LifecycleEmailer`]. With the `jobs` feature they are delivered by a
//! background worker through [`SendEmailJob`]. See [`lifecycle`] for details.
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::email::{Email, SmtpMailer, SmtpConfig};
//! use tideway::traits::mailer::Mailer;
//!
//! // Create mailer
//! let config = SmtpConfig::new("smtp.example.com")
//!     .credentials("user", "password")
//!     .from("noreply@example.com");
//! let mailer = SmtpMailer::new(config)?;
//!
//! // Send email
//! let email = Email::new("noreply@example.com", "user@example.com", "Welcome!")
//!     .text("Thanks for signing up!")
//!     .html("<h1>Thanks for signing up!</h1>");
//!
//! mailer.send(&email).await?;
//! ```

mod console;
#[cfg(feature = "jobs")]
mod job;
pub mod lifecycle;
mod resend;
mod smtp;

pub use console::ConsoleMailer;
#[cfg(feature = "jobs")]
pub use job::{SEND_EMAIL_JOB_TYPE, SendEmailJob, register_email_jobs};
pub use lifecycle::{
    Amount, DefaultEmailLayout, DefaultEmailTemplates, EmailAction, EmailBranding, EmailContent,
    EmailLayout, EmailTemplates, LifecycleEmail, LifecycleEmailKind, LifecycleEmailer,
    RenderedEmail, default_content,
};
pub use resend::{ResendConfig, ResendMailer};
pub use smtp::{SmtpConfig, SmtpMailer};

// Re-export Email from traits for convenience
pub use crate::traits::mailer::Email;
