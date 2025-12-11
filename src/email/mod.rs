//! Email sending functionality
//!
//! This module provides email sending capabilities with multiple backend options:
//! - `ConsoleMailer` - Prints emails to stdout (for development)
//! - `SmtpMailer` - Sends emails via SMTP using lettre
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
mod smtp;

pub use console::ConsoleMailer;
pub use smtp::{SmtpMailer, SmtpConfig};

// Re-export Email from traits for convenience
pub use crate::traits::mailer::Email;
