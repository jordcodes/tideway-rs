//! SMTP mailer using lettre
//!
//! Sends emails via SMTP server.

use crate::error::{Result, TidewayError};
use crate::traits::mailer::{Email, Mailer};
use async_trait::async_trait;
use lettre::{
    message::{header::ContentType, Mailbox, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use std::sync::Arc;
use tokio::sync::RwLock;

/// SMTP configuration
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    /// SMTP server hostname
    pub host: String,
    /// SMTP server port (default: 587 for STARTTLS)
    pub port: u16,
    /// Username for authentication
    pub username: Option<String>,
    /// Password for authentication
    pub password: Option<String>,
    /// Default "from" address
    pub default_from: Option<String>,
    /// Use STARTTLS (default: true)
    pub starttls: bool,
}

impl SmtpConfig {
    /// Create a new SMTP configuration with the server hostname
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: 587,
            username: None,
            password: None,
            default_from: None,
            starttls: true,
        }
    }

    /// Set the port (default: 587)
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set authentication credentials
    pub fn credentials(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    /// Set the default "from" address
    pub fn from(mut self, address: impl Into<String>) -> Self {
        self.default_from = Some(address.into());
        self
    }

    /// Disable STARTTLS (use plain connection or implicit TLS)
    pub fn no_starttls(mut self) -> Self {
        self.starttls = false;
        self
    }

    /// Create config from environment variables
    ///
    /// Reads from:
    /// - `SMTP_HOST` (required)
    /// - `SMTP_PORT` (optional, default: 587)
    /// - `SMTP_USERNAME` (optional)
    /// - `SMTP_PASSWORD` (optional)
    /// - `SMTP_FROM` (optional)
    /// - `SMTP_STARTTLS` (optional, default: true)
    pub fn from_env() -> Result<Self> {
        let host = std::env::var("SMTP_HOST")
            .map_err(|_| TidewayError::internal("SMTP_HOST environment variable not set"))?;

        let port = std::env::var("SMTP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(587);

        let username = std::env::var("SMTP_USERNAME").ok();
        let password = std::env::var("SMTP_PASSWORD").ok();
        let default_from = std::env::var("SMTP_FROM").ok();
        let starttls = std::env::var("SMTP_STARTTLS")
            .map(|v| v != "false" && v != "0")
            .unwrap_or(true);

        Ok(Self {
            host,
            port,
            username,
            password,
            default_from,
            starttls,
        })
    }
}

/// SMTP mailer using lettre
///
/// # Example
///
/// ```rust,ignore
/// use tideway::email::{SmtpMailer, SmtpConfig, Email};
/// use tideway::traits::mailer::Mailer;
///
/// let config = SmtpConfig::new("smtp.gmail.com")
///     .port(587)
///     .credentials("user@gmail.com", "app-password")
///     .from("noreply@myapp.com");
///
/// let mailer = SmtpMailer::new(config)?;
///
/// let email = Email::new("noreply@myapp.com", "user@example.com", "Welcome!")
///     .html("<h1>Welcome to our app!</h1>");
///
/// mailer.send(&email).await?;
/// ```
pub struct SmtpMailer {
    transport: Arc<RwLock<AsyncSmtpTransport<Tokio1Executor>>>,
    config: SmtpConfig,
}

impl SmtpMailer {
    /// Create a new SMTP mailer with the given configuration
    pub fn new(config: SmtpConfig) -> Result<Self> {
        let mut builder = if config.starttls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
                .map_err(|e| TidewayError::internal(format!("Failed to create SMTP transport: {}", e)))?
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
                .map_err(|e| TidewayError::internal(format!("Failed to create SMTP transport: {}", e)))?
        };

        builder = builder.port(config.port);

        if let (Some(username), Some(password)) = (&config.username, &config.password) {
            let credentials = Credentials::new(username.clone(), password.clone());
            builder = builder.credentials(credentials);
        }

        let transport = builder.build();

        Ok(Self {
            transport: Arc::new(RwLock::new(transport)),
            config,
        })
    }

    /// Create a new SMTP mailer from environment variables
    pub fn from_env() -> Result<Self> {
        let config = SmtpConfig::from_env()?;
        Self::new(config)
    }

    fn build_message(&self, email: &Email) -> Result<Message> {
        // Determine from address
        let from_str = if email.from.is_empty() {
            self.config.default_from.as_ref().ok_or_else(|| {
                TidewayError::bad_request("No 'from' address specified and no default configured")
            })?
        } else {
            &email.from
        };

        let from: Mailbox = from_str
            .parse()
            .map_err(|e| TidewayError::bad_request(format!("Invalid 'from' address: {}", e)))?;

        // Build message
        let mut builder = Message::builder()
            .from(from)
            .subject(&email.subject);

        // Add recipients
        for to in &email.to {
            let mailbox: Mailbox = to
                .parse()
                .map_err(|e| TidewayError::bad_request(format!("Invalid 'to' address '{}': {}", to, e)))?;
            builder = builder.to(mailbox);
        }

        // Add CC
        for cc in &email.cc {
            let mailbox: Mailbox = cc
                .parse()
                .map_err(|e| TidewayError::bad_request(format!("Invalid 'cc' address '{}': {}", cc, e)))?;
            builder = builder.cc(mailbox);
        }

        // Add BCC
        for bcc in &email.bcc {
            let mailbox: Mailbox = bcc
                .parse()
                .map_err(|e| TidewayError::bad_request(format!("Invalid 'bcc' address '{}': {}", bcc, e)))?;
            builder = builder.bcc(mailbox);
        }

        // Add reply-to
        if let Some(ref reply_to) = email.reply_to {
            let mailbox: Mailbox = reply_to
                .parse()
                .map_err(|e| TidewayError::bad_request(format!("Invalid 'reply_to' address: {}", e)))?;
            builder = builder.reply_to(mailbox);
        }

        // Build body
        let message = match (&email.text, &email.html) {
            (Some(text), Some(html)) => {
                // Multipart with both text and HTML
                builder
                    .multipart(
                        MultiPart::alternative()
                            .singlepart(
                                SinglePart::builder()
                                    .header(ContentType::TEXT_PLAIN)
                                    .body(text.clone()),
                            )
                            .singlepart(
                                SinglePart::builder()
                                    .header(ContentType::TEXT_HTML)
                                    .body(html.clone()),
                            ),
                    )
                    .map_err(|e| TidewayError::internal(format!("Failed to build email: {}", e)))?
            }
            (Some(text), None) => {
                // Plain text only
                builder
                    .header(ContentType::TEXT_PLAIN)
                    .body(text.clone())
                    .map_err(|e| TidewayError::internal(format!("Failed to build email: {}", e)))?
            }
            (None, Some(html)) => {
                // HTML only
                builder
                    .header(ContentType::TEXT_HTML)
                    .body(html.clone())
                    .map_err(|e| TidewayError::internal(format!("Failed to build email: {}", e)))?
            }
            (None, None) => {
                return Err(TidewayError::bad_request("Email must have either text or HTML body"));
            }
        };

        Ok(message)
    }
}

#[async_trait]
impl Mailer for SmtpMailer {
    async fn send(&self, email: &Email) -> Result<()> {
        email.validate()?;

        let message = self.build_message(email)?;

        let transport = self.transport.read().await;
        transport
            .send(message)
            .await
            .map_err(|e| TidewayError::internal(format!("Failed to send email: {}", e)))?;

        Ok(())
    }

    fn is_healthy(&self) -> bool {
        // We could test the connection here, but for now just return true
        // A more robust implementation would cache connection state
        true
    }
}

// Implement Debug manually since AsyncSmtpTransport doesn't impl Debug
impl std::fmt::Debug for SmtpMailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpMailer")
            .field("host", &self.config.host)
            .field("port", &self.config.port)
            .finish()
    }
}
