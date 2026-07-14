//! Resend HTTPS API mailer.

use crate::error::{Result, TidewayError};
use crate::traits::mailer::{Email, Mailer};
use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use serde::Serialize;
use std::time::Duration;

const DEFAULT_API_URL: &str = "https://api.resend.com/emails";

/// Configuration for [`ResendMailer`].
#[derive(Clone)]
pub struct ResendConfig {
    api_key: String,
    api_url: String,
    timeout: Duration,
}

impl ResendConfig {
    /// Create a Resend configuration. The API key is kept private and redacted
    /// from debug output.
    pub fn new(api_key: impl Into<String>) -> Result<Self> {
        let api_key = api_key.into();
        if api_key.trim().is_empty() {
            return Err(TidewayError::internal("RESEND_API_KEY must not be empty"));
        }

        Ok(Self {
            api_key,
            api_url: DEFAULT_API_URL.to_string(),
            timeout: Duration::from_secs(10),
        })
    }

    /// Load configuration from `RESEND_API_KEY`.
    pub fn from_env() -> Result<Self> {
        let api_key = std::env::var("RESEND_API_KEY")
            .map_err(|_| TidewayError::internal("RESEND_API_KEY must be set"))?;
        Self::new(api_key)
    }

    /// Set the request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[cfg(test)]
    fn api_url(mut self, api_url: impl Into<String>) -> Self {
        self.api_url = api_url.into();
        self
    }
}

impl std::fmt::Debug for ResendConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResendConfig")
            .field("api_key", &"[REDACTED]")
            .field("api_url", &self.api_url)
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// A provider adapter for Resend's HTTPS API.
pub struct ResendMailer {
    client: Client,
    config: ResendConfig,
}

impl ResendMailer {
    /// Create a mailer with a bounded request timeout.
    pub fn new(config: ResendConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|error| {
                TidewayError::internal(format!("failed to build email client: {error}"))
            })?;
        Ok(Self { client, config })
    }

    /// Create a mailer from `RESEND_API_KEY`.
    pub fn from_env() -> Result<Self> {
        Self::new(ResendConfig::from_env()?)
    }
}

#[derive(Serialize)]
struct ResendRequest<'a> {
    from: &'a str,
    to: &'a [String],
    subject: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    html: Option<&'a str>,
    #[serde(skip_serializing_if = "slice_is_empty")]
    cc: &'a [String],
    #[serde(skip_serializing_if = "slice_is_empty")]
    bcc: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to: Option<&'a str>,
}

fn slice_is_empty<T>(items: &[T]) -> bool {
    items.is_empty()
}

impl<'a> From<&'a Email> for ResendRequest<'a> {
    fn from(email: &'a Email) -> Self {
        Self {
            from: &email.from,
            to: &email.to,
            subject: &email.subject,
            text: email.text.as_deref(),
            html: email.html.as_deref(),
            cc: &email.cc,
            bcc: &email.bcc,
            reply_to: email.reply_to.as_deref(),
        }
    }
}

#[async_trait]
impl Mailer for ResendMailer {
    async fn send(&self, email: &Email) -> Result<()> {
        email.validate()?;

        let response = self
            .client
            .post(&self.config.api_url)
            .bearer_auth(&self.config.api_key)
            .json(&ResendRequest::from(email))
            .send()
            .await
            .map_err(|error| {
                TidewayError::internal(format!("email provider request failed: {error}"))
            })?;

        if response.status().is_success() {
            return Ok(());
        }

        // Do not include the response body: providers may echo message content
        // or recipient data in validation errors.
        let status = response.status();
        let message = if status == StatusCode::TOO_MANY_REQUESTS {
            "email provider rate limited the request"
        } else {
            "email provider rejected the request"
        };
        Err(TidewayError::internal(format!("{message} ({status})")))
    }

    fn is_healthy(&self) -> bool {
        !self.config.api_key.is_empty()
    }
}

impl std::fmt::Debug for ResendMailer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResendMailer")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_rejects_empty_keys_and_redacts_valid_ones() {
        assert!(ResendConfig::new(" ").is_err());
        let config = ResendConfig::new("re_secret").unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("re_secret"));
    }

    #[test]
    fn request_preserves_provider_neutral_email_fields() {
        let email = Email::new("from@example.com", "to@example.com", "Hello")
            .text("Plain")
            .html("<p>HTML</p>")
            .cc("cc@example.com")
            .reply_to("reply@example.com");
        let value = serde_json::to_value(ResendRequest::from(&email)).unwrap();
        assert_eq!(value["from"], "from@example.com");
        assert_eq!(value["to"][0], "to@example.com");
        assert_eq!(value["reply_to"], "reply@example.com");
        assert!(value.get("bcc").is_none());
    }

    #[test]
    fn test_only_api_url_override_is_available() {
        let config = ResendConfig::new("re_test")
            .unwrap()
            .api_url("http://localhost/emails");
        assert_eq!(config.api_url, "http://localhost/emails");
    }
}
