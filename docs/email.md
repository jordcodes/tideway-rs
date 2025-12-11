# Email

Tideway provides a trait-based email system for sending transactional emails. The `Mailer` trait allows you to swap between SMTP, third-party services (Resend, SendGrid, Postmark), or console output for development.

## Quick Start

```rust
use tideway::{App, AppContext, ConfigBuilder, ConsoleMailer, Email, Mailer};
use std::sync::Arc;

#[tokio::main]
async fn main() -> tideway::Result<()> {
    // Use console mailer for development
    let mailer: Arc<dyn Mailer> = Arc::new(ConsoleMailer::new());

    let ctx = AppContext::builder()
        .with_mailer(mailer.clone())
        .build();

    // Send an email
    let email = Email::new("noreply@myapp.com", "user@example.com", "Welcome!")
        .text("Thanks for signing up!")
        .html("<h1>Welcome!</h1><p>Thanks for signing up!</p>");

    mailer.send(&email).await?;

    Ok(())
}
```

## Email Builder

The `Email` struct uses a builder pattern:

```rust
use tideway::Email;

let email = Email::new("from@example.com", "to@example.com", "Subject Line")
    // Add more recipients
    .to("another@example.com")
    .to_many(vec!["user1@example.com", "user2@example.com"])
    // CC and BCC
    .cc("cc@example.com")
    .bcc("bcc@example.com")
    // Body (at least one required)
    .text("Plain text version")
    .html("<p>HTML version</p>")
    // Optional reply-to
    .reply_to("support@example.com");
```

## Built-in Mailers

### ConsoleMailer (Development)

Prints emails to stdout instead of sending them:

```rust
use tideway::ConsoleMailer;

// Default prefix "[EMAIL]"
let mailer = ConsoleMailer::new();

// Custom prefix
let mailer = ConsoleMailer::with_prefix("[MAIL]");
```

Output example:
```
[EMAIL] ════════════════════════════════════════
[EMAIL] From:    noreply@myapp.com
[EMAIL] To:      user@example.com
[EMAIL] Subject: Welcome!
[EMAIL] ────────────────────────────────────────
[EMAIL] [TEXT]
[EMAIL] Thanks for signing up!
[EMAIL] [HTML]
[EMAIL] <h1>Welcome!</h1>
[EMAIL] ════════════════════════════════════════
```

### SmtpMailer (Production)

Sends emails via SMTP using the `lettre` crate:

```rust
use tideway::{SmtpMailer, SmtpConfig};

// Builder pattern
let config = SmtpConfig::new("smtp.example.com")
    .port(587)                              // Default: 587
    .credentials("username", "password")
    .from("noreply@example.com")            // Default from address
    .no_starttls();                         // Use implicit TLS (port 465)

let mailer = SmtpMailer::new(config)?;

// Or from environment variables
let mailer = SmtpMailer::from_env()?;
```

Environment variables for `SmtpConfig::from_env()`:

```bash
SMTP_HOST=smtp.example.com       # Required
SMTP_PORT=587                    # Optional, default: 587
SMTP_USERNAME=your-username      # Optional
SMTP_PASSWORD=your-password      # Optional
SMTP_FROM=noreply@example.com    # Optional default from address
SMTP_STARTTLS=true               # Optional, default: true
```

## Third-Party Services

### Resend

[Resend](https://resend.com) provides an SMTP relay. Use `SmtpMailer` with Resend credentials:

```rust
use tideway::{SmtpMailer, SmtpConfig};

let config = SmtpConfig::new("smtp.resend.com")
    .port(465)
    .credentials("resend", "re_YOUR_API_KEY")
    .from("noreply@yourdomain.com")
    .no_starttls();  // Resend uses implicit TLS on 465

let mailer = SmtpMailer::new(config)?;
```

Environment setup:
```bash
SMTP_HOST=smtp.resend.com
SMTP_PORT=465
SMTP_USERNAME=resend
SMTP_PASSWORD=re_YOUR_API_KEY
SMTP_FROM=noreply@yourdomain.com
SMTP_STARTTLS=false
```

### SendGrid

[SendGrid](https://sendgrid.com) also provides SMTP relay:

```rust
use tideway::{SmtpMailer, SmtpConfig};

let config = SmtpConfig::new("smtp.sendgrid.net")
    .port(587)
    .credentials("apikey", "SG.YOUR_API_KEY")
    .from("noreply@yourdomain.com");

let mailer = SmtpMailer::new(config)?;
```

Environment setup:
```bash
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USERNAME=apikey
SMTP_PASSWORD=SG.YOUR_API_KEY
SMTP_FROM=noreply@yourdomain.com
```

### Postmark

[Postmark](https://postmarkapp.com) SMTP configuration:

```rust
let config = SmtpConfig::new("smtp.postmarkapp.com")
    .port(587)
    .credentials("YOUR_SERVER_TOKEN", "YOUR_SERVER_TOKEN")
    .from("noreply@yourdomain.com");
```

### AWS SES

[Amazon SES](https://aws.amazon.com/ses/) SMTP configuration:

```rust
let config = SmtpConfig::new("email-smtp.us-east-1.amazonaws.com")
    .port(587)
    .credentials("SMTP_USERNAME", "SMTP_PASSWORD")
    .from("noreply@yourdomain.com");
```

## Custom Mailer Implementation

Implement the `Mailer` trait for custom backends (e.g., Resend HTTP API):

```rust
use tideway::{Email, Mailer, Result, TidewayError};
use async_trait::async_trait;

pub struct ResendMailer {
    api_key: String,
    client: reqwest::Client,
}

impl ResendMailer {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl Mailer for ResendMailer {
    async fn send(&self, email: &Email) -> Result<()> {
        email.validate()?;

        let body = serde_json::json!({
            "from": email.from,
            "to": email.to,
            "subject": email.subject,
            "text": email.text,
            "html": email.html,
        });

        let response = self.client
            .post("https://api.resend.com/emails")
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| TidewayError::internal(format!("Failed to send email: {}", e)))?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(TidewayError::internal(format!("Resend API error: {}", error)));
        }

        Ok(())
    }

    fn is_healthy(&self) -> bool {
        true
    }
}
```

## Using Mailer from Handlers

Access the mailer from `AppContext` in your handlers:

```rust
use tideway::{AppContext, Email, Result};
use axum::Extension;

async fn send_welcome_email(
    Extension(ctx): Extension<AppContext>,
) -> Result<()> {
    let mailer = ctx.mailer()?;

    let email = Email::new(
        "noreply@myapp.com",
        "newuser@example.com",
        "Welcome to MyApp!",
    )
    .text("Thanks for joining!")
    .html("<h1>Welcome!</h1>");

    mailer.send(&email).await?;

    Ok(())
}
```

## Environment-Based Mailer Selection

Switch between console and SMTP based on environment:

```rust
use tideway::{ConsoleMailer, SmtpMailer, SmtpConfig, Mailer};
use std::sync::Arc;

fn create_mailer() -> tideway::Result<Arc<dyn Mailer>> {
    if std::env::var("SMTP_HOST").is_ok() {
        // Production: Use SMTP
        let config = SmtpConfig::from_env()?;
        Ok(Arc::new(SmtpMailer::new(config)?))
    } else {
        // Development: Use console
        Ok(Arc::new(ConsoleMailer::new()))
    }
}
```

## Background Email Jobs

Combine with the [background jobs](./background_jobs.md) system for async email sending:

```rust
use tideway::{Job, JobData, AppContext, Email, Result, TidewayError};
use serde::{Serialize, Deserialize};
use async_trait::async_trait;

#[derive(Debug, Serialize, Deserialize)]
struct SendEmailJob {
    to: String,
    subject: String,
    text: String,
    html: Option<String>,
}

#[async_trait]
impl Job for SendEmailJob {
    fn job_type(&self) -> &str {
        "send_email"
    }

    fn serialize(&self) -> Result<serde_json::Value> {
        serde_json::to_value(self)
            .map_err(|e| TidewayError::internal(format!("Serialize error: {}", e)))
    }

    async fn execute(&self, ctx: &AppContext) -> Result<()> {
        let mailer = ctx.mailer()?;

        let mut email = Email::new("noreply@myapp.com", &self.to, &self.subject)
            .text(&self.text);

        if let Some(ref html) = self.html {
            email = email.html(html);
        }

        mailer.send(&email).await
    }
}

// Enqueue email job from handler
async fn register_user(ctx: Extension<AppContext>) -> Result<()> {
    let queue = ctx.jobs()?;

    let job = SendEmailJob {
        to: "user@example.com".to_string(),
        subject: "Welcome!".to_string(),
        text: "Thanks for signing up!".to_string(),
        html: Some("<h1>Welcome!</h1>".to_string()),
    };

    queue.enqueue(&job).await?;
    Ok(())
}
```

## Testing

Use `ConsoleMailer` in tests to avoid sending real emails:

```rust
#[cfg(test)]
mod tests {
    use tideway::{AppContext, ConsoleMailer, Email, Mailer};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_email_sending() {
        let mailer: Arc<dyn Mailer> = Arc::new(ConsoleMailer::new());
        let ctx = AppContext::builder()
            .with_mailer(mailer.clone())
            .build();

        let email = Email::new("from@test.com", "to@test.com", "Test")
            .text("Test body");

        // This prints to console instead of sending
        let result = ctx.mailer().unwrap().send(&email).await;
        assert!(result.is_ok());
    }
}
```

## Best Practices

1. **Use environment variables** for SMTP credentials - never hardcode secrets
2. **Use ConsoleMailer in development** to avoid sending real emails
3. **Validate emails before sending** - the `send()` method calls `validate()` automatically
4. **Use background jobs for bulk emails** to avoid blocking HTTP requests
5. **Set a default from address** in `SmtpConfig` for consistency
6. **Handle errors gracefully** - email delivery can fail for many reasons

## Feature Flag

Email support requires the `email` feature:

```toml
[dependencies]
tideway = { version = "0.2", features = ["email"] }
```
