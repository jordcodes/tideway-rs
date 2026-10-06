# Email

Tideway provides a trait-based email system for sending transactional emails. The `Mailer` trait allows you to swap between SMTP, third-party services (Resend, SendGrid, Postmark), or console output for development.

## Generated API Starter

Apps created with `tideway new` (the API preset, or any app with `auth` and `database`) send
verification and password-reset emails out of the box. They use the default
[lifecycle templates](#lifecycle-emails), and background job workers started in `main.rs`
deliver them. The generated `.env.example` uses the development console provider:

```bash
TIDEWAY_ENV=development
APP_URL=http://localhost:5173       # frontend that serves /verify-email and /reset-password
EMAIL_PROVIDER=console              # console (development only), resend, or smtp
EMAIL_FROM="My App <noreply@example.com>"
REQUIRE_EMAIL_VERIFICATION=false    # true blocks login until the email link is used
```

Leaving `EMAIL_PROVIDER` unset disables `/auth/password/reset*` and `/auth/email/*`.
Customize wording or branding by overriding `EmailTemplates` methods on `AppEmailTemplates` in
`src/email.rs`. The generated in-memory queue drops undelivered emails on restart; use
`RedisJobQueue` (feature `jobs-redis`) for durable delivery.

## Generated SaaS Quick Start

Create the batteries-included SaaS API and start its local dependencies:

```bash
tideway new my_saas --preset saas
cd my_saas
docker compose up -d
tideway dev --fix-env
```

The generated `src/email.rs` owns the application templates and selects a
provider through environment variables. Verification and reset messages include
a neutral, accessible HTML design plus a plain-text fallback. Edit that file to
apply your product's colours, logo, wording, and legal copy without changing the
provider or auth integration. For local development, update `.env`:

```bash
TIDEWAY_ENV=development
APP_URL=http://localhost:5173
EMAIL_PROVIDER=console
EMAIL_FROM="My SaaS <noreply@example.com>"
EMAIL_CONSOLE_SHOW_BODY=true
REQUIRE_EMAIL_VERIFICATION=true
ALLOW_PUBLIC_REGISTRATION=true
```

`EMAIL_CONSOLE_SHOW_BODY=true` exposes reset and verification tokens, so use it
only on a trusted development machine. It defaults to `false`; production cannot
use the console provider. Public registration is also disabled by default. Enable
it explicitly only for an intentional self-service flow or while bootstrapping a
local first owner; invitation-only deployments should leave it disabled.

If you use the generated Vue registration form, also set
`VITE_ALLOW_PUBLIC_REGISTRATION=true` in the frontend environment (or pass
`registrationEnabled=true` to the component). This only reveals the form; the API-side
`ALLOW_PUBLIC_REGISTRATION` policy remains authoritative.

Registering a user sends a verification link. The B2B SaaS preset also requires
an organization name:

```bash
curl -X POST http://localhost:8000/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"dev@example.com","password":"correct horse battery staple","name":"Dev","organization_name":"Example Ltd"}'
```

`APP_URL` is the public browser/frontend origin. The generated email links point
to `/verify-email?token=...` and `/reset-password?token=...` on that origin. Your
frontend pages should read the token and call the API. Until those pages exist,
you can exercise the endpoints directly:

```bash
# Verify the token printed by the local console mailer.
curl -X POST http://localhost:8000/auth/email/verify \
  -H 'content-type: application/json' \
  -d '{"token":"TOKEN_FROM_EMAIL"}'

# Resend verification without revealing whether an account exists.
curl -X POST http://localhost:8000/auth/email/verification/resend \
  -H 'content-type: application/json' \
  -d '{"email":"dev@example.com"}'

# Request and complete a password reset.
curl -X POST http://localhost:8000/auth/password/reset \
  -H 'content-type: application/json' \
  -d '{"email":"dev@example.com"}'

curl -X POST http://localhost:8000/auth/password/reset/complete \
  -H 'content-type: application/json' \
  -d '{"token":"TOKEN_FROM_EMAIL","new_password":"a new correct horse battery staple"}'
```

Reset and resend requests are throttled by client IP and normalized email
address. Their responses deliberately do not reveal whether an account exists.

### Use Resend

Verify the sender/domain in Resend, then configure the deployment secret and
public application URL:

```bash
TIDEWAY_ENV=production
APP_URL=https://app.example.com
EMAIL_PROVIDER=resend
EMAIL_FROM="My SaaS <noreply@example.com>"
RESEND_API_KEY=re_replace_me
REQUIRE_EMAIL_VERIFICATION=true
```

### Use SMTP

SMTP keeps the same auth and template code and works with providers such as
Postmark, SendGrid, Amazon SES, and Resend's SMTP relay:

```bash
EMAIL_PROVIDER=smtp
EMAIL_FROM="My SaaS <noreply@example.com>"
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=replace_me
SMTP_PASSWORD=replace_me
SMTP_STARTTLS=true
```

### Use Another Provider

Implement Tideway's `Mailer` trait in the consuming application, then construct
the generated service with it:

```rust
use std::sync::Arc;
use my_saas::email::EmailService;

let email_service = Arc::new(EmailService::new(
    Arc::new(MyMailer::new(/* provider config */)),
    "My SaaS <noreply@example.com>",
    &app_config.app_name,
    &app_config.app_url,
)?);
```

Pass that service to the generated
`AuthModule::with_email_delivery(email_service)`. Provider code stays isolated;
auth and organization modules continue to depend only on the neutral contract.

Before enabling verification in production, confirm that the sender is verified,
`APP_URL` uses HTTPS, credentials come from a secret manager, and reset and
verification links reach the intended frontend pages.

## Framework Mailer Quick Start

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

[Resend](https://resend.com) has a built-in HTTPS adapter:

```rust
use tideway::{ResendConfig, ResendMailer};

let mailer = ResendMailer::from_env()?;
// Or: ResendMailer::new(ResendConfig::new("re_YOUR_API_KEY")?)?;
```

Environment setup:
```bash
RESEND_API_KEY=re_YOUR_API_KEY
```

Resend's SMTP relay remains available through `SmtpMailer` if your application
prefers one transport across providers.

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

Implement the `Mailer` trait for any custom backend:

```rust
use tideway::{Email, Mailer, Result};
use async_trait::async_trait;

pub struct MyMailer;

#[async_trait]
impl Mailer for MyMailer {
    async fn send(&self, email: &Email) -> Result<()> {
        email.validate()?;
        // Call your provider without logging credentials, recipients, tokens,
        // message content, or untrusted provider response bodies.
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

## Generated SaaS Provider Selection

The SaaS scaffold keeps templates application-owned in `src/email.rs` and uses
one environment switch for providers:

```bash
EMAIL_PROVIDER=resend # resend, smtp, console, or custom
EMAIL_FROM="My App <noreply@example.com>"
RESEND_API_KEY=re_YOUR_API_KEY
```

`console` is rejected outside development/test environments. `custom` is an
explicit extension point: implement `Mailer` in the consuming application and
construct the generated `EmailService` with it (or replace the `custom` branch).
Auth, password reset, and verification code remain provider-neutral. Production
`APP_URL` values must use HTTPS so generated reset and verification links are
not sent over plaintext HTTP.

## Lifecycle Emails

Tideway ships default, overridable templates for the six emails most SaaS apps
need: `VerifyEmail`, `PasswordReset`, `Invitation`, `TrialEnding`,
`PaymentFailed`, and `Receipt`. Each renders an accessible HTML body plus a
plain-text fallback, with all application values escaped.

`LifecycleEmailer` renders an email and delivers it. With the `jobs` feature,
`LifecycleEmailer::queued` enqueues a `SendEmailJob` (job type
`tideway.send_email`) so delivery happens in a background worker, with the
queue's retry policy, instead of on the request path:

```rust,ignore
use std::sync::Arc;
use tideway::email::{EmailBranding, LifecycleEmail, LifecycleEmailer, register_email_jobs};

// Worker side: the worker's AppContext must have a mailer.
let registry = JobRegistry::new();
register_email_jobs(&registry).await;
let ctx = Arc::new(AppContext::builder().with_mailer(mailer).with_job_queue(queue.clone()).build());
let workers = WorkerPool::new(queue.clone(), Arc::new(registry), ctx, 2);

// Request side: render now, deliver in the background.
let emails = LifecycleEmailer::queued(
    queue,
    "Acme <noreply@acme.example>",
    EmailBranding::new("Acme")
        .app_url("https://acme.example")
        .support_email("support@acme.example"),
);

// e.g. from PasswordResetStore::send_reset_email
let link = format!("https://acme.example/reset-password?token={token}");
emails
    .send(&user.email, &LifecycleEmail::password_reset(link, expires_in))
    .await?;
```

Use `LifecycleEmailer::direct(mailer, from, branding)` when you deliberately want
synchronous delivery (tests, scripts). Queued jobs contain the rendered body,
including one-time links, so protect the queue backend like any other secret
store.

### Overriding Templates

Implement `EmailTemplates`; every method has a default, so override only what
you need:

- `content` - change subject/copy for one or more emails, falling back to
  `default_content` for the rest.
- `layout` - return your own `EmailLayout` to rebrand every email at once.
- `render` - take over rendering entirely (for example with your own template
  engine).

```rust,ignore
use tideway::email::{
    EmailBranding, EmailContent, EmailLayout, EmailTemplates, LifecycleEmail, default_content,
};

struct AcmeTemplates;

impl EmailTemplates for AcmeTemplates {
    fn content(&self, email: &LifecycleEmail, branding: &EmailBranding) -> tideway::Result<EmailContent> {
        let mut content = default_content(email, branding)?;
        if let LifecycleEmail::VerifyEmail { .. } = email {
            content.subject = "Welcome to Acme - confirm your email".into();
        }
        Ok(content)
    }

    fn layout(&self) -> &dyn EmailLayout {
        &AcmeLayout // implements EmailLayout::html (text falls back to the default)
    }
}

let emails = emails.with_templates(Arc::new(AcmeTemplates));
```

Amounts on payment emails use `Amount { minor_units, currency }` (the shape
payment providers report) and are formatted as `USD 49.00`, honouring
zero-decimal currencies such as JPY. Override the templates for locale-aware
formatting.

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
tideway = { version = "0.9.0", features = ["email"] }
```
