//! Default, overridable lifecycle emails.
//!
//! Tideway ships templates for the six transactional emails almost every SaaS
//! application needs before users can sign up, recover access, or pay:
//!
//! | [`LifecycleEmail`] variant | Sent when |
//! |----------------------------|-----------|
//! | `VerifyEmail`              | A user registers or asks for a new verification link |
//! | `PasswordReset`            | A user requests a password reset |
//! | `Invitation`               | A user is invited to an organization |
//! | `TrialEnding`              | A subscription trial is about to end |
//! | `PaymentFailed`            | A subscription payment fails |
//! | `Receipt`                  | A payment succeeds |
//!
//! Rendering is split into two layers so applications can customize as little
//! or as much as they need without touching framework code:
//!
//! 1. [`EmailTemplates::content`] turns a [`LifecycleEmail`] into structured
//!    [`EmailContent`] (subject, heading, paragraphs, call to action, ...).
//! 2. An [`EmailLayout`] turns that content into HTML and plain-text bodies.
//!
//! Override `content` to change the copy of individual emails, return a
//! custom [`EmailLayout`] from [`EmailTemplates::layout`] to rebrand every
//! email at once, or override [`EmailTemplates::render`] to take over
//! rendering entirely (for example with your own template engine).
//!
//! [`LifecycleEmailer`] renders emails and delivers them. With the `jobs`
//! feature, [`LifecycleEmailer::queued`] enqueues a
//! [`SendEmailJob`](super::SendEmailJob) so delivery happens in a background
//! worker instead of on the request path.
//!
//! # Example
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use tideway::email::{
//!     EmailBranding, EmailContent, EmailTemplates, LifecycleEmail, LifecycleEmailer,
//!     default_content, register_email_jobs,
//! };
//!
//! // Override only the copy you care about; everything else uses the defaults.
//! struct MyTemplates;
//!
//! impl EmailTemplates for MyTemplates {
//!     fn content(&self, email: &LifecycleEmail, branding: &EmailBranding) -> tideway::Result<EmailContent> {
//!         let mut content = default_content(email, branding)?;
//!         if let LifecycleEmail::VerifyEmail { .. } = email {
//!             content.subject = format!("Welcome to {}! Please confirm your email", branding.app_name);
//!         }
//!         Ok(content)
//!     }
//! }
//!
//! register_email_jobs(&registry).await; // worker side: delivers via AppContext::mailer()
//!
//! let emailer = LifecycleEmailer::queued(
//!     queue,
//!     "Acme <noreply@acme.test>",
//!     EmailBranding::new("Acme").app_url("https://acme.test"),
//! )
//! .with_templates(Arc::new(MyTemplates));
//!
//! emailer
//!     .send("user@example.com", &LifecycleEmail::verify_email(link, ttl))
//!     .await?;
//! ```

use crate::error::{Result, TidewayError};
use crate::traits::mailer::{Email, Mailer};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "jobs")]
use crate::traits::job::JobQueue;

/// A monetary amount in the currency's minor unit (for example cents).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Amount {
    /// Amount in minor units, as reported by payment providers such as Stripe.
    pub minor_units: i64,
    /// ISO 4217 currency code (case-insensitive).
    pub currency: String,
}

impl Amount {
    /// Create an amount from minor units and an ISO 4217 currency code.
    pub fn new(minor_units: i64, currency: impl Into<String>) -> Self {
        Self {
            minor_units,
            currency: currency.into(),
        }
    }

    fn decimals(&self) -> u32 {
        // Stripe's zero-decimal currencies.
        const ZERO_DECIMAL: &[&str] = &[
            "BIF", "CLP", "DJF", "GNF", "JPY", "KMF", "KRW", "MGA", "PYG", "RWF", "UGX", "VND",
            "VUV", "XAF", "XOF", "XPF",
        ];
        let currency = self.currency.to_ascii_uppercase();
        if ZERO_DECIMAL.contains(&currency.as_str()) {
            0
        } else {
            2
        }
    }
}

impl fmt::Display for Amount {
    /// Formats as `"USD 12.34"`. Override the templates for locale-aware formatting.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let currency = self.currency.to_ascii_uppercase();
        let sign = if self.minor_units < 0 { "-" } else { "" };
        let value = self.minor_units.unsigned_abs();
        match self.decimals() {
            0 => write!(f, "{currency} {sign}{value}"),
            decimals => {
                let scale = 10u64.pow(decimals);
                write!(
                    f,
                    "{currency} {sign}{}.{:0width$}",
                    value / scale,
                    value % scale,
                    width = decimals as usize
                )
            }
        }
    }
}

/// The kind of a [`LifecycleEmail`], useful for logging and per-kind overrides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleEmailKind {
    VerifyEmail,
    PasswordReset,
    Invitation,
    TrialEnding,
    PaymentFailed,
    Receipt,
}

impl LifecycleEmailKind {
    /// Stable snake_case identifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VerifyEmail => "verify_email",
            Self::PasswordReset => "password_reset",
            Self::Invitation => "invitation",
            Self::TrialEnding => "trial_ending",
            Self::PaymentFailed => "payment_failed",
            Self::Receipt => "receipt",
        }
    }
}

impl fmt::Display for LifecycleEmailKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Data for one of the built-in lifecycle emails.
///
/// Links are passed in fully formed so applications control their own routes
/// (for example `https://app.example.com/verify-email?token=...`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LifecycleEmail {
    /// Confirm ownership of an email address.
    VerifyEmail {
        action_url: String,
        expires_in_secs: u64,
    },
    /// Reset a forgotten password.
    PasswordReset {
        action_url: String,
        expires_in_secs: u64,
    },
    /// Join an organization.
    Invitation {
        action_url: String,
        organization_name: String,
        inviter_name: Option<String>,
        expires_in_secs: u64,
    },
    /// A subscription trial ends soon.
    TrialEnding {
        action_url: String,
        plan_name: Option<String>,
        days_remaining: u32,
    },
    /// A subscription payment failed and billing details need attention.
    PaymentFailed {
        action_url: String,
        amount: Option<Amount>,
        plan_name: Option<String>,
    },
    /// A payment succeeded.
    Receipt {
        amount: Amount,
        description: Option<String>,
        receipt_number: Option<String>,
        receipt_url: Option<String>,
    },
}

impl LifecycleEmail {
    /// Email verification with a link that expires after `expires_in`.
    pub fn verify_email(action_url: impl Into<String>, expires_in: Duration) -> Self {
        Self::VerifyEmail {
            action_url: action_url.into(),
            expires_in_secs: expires_in.as_secs(),
        }
    }

    /// Password reset with a link that expires after `expires_in`.
    pub fn password_reset(action_url: impl Into<String>, expires_in: Duration) -> Self {
        Self::PasswordReset {
            action_url: action_url.into(),
            expires_in_secs: expires_in.as_secs(),
        }
    }

    /// Organization invitation with a link that expires after `expires_in`.
    pub fn invitation(
        action_url: impl Into<String>,
        organization_name: impl Into<String>,
        inviter_name: Option<String>,
        expires_in: Duration,
    ) -> Self {
        Self::Invitation {
            action_url: action_url.into(),
            organization_name: organization_name.into(),
            inviter_name,
            expires_in_secs: expires_in.as_secs(),
        }
    }

    /// Trial-ending reminder linking to the billing page.
    pub fn trial_ending(
        action_url: impl Into<String>,
        plan_name: Option<String>,
        days_remaining: u32,
    ) -> Self {
        Self::TrialEnding {
            action_url: action_url.into(),
            plan_name,
            days_remaining,
        }
    }

    /// Failed-payment notice linking to the billing page.
    pub fn payment_failed(
        action_url: impl Into<String>,
        amount: Option<Amount>,
        plan_name: Option<String>,
    ) -> Self {
        Self::PaymentFailed {
            action_url: action_url.into(),
            amount,
            plan_name,
        }
    }

    /// Payment receipt.
    pub fn receipt(amount: Amount) -> Self {
        Self::Receipt {
            amount,
            description: None,
            receipt_number: None,
            receipt_url: None,
        }
    }

    /// The kind of this email.
    pub fn kind(&self) -> LifecycleEmailKind {
        match self {
            Self::VerifyEmail { .. } => LifecycleEmailKind::VerifyEmail,
            Self::PasswordReset { .. } => LifecycleEmailKind::PasswordReset,
            Self::Invitation { .. } => LifecycleEmailKind::Invitation,
            Self::TrialEnding { .. } => LifecycleEmailKind::TrialEnding,
            Self::PaymentFailed { .. } => LifecycleEmailKind::PaymentFailed,
            Self::Receipt { .. } => LifecycleEmailKind::Receipt,
        }
    }
}

/// Application identity used by templates and layouts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EmailBranding {
    /// Product name shown in subjects and the email header.
    pub app_name: String,
    /// Public application URL, linked from the footer.
    pub app_url: Option<String>,
    /// Support address mentioned in the footer.
    pub support_email: Option<String>,
    /// Extra footer text such as a postal address or legal notice.
    pub footer: Option<String>,
}

impl EmailBranding {
    /// Branding with just a product name.
    pub fn new(app_name: impl Into<String>) -> Self {
        Self {
            app_name: app_name.into(),
            ..Self::default()
        }
    }

    /// Set the public application URL.
    pub fn app_url(mut self, url: impl Into<String>) -> Self {
        self.app_url = Some(url.into());
        self
    }

    /// Set the support email address.
    pub fn support_email(mut self, email: impl Into<String>) -> Self {
        self.support_email = Some(email.into());
        self
    }

    /// Set additional footer text.
    pub fn footer(mut self, footer: impl Into<String>) -> Self {
        self.footer = Some(footer.into());
        self
    }
}

/// A call-to-action button.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailAction {
    pub label: String,
    pub url: String,
}

/// Structured, layout-independent email content.
///
/// All fields are plain text; layouts are responsible for escaping.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EmailContent {
    pub subject: String,
    /// Hidden preview text shown by most inboxes next to the subject.
    pub preheader: String,
    pub heading: String,
    pub paragraphs: Vec<String>,
    pub action: Option<EmailAction>,
    /// Label/value rows, for example amounts on a receipt.
    pub details: Vec<(String, String)>,
    /// Smaller print after the main content (expiry, "ignore if unexpected").
    pub notes: Vec<String>,
}

/// A fully rendered email body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedEmail {
    pub subject: String,
    pub text: String,
    pub html: String,
}

/// Turns [`EmailContent`] into HTML and plain-text bodies.
///
/// Implement this to apply your own brand to every lifecycle email.
pub trait EmailLayout: Send + Sync {
    /// Render the HTML body.
    fn html(&self, branding: &EmailBranding, content: &EmailContent) -> String;

    /// Render the plain-text body.
    fn text(&self, branding: &EmailBranding, content: &EmailContent) -> String {
        default_text_layout(branding, content)
    }
}

/// Neutral, accessible, inline-styled HTML layout with a plain-text fallback.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultEmailLayout;

impl EmailLayout for DefaultEmailLayout {
    fn html(&self, branding: &EmailBranding, content: &EmailContent) -> String {
        default_html_layout(branding, content)
    }
}

/// Produces lifecycle emails. Every method has a default; override only what you need.
pub trait EmailTemplates: Send + Sync {
    /// Structured content for an email. Defaults to [`default_content`].
    fn content(&self, email: &LifecycleEmail, branding: &EmailBranding) -> Result<EmailContent> {
        default_content(email, branding)
    }

    /// Layout used to wrap the content. Defaults to [`DefaultEmailLayout`].
    fn layout(&self) -> &dyn EmailLayout {
        &DefaultEmailLayout
    }

    /// Render an email. Override to bypass the content/layout split entirely.
    fn render(&self, email: &LifecycleEmail, branding: &EmailBranding) -> Result<RenderedEmail> {
        let content = self.content(email, branding)?;
        let layout = self.layout();
        Ok(RenderedEmail {
            html: layout.html(branding, &content),
            text: layout.text(branding, &content),
            subject: content.subject,
        })
    }
}

/// The built-in templates with no overrides.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultEmailTemplates;

impl EmailTemplates for DefaultEmailTemplates {}

fn plural(count: u64, unit: &str) -> String {
    if count == 1 {
        format!("1 {unit}")
    } else {
        format!("{count} {unit}s")
    }
}

fn expiry_note(expires_in_secs: u64) -> String {
    let duration = if expires_in_secs >= 86_400 && expires_in_secs.is_multiple_of(86_400) {
        plural(expires_in_secs / 86_400, "day")
    } else if expires_in_secs >= 3_600 {
        plural(expires_in_secs.div_ceil(3_600), "hour")
    } else {
        plural(expires_in_secs.div_ceil(60).max(1), "minute")
    };
    format!("This link expires in {duration}.")
}

fn action(label: &str, url: &str) -> Option<EmailAction> {
    Some(EmailAction {
        label: label.to_string(),
        url: url.to_string(),
    })
}

/// The built-in content for each lifecycle email.
///
/// Call this from an [`EmailTemplates::content`] override to fall back to the
/// defaults for emails you do not customize.
pub fn default_content(email: &LifecycleEmail, branding: &EmailBranding) -> Result<EmailContent> {
    let app = branding.app_name.as_str();
    let content = match email {
        LifecycleEmail::VerifyEmail {
            action_url,
            expires_in_secs,
        } => EmailContent {
            subject: format!("Verify your {app} email"),
            preheader: "Confirm your email address to finish setting up your account.".into(),
            heading: "Verify your email".into(),
            paragraphs: vec![
                "Confirm this email address to finish setting up your account.".into(),
            ],
            action: action("Verify email", action_url),
            details: Vec::new(),
            notes: vec![
                expiry_note(*expires_in_secs),
                "If you did not create this account, you can safely ignore this email.".into(),
            ],
        },
        LifecycleEmail::PasswordReset {
            action_url,
            expires_in_secs,
        } => EmailContent {
            subject: format!("Reset your {app} password"),
            preheader: "Use this link to choose a new password.".into(),
            heading: "Reset your password".into(),
            paragraphs: vec![
                "Use the button below to choose a new password for your account.".into(),
            ],
            action: action("Reset password", action_url),
            details: Vec::new(),
            notes: vec![
                expiry_note(*expires_in_secs),
                "If you did not request this reset, you can safely ignore this email. Your password will not change.".into(),
            ],
        },
        LifecycleEmail::Invitation {
            action_url,
            organization_name,
            inviter_name,
            expires_in_secs,
        } => {
            let intro = match inviter_name {
                Some(inviter) => {
                    format!("{inviter} has invited you to join {organization_name} on {app}.")
                }
                None => format!("You have been invited to join {organization_name} on {app}."),
            };
            EmailContent {
                subject: format!("Join {organization_name} on {app}"),
                preheader: intro.clone(),
                heading: format!("Join {organization_name}"),
                paragraphs: vec![intro],
                action: action("Accept invitation", action_url),
                details: Vec::new(),
                notes: vec![
                    expiry_note(*expires_in_secs),
                    "If you were not expecting this invitation, you can safely ignore this email."
                        .into(),
                ],
            }
        }
        LifecycleEmail::TrialEnding {
            action_url,
            plan_name,
            days_remaining,
        } => {
            let when = match days_remaining {
                0 => "today".to_string(),
                1 => "tomorrow".to_string(),
                days => format!("in {days} days"),
            };
            let plan = plan_name
                .as_deref()
                .map(|plan| format!(" of the {plan} plan"))
                .unwrap_or_default();
            EmailContent {
                subject: format!("Your {app} trial ends {when}"),
                preheader: format!("Your free trial{plan} ends {when}."),
                heading: format!("Your trial ends {when}"),
                paragraphs: vec![
                    format!("Your free trial{plan} on {app} ends {when}."),
                    "Add or confirm your billing details to keep access without interruption."
                        .into(),
                ],
                action: action("Manage billing", action_url),
                details: Vec::new(),
                notes: vec![
                    "If you do not want to continue, no action is needed.".into(),
                ],
            }
        }
        LifecycleEmail::PaymentFailed {
            action_url,
            amount,
            plan_name,
        } => {
            let mut details = Vec::new();
            if let Some(plan) = plan_name {
                details.push(("Plan".into(), plan.clone()));
            }
            if let Some(amount) = amount {
                details.push(("Amount due".into(), amount.to_string()));
            }
            EmailContent {
                subject: format!("Action required: your {app} payment failed"),
                preheader: "We couldn't process your latest payment.".into(),
                heading: "Your payment failed".into(),
                paragraphs: vec![
                    format!("We couldn't process your latest payment for {app}."),
                    "Please update your payment method to avoid any interruption to your account."
                        .into(),
                ],
                action: action("Update payment method", action_url),
                details,
                notes: vec![
                    "If you have already updated your details, you can ignore this email.".into(),
                ],
            }
        }
        LifecycleEmail::Receipt {
            amount,
            description,
            receipt_number,
            receipt_url,
        } => {
            let mut details = Vec::new();
            if let Some(number) = receipt_number {
                details.push(("Receipt number".into(), number.clone()));
            }
            if let Some(description) = description {
                details.push(("Description".into(), description.clone()));
            }
            details.push(("Amount paid".into(), amount.to_string()));
            let subject = match receipt_number {
                Some(number) => format!("Your {app} receipt #{number}"),
                None => format!("Your {app} receipt"),
            };
            EmailContent {
                subject,
                preheader: format!("Thanks for your payment of {amount}."),
                heading: "Thanks for your payment".into(),
                paragraphs: vec![format!("We received your payment of {amount}.")],
                action: receipt_url
                    .as_deref()
                    .and_then(|url| action("View receipt", url)),
                details,
                notes: vec!["Keep this email for your records.".into()],
            }
        }
    };
    Ok(content)
}

/// Escape text for safe inclusion in HTML element content and attribute values.
pub fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn is_safe_link(url: &str) -> bool {
    let lower = url.trim_start().to_ascii_lowercase();
    lower.starts_with("https://") || lower.starts_with("http://") || lower.starts_with("mailto:")
}

fn footer_lines(branding: &EmailBranding) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(support) = &branding.support_email {
        lines.push(format!("Questions? Contact {support}."));
    }
    if let Some(footer) = &branding.footer {
        lines.push(footer.clone());
    }
    lines
}

/// The plain-text rendering used by [`DefaultEmailLayout`].
pub fn default_text_layout(branding: &EmailBranding, content: &EmailContent) -> String {
    let mut out = String::new();
    out.push_str(&content.heading);
    out.push_str("\n\n");
    for paragraph in &content.paragraphs {
        out.push_str(paragraph);
        out.push_str("\n\n");
    }
    if let Some(action) = &content.action {
        out.push_str(&format!("{}:\n{}\n\n", action.label, action.url));
    }
    if !content.details.is_empty() {
        for (label, value) in &content.details {
            out.push_str(&format!("{label}: {value}\n"));
        }
        out.push('\n');
    }
    for note in &content.notes {
        out.push_str(note);
        out.push('\n');
    }
    out.push_str("\n--\n");
    out.push_str(&branding.app_name);
    if let Some(url) = &branding.app_url {
        out.push_str(&format!("\n{url}"));
    }
    for line in footer_lines(branding) {
        out.push('\n');
        out.push_str(&line);
    }
    out.push('\n');
    out
}

/// The HTML rendering used by [`DefaultEmailLayout`].
pub fn default_html_layout(branding: &EmailBranding, content: &EmailContent) -> String {
    let app_name = escape_html(&branding.app_name);
    let heading = escape_html(&content.heading);
    let preheader = escape_html(&content.preheader);

    let paragraphs: String = content
        .paragraphs
        .iter()
        .map(|p| {
            format!(
                r#"<p style="margin:0 0 16px;color:#3f3f46;font-size:16px;line-height:1.6;">{}</p>"#,
                escape_html(p)
            )
        })
        .collect();

    let (button, fallback) = match &content.action {
        Some(action) if is_safe_link(&action.url) => {
            let url = escape_html(&action.url);
            (
                format!(
                    r#"<p style="margin:8px 0 24px;"><a href="{url}" style="display:inline-block;background:#18181b;color:#ffffff;text-decoration:none;font-size:16px;font-weight:700;padding:12px 20px;border-radius:8px;">{}</a></p>"#,
                    escape_html(&action.label)
                ),
                format!(
                    r#"<hr style="margin:28px 0;border:0;border-top:1px solid #e4e4e7;"><p style="margin:0;color:#71717a;font-size:12px;line-height:1.5;word-break:break-all;">If the button does not work, copy this link:<br>{url}</p>"#
                ),
            )
        }
        _ => (String::new(), String::new()),
    };

    let details = if content.details.is_empty() {
        String::new()
    } else {
        let rows: String = content
            .details
            .iter()
            .map(|(label, value)| {
                format!(
                    r#"<tr><td style="padding:8px 0;color:#52525b;font-size:14px;">{}</td><td align="right" style="padding:8px 0;color:#18181b;font-size:14px;font-weight:700;">{}</td></tr>"#,
                    escape_html(label),
                    escape_html(value)
                )
            })
            .collect();
        format!(
            r#"<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin:0 0 24px;border-top:1px solid #e4e4e7;border-bottom:1px solid #e4e4e7;">{rows}</table>"#
        )
    };

    let notes: String = content
        .notes
        .iter()
        .map(|note| {
            format!(
                r#"<p style="margin:0 0 8px;color:#71717a;font-size:13px;line-height:1.5;">{}</p>"#,
                escape_html(note)
            )
        })
        .collect();

    let mut footer = match branding.app_url.as_deref() {
        Some(url) if is_safe_link(url) => format!(
            r#"<a href="{}" style="color:#71717a;">{app_name}</a>"#,
            escape_html(url)
        ),
        _ => app_name.clone(),
    };
    for line in footer_lines(branding) {
        footer.push_str("<br>");
        footer.push_str(&escape_html(&line));
    }

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{heading}</title>
</head>
<body style="margin:0;background:#f4f4f5;color:#18181b;font-family:Arial,sans-serif;">
  <div style="display:none;max-height:0;overflow:hidden;">{preheader}</div>
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f4f4f5;padding:32px 16px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:560px;background:#ffffff;border:1px solid #e4e4e7;border-radius:12px;">
        <tr><td style="padding:32px;">
          <p style="margin:0 0 24px;color:#52525b;font-size:14px;font-weight:700;">{app_name}</p>
          <h1 style="margin:0 0 16px;font-size:24px;line-height:1.3;">{heading}</h1>
          {paragraphs}
          {button}
          {details}
          {notes}
          {fallback}
        </td></tr>
      </table>
      <p style="margin:16px 0 0;color:#a1a1aa;font-size:12px;line-height:1.5;">{footer}</p>
    </td></tr>
  </table>
</body>
</html>"#
    )
}

#[derive(Clone)]
enum Delivery {
    Direct(Arc<dyn Mailer>),
    #[cfg(feature = "jobs")]
    Queued(Arc<dyn JobQueue>),
}

/// Renders lifecycle emails and delivers them directly or through the job queue.
#[derive(Clone)]
pub struct LifecycleEmailer {
    from: String,
    reply_to: Option<String>,
    branding: EmailBranding,
    templates: Arc<dyn EmailTemplates>,
    delivery: Delivery,
}

impl LifecycleEmailer {
    /// Deliver emails by enqueueing a [`SendEmailJob`](super::SendEmailJob).
    ///
    /// Workers must register the job with
    /// [`register_email_jobs`](super::register_email_jobs) and have a mailer
    /// configured on their [`AppContext`](crate::AppContext). Rendered bodies
    /// (including any one-time links) are stored in the queue until delivered,
    /// so secure the queue backend accordingly.
    #[cfg(feature = "jobs")]
    pub fn queued(
        queue: Arc<dyn JobQueue>,
        from: impl Into<String>,
        branding: EmailBranding,
    ) -> Self {
        Self::with_delivery(Delivery::Queued(queue), from.into(), branding)
    }

    /// Deliver emails synchronously through `mailer`.
    ///
    /// Prefer [`Self::queued`] in request handlers so provider latency and
    /// outages do not affect responses.
    pub fn direct(
        mailer: Arc<dyn Mailer>,
        from: impl Into<String>,
        branding: EmailBranding,
    ) -> Self {
        Self::with_delivery(Delivery::Direct(mailer), from.into(), branding)
    }

    fn with_delivery(delivery: Delivery, from: String, branding: EmailBranding) -> Self {
        Self {
            from,
            reply_to: None,
            branding,
            templates: Arc::new(DefaultEmailTemplates),
            delivery,
        }
    }

    /// Use custom templates instead of [`DefaultEmailTemplates`].
    pub fn with_templates(mut self, templates: Arc<dyn EmailTemplates>) -> Self {
        self.templates = templates;
        self
    }

    /// Set a reply-to address on every email.
    pub fn with_reply_to(mut self, reply_to: impl Into<String>) -> Self {
        self.reply_to = Some(reply_to.into());
        self
    }

    /// The branding passed to templates.
    pub fn branding(&self) -> &EmailBranding {
        &self.branding
    }

    /// Render `email` for `to` without sending it.
    pub fn render(&self, to: &str, email: &LifecycleEmail) -> Result<Email> {
        if to.trim().is_empty() {
            return Err(TidewayError::bad_request("Email recipient is required"));
        }
        let rendered = self.templates.render(email, &self.branding)?;
        let mut message = Email::new(&self.from, to, rendered.subject)
            .text(rendered.text)
            .html(rendered.html);
        if let Some(reply_to) = &self.reply_to {
            message = message.reply_to(reply_to);
        }
        message.validate()?;
        Ok(message)
    }

    /// Render and deliver `email` to `to`.
    ///
    /// With queued delivery this returns once the job is enqueued; delivery
    /// failures are retried by the job worker.
    pub async fn send(&self, to: &str, email: &LifecycleEmail) -> Result<()> {
        let message = self.render(to, email)?;
        match &self.delivery {
            Delivery::Direct(mailer) => mailer.send(&message).await?,
            #[cfg(feature = "jobs")]
            Delivery::Queued(queue) => {
                let job_id = queue.enqueue(&super::SendEmailJob::new(message)).await?;
                tracing::debug!(
                    target: "tideway.email.lifecycle",
                    kind = %email.kind(),
                    %job_id,
                    "Lifecycle email enqueued"
                );
                return Ok(());
            }
        }
        tracing::debug!(
            target: "tideway.email.lifecycle",
            kind = %email.kind(),
            "Lifecycle email sent"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;

    fn branding() -> EmailBranding {
        EmailBranding::new("Acme")
            .app_url("https://acme.test")
            .support_email("help@acme.test")
    }

    fn all_emails() -> Vec<LifecycleEmail> {
        let ttl = Duration::from_secs(3600);
        vec![
            LifecycleEmail::verify_email("https://acme.test/verify?token=v", ttl),
            LifecycleEmail::password_reset("https://acme.test/reset?token=r", ttl),
            LifecycleEmail::invitation(
                "https://acme.test/invite?token=i",
                "Widgets Inc",
                Some("Sam".into()),
                Duration::from_secs(7 * 86_400),
            ),
            LifecycleEmail::trial_ending("https://acme.test/billing", Some("Pro".into()), 3),
            LifecycleEmail::payment_failed(
                "https://acme.test/billing",
                Some(Amount::new(4900, "usd")),
                Some("Pro".into()),
            ),
            LifecycleEmail::Receipt {
                amount: Amount::new(4900, "usd"),
                description: Some("Pro (monthly)".into()),
                receipt_number: Some("1001".into()),
                receipt_url: Some("https://pay.test/r/1001".into()),
            },
        ]
    }

    #[test]
    fn every_lifecycle_email_has_a_default_template() {
        for email in all_emails() {
            let rendered = DefaultEmailTemplates.render(&email, &branding()).unwrap();
            assert!(!rendered.subject.is_empty(), "{:?}", email.kind());
            assert!(rendered.subject.contains("Acme"), "{:?}", email.kind());
            assert!(rendered.html.starts_with("<!doctype html>"));
            assert!(rendered.html.contains("help@acme.test"));
            assert!(rendered.text.contains("help@acme.test"));
            if let LifecycleEmail::VerifyEmail { action_url, .. }
            | LifecycleEmail::PasswordReset { action_url, .. }
            | LifecycleEmail::Invitation { action_url, .. }
            | LifecycleEmail::TrialEnding { action_url, .. }
            | LifecycleEmail::PaymentFailed { action_url, .. } = &email
            {
                assert!(rendered.text.contains(action_url.as_str()));
                assert!(rendered.html.contains(&escape_html(action_url)));
            }
        }
    }

    #[test]
    fn default_templates_include_type_specific_details() {
        let emails = all_emails();
        let render = |i: usize| {
            DefaultEmailTemplates
                .render(&emails[i], &branding())
                .unwrap()
        };

        assert!(render(0).text.contains("expires in 1 hour."));
        assert!(
            render(2)
                .text
                .contains("Sam has invited you to join Widgets Inc")
        );
        assert!(render(2).text.contains("expires in 7 days."));
        assert_eq!(render(3).subject, "Your Acme trial ends in 3 days");
        assert!(render(4).text.contains("Amount due: USD 49.00"));
        let receipt = render(5);
        assert_eq!(receipt.subject, "Your Acme receipt #1001");
        assert!(receipt.text.contains("Amount paid: USD 49.00"));
        assert!(receipt.html.contains("https://pay.test/r/1001"));
    }

    #[test]
    fn amounts_respect_zero_decimal_currencies() {
        assert_eq!(Amount::new(4905, "usd").to_string(), "USD 49.05");
        assert_eq!(Amount::new(-5, "eur").to_string(), "EUR -0.05");
        assert_eq!(Amount::new(1200, "jpy").to_string(), "JPY 1200");
    }

    #[test]
    fn default_layout_escapes_application_values_and_rejects_unsafe_links() {
        let email = LifecycleEmail::invitation(
            "javascript:alert(1)",
            "<script>alert('org')</script>",
            None,
            Duration::from_secs(60),
        );
        let rendered = DefaultEmailTemplates
            .render(&email, &EmailBranding::new("A & B"))
            .unwrap();
        assert!(!rendered.html.contains("<script>"));
        assert!(rendered.html.contains("&lt;script&gt;"));
        assert!(rendered.html.contains("A &amp; B"));
        assert!(!rendered.html.contains("javascript:"));
    }

    struct CustomVerify;

    impl EmailTemplates for CustomVerify {
        fn content(
            &self,
            email: &LifecycleEmail,
            branding: &EmailBranding,
        ) -> Result<EmailContent> {
            let mut content = default_content(email, branding)?;
            if email.kind() == LifecycleEmailKind::VerifyEmail {
                content.subject = "Welcome aboard".into();
            }
            Ok(content)
        }
    }

    #[test]
    fn apps_can_override_one_template_and_keep_the_rest() {
        let emails = all_emails();
        let custom = CustomVerify.render(&emails[0], &branding()).unwrap();
        assert_eq!(custom.subject, "Welcome aboard");

        let reset = CustomVerify.render(&emails[1], &branding()).unwrap();
        let default_reset = DefaultEmailTemplates
            .render(&emails[1], &branding())
            .unwrap();
        assert_eq!(reset, default_reset);
    }

    struct BrandedLayout;

    impl EmailLayout for BrandedLayout {
        fn html(&self, branding: &EmailBranding, content: &EmailContent) -> String {
            format!(
                "<main data-brand=\"{}\">{}</main>",
                branding.app_name, content.heading
            )
        }
    }

    struct BrandedTemplates;

    impl EmailTemplates for BrandedTemplates {
        fn layout(&self) -> &dyn EmailLayout {
            &BrandedLayout
        }
    }

    #[test]
    fn apps_can_override_the_layout_for_every_email() {
        for email in all_emails() {
            let rendered = BrandedTemplates.render(&email, &branding()).unwrap();
            assert!(rendered.html.starts_with("<main data-brand=\"Acme\">"));
            // Text falls back to the default layout.
            assert!(rendered.text.contains("--\nAcme"));
        }
    }

    #[derive(Default)]
    struct RecordingMailer(Mutex<Vec<Email>>);

    #[async_trait]
    impl Mailer for RecordingMailer {
        async fn send(&self, email: &Email) -> Result<()> {
            self.0.lock().unwrap().push(email.clone());
            Ok(())
        }

        fn is_healthy(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn direct_delivery_sends_rendered_email() {
        let mailer = Arc::new(RecordingMailer::default());
        let emailer = LifecycleEmailer::direct(mailer.clone(), "noreply@acme.test", branding())
            .with_reply_to("help@acme.test");
        emailer
            .send("user@example.com", &all_emails()[1])
            .await
            .unwrap();

        let sent = mailer.0.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, vec!["user@example.com".to_string()]);
        assert_eq!(sent[0].from, "noreply@acme.test");
        assert_eq!(sent[0].reply_to.as_deref(), Some("help@acme.test"));
        assert_eq!(sent[0].subject, "Reset your Acme password");
        assert!(sent[0].html.is_some() && sent[0].text.is_some());
    }

    #[tokio::test]
    async fn rejects_empty_recipient() {
        let emailer = LifecycleEmailer::direct(
            Arc::new(RecordingMailer::default()),
            "noreply@acme.test",
            branding(),
        );
        assert!(emailer.send(" ", &all_emails()[0]).await.is_err());
    }

    #[test]
    fn lifecycle_email_round_trips_through_json() {
        for email in all_emails() {
            let json = serde_json::to_value(&email).unwrap();
            assert_eq!(json["kind"], email.kind().as_str());
            let back: LifecycleEmail = serde_json::from_value(json).unwrap();
            assert_eq!(back, email);
        }
    }
}
