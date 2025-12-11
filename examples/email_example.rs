//! Email example demonstrating email sending with Tideway
//!
//! Run with: cargo run --example email_example --features email

use std::sync::Arc;
use tideway::{
    App, AppContext, ConfigBuilder, ConsoleMailer, Email, Mailer, SmtpConfig, SmtpMailer,
};

#[tokio::main]
async fn main() -> tideway::Result<()> {
    tideway::init_tracing();

    // Choose mailer based on environment
    let mailer: Arc<dyn Mailer> = if std::env::var("SMTP_HOST").is_ok() {
        // Production: Use SMTP
        println!("Using SMTP mailer (SMTP_HOST detected)");
        let config = SmtpConfig::from_env()?;
        Arc::new(SmtpMailer::new(config)?)
    } else {
        // Development: Use console mailer
        println!("Using console mailer (set SMTP_HOST for SMTP)");
        Arc::new(ConsoleMailer::new())
    };

    // Build app context with mailer
    let context = AppContext::builder()
        .with_mailer(mailer.clone())
        .build();

    // Demo: Send an email
    let email = Email::new(
        "noreply@myapp.com",
        "user@example.com",
        "Welcome to MyApp!",
    )
    .text("Thanks for signing up! We're excited to have you.")
    .html("<h1>Welcome!</h1><p>Thanks for signing up! We're excited to have you.</p>");

    println!("\nSending welcome email...\n");
    mailer.send(&email).await?;
    println!("\nEmail sent successfully!");

    // Demo: Email with multiple recipients
    let newsletter = Email::new(
        "newsletter@myapp.com",
        "subscriber1@example.com",
        "Monthly Newsletter",
    )
    .to("subscriber2@example.com")
    .to("subscriber3@example.com")
    .cc("marketing@myapp.com")
    .text("Here's what's new this month...")
    .html("<h1>Monthly Newsletter</h1><p>Here's what's new this month...</p>");

    println!("\nSending newsletter...\n");
    mailer.send(&newsletter).await?;
    println!("\nNewsletter sent!");

    // Health check
    println!("\nMailer healthy: {}", mailer.is_healthy());

    // Example of building an app with the mailer in context
    let _config = ConfigBuilder::new().build();
    let _app = App::new().with_context(context);

    println!("\nTo use SMTP, set these environment variables:");
    println!("  SMTP_HOST=smtp.example.com");
    println!("  SMTP_PORT=587 (optional, default: 587)");
    println!("  SMTP_USERNAME=your-username");
    println!("  SMTP_PASSWORD=your-password");
    println!("  SMTP_FROM=noreply@example.com (optional default from)");
    println!("  SMTP_STARTTLS=true (optional, default: true)");

    Ok(())
}
