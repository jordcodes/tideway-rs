//! Tests for email functionality

#[cfg(feature = "email")]
mod email_tests {
    use std::sync::Arc;
    use tideway::{AppContext, ConsoleMailer, Email, Mailer, SmtpConfig};

    #[test]
    fn test_email_builder() {
        let email = Email::new("from@test.com", "to@test.com", "Test Subject")
            .text("Plain text body")
            .html("<p>HTML body</p>")
            .cc("cc@test.com")
            .bcc("bcc@test.com")
            .reply_to("reply@test.com");

        assert_eq!(email.from, "from@test.com");
        assert_eq!(email.to, vec!["to@test.com"]);
        assert_eq!(email.subject, "Test Subject");
        assert_eq!(email.text, Some("Plain text body".to_string()));
        assert_eq!(email.html, Some("<p>HTML body</p>".to_string()));
        assert_eq!(email.cc, vec!["cc@test.com"]);
        assert_eq!(email.bcc, vec!["bcc@test.com"]);
        assert_eq!(email.reply_to, Some("reply@test.com".to_string()));
    }

    #[test]
    fn test_email_multiple_recipients() {
        let email = Email::new("from@test.com", "to1@test.com", "Test")
            .to("to2@test.com")
            .to("to3@test.com")
            .cc("cc1@test.com")
            .cc("cc2@test.com")
            .bcc("bcc1@test.com")
            .text("body");

        assert_eq!(email.to, vec!["to1@test.com", "to2@test.com", "to3@test.com"]);
        assert_eq!(email.cc, vec!["cc1@test.com", "cc2@test.com"]);
        assert_eq!(email.bcc, vec!["bcc1@test.com"]);
    }

    #[test]
    fn test_email_validation_requires_body() {
        let email = Email::new("from@test.com", "to@test.com", "Test");
        let result = email.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("body"));
    }

    #[test]
    fn test_email_validation_requires_recipient() {
        let email = Email {
            from: "from@test.com".to_string(),
            to: vec![],
            cc: vec![],
            bcc: vec![],
            subject: "Test".to_string(),
            text: Some("body".to_string()),
            html: None,
            reply_to: None,
        };
        let result = email.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("'to' is required"));
    }

    #[test]
    fn test_email_validation_requires_subject() {
        let email = Email {
            from: "from@test.com".to_string(),
            to: vec!["to@test.com".to_string()],
            cc: vec![],
            bcc: vec![],
            subject: "".to_string(),
            text: Some("body".to_string()),
            html: None,
            reply_to: None,
        };
        let result = email.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("subject"));
    }

    #[test]
    fn test_email_validation_text_only() {
        let email = Email::new("from@test.com", "to@test.com", "Test")
            .text("text body");
        assert!(email.validate().is_ok());
    }

    #[test]
    fn test_email_validation_html_only() {
        let email = Email::new("from@test.com", "to@test.com", "Test")
            .html("<p>html body</p>");
        assert!(email.validate().is_ok());
    }

    #[test]
    fn test_email_validation_both_bodies() {
        let email = Email::new("from@test.com", "to@test.com", "Test")
            .text("text body")
            .html("<p>html body</p>");
        assert!(email.validate().is_ok());
    }

    #[tokio::test]
    async fn test_console_mailer_send() {
        let mailer = ConsoleMailer::new();
        let email = Email::new("from@test.com", "to@test.com", "Test Subject")
            .text("Test body");

        let result = mailer.send(&email).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_console_mailer_validates_email() {
        let mailer = ConsoleMailer::new();
        let email = Email::new("from@test.com", "to@test.com", "Test");
        // No body - should fail validation

        let result = mailer.send(&email).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_console_mailer_is_healthy() {
        let mailer = ConsoleMailer::new();
        assert!(mailer.is_healthy());
    }

    #[test]
    fn test_console_mailer_with_prefix() {
        let mailer = ConsoleMailer::with_prefix("[CUSTOM]");
        assert!(mailer.is_healthy());
    }

    #[test]
    fn test_smtp_config_builder() {
        let config = SmtpConfig::new("smtp.test.com")
            .port(465)
            .credentials("user", "pass")
            .from("noreply@test.com")
            .no_starttls();

        assert_eq!(config.host, "smtp.test.com");
        assert_eq!(config.port, 465);
        assert_eq!(config.username, Some("user".to_string()));
        assert_eq!(config.password, Some("pass".to_string()));
        assert_eq!(config.default_from, Some("noreply@test.com".to_string()));
        assert!(!config.starttls);
    }

    #[test]
    fn test_smtp_config_defaults() {
        let config = SmtpConfig::new("smtp.test.com");

        assert_eq!(config.host, "smtp.test.com");
        assert_eq!(config.port, 587);
        assert!(config.username.is_none());
        assert!(config.password.is_none());
        assert!(config.default_from.is_none());
        assert!(config.starttls);
    }

    #[test]
    fn test_app_context_with_mailer() {
        let mailer: Arc<dyn Mailer> = Arc::new(ConsoleMailer::new());
        let ctx = AppContext::builder()
            .with_mailer(mailer)
            .build();

        assert!(ctx.mailer_opt().is_some());
        assert!(ctx.mailer().is_ok());
    }

    #[test]
    fn test_app_context_without_mailer() {
        let ctx = AppContext::new();

        assert!(ctx.mailer_opt().is_none());
        assert!(ctx.mailer().is_err());
    }

    #[tokio::test]
    async fn test_mailer_from_context() {
        let mailer: Arc<dyn Mailer> = Arc::new(ConsoleMailer::new());
        let ctx = AppContext::builder()
            .with_mailer(mailer)
            .build();

        let email = Email::new("from@test.com", "to@test.com", "Test")
            .text("body");

        // Get mailer from context and send
        let result = ctx.mailer().unwrap().send(&email).await;
        assert!(result.is_ok());
    }
}
