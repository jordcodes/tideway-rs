//! Send lifecycle emails from billing webhook events.
//!
//! [`LifecycleEmailBillingSink`] is a [`BillingEventSink`] that sends the built-in
//! [`LifecycleEmail`] templates:
//!
//! | Billing event | Email |
//! |---------------|-------|
//! | [`BillingEvent::TrialWillEnd`] | [`LifecycleEmail::TrialEnding`] |
//! | [`BillingEvent::InvoicePaymentFailed`] | [`LifecycleEmail::PaymentFailed`] |
//! | [`BillingEvent::InvoicePaid`] (non-zero amount) | [`LifecycleEmail::Receipt`] |
//!
//! Invoice emails go to the invoice's `customer_email`. Trial reminders, and invoices without an
//! email, are addressed through an application-supplied [`BillingEmailRecipients`]. Events without
//! a resolvable recipient are skipped with a warning rather than failing the webhook.
//!
//! ```rust,ignore
//! use tideway::billing::{LifecycleEmailBillingSink, WebhookHandler};
//!
//! let sink = LifecycleEmailBillingSink::new(emailer, "https://app.example.com/settings/billing")
//!     .with_recipients(Arc::new(MyRecipients { db }))
//!     .with_plans(plans.clone())
//!     .with_inner(MyBillingEvents); // existing sink, runs first
//! let handler = WebhookHandler::new(store, secret, plans).with_event_sink(sink);
//! ```

use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::Arc;

use crate::email::{Amount, LifecycleEmail, LifecycleEmailKind, LifecycleEmailer};
use crate::error::Result;

use super::events::{BillingEvent, BillingEventSink, InvoiceSummary, NoOpBillingEventSink};
use super::plans::Plans;

/// Resolves the email address that should receive billing emails for a customer.
#[async_trait]
pub trait BillingEmailRecipients: Send + Sync {
    /// Return the recipient for a Stripe customer and, when known, the application billable ID.
    ///
    /// Return `Ok(None)` to skip the email. Returning an error fails the webhook so Stripe retries.
    async fn recipient(
        &self,
        customer_id: Option<&str>,
        billable_id: Option<&str>,
    ) -> Result<Option<String>>;
}

/// A [`BillingEventSink`] that sends trial-ending, payment-failed, and receipt emails.
///
/// The wrapped inner sink (see [`Self::with_inner`]) runs first; emails are only sent once it
/// succeeds, so a failing inner sink does not produce duplicate emails on Stripe's retry. Use a
/// [`LifecycleEmailer::queued`] emailer so provider latency stays out of the webhook request.
pub struct LifecycleEmailBillingSink<E = NoOpBillingEventSink> {
    emailer: LifecycleEmailer,
    billing_url: String,
    recipients: Option<Arc<dyn BillingEmailRecipients>>,
    plans: Option<Plans>,
    disabled: HashSet<LifecycleEmailKind>,
    inner: E,
}

impl LifecycleEmailBillingSink {
    /// Send billing emails with `emailer`, linking customers to `billing_url` to manage billing.
    pub fn new(emailer: LifecycleEmailer, billing_url: impl Into<String>) -> Self {
        Self {
            emailer,
            billing_url: billing_url.into(),
            recipients: None,
            plans: None,
            disabled: HashSet::new(),
            inner: NoOpBillingEventSink,
        }
    }
}

impl<E: BillingEventSink> LifecycleEmailBillingSink<E> {
    /// Resolve recipients for events that do not carry an email address.
    pub fn with_recipients(mut self, recipients: Arc<dyn BillingEmailRecipients>) -> Self {
        self.recipients = Some(recipients);
        self
    }

    /// Use plan display names in emails.
    pub fn with_plans(mut self, plans: Plans) -> Self {
        self.plans = Some(plans);
        self
    }

    /// Do not send `kind` (for example when Stripe already sends receipts).
    pub fn without(mut self, kind: LifecycleEmailKind) -> Self {
        self.disabled.insert(kind);
        self
    }

    /// Run `inner` for every event before sending emails.
    pub fn with_inner<E2: BillingEventSink>(self, inner: E2) -> LifecycleEmailBillingSink<E2> {
        LifecycleEmailBillingSink {
            emailer: self.emailer,
            billing_url: self.billing_url,
            recipients: self.recipients,
            plans: self.plans,
            disabled: self.disabled,
            inner,
        }
    }

    fn plan_name(&self, plan_id: &str) -> Option<String> {
        let plan = self.plans.as_ref()?.get(plan_id)?;
        Some(plan.display_name.clone().unwrap_or_else(|| plan.id.clone()))
    }

    async fn recipient(
        &self,
        email: Option<&str>,
        customer_id: Option<&str>,
        billable_id: Option<&str>,
    ) -> Result<Option<String>> {
        if let Some(email) = email.filter(|email| !email.trim().is_empty()) {
            return Ok(Some(email.to_string()));
        }
        match &self.recipients {
            Some(recipients) => recipients.recipient(customer_id, billable_id).await,
            None => Ok(None),
        }
    }

    /// Build the email for `event` and resolve its recipient, if any.
    async fn email_for(&self, event: &BillingEvent) -> Result<Option<(String, LifecycleEmail)>> {
        let (recipient, email) = match event {
            BillingEvent::TrialWillEnd {
                context,
                subscription,
            } => {
                let Some(trial_end) = subscription.trial_end else {
                    return Ok(None);
                };
                if subscription.status != "trialing" {
                    return Ok(None);
                }
                let days_remaining = trial_end.saturating_sub(context.created).div_ceil(86_400);
                let email = LifecycleEmail::trial_ending(
                    &self.billing_url,
                    self.plan_name(&subscription.plan_id),
                    u32::try_from(days_remaining).unwrap_or(u32::MAX),
                );
                let recipient = self
                    .recipient(
                        None,
                        Some(&subscription.customer_id),
                        subscription.metadata.billable_id.as_deref(),
                    )
                    .await?;
                (recipient, email)
            }
            BillingEvent::InvoicePaymentFailed {
                customer_id,
                invoice,
                ..
            } => {
                let email = LifecycleEmail::payment_failed(
                    &self.billing_url,
                    amount(invoice.amount_due, invoice),
                    None,
                );
                let recipient = self
                    .recipient(
                        invoice.customer_email.as_deref(),
                        customer_id.as_deref(),
                        None,
                    )
                    .await?;
                (recipient, email)
            }
            BillingEvent::InvoicePaid {
                customer_id,
                invoice,
                ..
            } => {
                // Skip $0 invoices such as trial starts.
                let Some(paid) = amount(invoice.amount_paid, invoice).filter(|a| a.minor_units > 0)
                else {
                    return Ok(None);
                };
                let email = LifecycleEmail::Receipt {
                    amount: paid,
                    description: None,
                    receipt_number: invoice.number.clone(),
                    receipt_url: invoice.hosted_invoice_url.clone(),
                };
                let recipient = self
                    .recipient(
                        invoice.customer_email.as_deref(),
                        customer_id.as_deref(),
                        None,
                    )
                    .await?;
                (recipient, email)
            }
            _ => return Ok(None),
        };

        if self.disabled.contains(&email.kind()) {
            return Ok(None);
        }
        match recipient {
            Some(recipient) => Ok(Some((recipient, email))),
            None => {
                tracing::warn!(
                    target: "tideway::billing::emails",
                    event_id = %event.event_id(),
                    kind = %email.kind(),
                    "No recipient for billing lifecycle email; skipping"
                );
                Ok(None)
            }
        }
    }
}

fn amount(minor_units: Option<u64>, invoice: &InvoiceSummary) -> Option<Amount> {
    let minor_units = i64::try_from(minor_units?).ok()?;
    Some(Amount::new(minor_units, invoice.currency.clone()?))
}

#[async_trait]
impl<E: BillingEventSink> BillingEventSink for LifecycleEmailBillingSink<E> {
    async fn handle(&self, event: &BillingEvent) -> Result<()> {
        self.inner.handle(event).await?;
        if let Some((recipient, email)) = self.email_for(event).await? {
            self.emailer.send(&recipient, &email).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::events::BillingEventContext;
    use crate::billing::subscription::{StripeSubscriptionData, SubscriptionMetadata};
    use crate::email::EmailBranding;
    use crate::error::TidewayError;
    use crate::traits::mailer::{Email, Mailer};
    use std::sync::Mutex;

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

    struct Directory;

    #[async_trait]
    impl BillingEmailRecipients for Directory {
        async fn recipient(
            &self,
            customer_id: Option<&str>,
            billable_id: Option<&str>,
        ) -> Result<Option<String>> {
            Ok(match (customer_id, billable_id) {
                (_, Some("org_1")) => Some("owner@org1.test".into()),
                (Some("cus_known"), _) => Some("billing@known.test".into()),
                _ => None,
            })
        }
    }

    struct FailingSink;

    #[async_trait]
    impl BillingEventSink for FailingSink {
        async fn handle(&self, _event: &BillingEvent) -> Result<()> {
            Err(TidewayError::internal("inner failed"))
        }
    }

    fn sink(mailer: Arc<RecordingMailer>) -> LifecycleEmailBillingSink {
        let emailer =
            LifecycleEmailer::direct(mailer, "billing@acme.test", EmailBranding::new("Acme"));
        LifecycleEmailBillingSink::new(emailer, "https://acme.test/billing")
            .with_recipients(Arc::new(Directory))
            .with_plans(
                Plans::builder()
                    .plan("pro")
                    .stripe_price("price_pro")
                    .display_name("Pro")
                    .done()
                    .unwrap()
                    .build()
                    .unwrap(),
            )
    }

    fn context() -> BillingEventContext {
        BillingEventContext {
            event_id: "evt_1".into(),
            created: 1_700_000_000,
        }
    }

    fn trial_will_end(status: &str) -> BillingEvent {
        BillingEvent::TrialWillEnd {
            context: context(),
            subscription: StripeSubscriptionData {
                id: "sub_1".into(),
                customer_id: "cus_1".into(),
                plan_id: "pro".into(),
                status: status.into(),
                current_period_start: 0,
                current_period_end: 0,
                extra_seats: 0,
                trial_end: Some(1_700_000_000 + 3 * 86_400),
                cancel_at_period_end: false,
                base_item_id: None,
                seat_item_id: None,
                metadata: SubscriptionMetadata {
                    billable_id: Some("org_1".into()),
                    billable_type: None,
                },
            },
        }
    }

    fn invoice(amount_paid: u64, customer_email: Option<&str>) -> InvoiceSummary {
        InvoiceSummary {
            number: Some("ACME-0001".into()),
            customer_email: customer_email.map(String::from),
            amount_due: Some(4900),
            amount_paid: Some(amount_paid),
            currency: Some("usd".into()),
            hosted_invoice_url: Some("https://invoice.stripe.test/i/1".into()),
            billing_reason: Some("subscription_cycle".into()),
        }
    }

    fn paid(amount_paid: u64, customer_email: Option<&str>) -> BillingEvent {
        BillingEvent::InvoicePaid {
            context: context(),
            invoice_id: Some("in_1".into()),
            subscription_id: Some("sub_1".into()),
            customer_id: Some("cus_known".into()),
            invoice: invoice(amount_paid, customer_email),
        }
    }

    fn failed(customer_id: &str, customer_email: Option<&str>) -> BillingEvent {
        BillingEvent::InvoicePaymentFailed {
            context: context(),
            invoice_id: Some("in_1".into()),
            subscription_id: Some("sub_1".into()),
            customer_id: Some(customer_id.into()),
            invoice: invoice(0, customer_email),
        }
    }

    #[tokio::test]
    async fn trial_will_end_sends_trial_ending_email_to_resolved_owner() {
        let mailer = Arc::new(RecordingMailer::default());
        sink(mailer.clone())
            .handle(&trial_will_end("trialing"))
            .await
            .unwrap();

        let sent = mailer.0.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, vec!["owner@org1.test".to_string()]);
        assert_eq!(sent[0].subject, "Your Acme trial ends in 3 days");
        let text = sent[0].text.as_deref().unwrap();
        assert!(text.contains("of the Pro plan"));
        assert!(text.contains("https://acme.test/billing"));
    }

    #[tokio::test]
    async fn trial_will_end_is_skipped_when_no_longer_trialing() {
        let mailer = Arc::new(RecordingMailer::default());
        sink(mailer.clone())
            .handle(&trial_will_end("canceled"))
            .await
            .unwrap();
        assert!(mailer.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn payment_failed_uses_invoice_email_and_amount_due() {
        let mailer = Arc::new(RecordingMailer::default());
        sink(mailer.clone())
            .handle(&failed("cus_unknown", Some("payer@acme.test")))
            .await
            .unwrap();

        let sent = mailer.0.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, vec!["payer@acme.test".to_string()]);
        assert_eq!(sent[0].subject, "Action required: your Acme payment failed");
        assert!(
            sent[0]
                .text
                .as_deref()
                .unwrap()
                .contains("Amount due: USD 49.00")
        );
    }

    #[tokio::test]
    async fn invoice_without_email_falls_back_to_resolver_or_is_skipped() {
        let mailer = Arc::new(RecordingMailer::default());
        let sink = sink(mailer.clone());
        sink.handle(&failed("cus_known", None)).await.unwrap();
        sink.handle(&failed("cus_unknown", None)).await.unwrap();

        let sent = mailer.0.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, vec!["billing@known.test".to_string()]);
    }

    #[tokio::test]
    async fn paid_invoice_sends_receipt_but_zero_invoices_do_not() {
        let mailer = Arc::new(RecordingMailer::default());
        let sink = sink(mailer.clone());
        sink.handle(&paid(0, Some("payer@acme.test")))
            .await
            .unwrap();
        sink.handle(&paid(4900, Some("payer@acme.test")))
            .await
            .unwrap();

        let sent = mailer.0.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].subject, "Your Acme receipt #ACME-0001");
        assert!(
            sent[0]
                .html
                .as_deref()
                .unwrap()
                .contains("https://invoice.stripe.test/i/1")
        );
    }

    #[tokio::test]
    async fn disabled_kinds_are_not_sent() {
        let mailer = Arc::new(RecordingMailer::default());
        sink(mailer.clone())
            .without(LifecycleEmailKind::Receipt)
            .handle(&paid(4900, Some("payer@acme.test")))
            .await
            .unwrap();
        assert!(mailer.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn inner_sink_failure_suppresses_email() {
        let mailer = Arc::new(RecordingMailer::default());
        let result = sink(mailer.clone())
            .with_inner(FailingSink)
            .handle(&paid(4900, Some("payer@acme.test")))
            .await;
        assert!(result.is_err());
        assert!(mailer.0.lock().unwrap().is_empty());
    }
}
