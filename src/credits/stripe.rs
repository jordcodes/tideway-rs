//! Stripe Checkout adapter for prepaid credit packs.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::billing::{
    BillingEvent, BillingEventSink, CheckoutConfig, CheckoutLineItem, CheckoutMetadata,
    CheckoutMode, CheckoutSession, CreateCheckoutSessionRequest, NoOpBillingEventSink,
    StripeCheckoutClient,
};
use crate::{Result, TidewayError};

use super::{CreditManager, CreditSource, CreditStore, GrantCredits};

const TOP_UP_BILLABLE_TYPE: &str = "credit_top_up";

/// Server-owned definition of a prepaid credit pack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreditTopUpPack {
    /// Immutable, versioned application identifier embedded in trusted Stripe metadata. Create a
    /// new ID when changing the Stripe price, credit type, or amount.
    pub id: String,
    /// Stripe Price ID for the one-time product.
    pub stripe_price_id: String,
    /// Application-defined unit, such as `sms` or `ai_tokens`.
    pub credit_type: String,
    /// Integer units granted after confirmed payment.
    pub amount: u64,
}

/// Validated server-side catalog of credit packs.
#[derive(Clone, Debug, Default)]
pub struct CreditTopUpCatalog {
    packs: HashMap<String, CreditTopUpPack>,
}

impl CreditTopUpCatalog {
    /// Build a catalog, rejecting unsafe or duplicate definitions.
    pub fn new(packs: impl IntoIterator<Item = CreditTopUpPack>) -> Result<Self> {
        let mut catalog = Self::default();
        for pack in packs {
            validate_identifier("credit pack id", &pack.id)?;
            validate_identifier("credit type", &pack.credit_type)?;
            if pack.stripe_price_id.trim().is_empty() || pack.stripe_price_id.len() > 256 {
                return Err(TidewayError::bad_request(
                    "Stripe price ID must contain between 1 and 256 bytes",
                ));
            }
            if pack.amount == 0 || pack.amount > i64::MAX as u64 {
                return Err(TidewayError::bad_request(
                    "Credit pack amount must be between 1 and i64::MAX",
                ));
            }
            let id = pack.id.clone();
            if catalog.packs.insert(id.clone(), pack).is_some() {
                return Err(TidewayError::conflict(format!(
                    "Duplicate credit pack id: {id}"
                )));
            }
        }
        Ok(catalog)
    }

    /// Look up a server-defined pack.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&CreditTopUpPack> {
        self.packs.get(id)
    }
}

/// Application request to start a one-time credit purchase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreditTopUpCheckoutRequest {
    /// Existing Stripe Customer ID owned by the account.
    pub customer_id: String,
    /// Application account or organization that will receive the credits.
    pub account_id: String,
    /// Server-defined [`CreditTopUpPack::id`].
    pub pack_id: String,
    pub success_url: String,
    pub cancel_url: String,
}

/// Creates one-time Stripe Checkout sessions from a trusted pack catalog.
pub struct CreditTopUpCheckoutManager<C> {
    client: C,
    catalog: CreditTopUpCatalog,
    checkout_config: CheckoutConfig,
}

impl<C: StripeCheckoutClient> CreditTopUpCheckoutManager<C> {
    #[must_use]
    pub fn new(client: C, catalog: CreditTopUpCatalog, checkout_config: CheckoutConfig) -> Self {
        Self {
            client,
            catalog,
            checkout_config,
        }
    }

    /// Create a payment-mode Checkout Session.
    ///
    /// The caller chooses only a pack ID. Price and granted quantity always come from the
    /// server-owned catalog and are later re-resolved from that catalog during fulfilment.
    pub async fn create_checkout(
        &self,
        request: CreditTopUpCheckoutRequest,
    ) -> Result<CheckoutSession> {
        validate_identifier("account id", &request.account_id)?;
        if request.customer_id.is_empty()
            || request.customer_id.len() > 256
            || request.customer_id.chars().any(char::is_control)
        {
            return Err(TidewayError::bad_request(
                "Stripe customer ID must contain between 1 and 256 bytes and no control characters",
            ));
        }
        self.checkout_config
            .validate_redirect_url(&request.success_url)?;
        self.checkout_config
            .validate_redirect_url(&request.cancel_url)?;
        let pack = self.catalog.get(&request.pack_id).ok_or_else(|| {
            TidewayError::bad_request(format!("Unknown credit pack: {}", request.pack_id))
        })?;

        self.client
            .create_checkout_session(CreateCheckoutSessionRequest {
                customer_id: request.customer_id,
                line_items: vec![CheckoutLineItem {
                    price_id: pack.stripe_price_id.clone(),
                    quantity: 1,
                }],
                success_url: request.success_url,
                cancel_url: request.cancel_url,
                mode: CheckoutMode::Payment,
                allow_promotion_codes: self.checkout_config.allow_promotion_codes,
                trial_period_days: None,
                metadata: CheckoutMetadata {
                    billable_id: request.account_id,
                    billable_type: TOP_UP_BILLABLE_TYPE.to_string(),
                    plan_id: pack.id.clone(),
                },
                tax_id_collection: self.checkout_config.collect_tax_id,
                billing_address_collection: self.checkout_config.collect_billing_address,
                coupon: None,
                payment_method_collection: None,
            })
            .await
    }
}

/// Billing event sink that fulfils paid Stripe credit top-ups exactly once.
///
/// Compose an existing application sink with [`Self::with_next`]. Tideway grants first; if the
/// downstream sink fails and Stripe retries, the event ID makes the grant idempotent.
pub struct CreditTopUpEventSink<S, E = NoOpBillingEventSink> {
    credits: CreditManager<S>,
    catalog: CreditTopUpCatalog,
    next: E,
}

impl<S: CreditStore> CreditTopUpEventSink<S, NoOpBillingEventSink> {
    #[must_use]
    pub fn new(credits: CreditManager<S>, catalog: CreditTopUpCatalog) -> Self {
        Self {
            credits,
            catalog,
            next: NoOpBillingEventSink,
        }
    }
}

impl<S, E> CreditTopUpEventSink<S, E> {
    #[must_use]
    pub fn with_next<E2>(self, next: E2) -> CreditTopUpEventSink<S, E2> {
        CreditTopUpEventSink {
            credits: self.credits,
            catalog: self.catalog,
            next,
        }
    }
}

#[async_trait]
impl<S, E> BillingEventSink for CreditTopUpEventSink<S, E>
where
    S: CreditStore,
    E: BillingEventSink,
{
    async fn handle(&self, event: &BillingEvent) -> Result<()> {
        if let BillingEvent::OneTimeCheckoutCompleted {
            context,
            checkout_session_id,
            customer_id,
            billable_id,
            billable_type,
            plan_id,
            payment_status,
        } = event
            && billable_type.as_deref() == Some(TOP_UP_BILLABLE_TYPE)
        {
            if !matches!(
                payment_status.as_deref(),
                Some("paid" | "no_payment_required")
            ) {
                self.next.handle(event).await?;
                return Ok(());
            }
            let account_id = billable_id.clone().ok_or_else(|| {
                TidewayError::bad_request("Paid credit top-up is missing billable_id metadata")
            })?;
            let pack_id = plan_id.as_deref().ok_or_else(|| {
                TidewayError::bad_request("Paid credit top-up is missing plan_id metadata")
            })?;
            let pack = self.catalog.get(pack_id).ok_or_else(|| {
                TidewayError::internal(format!(
                    "Paid credit top-up references unknown pack: {pack_id}"
                ))
            })?;
            self.credits
                .grant(GrantCredits {
                    account_id,
                    credit_type: pack.credit_type.clone(),
                    amount: pack.amount,
                    source: CreditSource::Purchased,
                    expires_at: None,
                    idempotency_key: format!("stripe-event:{}", context.event_id),
                    metadata: serde_json::json!({
                        "stripe_checkout_session_id": checkout_session_id,
                        "stripe_customer_id": customer_id,
                        "credit_pack_id": pack.id,
                    }),
                })
                .await?;
        }

        self.next.handle(event).await
    }
}

fn validate_identifier(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(TidewayError::bad_request(format!(
            "{field} must contain between 1 and 128 bytes and no control characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::billing::BillingEventContext;
    use crate::credits::{CreditHistoryQuery, MemoryCreditStore};

    #[derive(Clone, Default)]
    struct CheckoutClient {
        requests: Arc<Mutex<Vec<CreateCheckoutSessionRequest>>>,
    }

    impl StripeCheckoutClient for CheckoutClient {
        async fn create_checkout_session(
            &self,
            request: CreateCheckoutSessionRequest,
        ) -> Result<CheckoutSession> {
            self.requests.lock().unwrap().push(request);
            Ok(CheckoutSession {
                id: "cs_test_1".to_string(),
                url: "https://checkout.stripe.test/session".to_string(),
            })
        }
    }

    fn catalog() -> CreditTopUpCatalog {
        CreditTopUpCatalog::new([CreditTopUpPack {
            id: "sms_100".to_string(),
            stripe_price_id: "price_sms_100".to_string(),
            credit_type: "sms".to_string(),
            amount: 100,
        }])
        .unwrap()
    }

    #[tokio::test]
    async fn checkout_uses_server_owned_price_and_payment_mode() {
        let client = CheckoutClient::default();
        let requests = client.requests.clone();
        let manager = CreditTopUpCheckoutManager::new(
            client,
            catalog(),
            CheckoutConfig::new().allowed_redirect_domains(["app.example.com"]),
        );
        let _session = manager
            .create_checkout(CreditTopUpCheckoutRequest {
                customer_id: "cus_123".to_string(),
                account_id: "org-1".to_string(),
                pack_id: "sms_100".to_string(),
                success_url: "https://app.example.com/billing/success".to_string(),
                cancel_url: "https://app.example.com/billing".to_string(),
            })
            .await
            .unwrap();
        let requests = requests.lock().unwrap();
        assert_eq!(requests[0].mode, CheckoutMode::Payment);
        assert_eq!(requests[0].line_items[0].price_id, "price_sms_100");
        assert_eq!(requests[0].metadata.billable_id, "org-1");
        assert_eq!(requests[0].metadata.billable_type, TOP_UP_BILLABLE_TYPE);
    }

    #[tokio::test]
    async fn paid_webhook_grants_once_and_unpaid_does_not_grant() {
        let store = MemoryCreditStore::new();
        let sink = CreditTopUpEventSink::new(CreditManager::new(store.clone()), catalog());
        let event = |id: &str, status: &str| BillingEvent::OneTimeCheckoutCompleted {
            context: BillingEventContext {
                event_id: id.to_string(),
                created: 1,
            },
            checkout_session_id: "cs_1".to_string(),
            customer_id: Some("cus_1".to_string()),
            billable_id: Some("org-1".to_string()),
            billable_type: Some(TOP_UP_BILLABLE_TYPE.to_string()),
            plan_id: Some("sms_100".to_string()),
            payment_status: Some(status.to_string()),
        };

        sink.handle(&event("evt_unpaid", "unpaid")).await.unwrap();
        assert_eq!(
            store
                .balance("org-1", "sms", i64::MAX)
                .await
                .unwrap()
                .available,
            0
        );
        sink.handle(&event("evt_paid", "paid")).await.unwrap();
        sink.handle(&event("evt_paid", "paid")).await.unwrap();
        assert_eq!(
            store
                .balance("org-1", "sms", i64::MAX)
                .await
                .unwrap()
                .available,
            100
        );
        assert_eq!(
            store
                .history("org-1", "sms", CreditHistoryQuery::default())
                .await
                .unwrap()
                .len(),
            1
        );
    }
}
