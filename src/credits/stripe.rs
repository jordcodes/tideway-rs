//! Stripe Checkout adapter for prepaid credit packs.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::billing::{
    BillingEvent, BillingEventContext, BillingEventSink, CheckoutConfig, CheckoutLineItem,
    CheckoutMetadata, CheckoutMode, CheckoutSession, CreateCheckoutSessionRequest,
    NoOpBillingEventSink, StripeCheckoutClient,
};
use crate::{Result, TidewayError};

use super::{
    CreditManager, CreditSource, CreditStore, GrantCredits, RevocationAmount, RevokeCredits,
};

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

/// Billing event sink that fulfils paid Stripe credit top-ups exactly once and takes them back
/// when the payment is refunded or disputed.
///
/// Grants are keyed by the Stripe PaymentIntent, so `charge.refunded` and
/// `charge.dispute.created` can find them. Refunds revoke credits in proportion to the refunded
/// share of the charge; disputes revoke the whole pack. Checkouts that cost nothing, such as
/// with a 100%-off promotion code, grant no credits.
///
/// Compose an existing application sink with [`Self::with_next`]. Tideway updates credits first;
/// if the downstream sink fails and Stripe retries, the PaymentIntent key keeps grants idempotent
/// and cumulative revocation amounts keep revocations idempotent.
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
        match event {
            BillingEvent::OneTimeCheckoutCompleted {
                context,
                checkout_session_id,
                customer_id,
                billable_id,
                billable_type,
                plan_id,
                payment_status,
                payment_intent_id,
            } if billable_type.as_deref() == Some(TOP_UP_BILLABLE_TYPE) => {
                // `no_payment_required` means a 100%-off discount covered the purchase, so
                // nothing was paid for the credits.
                if payment_status.as_deref() == Some("paid") {
                    self.grant_paid_top_up(
                        context,
                        checkout_session_id,
                        customer_id.as_deref(),
                        billable_id.as_deref(),
                        plan_id.as_deref(),
                        payment_intent_id.as_deref(),
                    )
                    .await?;
                }
            }
            BillingEvent::ChargeRefunded {
                context,
                charge_id,
                payment_intent_id: Some(payment_intent_id),
                amount,
                amount_refunded,
                ..
            } if *amount > 0 && *amount_refunded > 0 => {
                // Stripe reports the cumulative refunded amount, so revoke the same share.
                self.revoke_top_up(
                    context,
                    payment_intent_id,
                    RevocationAmount::Fraction {
                        numerator: *amount_refunded,
                        denominator: *amount,
                    },
                    serde_json::json!({
                        "reason": "refund",
                        "stripe_charge_id": charge_id,
                        "stripe_amount": amount,
                        "stripe_amount_refunded": amount_refunded,
                    }),
                )
                .await?;
            }
            BillingEvent::ChargeDisputed {
                context,
                dispute_id,
                charge_id,
                payment_intent_id: Some(payment_intent_id),
                ..
            } => {
                self.revoke_top_up(
                    context,
                    payment_intent_id,
                    RevocationAmount::ALL,
                    serde_json::json!({
                        "reason": "dispute",
                        "stripe_charge_id": charge_id,
                        "stripe_dispute_id": dispute_id,
                    }),
                )
                .await?;
            }
            _ => {}
        }

        self.next.handle(event).await
    }
}

impl<S: CreditStore, E> CreditTopUpEventSink<S, E> {
    async fn grant_paid_top_up(
        &self,
        context: &BillingEventContext,
        checkout_session_id: &str,
        customer_id: Option<&str>,
        billable_id: Option<&str>,
        plan_id: Option<&str>,
        payment_intent_id: Option<&str>,
    ) -> Result<()> {
        let account_id = billable_id.ok_or_else(|| {
            TidewayError::bad_request("Paid credit top-up is missing billable_id metadata")
        })?;
        let pack_id = plan_id.ok_or_else(|| {
            TidewayError::bad_request("Paid credit top-up is missing plan_id metadata")
        })?;
        let payment_intent_id = payment_intent_id.ok_or_else(|| {
            TidewayError::bad_request("Paid credit top-up is missing its payment_intent")
        })?;
        let pack = self.catalog.get(pack_id).ok_or_else(|| {
            TidewayError::internal(format!(
                "Paid credit top-up references unknown pack: {pack_id}"
            ))
        })?;
        self.credits
            .grant(GrantCredits {
                account_id: account_id.to_string(),
                credit_type: pack.credit_type.clone(),
                amount: pack.amount,
                source: CreditSource::Purchased,
                expires_at: None,
                idempotency_key: top_up_grant_key(payment_intent_id),
                metadata: serde_json::json!({
                    "stripe_event_id": context.event_id,
                    "stripe_checkout_session_id": checkout_session_id,
                    "stripe_customer_id": customer_id,
                    "stripe_payment_intent_id": payment_intent_id,
                    "credit_pack_id": pack.id,
                }),
            })
            .await?;
        Ok(())
    }

    async fn revoke_top_up(
        &self,
        context: &BillingEventContext,
        payment_intent_id: &str,
        amount: RevocationAmount,
        metadata: serde_json::Value,
    ) -> Result<()> {
        let revocation = self
            .credits
            .revoke(RevokeCredits {
                grant_idempotency_key: top_up_grant_key(payment_intent_id),
                amount,
                idempotency_key: format!("stripe-event:{}", context.event_id),
                metadata,
            })
            .await?;
        match revocation {
            // Not a top-up, or a top-up granted before grants were keyed by PaymentIntent.
            None => tracing::debug!(
                event_id = %context.event_id,
                payment_intent_id,
                "No credit top-up grant matches the refunded or disputed payment"
            ),
            Some(revocation) if revocation.unrecovered_amount > 0 => tracing::warn!(
                event_id = %context.event_id,
                payment_intent_id,
                account_id = %revocation.bucket.account_id,
                credit_type = %revocation.bucket.credit_type,
                unrecovered = revocation.unrecovered_amount,
                "Refunded or disputed credit top-up was partly spent or reserved"
            ),
            Some(_) => {}
        }
        Ok(())
    }
}

fn top_up_grant_key(payment_intent_id: &str) -> String {
    format!("stripe-payment-intent:{payment_intent_id}")
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

    fn context(id: &str) -> BillingEventContext {
        BillingEventContext {
            event_id: id.to_string(),
            created: 1,
        }
    }

    fn checkout(id: &str, status: &str, payment_intent_id: Option<&str>) -> BillingEvent {
        BillingEvent::OneTimeCheckoutCompleted {
            context: context(id),
            checkout_session_id: "cs_1".to_string(),
            customer_id: Some("cus_1".to_string()),
            billable_id: Some("org-1".to_string()),
            billable_type: Some(TOP_UP_BILLABLE_TYPE.to_string()),
            plan_id: Some("sms_100".to_string()),
            payment_status: Some(status.to_string()),
            payment_intent_id: payment_intent_id.map(String::from),
        }
    }

    fn refund(id: &str, payment_intent_id: &str, amount_refunded: u64) -> BillingEvent {
        BillingEvent::ChargeRefunded {
            context: context(id),
            charge_id: "ch_1".to_string(),
            payment_intent_id: Some(payment_intent_id.to_string()),
            customer_id: Some("cus_1".to_string()),
            amount: 1_000,
            amount_refunded,
        }
    }

    fn dispute(id: &str, payment_intent_id: &str) -> BillingEvent {
        BillingEvent::ChargeDisputed {
            context: context(id),
            dispute_id: "dp_1".to_string(),
            charge_id: "ch_1".to_string(),
            payment_intent_id: Some(payment_intent_id.to_string()),
            amount: 1_000,
        }
    }

    async fn available(store: &MemoryCreditStore) -> u64 {
        store
            .balance("org-1", "sms", i64::MAX)
            .await
            .unwrap()
            .available
    }

    fn sink(store: &MemoryCreditStore) -> CreditTopUpEventSink<MemoryCreditStore> {
        CreditTopUpEventSink::new(CreditManager::new(store.clone()), catalog())
    }

    #[tokio::test]
    async fn paid_webhook_grants_once_and_unpaid_does_not_grant() {
        let store = MemoryCreditStore::new();
        let sink = sink(&store);

        sink.handle(&checkout("evt_unpaid", "unpaid", None))
            .await
            .unwrap();
        assert_eq!(available(&store).await, 0);
        // The async success event for the same payment does not grant twice.
        sink.handle(&checkout("evt_paid", "paid", Some("pi_1")))
            .await
            .unwrap();
        sink.handle(&checkout("evt_paid", "paid", Some("pi_1")))
            .await
            .unwrap();
        sink.handle(&checkout("evt_async_paid", "paid", Some("pi_1")))
            .await
            .unwrap();
        assert_eq!(available(&store).await, 100);
        assert_eq!(
            store
                .history("org-1", "sms", CreditHistoryQuery::default())
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn fully_discounted_checkout_grants_no_credits() {
        let store = MemoryCreditStore::new();
        sink(&store)
            .handle(&checkout("evt_free", "no_payment_required", None))
            .await
            .unwrap();
        assert_eq!(available(&store).await, 0);
    }

    #[tokio::test]
    async fn full_refund_revokes_the_top_up() {
        let store = MemoryCreditStore::new();
        let sink = sink(&store);
        sink.handle(&checkout("evt_paid", "paid", Some("pi_1")))
            .await
            .unwrap();

        sink.handle(&refund("evt_refund", "pi_1", 1_000))
            .await
            .unwrap();
        assert_eq!(available(&store).await, 0);
        let history = store
            .history("org-1", "sms", CreditHistoryQuery::default())
            .await
            .unwrap();
        let revoke = history
            .iter()
            .find(|entry| entry.kind == crate::credits::CreditTransactionKind::Revoke)
            .expect("refund is recorded in the ledger");
        assert_eq!(revoke.amount, 100);
    }

    #[tokio::test]
    async fn partial_refunds_revoke_a_cumulative_share_once() {
        let store = MemoryCreditStore::new();
        let sink = sink(&store);
        sink.handle(&checkout("evt_paid", "paid", Some("pi_1")))
            .await
            .unwrap();

        sink.handle(&refund("evt_refund_1", "pi_1", 250))
            .await
            .unwrap();
        assert_eq!(available(&store).await, 75);
        // Replays and out-of-order older totals change nothing.
        sink.handle(&refund("evt_refund_1", "pi_1", 250))
            .await
            .unwrap();
        sink.handle(&refund("evt_refund_old", "pi_1", 100))
            .await
            .unwrap();
        assert_eq!(available(&store).await, 75);
        // A second partial refund carries the cumulative refunded amount.
        sink.handle(&refund("evt_refund_2", "pi_1", 501))
            .await
            .unwrap();
        assert_eq!(available(&store).await, 49);
    }

    #[tokio::test]
    async fn dispute_revokes_the_top_up() {
        let store = MemoryCreditStore::new();
        let sink = sink(&store);
        sink.handle(&checkout("evt_paid", "paid", Some("pi_1")))
            .await
            .unwrap();

        sink.handle(&dispute("evt_dispute", "pi_1")).await.unwrap();
        assert_eq!(available(&store).await, 0);
    }

    #[tokio::test]
    async fn refund_of_another_payment_is_passed_through() {
        let store = MemoryCreditStore::new();
        let sink = sink(&store);
        sink.handle(&checkout("evt_paid", "paid", Some("pi_1")))
            .await
            .unwrap();

        sink.handle(&refund("evt_refund", "pi_other", 1_000))
            .await
            .unwrap();
        sink.handle(&dispute("evt_dispute", "pi_other"))
            .await
            .unwrap();
        assert_eq!(available(&store).await, 100);
    }

    /// A custom store written before `CreditStore::revoke` existed.
    #[derive(Clone, Default)]
    struct LegacyStore(MemoryCreditStore);

    #[async_trait]
    impl CreditStore for LegacyStore {
        async fn grant(
            &self,
            request: &GrantCredits,
            now: i64,
        ) -> Result<crate::credits::CreditBucket> {
            self.0.grant(request, now).await
        }

        async fn reserve(
            &self,
            request: &crate::credits::ReserveCredits,
            reservation_expires_at: i64,
            now: i64,
        ) -> Result<crate::credits::CreditReservation> {
            self.0.reserve(request, reservation_expires_at, now).await
        }

        async fn commit(
            &self,
            account_id: &str,
            reservation_id: &str,
            now: i64,
        ) -> Result<crate::credits::CreditReservation> {
            self.0.commit(account_id, reservation_id, now).await
        }

        async fn release(
            &self,
            account_id: &str,
            reservation_id: &str,
            now: i64,
        ) -> Result<crate::credits::CreditReservation> {
            self.0.release(account_id, reservation_id, now).await
        }

        async fn balance(
            &self,
            account_id: &str,
            credit_type: &str,
            now: i64,
        ) -> Result<crate::credits::CreditBalance> {
            self.0.balance(account_id, credit_type, now).await
        }

        async fn history(
            &self,
            account_id: &str,
            credit_type: &str,
            query: CreditHistoryQuery,
        ) -> Result<Vec<crate::credits::CreditTransaction>> {
            self.0.history(account_id, credit_type, query).await
        }

        async fn release_expired(&self, now: i64, limit: u64) -> Result<u64> {
            self.0.release_expired(now, limit).await
        }
    }

    #[derive(Clone, Default)]
    struct RecordingSink(Arc<Mutex<Vec<String>>>);

    #[async_trait]
    impl BillingEventSink for RecordingSink {
        async fn handle(&self, event: &BillingEvent) -> Result<()> {
            let id = match event {
                BillingEvent::OneTimeCheckoutCompleted { context, .. }
                | BillingEvent::ChargeRefunded { context, .. }
                | BillingEvent::ChargeDisputed { context, .. } => context.event_id.clone(),
                _ => "other".to_string(),
            };
            self.0.lock().unwrap().push(id);
            Ok(())
        }
    }

    #[tokio::test]
    async fn store_without_revoke_does_not_fail_refund_or_dispute_webhooks() {
        let store = LegacyStore::default();
        let next = RecordingSink::default();
        let sink = CreditTopUpEventSink::new(CreditManager::new(store.clone()), catalog())
            .with_next(next.clone());
        sink.handle(&checkout("evt_paid", "paid", Some("pi_1")))
            .await
            .unwrap();

        sink.handle(&refund("evt_refund", "pi_1", 1_000))
            .await
            .unwrap();
        // A refund of an ordinary subscription payment also reaches the store.
        sink.handle(&refund("evt_sub_refund", "pi_subscription", 500))
            .await
            .unwrap();
        sink.handle(&dispute("evt_dispute", "pi_1")).await.unwrap();

        assert_eq!(
            *next.0.lock().unwrap(),
            ["evt_paid", "evt_refund", "evt_sub_refund", "evt_dispute"]
        );
        // The store cannot revoke, so the credits stay.
        assert_eq!(available(&store.0).await, 100);
    }

    #[tokio::test]
    async fn credits_held_at_refund_time_are_not_restored_on_release() {
        let store = MemoryCreditStore::new();
        let manager = CreditManager::new(store.clone());
        let sink = sink(&store);
        sink.handle(&checkout("evt_paid", "paid", Some("pi_1")))
            .await
            .unwrap();
        let spent = manager
            .reserve(crate::credits::ReserveCredits {
                account_id: "org-1".to_string(),
                credit_type: "sms".to_string(),
                amount: 30,
                idempotency_key: "send-1".to_string(),
                order: crate::credits::ConsumptionOrder::AllowanceFirst,
                metadata: serde_json::json!({}),
            })
            .await
            .unwrap();
        let held = manager
            .reserve(crate::credits::ReserveCredits {
                account_id: "org-1".to_string(),
                credit_type: "sms".to_string(),
                amount: 50,
                idempotency_key: "send-2".to_string(),
                order: crate::credits::ConsumptionOrder::AllowanceFirst,
                metadata: serde_json::json!({}),
            })
            .await
            .unwrap();
        manager.commit("org-1", &spent.id).await.unwrap();

        sink.handle(&refund("evt_refund", "pi_1", 1_000))
            .await
            .unwrap();
        assert_eq!(available(&store).await, 0);
        manager.release("org-1", &held.id).await.unwrap();
        assert_eq!(available(&store).await, 0);
    }
}
