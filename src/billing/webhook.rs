//! Stripe webhook handling.
//!
//! Handles webhook signature verification, event routing, and subscription state syncing.

use crate::error::Result;
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::error::BillingError;
use super::plans::Plans;
use super::storage::BillingStore;
use super::subscription::{StripeSubscriptionData, SubscriptionManager, SubscriptionMetadata};

/// Webhook handler for Stripe events.
///
/// Handles webhook signature verification, idempotency, and event processing.
///
/// The webhook secret is stored using [`SecretString`] to prevent accidental
/// exposure in logs or debug output.
pub struct WebhookHandler<S: BillingStore> {
    store: S,
    webhook_secret: SecretString,
    plans: Plans,
}

impl<S: BillingStore + Clone> WebhookHandler<S> {
    /// Create a new webhook handler.
    ///
    /// The webhook secret is stored securely and won't be exposed in debug output.
    #[must_use]
    pub fn new(store: S, webhook_secret: impl Into<SecretString>, plans: Plans) -> Self {
        Self {
            store,
            webhook_secret: webhook_secret.into(),
            plans,
        }
    }

    /// Verify the webhook signature and parse the event.
    ///
    /// # Arguments
    /// * `payload` - The raw request body
    /// * `signature` - The `Stripe-Signature` header value
    ///
    /// # Errors
    /// Returns an error if signature verification fails or payload is invalid.
    pub fn verify_signature(&self, payload: &[u8], signature: &str) -> Result<WebhookEvent> {
        // Parse the signature header
        let sig_parts = parse_signature_header(signature)?;

        // Check timestamp is recent (within 5 minutes)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0) as i64;

        let timestamp_diff = (now - sig_parts.timestamp).abs();
        if timestamp_diff > 300 {
            return Err(crate::error::TidewayError::BadRequest(
                "Webhook timestamp too old".to_string()
            ));
        }

        // Compute expected signature
        let signed_payload = format!("{}.{}", sig_parts.timestamp, String::from_utf8_lossy(payload));
        let expected_sig = compute_signature(self.webhook_secret.expose_secret(), signed_payload.as_bytes())?;

        // Verify signature matches (constant-time comparison)
        let expected_bytes = hex::decode(&expected_sig)
            .map_err(|_| crate::error::TidewayError::Internal("Hex decode error".to_string()))?;
        let provided_bytes = hex::decode(&sig_parts.signature)
            .map_err(|_| crate::error::TidewayError::BadRequest("Invalid signature format".to_string()))?;

        if expected_bytes.ct_eq(&provided_bytes).unwrap_u8() != 1 {
            return Err(crate::error::TidewayError::BadRequest(
                "Invalid webhook signature".to_string()
            ));
        }

        // Parse the JSON payload
        // Log detailed error internally but return generic message to prevent information leakage
        let event: WebhookEvent = serde_json::from_slice(payload)
            .map_err(|e| {
                tracing::warn!(
                    target: "tideway::billing::webhook",
                    error = %e,
                    "Failed to parse webhook payload"
                );
                BillingError::InvalidWebhookPayload {
                    message: "malformed JSON payload".to_string(),
                }
            })?;

        Ok(event)
    }

    /// Process a verified webhook event.
    ///
    /// This method handles idempotency and routes to the appropriate handler.
    pub async fn handle_event(&self, event: WebhookEvent) -> Result<WebhookOutcome> {
        // Check idempotency
        if self.store.is_event_processed(&event.id).await? {
            return Ok(WebhookOutcome::AlreadyProcessed);
        }

        // Route to handler
        let outcome = match event.event_type.as_str() {
            "checkout.session.completed" => self.handle_checkout_completed(&event).await?,
            "customer.subscription.created" | "customer.subscription.updated" => {
                self.handle_subscription_updated(&event).await?
            }
            "customer.subscription.deleted" => self.handle_subscription_deleted(&event).await?,
            "invoice.paid" => self.handle_invoice_paid(&event).await?,
            "invoice.payment_failed" => self.handle_payment_failed(&event).await?,
            _ => WebhookOutcome::Ignored,
        };

        // Mark as processed (only for non-ignored events)
        if !matches!(outcome, WebhookOutcome::Ignored) {
            self.store.mark_event_processed(&event.id).await?;
        }

        Ok(outcome)
    }

    /// Handle checkout.session.completed event.
    async fn handle_checkout_completed(&self, event: &WebhookEvent) -> Result<WebhookOutcome> {
        // Extract subscription data from checkout session
        let session = event.data.object.as_object()
            .ok_or_else(|| crate::error::TidewayError::BadRequest("Invalid event data".to_string()))?;

        // Get subscription ID from the completed checkout
        let subscription_id = session.get("subscription")
            .and_then(|v| v.as_str());

        if subscription_id.is_none() {
            // Not a subscription checkout (maybe one-time payment)
            return Ok(WebhookOutcome::Ignored);
        }

        // The subscription.created webhook will handle syncing the actual subscription
        Ok(WebhookOutcome::Processed)
    }

    /// Handle subscription created/updated events.
    async fn handle_subscription_updated(&self, event: &WebhookEvent) -> Result<WebhookOutcome> {
        let sub_data = self.parse_subscription_data(&event.data.object)?;

        // Update local state
        let sub_manager = SubscriptionManager::new(
            self.store.clone(),
            NullSubscriptionClient,
            self.plans.clone(),
        );
        sub_manager.sync_from_stripe(sub_data).await?;

        Ok(WebhookOutcome::Processed)
    }

    /// Handle subscription deleted event.
    async fn handle_subscription_deleted(&self, event: &WebhookEvent) -> Result<WebhookOutcome> {
        let subscription_id = event.data.object.get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::error::TidewayError::BadRequest(
                "Missing subscription ID".to_string()
            ))?;

        let sub_manager = SubscriptionManager::new(
            self.store.clone(),
            NullSubscriptionClient,
            self.plans.clone(),
        );
        sub_manager.delete_subscription(subscription_id).await?;

        Ok(WebhookOutcome::Processed)
    }

    /// Handle invoice.paid event.
    async fn handle_invoice_paid(&self, event: &WebhookEvent) -> Result<WebhookOutcome> {
        // Invoice paid - subscription period updated
        // The subscription.updated webhook will handle the actual update
        // This is mainly for triggering any custom logic on successful payment

        let _subscription_id = event.data.object.get("subscription")
            .and_then(|v| v.as_str());

        // Could emit custom event here for app-specific logic
        Ok(WebhookOutcome::Processed)
    }

    /// Handle invoice.payment_failed event.
    async fn handle_payment_failed(&self, event: &WebhookEvent) -> Result<WebhookOutcome> {
        // Payment failed - the subscription.updated webhook will mark it past_due
        // This is mainly for triggering notifications

        let _subscription_id = event.data.object.get("subscription")
            .and_then(|v| v.as_str());

        // Could emit custom event here for app-specific notification logic
        Ok(WebhookOutcome::Processed)
    }

    /// Parse subscription data from Stripe webhook payload.
    fn parse_subscription_data(&self, object: &serde_json::Value) -> Result<StripeSubscriptionData> {
        let obj = object.as_object()
            .ok_or_else(|| crate::error::TidewayError::BadRequest("Invalid subscription data".to_string()))?;

        let id = obj.get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::error::TidewayError::BadRequest("Missing subscription ID".to_string()))?
            .to_string();

        let customer_id = obj.get("customer")
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::error::TidewayError::BadRequest("Missing customer ID".to_string()))?
            .to_string();

        let status = obj.get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("active")
            .to_string();

        let current_period_start = obj.get("current_period_start")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let current_period_end = obj.get("current_period_end")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let trial_end = obj.get("trial_end")
            .and_then(|v| v.as_u64());

        let cancel_at_period_end = obj.get("cancel_at_period_end")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Parse items to get plan and seat info
        let (plan_id, base_item_id, seat_item_id, extra_seats) = self.parse_subscription_items(obj)?;

        // Get metadata
        let metadata = obj.get("metadata")
            .and_then(|v| v.as_object())
            .map(|m| SubscriptionMetadata {
                billable_id: m.get("billable_id").and_then(|v| v.as_str()).map(String::from),
                billable_type: m.get("billable_type").and_then(|v| v.as_str()).map(String::from),
            })
            .unwrap_or_default();

        Ok(StripeSubscriptionData {
            id,
            customer_id,
            plan_id,
            status,
            current_period_start,
            current_period_end,
            extra_seats,
            trial_end,
            cancel_at_period_end,
            base_item_id,
            seat_item_id,
            metadata,
        })
    }

    /// Parse subscription items to extract plan and seat information.
    fn parse_subscription_items(&self, obj: &serde_json::Map<String, serde_json::Value>) -> Result<(String, Option<String>, Option<String>, u32)> {
        let items = obj.get("items")
            .and_then(|v| v.get("data"))
            .and_then(|v| v.as_array())
            .ok_or_else(|| crate::error::TidewayError::BadRequest("Missing subscription items".to_string()))?;

        let mut plan_id = String::new();
        let mut base_item_id = None;
        let mut seat_item_id = None;
        let mut extra_seats = 0u32;

        // Get all seat price IDs for lookup
        let seat_prices: std::collections::HashSet<_> = self.plans.iter()
            .filter_map(|(_, p)| p.extra_seat_price_id.clone())
            .collect();

        for item in items {
            let item_obj = item.as_object().ok_or_else(|| {
                crate::error::TidewayError::BadRequest("Invalid item".to_string())
            })?;

            let item_id = item_obj.get("id")
                .and_then(|v| v.as_str())
                .map(String::from);

            let price_id = item_obj.get("price")
                .and_then(|v| v.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let quantity = item_obj.get("quantity")
                .and_then(|v| v.as_u64())
                .unwrap_or(1) as u32;

            // Check if this is a seat item
            if seat_prices.contains(price_id) {
                seat_item_id = item_id;
                extra_seats = quantity;
            } else {
                // This is the base plan
                base_item_id = item_id;

                // Find plan by price ID
                if let Some(plan) = self.plans.find_by_stripe_price(price_id) {
                    plan_id = plan.id.clone();
                }
            }
        }

        if plan_id.is_empty() {
            return Err(crate::error::TidewayError::BadRequest(
                "Could not determine plan from subscription".to_string()
            ));
        }

        Ok((plan_id, base_item_id, seat_item_id, extra_seats))
    }
}

/// Parsed webhook event.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct WebhookEvent {
    /// Event ID.
    pub id: String,
    /// Event type (e.g., "checkout.session.completed").
    #[serde(rename = "type")]
    pub event_type: String,
    /// Event data.
    pub data: WebhookEventData,
    /// Timestamp when the event was created.
    pub created: u64,
}

/// Webhook event data.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct WebhookEventData {
    /// The object that triggered the event.
    pub object: serde_json::Value,
}

/// Outcome of webhook processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookOutcome {
    /// Event was processed successfully.
    Processed,
    /// Event was ignored (not relevant).
    Ignored,
    /// Event was already processed (idempotency).
    AlreadyProcessed,
}

/// Parsed signature header parts.
struct SignatureParts {
    timestamp: i64,
    signature: String,
}

/// Parse the Stripe-Signature header.
fn parse_signature_header(header: &str) -> Result<SignatureParts> {
    let mut timestamp = None;
    let mut signature = None;

    for part in header.split(',') {
        let (key, value) = part.split_once('=')
            .ok_or_else(|| crate::error::TidewayError::BadRequest(
                "Invalid signature header format".to_string()
            ))?;

        match key.trim() {
            "t" => timestamp = value.parse().ok(),
            "v1" => signature = Some(value.to_string()),
            _ => {} // Ignore other versions
        }
    }

    Ok(SignatureParts {
        timestamp: timestamp.ok_or_else(|| crate::error::TidewayError::BadRequest(
            "Missing timestamp in signature".to_string()
        ))?,
        signature: signature.ok_or_else(|| crate::error::TidewayError::BadRequest(
            "Missing v1 signature".to_string()
        ))?,
    })
}

/// Compute HMAC-SHA256 signature.
fn compute_signature(secret: &str, payload: &[u8]) -> Result<String> {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| crate::error::TidewayError::Internal("HMAC error".to_string()))?;

    mac.update(payload);
    let result = mac.finalize();

    Ok(hex::encode(result.into_bytes()))
}

/// Null subscription client for webhook handler (doesn't need to make API calls).
struct NullSubscriptionClient;

impl super::subscription::StripeSubscriptionClient for NullSubscriptionClient {
    async fn cancel_subscription(&self, _subscription_id: &str) -> Result<()> {
        Ok(())
    }

    async fn cancel_subscription_at_period_end(&self, _subscription_id: &str) -> Result<()> {
        Ok(())
    }

    async fn resume_subscription(&self, _subscription_id: &str) -> Result<()> {
        Ok(())
    }

    async fn get_subscription(&self, _subscription_id: &str) -> Result<StripeSubscriptionData> {
        Err(crate::error::TidewayError::Internal("Not implemented".to_string()))
    }

    async fn update_subscription(
        &self,
        _subscription_id: &str,
        _update: super::subscription::UpdateSubscriptionRequest,
    ) -> Result<StripeSubscriptionData> {
        Err(crate::error::TidewayError::Internal("Not implemented".to_string()))
    }

    async fn extend_trial(
        &self,
        _subscription_id: &str,
        _new_trial_end: u64,
    ) -> Result<StripeSubscriptionData> {
        Err(crate::error::TidewayError::Internal("Not implemented".to_string()))
    }

    async fn pause_subscription(&self, _subscription_id: &str) -> Result<()> {
        Ok(())
    }

    async fn resume_paused_subscription(&self, _subscription_id: &str) -> Result<StripeSubscriptionData> {
        Err(crate::error::TidewayError::Internal("Not implemented".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::storage::test::InMemoryBillingStore;
    use crate::billing::Plans;

    fn create_test_plans() -> Plans {
        Plans::builder()
            .plan("starter")
                .stripe_price("price_starter")
                .extra_seat_price("price_seat")
                .included_seats(3)
                .done()
            .build()
    }

    fn create_test_webhook_secret() -> String {
        "whsec_test_secret".to_string()
    }

    fn create_test_signature(secret: &str, payload: &[u8], timestamp: i64) -> String {
        let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(payload));
        let sig = compute_signature(secret, signed_payload.as_bytes()).unwrap();
        format!("t={},v1={}", timestamp, sig)
    }

    #[test]
    fn test_parse_signature_header() {
        let header = "t=1234567890,v1=abc123def456";
        let parts = parse_signature_header(header).unwrap();
        assert_eq!(parts.timestamp, 1234567890);
        assert_eq!(parts.signature, "abc123def456");
    }

    #[test]
    fn test_parse_signature_header_invalid() {
        let result = parse_signature_header("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_signature_valid() {
        let store = InMemoryBillingStore::new();
        let plans = create_test_plans();
        let secret = create_test_webhook_secret();
        let signature_secret = secret.clone();
        let handler = WebhookHandler::new(store, secret, plans);

        let payload = r#"{"id":"evt_123","type":"test","data":{"object":{}},"created":1234567890}"#;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let signature = create_test_signature(&signature_secret, payload.as_bytes(), timestamp);

        let result = handler.verify_signature(payload.as_bytes(), &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_signature_invalid() {
        let store = InMemoryBillingStore::new();
        let plans = create_test_plans();
        let handler = WebhookHandler::new(store, "whsec_test", plans);

        let payload = r#"{"id":"evt_123","type":"test","data":{"object":{}},"created":1234567890}"#;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Wrong signature
        let signature = format!("t={},v1=invalid_signature_hex", timestamp);
        let result = handler.verify_signature(payload.as_bytes(), &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_signature_old_timestamp() {
        let store = InMemoryBillingStore::new();
        let plans = create_test_plans();
        let secret = create_test_webhook_secret();
        let signature_secret = secret.clone();
        let handler = WebhookHandler::new(store, secret, plans);

        let payload = r#"{"id":"evt_123","type":"test","data":{"object":{}},"created":1234567890}"#;
        let old_timestamp = 1000000000i64; // Very old

        let signature = create_test_signature(&signature_secret, payload.as_bytes(), old_timestamp);

        let result = handler.verify_signature(payload.as_bytes(), &signature);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_event_idempotency() {
        let store = InMemoryBillingStore::new();
        let plans = create_test_plans();
        let handler = WebhookHandler::new(store.clone(), "whsec_test", plans);

        let event = WebhookEvent {
            id: "evt_test_123".to_string(),
            event_type: "invoice.paid".to_string(),
            data: WebhookEventData {
                object: serde_json::json!({"subscription": "sub_123"}),
            },
            created: 1234567890,
        };

        // First call processes
        let result = handler.handle_event(event.clone()).await.unwrap();
        assert_eq!(result, WebhookOutcome::Processed);

        // Second call returns already processed
        let result = handler.handle_event(event).await.unwrap();
        assert_eq!(result, WebhookOutcome::AlreadyProcessed);
    }

    #[tokio::test]
    async fn test_handle_event_ignored() {
        let store = InMemoryBillingStore::new();
        let plans = create_test_plans();
        let handler = WebhookHandler::new(store, "whsec_test", plans);

        let event = WebhookEvent {
            id: "evt_unknown".to_string(),
            event_type: "unknown.event.type".to_string(),
            data: WebhookEventData {
                object: serde_json::json!({}),
            },
            created: 1234567890,
        };

        let result = handler.handle_event(event).await.unwrap();
        assert_eq!(result, WebhookOutcome::Ignored);
    }

    #[tokio::test]
    async fn test_handle_subscription_updated() {
        let store = InMemoryBillingStore::new();
        let plans = create_test_plans();
        let handler = WebhookHandler::new(store.clone(), "whsec_test", plans);

        let event = WebhookEvent {
            id: "evt_sub_updated".to_string(),
            event_type: "customer.subscription.updated".to_string(),
            data: WebhookEventData {
                object: serde_json::json!({
                    "id": "sub_123",
                    "customer": "cus_123",
                    "status": "active",
                    "current_period_start": 1700000000u64,
                    "current_period_end": 1702592000u64,
                    "items": {
                        "data": [
                            {
                                "id": "si_base",
                                "price": {"id": "price_starter"},
                                "quantity": 1
                            },
                            {
                                "id": "si_seat",
                                "price": {"id": "price_seat"},
                                "quantity": 2
                            }
                        ]
                    },
                    "metadata": {
                        "billable_id": "org_123",
                        "billable_type": "org"
                    }
                }),
            },
            created: 1234567890,
        };

        let result = handler.handle_event(event).await.unwrap();
        assert_eq!(result, WebhookOutcome::Processed);

        // Verify subscription was stored
        let sub = store.get_subscription("org_123").await.unwrap();
        assert!(sub.is_some());
        let sub = sub.unwrap();
        assert_eq!(sub.plan_id, "starter");
        assert_eq!(sub.extra_seats, 2);
    }
}
