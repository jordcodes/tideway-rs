//! Input validation for billing operations.
//!
//! Provides validation functions for billable IDs, plan data, and other inputs
//! to prevent injection attacks and ensure data integrity.
//!
//! # Stripe Price Validation
//!
//! For production deployments, validate that Stripe price IDs exist before creating plans:
//!
//! ```rust,ignore
//! use tideway::billing::{validate_plan_with_stripe, StripePriceValidator, LiveStripeClient};
//!
//! let client = LiveStripeClient::new(config)?;
//! let plan = StoredPlan::new("starter", "price_abc123");
//!
//! // Validates format AND checks price exists in Stripe
//! validate_plan_with_stripe(&plan, &client).await?;
//! ```

use crate::error::Result;
use async_trait::async_trait;
use super::error::BillingError;
use super::storage::StoredPlan;

/// Maximum length for billable IDs.
const MAX_BILLABLE_ID_LENGTH: usize = 256;

/// Maximum length for plan IDs.
const MAX_PLAN_ID_LENGTH: usize = 64;

/// Validate a billable entity ID.
///
/// Billable IDs must:
/// - Not be empty
/// - Not exceed 256 characters
/// - Contain only alphanumeric characters, underscores, and hyphens
///
/// # Errors
///
/// Returns `BillingError::InvalidBillableId` if validation fails.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::billing::validation::validate_billable_id;
///
/// validate_billable_id("org_123")?;  // Ok
/// validate_billable_id("")?;         // Err - empty
/// validate_billable_id("org<script>")? // Err - invalid chars
/// ```
pub fn validate_billable_id(id: &str) -> Result<()> {
    if id.is_empty() {
        return Err(BillingError::InvalidBillableId {
            id: id.to_string(),
            reason: "billable_id cannot be empty".to_string(),
        }.into());
    }

    if id.len() > MAX_BILLABLE_ID_LENGTH {
        return Err(BillingError::InvalidBillableId {
            id: truncate_for_error(id),
            reason: format!("billable_id exceeds maximum length of {}", MAX_BILLABLE_ID_LENGTH),
        }.into());
    }

    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err(BillingError::InvalidBillableId {
            id: sanitize_for_error(id),
            reason: "billable_id contains invalid characters (only alphanumeric, underscore, and hyphen allowed)".to_string(),
        }.into());
    }

    Ok(())
}

/// Validate a plan ID.
///
/// Plan IDs must:
/// - Not be empty
/// - Not exceed 64 characters
/// - Contain only alphanumeric characters, underscores, and hyphens
///
/// # Errors
///
/// Returns `BillingError::InvalidPlanId` if validation fails.
pub fn validate_plan_id(id: &str) -> Result<()> {
    if id.is_empty() {
        return Err(BillingError::InvalidPlanId {
            id: id.to_string(),
            reason: "plan_id cannot be empty".to_string(),
        }.into());
    }

    if id.len() > MAX_PLAN_ID_LENGTH {
        return Err(BillingError::InvalidPlanId {
            id: truncate_for_error(id),
            reason: format!("plan_id exceeds maximum length of {}", MAX_PLAN_ID_LENGTH),
        }.into());
    }

    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err(BillingError::InvalidPlanId {
            id: sanitize_for_error(id),
            reason: "plan_id contains invalid characters".to_string(),
        }.into());
    }

    Ok(())
}

/// Valid ISO 4217 currency codes (lowercase).
const VALID_CURRENCIES: &[&str] = &[
    "usd", "eur", "gbp", "cad", "aud", "jpy", "chf", "sek", "nok", "dkk",
    "nzd", "sgd", "hkd", "inr", "brl", "mxn", "pln", "czk", "huf", "ron",
];

/// Maximum length for plan name.
const MAX_PLAN_NAME_LENGTH: usize = 128;

/// Maximum length for plan description.
const MAX_PLAN_DESCRIPTION_LENGTH: usize = 1024;

/// Maximum length for Stripe price ID.
const MAX_STRIPE_PRICE_ID_LENGTH: usize = 256;

/// Validate a complete StoredPlan.
///
/// Validates all fields including:
/// - Plan ID format
/// - Name length
/// - Description length
/// - Stripe price ID format
/// - Price (non-negative)
/// - Currency (valid ISO code)
/// - Included seats (at least 1)
///
/// # Errors
///
/// Returns `BillingError::InvalidPlanId` with details if validation fails.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::billing::{validate_plan, StoredPlan};
///
/// let plan = StoredPlan::new("starter", "price_abc123");
/// validate_plan(&plan)?;
/// ```
pub fn validate_plan(plan: &StoredPlan) -> Result<()> {
    // Validate plan ID
    validate_plan_id(&plan.id)?;

    // Validate name
    if plan.name.is_empty() {
        return Err(BillingError::InvalidPlanId {
            id: plan.id.clone(),
            reason: "plan name cannot be empty".to_string(),
        }.into());
    }

    if plan.name.len() > MAX_PLAN_NAME_LENGTH {
        return Err(BillingError::InvalidPlanId {
            id: plan.id.clone(),
            reason: format!("plan name exceeds maximum length of {}", MAX_PLAN_NAME_LENGTH),
        }.into());
    }

    // Validate description length
    if let Some(ref desc) = plan.description {
        if desc.len() > MAX_PLAN_DESCRIPTION_LENGTH {
            return Err(BillingError::InvalidPlanId {
                id: plan.id.clone(),
                reason: format!("plan description exceeds maximum length of {}", MAX_PLAN_DESCRIPTION_LENGTH),
            }.into());
        }
    }

    // Validate Stripe price ID
    validate_stripe_price_id(&plan.stripe_price_id, &plan.id)?;

    // Validate seat price ID if present
    if let Some(ref seat_price_id) = plan.stripe_seat_price_id {
        validate_stripe_price_id(seat_price_id, &plan.id)?;
    }

    // Validate price (non-negative)
    if plan.price_cents < 0 {
        return Err(BillingError::InvalidPlanId {
            id: plan.id.clone(),
            reason: "price_cents cannot be negative".to_string(),
        }.into());
    }

    // Validate currency
    let currency_lower = plan.currency.to_lowercase();
    if !VALID_CURRENCIES.contains(&currency_lower.as_str()) {
        return Err(BillingError::InvalidPlanId {
            id: plan.id.clone(),
            reason: format!("invalid currency '{}', must be a valid ISO 4217 code", plan.currency),
        }.into());
    }

    // Validate included seats
    if plan.included_seats == 0 {
        return Err(BillingError::InvalidPlanId {
            id: plan.id.clone(),
            reason: "included_seats must be at least 1".to_string(),
        }.into());
    }

    Ok(())
}

/// Validate a Stripe price ID.
fn validate_stripe_price_id(price_id: &str, plan_id: &str) -> Result<()> {
    if price_id.is_empty() {
        return Err(BillingError::InvalidPlanId {
            id: plan_id.to_string(),
            reason: "stripe_price_id cannot be empty".to_string(),
        }.into());
    }

    if price_id.len() > MAX_STRIPE_PRICE_ID_LENGTH {
        return Err(BillingError::InvalidPlanId {
            id: plan_id.to_string(),
            reason: format!("stripe_price_id exceeds maximum length of {}", MAX_STRIPE_PRICE_ID_LENGTH),
        }.into());
    }

    // Stripe price IDs should start with "price_"
    if !price_id.starts_with("price_") {
        return Err(BillingError::InvalidPlanId {
            id: plan_id.to_string(),
            reason: "stripe_price_id should start with 'price_'".to_string(),
        }.into());
    }

    Ok(())
}

/// Truncate a string for error messages to prevent log flooding.
fn truncate_for_error(s: &str) -> String {
    if s.len() <= 50 {
        s.to_string()
    } else {
        format!("{}...", &s[..47])
    }
}

/// Sanitize a string for error messages to prevent log injection.
fn sanitize_for_error(s: &str) -> String {
    let sanitized: String = s
        .chars()
        .take(50)
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '?' })
        .collect();

    if s.len() > 50 {
        format!("{}...", sanitized)
    } else {
        sanitized
    }
}

// =============================================================================
// Stripe Price Validation
// =============================================================================

/// Information about a Stripe price.
///
/// Represents the response from Stripe's price API.
#[derive(Debug, Clone)]
pub struct StripePrice {
    /// The Stripe price ID.
    pub id: String,
    /// Whether the price is active.
    pub active: bool,
    /// The currency of the price (lowercase ISO code).
    pub currency: String,
    /// Price amount in the smallest currency unit (e.g., cents).
    pub unit_amount: Option<i64>,
    /// Billing interval (e.g., "month", "year").
    pub interval: Option<String>,
    /// The product this price belongs to.
    pub product_id: String,
}

/// Trait for validating Stripe prices.
///
/// Implement this trait to enable price validation against your Stripe account.
/// The live client implementation will make API calls to Stripe.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::billing::{StripePriceValidator, StripePrice};
///
/// struct MyStripeClient { /* ... */ }
///
/// #[async_trait]
/// impl StripePriceValidator for MyStripeClient {
///     async fn get_price(&self, price_id: &str) -> Result<Option<StripePrice>> {
///         // Call Stripe API to fetch price
///     }
/// }
/// ```
#[async_trait]
pub trait StripePriceValidator: Send + Sync {
    /// Fetch a price from Stripe by ID.
    ///
    /// Returns `None` if the price does not exist.
    /// Returns `Err` if there was an API error.
    async fn get_price(&self, price_id: &str) -> Result<Option<StripePrice>>;
}

/// Validate a plan including Stripe price existence.
///
/// This performs all the validations from `validate_plan`, plus:
/// - Verifies the base Stripe price ID exists and is active
/// - Verifies the seat Stripe price ID exists and is active (if configured)
/// - Validates currency matches the Stripe price currency
///
/// Use this for production deployments to ensure prices are correctly configured.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::billing::{validate_plan_with_stripe, StoredPlan, LiveStripeClient};
///
/// let client = LiveStripeClient::new(config)?;
/// let plan = StoredPlan::new("starter", "price_abc123");
/// plan.name = "Starter Plan".to_string();
/// plan.price_cents = 999;
/// plan.currency = "usd".to_string();
///
/// validate_plan_with_stripe(&plan, &client).await?;
/// ```
pub async fn validate_plan_with_stripe<V: StripePriceValidator>(
    plan: &StoredPlan,
    validator: &V,
) -> Result<()> {
    // First, run all local validations
    validate_plan(plan)?;

    // Validate base price exists in Stripe
    let price = validator.get_price(&plan.stripe_price_id).await?;
    match price {
        None => {
            return Err(BillingError::InvalidStripePrice {
                price_id: plan.stripe_price_id.clone(),
                reason: "price does not exist in Stripe".to_string(),
            }.into());
        }
        Some(stripe_price) => {
            // Check price is active
            if !stripe_price.active {
                return Err(BillingError::InvalidStripePrice {
                    price_id: plan.stripe_price_id.clone(),
                    reason: "price is not active in Stripe".to_string(),
                }.into());
            }

            // Validate currency matches
            if stripe_price.currency.to_lowercase() != plan.currency.to_lowercase() {
                return Err(BillingError::InvalidStripePrice {
                    price_id: plan.stripe_price_id.clone(),
                    reason: format!(
                        "currency mismatch: plan has '{}' but Stripe price has '{}'",
                        plan.currency, stripe_price.currency
                    ),
                }.into());
            }
        }
    }

    // Validate seat price if configured
    if let Some(ref seat_price_id) = plan.stripe_seat_price_id {
        let seat_price = validator.get_price(seat_price_id).await?;
        match seat_price {
            None => {
                return Err(BillingError::InvalidStripePrice {
                    price_id: seat_price_id.clone(),
                    reason: "seat price does not exist in Stripe".to_string(),
                }.into());
            }
            Some(stripe_price) => {
                if !stripe_price.active {
                    return Err(BillingError::InvalidStripePrice {
                        price_id: seat_price_id.clone(),
                        reason: "seat price is not active in Stripe".to_string(),
                    }.into());
                }

                // Seat price should use the same currency
                if stripe_price.currency.to_lowercase() != plan.currency.to_lowercase() {
                    return Err(BillingError::InvalidStripePrice {
                        price_id: seat_price_id.clone(),
                        reason: format!(
                            "seat price currency mismatch: plan has '{}' but Stripe price has '{}'",
                            plan.currency, stripe_price.currency
                        ),
                    }.into());
                }
            }
        }
    }

    Ok(())
}

/// Mock price validator for testing.
///
/// Returns pre-configured prices for testing purposes.
#[cfg(any(test, feature = "test-billing"))]
pub mod test {
    use super::*;
    use std::collections::HashMap;
    use std::sync::RwLock;

    /// Mock implementation of StripePriceValidator for testing.
    #[derive(Default)]
    pub struct MockPriceValidator {
        prices: RwLock<HashMap<String, StripePrice>>,
    }

    impl MockPriceValidator {
        /// Create a new mock validator.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Add a price to the mock.
        pub fn add_price(&self, price: StripePrice) {
            self.prices.write().unwrap().insert(price.id.clone(), price);
        }

        /// Add a simple active price.
        pub fn add_active_price(&self, price_id: &str, currency: &str, amount: i64) {
            self.add_price(StripePrice {
                id: price_id.to_string(),
                active: true,
                currency: currency.to_string(),
                unit_amount: Some(amount),
                interval: Some("month".to_string()),
                product_id: format!("prod_{}", price_id.replace("price_", "")),
            });
        }
    }

    #[async_trait]
    impl StripePriceValidator for MockPriceValidator {
        async fn get_price(&self, price_id: &str) -> Result<Option<StripePrice>> {
            Ok(self.prices.read().unwrap().get(price_id).cloned())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_billable_id_valid() {
        assert!(validate_billable_id("org_123").is_ok());
        assert!(validate_billable_id("user-456").is_ok());
        assert!(validate_billable_id("ABC123").is_ok());
        assert!(validate_billable_id("a").is_ok());
    }

    #[test]
    fn test_validate_billable_id_empty() {
        let result = validate_billable_id("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_billable_id_too_long() {
        let long_id = "a".repeat(300);
        let result = validate_billable_id(&long_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_billable_id_invalid_chars() {
        assert!(validate_billable_id("org<script>").is_err());
        assert!(validate_billable_id("org 123").is_err());
        assert!(validate_billable_id("org/123").is_err());
        assert!(validate_billable_id("org\n123").is_err());
        assert!(validate_billable_id("org;DROP TABLE").is_err());
    }

    #[test]
    fn test_validate_plan_id_valid() {
        assert!(validate_plan_id("starter").is_ok());
        assert!(validate_plan_id("pro-monthly").is_ok());
        assert!(validate_plan_id("enterprise_annual").is_ok());
    }

    #[test]
    fn test_validate_plan_id_invalid() {
        assert!(validate_plan_id("").is_err());
        assert!(validate_plan_id("plan with spaces").is_err());
        assert!(validate_plan_id(&"a".repeat(100)).is_err());
    }

    #[test]
    fn test_sanitize_for_error() {
        assert_eq!(sanitize_for_error("valid_id"), "valid_id");
        assert_eq!(sanitize_for_error("has<script>chars"), "has?script?chars");

        let long = "a".repeat(100);
        let result = sanitize_for_error(&long);
        assert!(result.ends_with("..."));
        assert!(result.len() <= 53); // 50 chars + "..."
    }

    use super::super::storage::PlanInterval;

    fn make_valid_plan() -> StoredPlan {
        StoredPlan {
            id: "starter".to_string(),
            name: "Starter Plan".to_string(),
            description: Some("A great starter plan".to_string()),
            stripe_price_id: "price_abc123".to_string(),
            stripe_seat_price_id: None,
            price_cents: 999,
            currency: "usd".to_string(),
            interval: PlanInterval::Monthly,
            included_seats: 1,
            features: serde_json::json!({}),
            limits: serde_json::json!({}),
            trial_days: Some(14),
            is_active: true,
            sort_order: 0,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn test_validate_plan_valid() {
        let plan = make_valid_plan();
        assert!(validate_plan(&plan).is_ok());
    }

    #[test]
    fn test_validate_plan_empty_name() {
        let mut plan = make_valid_plan();
        plan.name = "".to_string();
        assert!(validate_plan(&plan).is_err());
    }

    #[test]
    fn test_validate_plan_invalid_id() {
        let mut plan = make_valid_plan();
        plan.id = "plan with spaces".to_string();
        assert!(validate_plan(&plan).is_err());
    }

    #[test]
    fn test_validate_plan_invalid_stripe_price() {
        let mut plan = make_valid_plan();
        plan.stripe_price_id = "invalid".to_string();
        assert!(validate_plan(&plan).is_err());

        plan.stripe_price_id = "".to_string();
        assert!(validate_plan(&plan).is_err());
    }

    #[test]
    fn test_validate_plan_negative_price() {
        let mut plan = make_valid_plan();
        plan.price_cents = -100;
        assert!(validate_plan(&plan).is_err());
    }

    #[test]
    fn test_validate_plan_invalid_currency() {
        let mut plan = make_valid_plan();
        plan.currency = "xyz".to_string();
        assert!(validate_plan(&plan).is_err());
    }

    #[test]
    fn test_validate_plan_zero_seats() {
        let mut plan = make_valid_plan();
        plan.included_seats = 0;
        assert!(validate_plan(&plan).is_err());
    }

    #[test]
    fn test_validate_plan_currencies() {
        let mut plan = make_valid_plan();

        // Test valid currencies
        for currency in &["usd", "EUR", "GBP", "cad", "aud"] {
            plan.currency = currency.to_string();
            assert!(validate_plan(&plan).is_ok(), "Currency {} should be valid", currency);
        }
    }

    // Stripe validation tests
    use super::test::MockPriceValidator;

    #[tokio::test]
    async fn test_validate_plan_with_stripe_success() {
        let validator = MockPriceValidator::new();
        validator.add_active_price("price_abc123", "usd", 999);

        let plan = make_valid_plan();
        assert!(validate_plan_with_stripe(&plan, &validator).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_plan_with_stripe_price_not_found() {
        let validator = MockPriceValidator::new();
        // Don't add any prices

        let plan = make_valid_plan();
        let result = validate_plan_with_stripe(&plan, &validator).await;
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(err_str.contains("does not exist"));
    }

    #[tokio::test]
    async fn test_validate_plan_with_stripe_price_inactive() {
        let validator = MockPriceValidator::new();
        validator.add_price(StripePrice {
            id: "price_abc123".to_string(),
            active: false,
            currency: "usd".to_string(),
            unit_amount: Some(999),
            interval: Some("month".to_string()),
            product_id: "prod_abc123".to_string(),
        });

        let plan = make_valid_plan();
        let result = validate_plan_with_stripe(&plan, &validator).await;
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(err_str.contains("not active"));
    }

    #[tokio::test]
    async fn test_validate_plan_with_stripe_currency_mismatch() {
        let validator = MockPriceValidator::new();
        validator.add_active_price("price_abc123", "eur", 999); // EUR, not USD

        let plan = make_valid_plan(); // uses USD
        let result = validate_plan_with_stripe(&plan, &validator).await;
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(err_str.contains("currency mismatch"));
    }

    #[tokio::test]
    async fn test_validate_plan_with_stripe_seat_price() {
        let validator = MockPriceValidator::new();
        validator.add_active_price("price_abc123", "usd", 999);
        validator.add_active_price("price_seat123", "usd", 500);

        let mut plan = make_valid_plan();
        plan.stripe_seat_price_id = Some("price_seat123".to_string());

        assert!(validate_plan_with_stripe(&plan, &validator).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_plan_with_stripe_seat_price_not_found() {
        let validator = MockPriceValidator::new();
        validator.add_active_price("price_abc123", "usd", 999);
        // Don't add seat price

        let mut plan = make_valid_plan();
        plan.stripe_seat_price_id = Some("price_seat123".to_string());

        let result = validate_plan_with_stripe(&plan, &validator).await;
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(err_str.contains("seat price does not exist"));
    }

    #[tokio::test]
    async fn test_validate_plan_with_stripe_seat_price_currency_mismatch() {
        let validator = MockPriceValidator::new();
        validator.add_active_price("price_abc123", "usd", 999);
        validator.add_active_price("price_seat123", "eur", 500); // Different currency

        let mut plan = make_valid_plan();
        plan.stripe_seat_price_id = Some("price_seat123".to_string());

        let result = validate_plan_with_stripe(&plan, &validator).await;
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(err_str.contains("seat price currency mismatch"));
    }
}
