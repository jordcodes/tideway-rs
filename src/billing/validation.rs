//! Input validation for billing operations.
//!
//! Provides validation functions for billable IDs, plan data, and other inputs
//! to prevent injection attacks and ensure data integrity.

use crate::error::Result;
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
}
