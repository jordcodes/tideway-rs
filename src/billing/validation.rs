//! Input validation for billing operations.
//!
//! Provides validation functions for billable IDs and other inputs
//! to prevent injection attacks and ensure data integrity.

use crate::error::Result;
use super::error::BillingError;

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
}
