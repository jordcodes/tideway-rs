//! Custom validators for common validation patterns
//!
//! These validators extend the `validator` crate with domain-specific
//! validation rules for APIs.

use validator::ValidationError;

/// Validates that a string is a valid UUID v4
///
/// # Example
///
/// ```rust,no_run
/// use tideway::validation::validators::validate_uuid;
/// use validator::Validate;
///
/// #[derive(Validate)]
/// struct Request {
///     #[validate(custom = "validate_uuid")]
///     id: String,
/// }
/// ```
pub fn validate_uuid(id: &str) -> Result<(), ValidationError> {
    uuid::Uuid::parse_str(id)
        .map_err(|_| {
            let mut err = ValidationError::new("uuid");
            err.message = Some(std::borrow::Cow::Borrowed("must be a valid UUID"));
            err
        })?;
    Ok(())
}

/// Validates that a string is a valid slug (lowercase alphanumeric, hyphens, underscores)
///
/// # Example
///
/// ```rust,no_run
/// use tideway::validation::validators::validate_slug;
/// use validator::Validate;
///
/// #[derive(Validate)]
/// struct Request {
///     #[validate(custom = "validate_slug")]
///     slug: String,
/// }
/// ```
pub fn validate_slug(slug: &str) -> Result<(), ValidationError> {
    if slug.is_empty() {
        let mut err = ValidationError::new("slug");
        err.message = Some(std::borrow::Cow::Borrowed("cannot be empty"));
        return Err(err);
    }

    if slug.len() > 100 {
        let mut err = ValidationError::new("slug");
        err.message = Some(std::borrow::Cow::Borrowed("must be 100 characters or less"));
        return Err(err);
    }

    if !slug.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
        let mut err = ValidationError::new("slug");
        err.message = Some(std::borrow::Cow::Borrowed(
            "must contain only lowercase alphanumeric characters, hyphens, and underscores",
        ));
        return Err(err);
    }

    Ok(())
}

/// Validates that a string is a valid phone number (E.164 format recommended)
///
/// # Example
///
/// ```rust,no_run
/// use tideway::validation::validators::validate_phone;
/// use validator::Validate;
///
/// #[derive(Validate)]
/// struct Request {
///     #[validate(custom = "validate_phone")]
///     phone: String,
/// }
/// ```
pub fn validate_phone(phone: &str) -> Result<(), ValidationError> {
    // Remove common formatting characters
    let cleaned: String = phone.chars().filter(|c| !c.is_whitespace() && *c != '-' && *c != '(' && *c != ')').collect();

    // E.164 format: + followed by 1-15 digits
    if cleaned.starts_with('+') {
        let digits: String = cleaned.chars().skip(1).collect();
        if !digits.is_empty() && digits.len() <= 15 && digits.chars().all(|c| c.is_ascii_digit()) {
            return Ok(());
        }
    }

    // Also accept 10-digit US format
    if cleaned.len() == 10 && cleaned.chars().all(|c| c.is_ascii_digit()) {
        return Ok(());
    }

    let mut err = ValidationError::new("phone");
    err.message = Some(std::borrow::Cow::Borrowed(
        "must be a valid phone number (E.164 format: +1234567890 or 10-digit format)",
    ));
    Err(err)
}

/// Validates that a string is valid JSON
///
/// # Example
///
/// ```rust,no_run
/// use tideway::validation::validators::validate_json_string;
/// use validator::Validate;
///
/// #[derive(Validate)]
/// struct Request {
///     #[validate(custom = "validate_json_string")]
///     data: String,
/// }
/// ```
pub fn validate_json_string(json: &str) -> Result<(), ValidationError> {
    serde_json::from_str::<serde_json::Value>(json)
        .map_err(|_| {
            let mut err = ValidationError::new("json");
            err.message = Some(std::borrow::Cow::Borrowed("must be valid JSON"));
            err
        })?;
    Ok(())
}

/// Validates that a string is a valid duration (e.g., "30s", "5m", "1h")
///
/// Accepts formats like: "30s", "5m", "1h", "2d"
///
/// # Example
///
/// ```rust,no_run
/// use tideway::validation::validators::validate_duration;
/// use validator::Validate;
///
/// #[derive(Validate)]
/// struct Request {
///     #[validate(custom = "validate_duration")]
///     timeout: String,
/// }
/// ```
pub fn validate_duration(duration: &str) -> Result<(), ValidationError> {
    if duration.is_empty() {
        let mut err = ValidationError::new("duration");
        err.message = Some(std::borrow::Cow::Borrowed("cannot be empty"));
        return Err(err);
    }

    let Some(suffix) = duration.chars().last() else {
        let mut err = ValidationError::new("duration");
        err.message = Some(std::borrow::Cow::Borrowed("cannot be empty"));
        return Err(err);
    };
    let number: String = duration.chars().take_while(|c| c.is_ascii_digit()).collect();

    if number.is_empty() {
        let mut err = ValidationError::new("duration");
        err.message = Some(std::borrow::Cow::Borrowed("must include a number"));
        return Err(err);
    }

    match suffix {
        's' | 'm' | 'h' | 'd' => {
            // Validate that the number part is valid
            if number.parse::<u64>().is_err() {
                let mut err = ValidationError::new("duration");
                err.message = Some(std::borrow::Cow::Borrowed("invalid number"));
                return Err(err);
            }
            Ok(())
        }
        _ => {
            let mut err = ValidationError::new("duration");
            err.message = Some(std::borrow::Cow::Borrowed(
                "must end with 's' (seconds), 'm' (minutes), 'h' (hours), or 'd' (days)",
            ));
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_uuid() {
        assert!(validate_uuid("550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(validate_uuid("invalid-uuid").is_err());
        assert!(validate_uuid("").is_err());
    }

    #[test]
    fn test_validate_slug() {
        assert!(validate_slug("my-slug").is_ok());
        assert!(validate_slug("my_slug").is_ok());
        assert!(validate_slug("my-slug-123").is_ok());
        assert!(validate_slug("").is_err());
        assert!(validate_slug("My-Slug").is_err()); // uppercase
        assert!(validate_slug("my slug").is_err()); // space
        assert!(validate_slug(&"a".repeat(101)).is_err()); // too long
    }

    #[test]
    fn test_validate_phone() {
        assert!(validate_phone("+1234567890").is_ok());
        assert!(validate_phone("1234567890").is_ok());
        assert!(validate_phone("(123) 456-7890").is_ok());
        assert!(validate_phone("123-456-7890").is_ok());
        assert!(validate_phone("invalid").is_err());
        assert!(validate_phone("").is_err());
    }

    #[test]
    fn test_validate_json_string() {
        assert!(validate_json_string(r#"{"key": "value"}"#).is_ok());
        assert!(validate_json_string(r#"[1, 2, 3]"#).is_ok());
        assert!(validate_json_string("invalid json").is_err());
        assert!(validate_json_string("{invalid}").is_err());
    }

    #[test]
    fn test_validate_duration() {
        assert!(validate_duration("30s").is_ok());
        assert!(validate_duration("5m").is_ok());
        assert!(validate_duration("1h").is_ok());
        assert!(validate_duration("2d").is_ok());
        assert!(validate_duration("").is_err());
        assert!(validate_duration("30").is_err()); // no suffix
        assert!(validate_duration("s").is_err()); // no number
        assert!(validate_duration("30x").is_err()); // invalid suffix
    }
}
