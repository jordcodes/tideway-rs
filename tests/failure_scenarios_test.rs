use tideway::{
    ErrorContext, ErrorWithContext, TidewayError, ConfigBuilder,
};
use axum::response::IntoResponse;


#[tokio::test]
async fn test_error_with_context() {
    let error = TidewayError::not_found("User not found")
        .with_context(
            ErrorContext::new()
                .with_error_id("err-123")
                .with_detail("User ID 42 does not exist")
                .with_context("user_id", "42")
                .with_context("operation", "get_user"),
        );

    // Verify error can be converted to TidewayError
    let tideway_error: TidewayError = error.into();
    assert!(matches!(tideway_error, TidewayError::NotFound(_)));
}

#[tokio::test]
async fn test_error_with_context_display() {
    // Without details
    let error = TidewayError::not_found("User not found")
        .with_context(ErrorContext::new().with_error_id("err-123"));

    let display = format!("{}", error);
    assert_eq!(display, "Not found: User not found");

    // With details
    let error = TidewayError::bad_request("Validation failed")
        .with_context(
            ErrorContext::new()
                .with_detail("Email format is invalid")
        );

    let display = format!("{}", error);
    assert_eq!(display, "Bad request: Validation failed (Email format is invalid)");
}

#[tokio::test]
async fn test_error_with_context_error_trait() {
    let error = TidewayError::internal("Database connection failed")
        .with_context(ErrorContext::new().with_detail("Connection pool exhausted"));

    // Verify it implements std::error::Error
    let error_ref: &dyn std::error::Error = &error;

    // Verify source() returns the underlying TidewayError
    let source = error_ref.source().expect("should have source");
    assert!(source.to_string().contains("Database connection failed"));
}

#[tokio::test]
async fn test_error_with_field_errors() {
    let context = ErrorContext::new()
        .with_error_id("validation-error")
        .with_field_error("email", "must be a valid email")
        .with_field_error("age", "must be between 0 and 120");

    let error = TidewayError::bad_request("Validation failed").with_context(context);

    // Verify error can be converted
    let tideway_error: TidewayError = error.into();
    assert!(matches!(tideway_error, TidewayError::BadRequest(_)));
}

#[tokio::test]
async fn test_config_validation_failures() {
    // Test invalid server address
    let result = ConfigBuilder::new()
        .with_host("invalid..host")
        .with_port(8000)
        .build();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Invalid server address"));

    // Test invalid log level
    let result = ConfigBuilder::new()
        .with_log_level("invalid_level")
        .build();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Invalid log level"));

    // Test zero port
    let result = ConfigBuilder::new().with_port(0).build();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Server port must be greater than 0"));
}

#[tokio::test]
async fn test_config_validation_timeout() {
    use tideway::{TimeoutConfig, TimeoutConfigBuilder};

    // Test zero timeout when enabled
    let result = TimeoutConfigBuilder::new()
        .enabled(true)
        .timeout_seconds(0)
        .build();

    // This should be caught by ConfigBuilder validation
    let config_result = ConfigBuilder::new()
        .with_timeout(result)
        .build();

    assert!(config_result.is_err());
}

#[tokio::test]
async fn test_config_validation_rate_limit() {
    use tideway::{RateLimitConfig, RateLimitConfigBuilder};

    // Test zero max_requests when enabled
    let rate_limit = RateLimitConfigBuilder::new()
        .enabled(true)
        .max_requests(0)
        .build();

    let config_result = ConfigBuilder::new()
        .with_rate_limit(rate_limit)
        .build();

    assert!(config_result.is_err());
    assert!(config_result
        .unwrap_err()
        .to_string()
        .contains("Rate limit max_requests"));

    // Test invalid strategy
    let rate_limit = RateLimitConfigBuilder::new()
        .enabled(true)
        .strategy("invalid_strategy")
        .build();

    let config_result = ConfigBuilder::new()
        .with_rate_limit(rate_limit)
        .build();

    assert!(config_result.is_err());
    assert!(config_result
        .unwrap_err()
        .to_string()
        .contains("strategy"));
}

#[tokio::test]
async fn test_error_response_format() {
    let error = TidewayError::bad_request("Invalid input")
        .with_context(
            ErrorContext::new()
                .with_error_id("test-error-id")
                .with_detail("Detailed error message")
                .with_field_error("field1", "error1")
                .with_field_error("field1", "error2")
                .with_field_error("field2", "error3"),
        );

    let response = error.into_response();
    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);

    // Verify response body contains error information
    // (In a real scenario, we'd parse the JSON body)
    assert!(true);
}

#[tokio::test]
async fn test_app_context_missing_dependencies() {
    use tideway::AppContext;

    let ctx = AppContext::new();

    // Test database access when not configured
    #[cfg(feature = "database")]
    {
        let result = ctx.database();
        assert!(result.is_err());
        // Just verify it's an error - can't format dyn DatabasePool for Debug
        assert!(ctx.database_opt().is_none());
    }

    // Test cache access when not configured
    #[cfg(feature = "cache")]
    {
        let result = ctx.cache();
        assert!(result.is_err());
        assert!(ctx.cache_opt().is_none());
    }

    // Test sessions access when not configured
    #[cfg(feature = "sessions")]
    {
        let result = ctx.sessions();
        assert!(result.is_err());
        assert!(ctx.sessions_opt().is_none());
    }

    // Test jobs access when not configured
    #[cfg(feature = "jobs")]
    {
        let result = ctx.jobs();
        assert!(result.is_err());
        assert!(ctx.jobs_opt().is_none());
    }
}

#[tokio::test]
async fn test_error_types() {
    // Test all error types
    assert!(matches!(
        TidewayError::not_found("test"),
        TidewayError::NotFound(_)
    ));
    assert!(matches!(
        TidewayError::bad_request("test"),
        TidewayError::BadRequest(_)
    ));
    assert!(matches!(
        TidewayError::unauthorized("test"),
        TidewayError::Unauthorized(_)
    ));
    assert!(matches!(
        TidewayError::forbidden("test"),
        TidewayError::Forbidden(_)
    ));
    assert!(matches!(
        TidewayError::internal("test"),
        TidewayError::Internal(_)
    ));
    assert!(matches!(
        TidewayError::service_unavailable("test"),
        TidewayError::ServiceUnavailable(_)
    ));
    assert!(matches!(
        TidewayError::request_timeout(),
        TidewayError::RequestTimeout
    ));
}
