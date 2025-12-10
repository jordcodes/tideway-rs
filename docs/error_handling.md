# Error Handling

Tideway provides comprehensive error handling with rich error context, tracking IDs, and development-mode debugging.

## Overview

Tideway's error handling system provides:

- **Unified Error Type**: `TidewayError` for all application errors
- **Error Context**: Additional context, details, and field errors
- **Error Tracking**: Unique error IDs for tracking and debugging
- **Development Mode**: Enhanced error responses with stack traces

## Basic Usage

### Creating Errors

```rust
use tideway::{Result, TidewayError};

async fn get_user(id: u64) -> Result<User> {
    let user = database.find(id)
        .ok_or_else(|| TidewayError::not_found("User not found"))?;

    Ok(user)
}

async fn validate_input(data: &str) -> Result<()> {
    if data.is_empty() {
        return Err(TidewayError::bad_request("Input cannot be empty"));
    }
    Ok(())
}
```

### Error Types

```rust
TidewayError::not_found(msg)           // 404 Not Found
TidewayError::bad_request(msg)         // 400 Bad Request
TidewayError::unauthorized(msg)        // 401 Unauthorized
TidewayError::forbidden(msg)           // 403 Forbidden
TidewayError::internal(msg)            // 500 Internal Server Error
TidewayError::service_unavailable(msg) // 503 Service Unavailable
TidewayError::request_timeout()        // 408 Request Timeout
```

## Enhanced Error Context

### ErrorContext

Add context, details, and field errors to your errors:

```rust
use tideway::{ErrorContext, TidewayError};

let error = TidewayError::bad_request("Validation failed")
    .with_context(
        ErrorContext::new()
            .with_error_id("custom-error-id")
            .with_detail("Additional error details")
            .with_context("user_id", "123")
            .with_context("operation", "create_user")
            .with_field_error("email", "must be a valid email")
            .with_field_error("password", "must be at least 8 characters")
    );
```

### Field Errors

For validation errors, provide field-specific errors:

```rust
use tideway::{ErrorContext, TidewayError};

fn validate_user(user: &User) -> Result<()> {
    let mut context = ErrorContext::new();

    if !is_valid_email(&user.email) {
        context = context.with_field_error("email", "must be a valid email");
    }

    if user.password.len() < 8 {
        context = context.with_field_error("password", "must be at least 8 characters");
    }

    if !context.field_errors.is_empty() {
        return Err(
            TidewayError::bad_request("Validation failed")
                .with_context(context)
        );
    }

    Ok(())
}
```

## Error Responses

### Standard Error Response

All errors automatically return JSON responses:

```json
{
  "error": "Not found: User not found",
  "error_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Enhanced Error Response

With context and field errors:

```json
{
  "error": "Bad request: Validation failed",
  "error_id": "550e8400-e29b-41d4-a716-446655440000",
  "details": "Invalid input data",
  "context": {
    "user_id": "123",
    "operation": "create_user"
  },
  "field_errors": {
    "email": ["must be a valid email"],
    "password": ["must be at least 8 characters"]
  }
}
```

### Development Mode Response

With stack traces (dev mode only):

```json
{
  "error": "Internal server error: Database connection failed",
  "error_id": "550e8400-e29b-41d4-a716-446655440000",
  "details": "Failed to connect to database",
  "stack_trace": "Error: Database connection failed\n  at ..."
}
```

## Error Info

### ErrorInfo

For advanced error handling, use `ErrorInfo`:

```rust
use tideway::{ErrorInfo, ErrorContext, TidewayError};

let error_info = ErrorInfo::new()
    .with_context(
        ErrorContext::new()
            .with_error_id("custom-id")
            .with_detail("Detailed error message")
            .with_field_error("field", "error message")
    )
    .with_stack_trace(format!("{:?}", error));

// Convert error to response with info
let response = error.into_response_with_info(Some(error_info), dev_mode);
```

## Error Propagation

### Using ?

Errors automatically convert to `TidewayError`:

```rust
use tideway::Result;

async fn database_operation() -> Result<User> {
    // SeaORM errors automatically convert
    let user = User::find_by_id(1)
        .one(&db)
        .await?; // Converts DbErr to TidewayError

    Ok(user)
}
```

### Manual Conversion

```rust
use tideway::TidewayError;

fn parse_id(id_str: &str) -> Result<u64> {
    id_str.parse()
        .map_err(|_| TidewayError::bad_request("Invalid ID format"))
}
```

## Development Mode

### Enabling Dev Mode

```rust
use tideway::{ConfigBuilder, DevConfigBuilder};

let config = ConfigBuilder::new()
    .with_dev_config(
        DevConfigBuilder::new()
            .enabled(true)
            .with_stack_traces(true)
            .build()
    )
    .build();
```

### Environment Variables

```bash
TIDEWAY_DEV_MODE=true
TIDEWAY_DEV_STACK_TRACES=true
```

## Best Practices

1. **Specific Errors**: Use the most specific error type
2. **Error Context**: Add context for debugging
3. **Field Errors**: Provide field-specific errors for validation
4. **Error IDs**: Use custom error IDs for tracking
5. **Error Messages**: Provide clear, actionable error messages
6. **Development Mode**: Enable stack traces only in development

## Error Handling Patterns

### Validation Errors

```rust
use tideway::{ErrorContext, TidewayError, Result};

fn validate_user(user: &CreateUserRequest) -> Result<()> {
    let mut context = ErrorContext::new();

    if !is_valid_email(&user.email) {
        context = context.with_field_error("email", "must be a valid email");
    }

    if user.password.len() < 8 {
        context = context.with_field_error("password", "must be at least 8 characters");
    }

    if !context.field_errors.is_empty() {
        return Err(
            TidewayError::bad_request("Validation failed")
                .with_context(context)
        );
    }

    Ok(())
}
```

### Database Errors

```rust
use tideway::Result;

async fn get_user(id: u64) -> Result<User> {
    User::find_by_id(id)
        .one(&db)
        .await?
        .ok_or_else(|| TidewayError::not_found("User not found"))
}
```

### External API Errors

```rust
use tideway::{ErrorContext, TidewayError, Result};

async fn call_external_api() -> Result<Response> {
    let response = reqwest::get("https://api.example.com/data")
        .await
        .map_err(|e| {
            TidewayError::service_unavailable("External API unavailable")
                .with_context(
                    ErrorContext::new()
                        .with_detail(format!("Request failed: {}", e))
                )
        })?;

    // Process response
    Ok(response)
}
```

## See Also

- [Validation Guide](./validation.md)
- [Testing Guide](./testing.md)
- [Development Mode](../examples/dev_mode.rs)
