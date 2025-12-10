# Request Validation

Tideway provides comprehensive request validation using the `validator` crate with custom validators and type-safe extractors.

## Overview

Request validation ensures that incoming data meets your application's requirements before it reaches your handlers. Tideway provides:

- **Validated Extractors**: Automatic validation when extracting request data
- **Custom Validators**: Domain-specific validation rules
- **Error Context**: Detailed validation error messages

## Basic Usage

### ValidatedJson

Validate JSON request bodies:

```rust
use tideway::validation::ValidatedJson;
use validator::Validate;
use serde::Deserialize;

#[derive(Deserialize, Validate)]
struct CreateUserRequest {
    #[validate(email)]
    email: String,

    #[validate(length(min = 8))]
    password: String,

    #[validate(range(min = 18, max = 100))]
    age: Option<u32>,
}

async fn create_user(
    ValidatedJson(req): ValidatedJson<CreateUserRequest>
) -> tideway::Result<axum::Json<serde_json::Value>> {
    // req is guaranteed to be valid
    Ok(axum::Json(serde_json::json!({"status": "created"})))
}
```

### ValidatedQuery

Validate query parameters:

```rust
use tideway::validation::ValidatedQuery;
use validator::Validate;
use serde::Deserialize;

#[derive(Deserialize, Validate)]
struct SearchQuery {
    #[validate(length(min = 1, max = 100))]
    q: String,

    #[validate(range(min = 1, max = 100))]
    limit: Option<u32>,

    #[validate(custom = "tideway::validation::validate_uuid")]
    user_id: Option<String>,
}

async fn search(
    ValidatedQuery(query): ValidatedQuery<SearchQuery>
) -> tideway::Result<axum::Json<serde_json::Value>> {
    // query is guaranteed to be valid
    Ok(axum::Json(serde_json::json!({"results": []})))
}
```

### ValidatedForm

Validate form data:

```rust
use tideway::validation::{ValidatedForm, validate_form};
use validator::Validate;
use serde::Deserialize;

#[derive(Deserialize, Validate)]
struct ContactForm {
    #[validate(email)]
    email: String,

    #[validate(length(min = 10, max = 500))]
    message: String,
}

async fn submit_contact(
    form: axum::extract::Form<ContactForm>
) -> tideway::Result<axum::Json<serde_json::Value>> {
    let ValidatedForm(data) = validate_form(form)?;
    // data is guaranteed to be valid
    Ok(axum::Json(serde_json::json!({"status": "sent"})))
}
```

## Custom Validators

Tideway provides several custom validators for common use cases:

### UUID Validation

```rust
use tideway::validation::validate_uuid;

#[derive(Validate)]
struct Request {
    #[validate(custom = "validate_uuid")]
    id: String,
}
```

### Slug Validation

Validates lowercase alphanumeric strings with hyphens and underscores:

```rust
use tideway::validation::validate_slug;

#[derive(Validate)]
struct Request {
    #[validate(custom = "validate_slug")]
    slug: String, // e.g., "my-awesome-slug_123"
}
```

### Phone Validation

Supports E.164 format (+1234567890) and 10-digit US format:

```rust
use tideway::validation::validate_phone;

#[derive(Validate)]
struct Request {
    #[validate(custom = "validate_phone")]
    phone: String, // e.g., "+1234567890" or "1234567890"
}
```

### JSON String Validation

Validates that a string contains valid JSON:

```rust
use tideway::validation::validate_json_string;

#[derive(Validate)]
struct Request {
    #[validate(custom = "validate_json_string")]
    config: String, // Must be valid JSON
}
```

### Duration Validation

Validates duration strings like "30s", "5m", "1h", "2d":

```rust
use tideway::validation::validate_duration;

#[derive(Validate)]
struct Request {
    #[validate(custom = "validate_duration")]
    timeout: String, // e.g., "30s", "5m", "1h", "2d"
}
```

## Built-in Validators

The `validator` crate provides many built-in validators:

```rust
#[derive(Validate)]
struct UserRequest {
    #[validate(email)]
    email: String,

    #[validate(url)]
    website: Option<String>,

    #[validate(length(min = 8, max = 64))]
    password: String,

    #[validate(range(min = 18, max = 100))]
    age: u32,

    #[validate(regex = "PHONE_REGEX")]
    phone: String,

    #[validate(contains = "@example.com")]
    company_email: String,
}
```

## Error Handling

Validation errors automatically return detailed error responses:

```json
{
  "error": "Bad request: Validation failed",
  "error_id": "550e8400-e29b-41d4-a716-446655440000",
  "field_errors": {
    "email": ["must be a valid email"],
    "password": ["must be at least 8 characters"],
    "age": ["must be between 18 and 100"]
  }
}
```

Access field errors in your error handler:

```rust
use tideway::{ErrorContext, TidewayError};

let context = ErrorContext::new()
    .with_field_error("email", "must be a valid email")
    .with_field_error("password", "must be at least 8 characters");

let error = TidewayError::bad_request("Validation failed")
    .with_context(context);
```

## Advanced Usage

### Nested Validation

Validate nested structures:

```rust
#[derive(Deserialize, Validate)]
struct Address {
    #[validate(length(min = 1))]
    street: String,

    #[validate(length(min = 1))]
    city: String,

    #[validate(length(min = 5, max = 10))]
    zip_code: String,
}

#[derive(Deserialize, Validate)]
struct CreateUserRequest {
    #[validate(email)]
    email: String,

    #[validate]
    address: Address, // Nested validation
}
```

### Conditional Validation

Use custom validation logic:

```rust
use validator::ValidationError;

fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    if password.len() < 8 {
        return Err(ValidationError::new("password_strength"));
    }

    if !password.chars().any(|c| c.is_uppercase()) {
        return Err(ValidationError::new("password_strength"));
    }

    Ok(())
}

#[derive(Validate)]
struct Request {
    #[validate(custom = "validate_password_strength")]
    password: String,
}
```

## Best Practices

1. **Validate Early**: Use validated extractors to catch errors before business logic
2. **Custom Validators**: Create domain-specific validators for common patterns
3. **Error Messages**: Provide clear, actionable error messages
4. **Field Errors**: Use field-specific errors for better UX
5. **Nested Structures**: Validate nested data structures for complete type safety

## See Also

- [Validator Crate Documentation](https://docs.rs/validator/)
- [Error Handling Guide](./error_handling.md)
- [Request Handling Examples](../examples/validation_example.rs)
