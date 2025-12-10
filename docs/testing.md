# Testing Guide

Tideway provides comprehensive testing utilities inspired by .NET's Alba framework, making it easy to test HTTP endpoints without running a full server.

## Overview

Tideway's testing utilities provide:

- **Alba-style Testing**: Fluent API for HTTP endpoint testing
- **Test Fixtures**: Factory pattern for creating test data
- **Database Testing**: Isolated database testing with transactions
- **Fake Data**: Helpers for generating test data

## Basic Testing

### Simple GET Request

```rust
use tideway::testing::{get, post};
use axum::{routing::get as axum_get, Router, Json};
use serde_json::json;

async fn hello_handler() -> Json<serde_json::Value> {
    Json(json!({"message": "Hello, World!"}))
}

#[tokio::test]
async fn test_hello() {
    let app = Router::new().route("/hello", axum_get(hello_handler));

    get(app, "/hello")
        .execute()
        .await
        .assert_ok()
        .assert_json_path("message", json!("Hello, World!"));
}
```

### POST Request with JSON

```rust
use tideway::testing::post;

#[tokio::test]
async fn test_create_user() {
    let app = create_app();

    post(app, "/api/users")
        .with_json(&json!({
            "email": "test@example.com",
            "name": "Test User",
        }))
        .execute()
        .await
        .assert_status(201)
        .assert_json_path("data.email", json!("test@example.com"));
}
```

## Assertions

### Status Code Assertions

```rust
response.assert_ok();        // 200 OK
response.assert_status(201); // Specific status code
response.assert_not_found(); // 404 Not Found
response.assert_bad_request(); // 400 Bad Request
```

### JSON Assertions

```rust
response.assert_json(); // Validates JSON response

// Assert specific JSON path
response.assert_json_path("data.id", json!(123));

// Assert response contains text
response.assert_contains("success");
```

### Header Assertions

```rust
response.assert_header("content-type", "application/json");
response.assert_header_exists("x-request-id");
```

## Request Modifiers

### Query Parameters

```rust
get(app, "/api/users")
    .with_query(&[("page", "1"), ("limit", "20")])
    .execute()
    .await
    .assert_ok();
```

### Authentication

```rust
get(app, "/api/protected")
    .with_auth("Bearer token-123")
    .execute()
    .await
    .assert_ok();
```

### Custom Headers

```rust
get(app, "/api/data")
    .with_header("X-Custom-Header", "value")
    .execute()
    .await
    .assert_ok();
```

### Request Body

```rust
post(app, "/api/users")
    .with_json(&user_data)
    .execute()
    .await
    .assert_status(201);

put(app, "/api/users/123")
    .with_json(&update_data)
    .execute()
    .await
    .assert_ok();
```

## Test Fixtures

### TestFactory Trait

Create reusable test data factories:

```rust
use tideway::testing::TestFactory;

struct UserFactory;

impl TestFactory<User> for UserFactory {
    fn build() -> User {
        User {
            id: 0,
            email: tideway::testing::fake::email(),
            name: tideway::testing::fake::name(),
        }
    }

    fn build_with<F>(f: F) -> User
    where
        F: FnOnce(&mut User),
    {
        let mut user = Self::build();
        f(&mut user);
        user
    }
}

#[tokio::test]
async fn test_create_user() {
    let user = UserFactory::build_with(|u| {
        u.email = "custom@example.com".to_string();
    });

    // Use user in test
}
```

### Fake Data Helpers

Generate realistic test data:

```rust
use tideway::testing::fake;

let email = fake::email();           // "user123@example.com"
let uuid = fake::uuid();             // UUID v4
let name = fake::name();             // "John Doe"
let username = fake::username();     // "johndoe123"
let phone = fake::phone();           // "+1234567890"
```

## Database Testing

### TestDb

Test database operations in isolation:

```rust
use tideway::testing::TestDb;

#[tokio::test]
async fn test_user_creation() {
    let db = TestDb::new("sqlite::memory:").await.unwrap();

    // Seed database
    db.seed("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT)")
        .await
        .unwrap();

    // Run migrations if needed
    db.run_migrations(&migrator).await.unwrap();

    // Test in transaction (always rolled back)
    db.with_transaction_rollback(|tx| async move {
        // Your test code here
        // Transaction is automatically rolled back
    }).await.unwrap();

    // Reset database
    db.reset().await.unwrap();
}
```

### Transaction Rollback

Ensure test isolation:

```rust
#[tokio::test]
async fn test_multiple_operations() {
    let db = TestDb::new("sqlite::memory:").await.unwrap();

    db.with_transaction_rollback(|tx| async move {
        // All operations in this block are rolled back
        // Database state is unchanged after test
        create_user(&tx).await;
        update_user(&tx).await;
        delete_user(&tx).await;
    }).await.unwrap();
}
```

## Advanced Testing

### Testing Error Cases

```rust
#[tokio::test]
async fn test_not_found() {
    let app = create_app();

    get(app, "/api/users/999")
        .execute()
        .await
        .assert_not_found()
        .assert_json_path("error", json!("Not found: User not found"));
}
```

### Testing Validation Errors

```rust
#[tokio::test]
async fn test_validation_error() {
    let app = create_app();

    post(app, "/api/users")
        .with_json(&json!({
            "email": "invalid-email", // Invalid email
            "password": "short",       // Too short
        }))
        .execute()
        .await
        .assert_bad_request()
        .assert_json_path("field_errors.email", json!(["must be a valid email"]));
}
```

### Testing Authentication

```rust
#[tokio::test]
async fn test_unauthorized() {
    let app = create_app();

    get(app, "/api/protected")
        .execute()
        .await
        .assert_status(401);
}

#[tokio::test]
async fn test_authorized() {
    let app = create_app();
    let token = create_test_token();

    get(app, "/api/protected")
        .with_auth(&format!("Bearer {}", token))
        .execute()
        .await
        .assert_ok();
}
```

### Debugging Responses

```rust
#[tokio::test]
async fn test_debug_response() {
    let app = create_app();

    let response = get(app, "/api/users")
        .execute()
        .await
        .assert_ok();

    // Dump response for debugging
    response.dump().await;

    // Or get response body as string
    let body = response.text().await;
    println!("Response: {}", body);
}
```

## Best Practices

1. **Isolation**: Use `with_transaction_rollback` for database tests
2. **Fixtures**: Use `TestFactory` for reusable test data
3. **Fake Data**: Use `fake` helpers for realistic test data
4. **Clear Assertions**: Use descriptive assertion methods
5. **Error Testing**: Test both success and error cases
6. **Test Organization**: Group related tests in modules

## Example Test Suite

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tideway::testing::{get, post, TestDb, TestFactory};
    use tideway::testing::fake;

    #[tokio::test]
    async fn test_list_users() {
        let app = create_app();
        let db = setup_test_db().await;

        get(app, "/api/users")
            .execute()
            .await
            .assert_ok()
            .assert_json_path("data", json!([]));
    }

    #[tokio::test]
    async fn test_create_user() {
        let app = create_app();
        let db = setup_test_db().await;

        let user_data = json!({
            "email": fake::email(),
            "name": fake::name(),
        });

        post(app, "/api/users")
            .with_json(&user_data)
            .execute()
            .await
            .assert_status(201)
            .assert_json_path("data.email", user_data["email"]);
    }

    #[tokio::test]
    async fn test_get_user() {
        let app = create_app();
        let db = setup_test_db().await;

        let user = create_test_user(&db).await;

        get(app, &format!("/api/users/{}", user.id))
            .execute()
            .await
            .assert_ok()
            .assert_json_path("data.id", json!(user.id));
    }
}
```

## See Also

- [Testing Examples](../examples/testing_example.rs)
- [Validation Guide](./validation.md)
- [Error Handling Guide](./error_handling.md)
