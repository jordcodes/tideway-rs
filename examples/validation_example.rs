//! Validation Example
//!
//! Demonstrates request validation with ValidatedJson, ValidatedQuery,
//! and custom validators.

#[cfg(not(feature = "validation"))]
fn main() {
    println!("This example requires the 'validation' feature:");
    println!("cargo run --example validation_example --features validation");
}

#[cfg(feature = "validation")]
fn main() {
    println!("Validation example - see tests in the source code");
    println!("Run: cargo test --example validation_example --features validation");
}

#[cfg(feature = "validation")]
#[cfg(test)]
mod tests {
    use axum::{routing::{get as axum_get, post as axum_post}, Router, Json};
    use serde::Deserialize;
    use tideway::{
        testing::{get as test_get, post as test_post},
        validation::{ValidatedJson, ValidatedQuery, validate_uuid, validate_slug},
    };
    use validator::Validate;

    #[derive(Deserialize, Validate)]
    struct CreateUserRequest {
        #[validate(email)]
        email: String,

        #[validate(length(min = 8))]
        password: String,

        #[validate(custom = "validate_uuid")]
        organization_id: String,

        #[validate(custom = "validate_slug")]
        username: String,
    }

    #[derive(Deserialize, Validate)]
    struct SearchQuery {
        #[validate(length(min = 1, max = 100))]
        q: String,

        #[validate(range(min = 1, max = 100))]
        limit: Option<u32>,
    }

    async fn create_user(
        ValidatedJson(req): ValidatedJson<CreateUserRequest>,
    ) -> tideway::Result<Json<serde_json::Value>> {
        Ok(Json(serde_json::json!({
            "status": "created",
            "user": {
                "email": req.email,
                "username": req.username,
            }
        })))
    }

    async fn search(
        ValidatedQuery(query): ValidatedQuery<SearchQuery>,
    ) -> tideway::Result<Json<serde_json::Value>> {
        Ok(Json(serde_json::json!({
            "query": query.q,
            "limit": query.limit.unwrap_or(10),
            "results": []
        })))
    }

    #[tokio::test]
    async fn test_valid_user_creation() {
        let app = Router::new().route("/users", axum_post(create_user));

        test_post(app, "/users")
            .with_json(&serde_json::json!({
                "email": "test@example.com",
                "password": "password123",
                "organization_id": "550e8400-e29b-41d4-a716-446655440000",
                "username": "test-user"
            }))
            .execute()
            .await
            .assert_status(200)
            .assert_json_path("status", serde_json::json!("created"));
    }

    #[tokio::test]
    async fn test_invalid_email() {
        let app = Router::new().route("/users", axum_post(create_user));

        test_post(app, "/users")
            .with_json(&serde_json::json!({
                "email": "invalid-email",
                "password": "password123",
                "organization_id": "550e8400-e29b-41d4-a716-446655440000",
                "username": "test-user"
            }))
            .execute()
            .await
            .assert_bad_request()
            .assert_json_path("field_errors.email", serde_json::json!(["must be a valid email"]));
    }

    #[tokio::test]
    async fn test_invalid_uuid() {
        let app = Router::new().route("/users", axum_post(create_user));

        test_post(app, "/users")
            .with_json(&serde_json::json!({
                "email": "test@example.com",
                "password": "password123",
                "organization_id": "invalid-uuid",
                "username": "test-user"
            }))
            .execute()
            .await
            .assert_bad_request();
    }

    #[tokio::test]
    async fn test_valid_search() {
        use tideway::testing::get as test_get;
        use axum::routing::get as axum_get;

        let app = Router::new().route("/search", axum_get(search));

        let response = test_get(app, "/search")
            .with_query(&[("q", "test"), ("limit", "20")])
            .execute()
            .await
            .assert_ok();

        response.assert_json_path("query", serde_json::json!("test")).await;
        response.assert_json_path("limit", serde_json::json!(20)).await;
    }

    #[tokio::test]
    async fn test_invalid_search_limit() {
        use tideway::testing::get as test_get;
        use axum::routing::get as axum_get;

        let app = Router::new().route("/search", axum_get(search));

        test_get(app, "/search")
            .with_query(&[("q", "test"), ("limit", "200")]) // limit > 100
            .execute()
            .await
            .assert_bad_request();
    }
}
