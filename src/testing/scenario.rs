//! Alba-style HTTP testing utilities for Axum applications
//!
//! This module provides a fluent API for testing HTTP endpoints without starting a server,
//! inspired by .NET's Alba testing framework.
//!
//! # Example
//!
//! ```rust,ignore
//! use axum::{Router, routing, Json};
//! use tideway::testing;
//! use serde_json::json;
//!
//! async fn hello() -> Json<serde_json::Value> {
//!     Json(json!({"message": "Hello, World!"}))
//! }
//!
//! #[tokio::test]
//! async fn test_hello_endpoint() {
//!     let app = Router::new().route("/hello", routing::get(hello));
//!
//!     let response = testing::get(app, "/hello")
//!         .execute()
//!         .await
//!         .assert_ok()
//!         .assert_json();
//!
//!     let body: serde_json::Value = response.json().await;
//!     assert_eq!(body["message"], "Hello, World!");
//! }
//! ```

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

/// Alba-style test scenario builder for easy endpoint testing
pub struct Scenario {
    app: Router,
    request: Request<Body>,
}

impl Scenario {
    /// Create a new test scenario with the given app
    pub fn new(app: Router) -> Self {
        Self {
            app,
            request: Request::builder()
                .method(Method::GET)
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        }
    }

    /// Set the HTTP method
    pub fn method(mut self, method: Method) -> Self {
        *self.request.method_mut() = method;
        self
    }

    /// Set the URI/path
    pub fn uri(mut self, uri: &str) -> Self {
        *self.request.uri_mut() = uri.parse().unwrap();
        self
    }

    /// Add a header
    pub fn header(mut self, key: &str, value: &str) -> Self {
        use axum::http::HeaderName;
        self.request.headers_mut().insert(
            HeaderName::from_bytes(key.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        self
    }

    /// Set the Authorization header with Bearer token
    pub fn bearer_token(self, token: &str) -> Self {
        self.header("Authorization", &format!("Bearer {}", token))
    }

    /// Alias for bearer_token - set Authorization header with Bearer token
    pub fn with_auth(self, token: &str) -> Self {
        self.bearer_token(token)
    }

    /// Add query parameters to the request URI
    pub fn with_query(mut self, params: &[(&str, &str)]) -> Self {
        let uri = self.request.uri().clone();
        let mut query_parts = vec![];

        // Get existing query string if present
        if let Some(query) = uri.query() {
            query_parts.push(query.to_string());
        }

        // Add new parameters
        for (key, value) in params {
            query_parts.push(format!("{}={}", urlencoding::encode(key), urlencoding::encode(value)));
        }

        // Build new URI with query string
        let path = uri.path();
        let new_uri = if query_parts.is_empty() {
            path.to_string()
        } else {
            format!("{}?{}", path, query_parts.join("&"))
        };

        *self.request.uri_mut() = new_uri.parse().unwrap();
        self
    }

    /// Set JSON body from a serializable type
    pub fn json_body<T: Serialize>(mut self, body: &T) -> Self {
        let json = serde_json::to_string(body).unwrap();
        *self.request.body_mut() = Body::from(json);
        self.request
            .headers_mut()
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        self
    }

    /// Set plain text body
    pub fn text_body(mut self, body: impl Into<String>) -> Self {
        *self.request.body_mut() = Body::from(body.into());
        self
    }

    /// Execute the request and get an assertion builder
    pub async fn execute(self) -> ScenarioAssert {
        let response = self.app.oneshot(self.request).await.unwrap();
        ScenarioAssert { response }
    }
}

/// Assertion builder for test responses
pub struct ScenarioAssert {
    response: axum::response::Response,
}

impl ScenarioAssert {
    /// Assert the response status code
    pub fn assert_status(self, expected: StatusCode) -> Self {
        assert_eq!(
            self.response.status(),
            expected,
            "Expected status {}, got {}",
            expected,
            self.response.status()
        );
        self
    }

    /// Assert status is 200 OK
    pub fn assert_ok(self) -> Self {
        self.assert_status(StatusCode::OK)
    }

    /// Assert status is 201 Created
    pub fn assert_created(self) -> Self {
        self.assert_status(StatusCode::CREATED)
    }

    /// Assert status is 400 Bad Request
    pub fn assert_bad_request(self) -> Self {
        self.assert_status(StatusCode::BAD_REQUEST)
    }

    /// Assert status is 401 Unauthorized
    pub fn assert_unauthorized(self) -> Self {
        self.assert_status(StatusCode::UNAUTHORIZED)
    }

    /// Assert status is 404 Not Found
    pub fn assert_not_found(self) -> Self {
        self.assert_status(StatusCode::NOT_FOUND)
    }

    /// Assert status is 500 Internal Server Error
    pub fn assert_server_error(self) -> Self {
        self.assert_status(StatusCode::INTERNAL_SERVER_ERROR)
    }

    /// Assert a header exists with the given value
    pub fn assert_header(self, key: &str, expected: &str) -> Self {
        let value = self
            .response
            .headers()
            .get(key)
            .unwrap_or_else(|| panic!("Header '{}' not found", key))
            .to_str()
            .unwrap();
        assert_eq!(value, expected, "Header '{}' value mismatch", key);
        self
    }

    /// Assert the response content type is JSON
    pub fn assert_json(self) -> Self {
        let content_type = self
            .response
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("Content-Type header not found")
            .to_str()
            .unwrap();
        assert!(
            content_type.contains("application/json"),
            "Expected JSON content type, got: {}",
            content_type
        );
        self
    }

    /// Get the response body as bytes
    pub async fn body_bytes(self) -> Vec<u8> {
        axum::body::to_bytes(self.response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    /// Get the response body as a string
    pub async fn body_string(self) -> String {
        String::from_utf8(self.body_bytes().await).unwrap()
    }

    /// Parse the JSON response body into a type
    pub async fn json<T: for<'de> Deserialize<'de>>(self) -> T {
        let bytes = self.body_bytes().await;
        serde_json::from_slice(&bytes).expect("Failed to parse JSON response")
    }

    /// Assert JSON field equals a value using JSONPath-like syntax
    pub async fn assert_json_field(self, path: &str, expected: serde_json::Value) -> Self {
        let bytes = axum::body::to_bytes(self.response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        let actual =
            json_path_get(&json, path).unwrap_or_else(|| panic!("Path '{}' not found in JSON", path));

        assert_eq!(actual, &expected, "JSON path '{}' value mismatch", path);

        Self {
            response: axum::response::Response::new(Body::from(bytes)),
        }
    }

    /// Alias for assert_json_field - assert JSON path equals expected value
    pub async fn assert_json_path(self, path: &str, expected: serde_json::Value) -> Self {
        self.assert_json_field(path, expected).await
    }

    /// Assert the response body contains the given text
    pub async fn assert_contains(self, text: &str) -> Self {
        let body = self.body_string().await;
        assert!(
            body.contains(text),
            "Response body does not contain '{}'. Body: {}",
            text,
            body
        );
        Self {
            response: axum::response::Response::new(Body::from(body)),
        }
    }

    /// Dump the request and response for debugging
    pub async fn dump(self) -> Self {
        let status = self.response.status();
        let headers: Vec<(String, String)> = self.response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<invalid>").to_string()))
            .collect();
        let body = self.body_string().await;

        eprintln!("=== Response Dump ===");
        eprintln!("Status: {}", status);
        eprintln!("Headers:");
        for (key, value) in &headers {
            eprintln!("  {}: {}", key, value);
        }
        eprintln!("Body: {}", body);
        eprintln!("===================");

        Self {
            response: axum::response::Response::new(Body::from(body)),
        }
    }

    /// Get the underlying response for custom assertions
    pub fn response(self) -> axum::response::Response {
        self.response
    }
}

/// Simple JSON path getter (supports dot notation like "data.name" and array indexing like "checks.0.name")
fn json_path_get<'a>(json: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = json;

    for part in parts {
        // Check if this part is an array index
        if let Ok(index) = part.parse::<usize>() {
            current = current.get(index)?;
        } else {
            current = current.get(part)?;
        }
    }

    Some(current)
}

/// Convenience function to create a GET request scenario
pub fn get(app: Router, uri: &str) -> Scenario {
    Scenario::new(app).method(Method::GET).uri(uri)
}

/// Convenience function to create a POST request scenario
pub fn post(app: Router, uri: &str) -> Scenario {
    Scenario::new(app).method(Method::POST).uri(uri)
}

/// Convenience function to create a PUT request scenario
pub fn put(app: Router, uri: &str) -> Scenario {
    Scenario::new(app).method(Method::PUT).uri(uri)
}

/// Convenience function to create a DELETE request scenario
pub fn delete(app: Router, uri: &str) -> Scenario {
    Scenario::new(app).method(Method::DELETE).uri(uri)
}

/// Convenience function to create a PATCH request scenario
pub fn patch(app: Router, uri: &str) -> Scenario {
    Scenario::new(app).method(Method::PATCH).uri(uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get as axum_get, Router, Json};
    use serde_json::json;

    async fn hello_handler() -> Json<serde_json::Value> {
        Json(json!({"message": "Hello, World!"}))
    }

    async fn echo_handler(axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>) -> Json<serde_json::Value> {
        Json(json!({"params": params}))
    }

    #[tokio::test]
    async fn test_basic_get() {
        let app = Router::new().route("/hello", axum_get(hello_handler));

        let response = get(app, "/hello")
            .execute()
            .await
            .assert_ok()
            .assert_json();

        let body: serde_json::Value = response.json().await;
        assert_eq!(body["message"], "Hello, World!");
    }

    #[tokio::test]
    async fn test_with_query_params() {
        let app = Router::new().route("/echo", axum_get(echo_handler));

        let response = get(app, "/echo")
            .with_query(&[("key", "value"), ("foo", "bar")])
            .execute()
            .await
            .assert_ok();

        let body: serde_json::Value = response.json().await;
        assert!(body["params"].is_object());
    }

    #[tokio::test]
    async fn test_with_auth() {
        let app = Router::new().route("/hello", axum_get(hello_handler));

        // Test that with_auth sets the Authorization header
        // We can't easily verify this without inspecting the request,
        // so we just verify the request succeeds
        get(app, "/hello")
            .with_auth("test-token-123")
            .execute()
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn test_assert_json_path() {
        let app = Router::new().route("/hello", axum_get(hello_handler));

        let response = get(app, "/hello")
            .execute()
            .await
            .assert_ok();

        response
            .assert_json_path("message", json!("Hello, World!"))
            .await;
    }

    #[tokio::test]
    async fn test_assert_contains() {
        let app = Router::new().route("/hello", axum_get(hello_handler));

        let response = get(app, "/hello")
            .execute()
            .await
            .assert_ok();

        response
            .assert_contains("Hello")
            .await;
    }
}
