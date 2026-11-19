use crate::error::{Result, TidewayError};
use axum::{
    Json,
    extract::{Request, rejection::JsonRejection},
    http::StatusCode,
};
use serde::Deserialize;
use std::future::Future;
use validator::Validate;

/// Wrapper for validated JSON data
///
/// Use this as an extractor to automatically validate JSON request bodies.
///
/// # Example
///
/// ```rust,no_run
/// use tideway::validation::ValidatedJson;
/// use validator::Validate;
/// use serde::Deserialize;
///
/// #[derive(Deserialize, Validate)]
/// struct CreateUserRequest {
///     #[validate(email)]
///     email: String,
/// }
///
/// async fn create_user(
///     ValidatedJson(req): ValidatedJson<CreateUserRequest>
/// ) -> tideway::Result<axum::Json<serde_json::Value>> {
///     // req is guaranteed to be valid
///     Ok(axum::Json(serde_json::json!({"status": "ok"})))
/// }
/// ```
pub struct ValidatedJson<T>(pub T);

impl<T, S> axum::extract::FromRequest<S> for ValidatedJson<T>
where
    T: for<'de> Deserialize<'de> + Validate + Send,
    S: Send + Sync,
{
    type Rejection = TidewayError;

    async fn from_request(req: Request, state: &S) -> std::result::Result<Self, Self::Rejection> {
        let json: Json<T> = Json::from_request(req, state)
            .await
            .map_err(json_rejection_error)?;

        json.0.validate().map_err(|errors| {
            let error_messages: Vec<String> = errors
                .field_errors()
                .iter()
                .flat_map(|(field, errors)| {
                    errors.iter().map(move |error| {
                        let msg = error
                            .message
                            .as_ref()
                            .map(|m| m.as_ref())
                            .unwrap_or_else(|| error.code.as_ref());
                        format!("{}: {}", field, msg)
                    })
                })
                .collect();

            TidewayError::bad_request(format!("Validation failed: {}", error_messages.join(", ")))
        })?;

        Ok(ValidatedJson(json.0))
    }
}

/// Convert a JSON extractor rejection, keeping 413 and 415 and leaving serde detail out of
/// the client-facing message.
fn json_rejection_error(rejection: JsonRejection) -> TidewayError {
    match rejection.status() {
        StatusCode::PAYLOAD_TOO_LARGE => {
            TidewayError::payload_too_large("Request body exceeds the size limit")
        }
        StatusCode::UNSUPPORTED_MEDIA_TYPE => {
            TidewayError::unsupported_media_type("Expected `Content-Type: application/json`")
        }
        _ => {
            tracing::debug!(error = %rejection.body_text(), "Rejected invalid JSON body");
            TidewayError::bad_request("Invalid JSON: invalid or unexpected JSON")
        }
    }
}

/// Validate JSON data and return ValidatedJson wrapper
///
/// This function validates the data in a `Json<T>` extractor and returns
/// a `ValidatedJson<T>` wrapper if validation succeeds.
///
/// # Example
///
/// ```rust,no_run
/// use tideway::validation::{validate_json, ValidatedJson};
/// use validator::Validate;
/// use serde::Deserialize;
///
/// #[derive(Deserialize, Validate)]
/// struct CreateUserRequest {
///     #[validate(email)]
///     email: String,
/// }
///
/// async fn create_user(
///     json: axum::Json<CreateUserRequest>
/// ) -> tideway::Result<axum::Json<serde_json::Value>> {
///     let ValidatedJson(req) = validate_json(json)?;
///     Ok(axum::Json(serde_json::json!({"status": "ok"})))
/// }
/// ```
pub fn validate_json<T: Validate>(json: Json<T>) -> Result<ValidatedJson<T>> {
    // Validate the data
    json.0.validate().map_err(|errors| {
        let error_messages: Vec<String> = errors
            .field_errors()
            .iter()
            .flat_map(|(field, errors)| {
                errors.iter().map(move |error| {
                    let msg = error
                        .message
                        .as_ref()
                        .map(|m| m.as_ref())
                        .unwrap_or_else(|| error.code.as_ref());
                    format!("{}: {}", field, msg)
                })
            })
            .collect();

        TidewayError::bad_request(format!("Validation failed: {}", error_messages.join(", ")))
    })?;

    Ok(ValidatedJson(json.0))
}

/// Wrapper for validated query parameters
///
/// Use this as an extractor to automatically validate query parameters.
///
/// # Example
///
/// ```rust,no_run
/// use tideway::validation::ValidatedQuery;
/// use validator::Validate;
/// use serde::Deserialize;
///
/// #[derive(Deserialize, Validate)]
/// struct SearchQuery {
///     #[validate(length(min = 1, max = 100))]
///     q: String,
///     #[validate(range(min = 1, max = 100))]
///     limit: Option<u32>,
/// }
///
/// async fn search(
///     ValidatedQuery(query): ValidatedQuery<SearchQuery>
/// ) -> tideway::Result<axum::Json<serde_json::Value>> {
///     // query is guaranteed to be valid
///     Ok(axum::Json(serde_json::json!({"status": "ok"})))
/// }
/// ```
pub struct ValidatedQuery<T>(pub T);

impl<T, S> axum::extract::FromRequestParts<S> for ValidatedQuery<T>
where
    T: for<'de> Deserialize<'de> + Validate + Send,
    S: Send + Sync,
{
    type Rejection = TidewayError;

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = std::result::Result<Self, Self::Rejection>> + Send {
        Box::pin(async move {
            let query_string = parts.uri.query().unwrap_or("");
            let query: T = serde_urlencoded::from_str(query_string).map_err(|e| {
                TidewayError::bad_request(format!("Invalid query parameters: {}", e))
            })?;

            query.validate().map_err(|errors| {
                let error_messages: Vec<String> = errors
                    .field_errors()
                    .iter()
                    .flat_map(|(field, errors)| {
                        errors.iter().map(move |error| {
                            let msg = error
                                .message
                                .as_ref()
                                .map(|m| m.as_ref())
                                .unwrap_or_else(|| error.code.as_ref());
                            format!("{}: {}", field, msg)
                        })
                    })
                    .collect();

                TidewayError::bad_request(format!(
                    "Validation failed: {}",
                    error_messages.join(", ")
                ))
            })?;

            Ok(ValidatedQuery(query))
        })
    }
}

/// Wrapper for validated form data
///
/// Use this with `validate_form` helper function to get validated form data.
///
/// # Example
///
/// ```rust,no_run
/// use tideway::validation::{validate_form, ValidatedForm};
/// use validator::Validate;
/// use serde::Deserialize;
///
/// #[derive(Deserialize, Validate)]
/// struct CreateUserForm {
///     #[validate(email)]
///     email: String,
///     #[validate(length(min = 8))]
///     password: String,
/// }
///
/// async fn create_user(
///     form: axum::extract::Form<CreateUserForm>
/// ) -> tideway::Result<axum::Json<serde_json::Value>> {
///     let ValidatedForm(data) = validate_form(form)?;
///     // data is guaranteed to be valid
///     Ok(axum::Json(serde_json::json!({"status": "ok"})))
/// }
/// ```
pub struct ValidatedForm<T>(pub T);

/// Validate form data and return ValidatedForm wrapper
///
/// This function validates the data in a `Form<T>` extractor and returns
/// a `ValidatedForm<T>` wrapper if validation succeeds.
///
/// # Example
///
/// ```rust,no_run
/// use tideway::validation::{validate_form, ValidatedForm};
/// use validator::Validate;
/// use serde::Deserialize;
///
/// #[derive(Deserialize, Validate)]
/// struct CreateUserForm {
///     #[validate(email)]
///     email: String,
/// }
///
/// async fn create_user(
///     form: axum::extract::Form<CreateUserForm>
/// ) -> tideway::Result<axum::Json<serde_json::Value>> {
///     let ValidatedForm(data) = validate_form(form)?;
///     Ok(axum::Json(serde_json::json!({"status": "ok"})))
/// }
/// ```
pub fn validate_form<T: Validate>(form: axum::extract::Form<T>) -> Result<ValidatedForm<T>> {
    form.0.validate().map_err(|errors| {
        let error_messages: Vec<String> = errors
            .field_errors()
            .iter()
            .flat_map(|(field, errors)| {
                errors.iter().map(move |error| {
                    let msg = error
                        .message
                        .as_ref()
                        .map(|m| m.as_ref())
                        .unwrap_or_else(|| error.code.as_ref());
                    format!("{}: {}", field, msg)
                })
            })
            .collect();

        TidewayError::bad_request(format!("Validation failed: {}", error_messages.join(", ")))
    })?;

    Ok(ValidatedForm(form.0))
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use validator::Validate;

    #[derive(Deserialize, Validate)]
    struct TestRequest {
        #[validate(email)]
        email: String,
        #[validate(range(min = 18, max = 100))]
        age: u32,
    }

    #[tokio::test]
    async fn test_validated_json_success() {
        // This test would require a full request setup
        // For now, we'll test the validation logic separately
        let valid_request = TestRequest {
            email: "test@example.com".to_string(),
            age: 25,
        };

        assert!(valid_request.validate().is_ok());
    }

    #[test]
    fn test_validation_failure() {
        let invalid_request = TestRequest {
            email: "not-an-email".to_string(),
            age: 15, // Below minimum
        };

        let result = invalid_request.validate();
        assert!(result.is_err());
    }

    async fn post_json(
        body: &str,
        content_type: Option<&str>,
    ) -> axum::http::Response<axum::body::Body> {
        use axum::{Router, extract::DefaultBodyLimit, routing::post};
        use tower::ServiceExt;

        async fn handler(super::ValidatedJson(_req): super::ValidatedJson<TestRequest>) {}

        let app = Router::new()
            .route("/", post(handler))
            .layer(DefaultBodyLimit::max(64));
        let mut request = axum::http::Request::post("/");
        if let Some(content_type) = content_type {
            request = request.header("content-type", content_type);
        }
        app.oneshot(
            request
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn json_rejections_keep_their_status_and_hide_serde_detail() {
        use axum::http::StatusCode;

        let oversized = format!(r#"{{"email":"{}@example.com","age":20}}"#, "a".repeat(100));
        let response = post_json(&oversized, Some("application/json")).await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let response = post_json(r#"{"email":"a@example.com","age":20}"#, None).await;
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let response = post_json(r#"{"email":"a@example.com"}"#, Some("application/json")).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(!body.contains("age"), "{body}");
    }
}
