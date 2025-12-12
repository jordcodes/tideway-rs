use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::collections::HashMap;

/// The main error type for Tideway applications
#[derive(Debug, thiserror::Error)]
pub enum TidewayError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("Request timeout")]
    RequestTimeout,

    #[error("Too many requests: {0}")]
    TooManyRequests(String),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),

    #[cfg(feature = "database")]
    #[error("Database error: {0}")]
    Database(String),
}

/// Error context for additional error information
#[derive(Debug, Clone, Default)]
pub struct ErrorContext {
    /// Unique error ID for tracking
    pub error_id: Option<String>,
    /// Additional error details
    pub details: Option<String>,
    /// Contextual key-value pairs
    pub context: HashMap<String, String>,
    /// Field-specific validation errors
    pub field_errors: HashMap<String, Vec<String>>,
}

impl ErrorContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_error_id(mut self, id: impl Into<String>) -> Self {
        self.error_id = Some(id.into());
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.details = Some(detail.into());
        self
    }

    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    pub fn with_field_error(mut self, field: impl Into<String>, error: impl Into<String>) -> Self {
        self.field_errors
            .entry(field.into())
            .or_default()
            .push(error.into());
        self
    }
}

/// Extended error information for enhanced error responses
#[derive(Debug, Clone, Default)]
pub struct ErrorInfo {
    pub context: ErrorContext,
    pub stack_trace: Option<String>,
}

impl ErrorInfo {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_context(mut self, context: ErrorContext) -> Self {
        self.context = context;
        self
    }

    pub fn with_stack_trace(mut self, stack_trace: impl Into<String>) -> Self {
        self.stack_trace = Some(stack_trace.into());
        self
    }
}

/// Error with attached context
///
/// This type allows attaching context to a TidewayError while still
/// being usable as a TidewayError via `Into` trait.
#[derive(Debug)]
pub struct ErrorWithContext {
    error: TidewayError,
    context: ErrorContext,
}

impl ErrorWithContext {
    /// Create a new error with context
    pub fn new(error: TidewayError, context: ErrorContext) -> Self {
        Self { error, context }
    }

    /// Convert to ErrorInfo for enhanced responses
    pub fn into_error_info(self) -> ErrorInfo {
        ErrorInfo::new().with_context(self.context)
    }

    /// Get a reference to the underlying error
    pub fn error(&self) -> &TidewayError {
        &self.error
    }

    /// Get a reference to the context
    pub fn context(&self) -> &ErrorContext {
        &self.context
    }
}

impl std::fmt::Display for ErrorWithContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)?;
        if let Some(ref details) = self.context.details {
            write!(f, " ({})", details)?;
        }
        Ok(())
    }
}

impl std::error::Error for ErrorWithContext {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl From<ErrorWithContext> for TidewayError {
    fn from(err: ErrorWithContext) -> Self {
        err.error
    }
}

impl IntoResponse for ErrorWithContext {
    fn into_response(self) -> Response {
        let error = self.error;
        let error_info = ErrorInfo::new().with_context(self.context);
        error.into_response_with_info(Some(error_info), false)
    }
}

/// Standard error response format for API errors.
///
/// This is used in OpenAPI documentation for error responses.
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    field_errors: Option<HashMap<String, Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stack_trace: Option<String>,
}

impl TidewayError {
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::Unauthorized(msg.into())
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::Forbidden(msg.into())
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    pub fn service_unavailable(msg: impl Into<String>) -> Self {
        Self::ServiceUnavailable(msg.into())
    }

    pub fn request_timeout() -> Self {
        Self::RequestTimeout
    }

    pub fn too_many_requests(msg: impl Into<String>) -> Self {
        Self::TooManyRequests(msg.into())
    }

    /// Add context to this error, returning an ErrorWithContext
    ///
    /// This allows you to attach context to an error while still being able
    /// to use it as a TidewayError (via `Into` trait) or convert it to a
    /// response with enhanced information.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use tideway::{TidewayError, ErrorContext};
    ///
    /// // In ok_or_else, you can use it directly:
    /// let error: TidewayError = TidewayError::not_found("User not found")
    ///     .with_context(ErrorContext::new()
    ///         .with_error_id("err-123")
    ///         .with_detail("User ID 42 does not exist"))
    ///     .into();
    ///
    /// // Or use ErrorWithContext directly for enhanced responses:
    /// let error_with_ctx = TidewayError::not_found("User not found")
    ///     .with_context(ErrorContext::new()
    ///         .with_error_id("err-123")
    ///         .with_detail("User ID 42 does not exist"));
    /// ```
    pub fn with_context(self, context: ErrorContext) -> ErrorWithContext {
        ErrorWithContext::new(self, context)
    }

    /// Convert error to response with enhanced information
    ///
    /// # Security
    ///
    /// Internal error details are only exposed when `dev_mode` is `true`.
    /// In production (dev_mode=false), internal errors show a generic message
    /// to prevent information disclosure to attackers.
    pub fn into_response_with_info(self, info: Option<ErrorInfo>, dev_mode: bool) -> Response {
        let status = self.status_code();

        // In production, hide internal error details from clients
        // to prevent information disclosure (CWE-209)
        let error_msg = if dev_mode {
            self.to_string()
        } else {
            self.safe_message()
        };

        let mut response = ErrorResponse {
            error: error_msg,
            error_id: None,
            details: None,
            context: None,
            field_errors: None,
            stack_trace: None,
        };

        if let Some(info) = info {
            response.error_id = info.context.error_id;
            response.details = info.context.details;
            if !info.context.context.is_empty() {
                response.context = Some(info.context.context);
            }
            if !info.context.field_errors.is_empty() {
                response.field_errors = Some(info.context.field_errors);
            }
            if dev_mode {
                response.stack_trace = info.stack_trace;
            }
        }

        // Generate error ID if not provided
        let error_id = response.error_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        response.error_id = Some(error_id.clone());

        let body = Json(response);

        // Log full error details server-side (not exposed to clients in production)
        tracing::error!(
            status = status.as_u16(),
            error_id = %error_id,
            error = %self, // Full error message for server logs
            "Request failed"
        );

        (status, body).into_response()
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::Internal(_) | Self::Anyhow(_) => StatusCode::INTERNAL_SERVER_ERROR,
            #[cfg(feature = "database")]
            Self::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
            Self::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
        }
    }

    /// Returns a safe error message suitable for client responses in production.
    ///
    /// For client errors (4xx), returns the actual error message since these
    /// are typically safe and useful for the client.
    ///
    /// For server errors (5xx), returns a generic message to prevent
    /// information disclosure (CWE-209). The actual error details are
    /// logged server-side but not exposed to clients.
    fn safe_message(&self) -> String {
        match self {
            // Client errors - safe to expose (user needs to know what went wrong)
            Self::NotFound(msg) => format!("Not found: {}", msg),
            Self::BadRequest(msg) => format!("Bad request: {}", msg),
            Self::Unauthorized(msg) => format!("Unauthorized: {}", msg),
            Self::Forbidden(msg) => format!("Forbidden: {}", msg),
            Self::TooManyRequests(msg) => format!("Too many requests: {}", msg),
            Self::RequestTimeout => "Request timeout".to_string(),

            // Server errors - hide details in production
            Self::Internal(_) => "Internal server error".to_string(),
            Self::Anyhow(_) => "Internal server error".to_string(),
            Self::ServiceUnavailable(_) => "Service unavailable".to_string(),

            #[cfg(feature = "database")]
            Self::Database(_) => "Database error".to_string(),
        }
    }
}

impl IntoResponse for TidewayError {
    fn into_response(self) -> Response {
        self.into_response_with_info(None, false)
    }
}

/// Result type alias for Tideway handlers
pub type Result<T> = std::result::Result<T, TidewayError>;

// Common error type conversions

impl From<serde_json::Error> for TidewayError {
    fn from(err: serde_json::Error) -> Self {
        // Classify based on error category
        if err.is_data() || err.is_syntax() || err.is_eof() {
            TidewayError::BadRequest(format!("JSON error: {}", err))
        } else {
            // IO errors are internal
            TidewayError::Internal(format!("JSON serialization error: {}", err))
        }
    }
}

impl From<reqwest::Error> for TidewayError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            TidewayError::RequestTimeout
        } else if err.is_connect() {
            TidewayError::ServiceUnavailable(format!("Connection error: {}", err))
        } else if err.is_status() {
            // Map HTTP status codes from upstream services
            if let Some(status) = err.status() {
                match status.as_u16() {
                    401 => TidewayError::Unauthorized("Upstream authentication failed".to_string()),
                    403 => TidewayError::Forbidden("Upstream access denied".to_string()),
                    404 => TidewayError::NotFound("Upstream resource not found".to_string()),
                    429 => TidewayError::TooManyRequests("Upstream rate limit exceeded".to_string()),
                    503 => TidewayError::ServiceUnavailable("Upstream service unavailable".to_string()),
                    _ => TidewayError::Internal(format!("Upstream error: {}", err)),
                }
            } else {
                TidewayError::Internal(format!("HTTP error: {}", err))
            }
        } else {
            TidewayError::Internal(format!("Request error: {}", err))
        }
    }
}

#[cfg(feature = "validation")]
impl From<validator::ValidationErrors> for TidewayError {
    fn from(err: validator::ValidationErrors) -> Self {
        // Build a user-friendly message with field errors
        let field_errors: Vec<String> = err
            .field_errors()
            .iter()
            .map(|(field, errors)| {
                let messages: Vec<&str> = errors
                    .iter()
                    .filter_map(|e| e.message.as_ref().map(|m| m.as_ref()))
                    .collect();
                if messages.is_empty() {
                    format!("{}: invalid", field)
                } else {
                    format!("{}: {}", field, messages.join(", "))
                }
            })
            .collect();

        TidewayError::BadRequest(format!("Validation failed: {}", field_errors.join("; ")))
    }
}

#[cfg(feature = "database")]
impl From<sea_orm::DbErr> for TidewayError {
    fn from(err: sea_orm::DbErr) -> Self {
        match &err {
            sea_orm::DbErr::RecordNotFound(msg) => TidewayError::NotFound(if msg.is_empty() {
                "Record not found".to_string()
            } else {
                msg.clone()
            }),
            sea_orm::DbErr::Query(inner) => {
                TidewayError::Database(format!("Query error: {}", inner))
            }
            sea_orm::DbErr::Exec(inner) => {
                TidewayError::Database(format!("Execution error: {}", inner))
            }
            sea_orm::DbErr::Conn(inner) => {
                TidewayError::Database(format!("Connection error: {}", inner))
            }
            sea_orm::DbErr::Type(inner) => TidewayError::Database(format!("Type error: {}", inner)),
            sea_orm::DbErr::Json(inner) => TidewayError::Database(format!("JSON error: {}", inner)),
            sea_orm::DbErr::Migration(inner) => {
                TidewayError::Database(format!("Migration error: {}", inner))
            }
            _ => TidewayError::Database(format!("Database error: {}", err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============ TidewayError variant creation tests ============

    #[test]
    fn test_not_found_error() {
        let err = TidewayError::not_found("User not found");
        assert!(matches!(err, TidewayError::NotFound(_)));
        assert_eq!(err.to_string(), "Not found: User not found");
        assert_eq!(err.status_code(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_bad_request_error() {
        let err = TidewayError::bad_request("Invalid input");
        assert!(matches!(err, TidewayError::BadRequest(_)));
        assert_eq!(err.to_string(), "Bad request: Invalid input");
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_unauthorized_error() {
        let err = TidewayError::unauthorized("Invalid token");
        assert!(matches!(err, TidewayError::Unauthorized(_)));
        assert_eq!(err.to_string(), "Unauthorized: Invalid token");
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_forbidden_error() {
        let err = TidewayError::forbidden("Access denied");
        assert!(matches!(err, TidewayError::Forbidden(_)));
        assert_eq!(err.to_string(), "Forbidden: Access denied");
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_internal_error() {
        let err = TidewayError::internal("Something went wrong");
        assert!(matches!(err, TidewayError::Internal(_)));
        assert_eq!(err.to_string(), "Internal server error: Something went wrong");
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_service_unavailable_error() {
        let err = TidewayError::service_unavailable("Database is down");
        assert!(matches!(err, TidewayError::ServiceUnavailable(_)));
        assert_eq!(err.to_string(), "Service unavailable: Database is down");
        assert_eq!(err.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_request_timeout_error() {
        let err = TidewayError::request_timeout();
        assert!(matches!(err, TidewayError::RequestTimeout));
        assert_eq!(err.to_string(), "Request timeout");
        assert_eq!(err.status_code(), StatusCode::REQUEST_TIMEOUT);
    }

    #[test]
    fn test_too_many_requests_error() {
        let err = TidewayError::too_many_requests("Rate limit exceeded");
        assert!(matches!(err, TidewayError::TooManyRequests(_)));
        assert_eq!(err.to_string(), "Too many requests: Rate limit exceeded");
        assert_eq!(err.status_code(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_anyhow_error() {
        let anyhow_err = anyhow::anyhow!("Something unexpected");
        let err: TidewayError = anyhow_err.into();
        assert!(matches!(err, TidewayError::Anyhow(_)));
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[cfg(feature = "database")]
    #[test]
    fn test_database_error_status_code() {
        let err = TidewayError::Database("Connection failed".to_string());
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ============ ErrorContext tests ============

    #[test]
    fn test_error_context_new() {
        let ctx = ErrorContext::new();
        assert!(ctx.error_id.is_none());
        assert!(ctx.details.is_none());
        assert!(ctx.context.is_empty());
        assert!(ctx.field_errors.is_empty());
    }

    #[test]
    fn test_error_context_with_error_id() {
        let ctx = ErrorContext::new().with_error_id("err-123");
        assert_eq!(ctx.error_id, Some("err-123".to_string()));
    }

    #[test]
    fn test_error_context_with_detail() {
        let ctx = ErrorContext::new().with_detail("Additional info");
        assert_eq!(ctx.details, Some("Additional info".to_string()));
    }

    #[test]
    fn test_error_context_with_context() {
        let ctx = ErrorContext::new()
            .with_context("user_id", "42")
            .with_context("action", "create");
        assert_eq!(ctx.context.get("user_id"), Some(&"42".to_string()));
        assert_eq!(ctx.context.get("action"), Some(&"create".to_string()));
    }

    #[test]
    fn test_error_context_with_field_error() {
        let ctx = ErrorContext::new()
            .with_field_error("email", "Invalid email format")
            .with_field_error("email", "Email already taken")
            .with_field_error("password", "Too short");

        let email_errors = ctx.field_errors.get("email").unwrap();
        assert_eq!(email_errors.len(), 2);
        assert!(email_errors.contains(&"Invalid email format".to_string()));
        assert!(email_errors.contains(&"Email already taken".to_string()));

        let password_errors = ctx.field_errors.get("password").unwrap();
        assert_eq!(password_errors.len(), 1);
    }

    #[test]
    fn test_error_context_builder_chain() {
        let ctx = ErrorContext::new()
            .with_error_id("err-456")
            .with_detail("User creation failed")
            .with_context("attempt", "3")
            .with_field_error("username", "Already exists");

        assert_eq!(ctx.error_id, Some("err-456".to_string()));
        assert_eq!(ctx.details, Some("User creation failed".to_string()));
        assert_eq!(ctx.context.get("attempt"), Some(&"3".to_string()));
        assert!(ctx.field_errors.contains_key("username"));
    }

    // ============ ErrorInfo tests ============

    #[test]
    fn test_error_info_new() {
        let info = ErrorInfo::new();
        assert!(info.context.error_id.is_none());
        assert!(info.stack_trace.is_none());
    }

    #[test]
    fn test_error_info_with_context() {
        let ctx = ErrorContext::new().with_error_id("test-id");
        let info = ErrorInfo::new().with_context(ctx);
        assert_eq!(info.context.error_id, Some("test-id".to_string()));
    }

    #[test]
    fn test_error_info_with_stack_trace() {
        let info = ErrorInfo::new().with_stack_trace("at line 42\nat line 100");
        assert_eq!(info.stack_trace, Some("at line 42\nat line 100".to_string()));
    }

    // ============ ErrorWithContext tests ============

    #[test]
    fn test_error_with_context_creation() {
        let err = TidewayError::not_found("Resource");
        let ctx = ErrorContext::new().with_detail("ID: 123");
        let with_ctx = ErrorWithContext::new(err, ctx);

        assert!(matches!(with_ctx.error(), TidewayError::NotFound(_)));
        assert_eq!(with_ctx.context().details, Some("ID: 123".to_string()));
    }

    #[test]
    fn test_error_with_context_display() {
        let err = TidewayError::not_found("User");
        let ctx = ErrorContext::new().with_detail("ID 42 not found");
        let with_ctx = ErrorWithContext::new(err, ctx);

        assert_eq!(with_ctx.to_string(), "Not found: User (ID 42 not found)");
    }

    #[test]
    fn test_error_with_context_display_no_detail() {
        let err = TidewayError::not_found("User");
        let ctx = ErrorContext::new();
        let with_ctx = ErrorWithContext::new(err, ctx);

        assert_eq!(with_ctx.to_string(), "Not found: User");
    }

    #[test]
    fn test_error_with_context_into_tideway_error() {
        let err = TidewayError::bad_request("Invalid");
        let ctx = ErrorContext::new().with_detail("test");
        let with_ctx = ErrorWithContext::new(err, ctx);

        let converted: TidewayError = with_ctx.into();
        assert!(matches!(converted, TidewayError::BadRequest(_)));
    }

    #[test]
    fn test_error_with_context_into_error_info() {
        let err = TidewayError::internal("fail");
        let ctx = ErrorContext::new()
            .with_error_id("err-999")
            .with_detail("details here");
        let with_ctx = ErrorWithContext::new(err, ctx);

        let info = with_ctx.into_error_info();
        assert_eq!(info.context.error_id, Some("err-999".to_string()));
        assert_eq!(info.context.details, Some("details here".to_string()));
    }

    #[test]
    fn test_tideway_error_with_context_method() {
        let with_ctx = TidewayError::not_found("Item")
            .with_context(ErrorContext::new()
                .with_error_id("ctx-001")
                .with_detail("Item ID 5"));

        assert!(matches!(with_ctx.error(), TidewayError::NotFound(_)));
        assert_eq!(with_ctx.context().error_id, Some("ctx-001".to_string()));
    }

    // ============ Error response serialization tests ============

    #[test]
    fn test_error_response_serialization_minimal() {
        let response = ErrorResponse {
            error: "Test error".to_string(),
            error_id: Some("id-123".to_string()),
            details: None,
            context: None,
            field_errors: None,
            stack_trace: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"error\":\"Test error\""));
        assert!(json.contains("\"error_id\":\"id-123\""));
        assert!(!json.contains("details"));
        assert!(!json.contains("context"));
        assert!(!json.contains("field_errors"));
        assert!(!json.contains("stack_trace"));
    }

    #[test]
    fn test_error_response_serialization_full() {
        let mut context = HashMap::new();
        context.insert("key".to_string(), "value".to_string());

        let mut field_errors = HashMap::new();
        field_errors.insert("email".to_string(), vec!["invalid".to_string()]);

        let response = ErrorResponse {
            error: "Validation failed".to_string(),
            error_id: Some("id-456".to_string()),
            details: Some("Check your input".to_string()),
            context: Some(context),
            field_errors: Some(field_errors),
            stack_trace: Some("trace here".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"details\":\"Check your input\""));
        assert!(json.contains("\"context\""));
        assert!(json.contains("\"field_errors\""));
        assert!(json.contains("\"stack_trace\":\"trace here\""));
    }

    // ============ From trait implementation tests ============

    #[test]
    fn test_from_serde_json_syntax_error() {
        let result: std::result::Result<serde_json::Value, _> = serde_json::from_str("{ invalid json }");
        let json_err = result.unwrap_err();
        let err: TidewayError = json_err.into();

        assert!(matches!(err, TidewayError::BadRequest(_)));
        assert!(err.to_string().contains("JSON error"));
    }

    #[test]
    fn test_from_serde_json_data_error() {
        #[derive(serde::Deserialize, Debug)]
        struct Test { _value: i32 }

        let result: std::result::Result<Test, _> = serde_json::from_str(r#"{"_value": "not a number"}"#);
        let json_err = result.unwrap_err();
        let err: TidewayError = json_err.into();

        assert!(matches!(err, TidewayError::BadRequest(_)));
    }

    #[test]
    fn test_from_serde_json_eof_error() {
        let result: std::result::Result<serde_json::Value, _> = serde_json::from_str("{");
        let json_err = result.unwrap_err();
        let err: TidewayError = json_err.into();

        assert!(matches!(err, TidewayError::BadRequest(_)));
    }

    // ============ IntoResponse tests ============

    #[tokio::test]
    async fn test_into_response_not_found() {
        let err = TidewayError::not_found("Resource");
        let response = err.into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_into_response_bad_request() {
        let err = TidewayError::bad_request("Invalid");
        let response = err.into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_into_response_unauthorized() {
        let err = TidewayError::unauthorized("No token");
        let response = err.into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_into_response_forbidden() {
        let err = TidewayError::forbidden("Not allowed");
        let response = err.into_response();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_into_response_internal() {
        let err = TidewayError::internal("Oops");
        let response = err.into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_error_with_context_into_response() {
        let with_ctx = TidewayError::not_found("Item")
            .with_context(ErrorContext::new().with_detail("test"));
        let response = with_ctx.into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ============ into_response_with_info tests ============

    #[tokio::test]
    async fn test_into_response_with_info_includes_context() {
        let err = TidewayError::bad_request("Invalid input");
        let info = ErrorInfo::new().with_context(
            ErrorContext::new()
                .with_error_id("custom-id")
                .with_detail("More info")
                .with_context("user", "123")
        );

        let response = err.into_response_with_info(Some(info), false);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["error_id"], "custom-id");
        assert_eq!(json["details"], "More info");
        assert_eq!(json["context"]["user"], "123");
    }

    #[tokio::test]
    async fn test_into_response_with_info_dev_mode_includes_stack_trace() {
        let err = TidewayError::internal("Error");
        let info = ErrorInfo::new()
            .with_context(ErrorContext::new())
            .with_stack_trace("stack trace here");

        let response = err.into_response_with_info(Some(info), true);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["stack_trace"], "stack trace here");
    }

    #[tokio::test]
    async fn test_into_response_with_info_prod_mode_excludes_stack_trace() {
        let err = TidewayError::internal("Error");
        let info = ErrorInfo::new()
            .with_context(ErrorContext::new())
            .with_stack_trace("stack trace here");

        let response = err.into_response_with_info(Some(info), false);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(json.get("stack_trace").is_none());
    }

    #[tokio::test]
    async fn test_into_response_with_info_generates_error_id_if_missing() {
        let err = TidewayError::internal("Error");
        let info = ErrorInfo::new().with_context(ErrorContext::new());

        let response = err.into_response_with_info(Some(info), false);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Should have a UUID-like error_id
        let error_id = json["error_id"].as_str().unwrap();
        assert!(!error_id.is_empty());
        assert!(uuid::Uuid::parse_str(error_id).is_ok());
    }

    #[tokio::test]
    async fn test_into_response_with_info_field_errors() {
        let err = TidewayError::bad_request("Validation failed");
        let info = ErrorInfo::new().with_context(
            ErrorContext::new()
                .with_field_error("email", "Invalid format")
                .with_field_error("password", "Too short")
        );

        let response = err.into_response_with_info(Some(info), false);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(json["field_errors"]["email"].as_array().unwrap().contains(&serde_json::json!("Invalid format")));
        assert!(json["field_errors"]["password"].as_array().unwrap().contains(&serde_json::json!("Too short")));
    }

    #[tokio::test]
    async fn test_into_response_without_info() {
        let err = TidewayError::not_found("Item");
        let response = err.into_response_with_info(None, false);

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["error"], "Not found: Item");
        // Should still generate an error_id
        assert!(json["error_id"].as_str().is_some());
    }

    // ============ safe_message tests (information disclosure prevention) ============

    #[test]
    fn test_safe_message_client_errors_exposed() {
        // Client errors should expose their message (user needs to know what's wrong)
        assert_eq!(
            TidewayError::not_found("User").safe_message(),
            "Not found: User"
        );
        assert_eq!(
            TidewayError::bad_request("Invalid email").safe_message(),
            "Bad request: Invalid email"
        );
        assert_eq!(
            TidewayError::unauthorized("Token expired").safe_message(),
            "Unauthorized: Token expired"
        );
        assert_eq!(
            TidewayError::forbidden("Admin only").safe_message(),
            "Forbidden: Admin only"
        );
        assert_eq!(
            TidewayError::too_many_requests("Rate limit").safe_message(),
            "Too many requests: Rate limit"
        );
        assert_eq!(
            TidewayError::request_timeout().safe_message(),
            "Request timeout"
        );
    }

    #[test]
    fn test_safe_message_server_errors_hidden() {
        // Server errors should hide details in production
        assert_eq!(
            TidewayError::internal("SQL injection detected: SELECT * FROM users").safe_message(),
            "Internal server error"
        );
        assert_eq!(
            TidewayError::internal("Connection to db-prod-01:5432 failed").safe_message(),
            "Internal server error"
        );
        assert_eq!(
            TidewayError::service_unavailable("Redis at cache.internal:6379 unreachable").safe_message(),
            "Service unavailable"
        );

        let anyhow_err = anyhow::anyhow!("Sensitive stack trace info");
        let err: TidewayError = anyhow_err.into();
        assert_eq!(err.safe_message(), "Internal server error");
    }

    #[cfg(feature = "database")]
    #[test]
    fn test_safe_message_database_errors_hidden() {
        let err = TidewayError::Database("Query error: relation \"users\" does not exist".to_string());
        assert_eq!(err.safe_message(), "Database error");
    }

    #[tokio::test]
    async fn test_production_mode_hides_internal_details() {
        let err = TidewayError::internal("Sensitive: db password is 'secret123'");
        let response = err.into_response_with_info(None, false); // dev_mode = false

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Should NOT contain the sensitive details
        assert_eq!(json["error"], "Internal server error");
        assert!(!json["error"].as_str().unwrap().contains("secret123"));
    }

    #[tokio::test]
    async fn test_dev_mode_shows_internal_details() {
        let err = TidewayError::internal("Debug info: connection pool exhausted");
        let response = err.into_response_with_info(None, true); // dev_mode = true

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Should contain the full error in dev mode
        assert!(json["error"].as_str().unwrap().contains("connection pool exhausted"));
    }
}
