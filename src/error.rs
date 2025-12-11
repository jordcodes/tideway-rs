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
    pub fn into_response_with_info(self, info: Option<ErrorInfo>, dev_mode: bool) -> Response {
        let status = self.status_code();
        let error_msg = self.to_string();

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

        tracing::error!(
            status = status.as_u16(),
            error_id = %error_id,
            error = ?self,
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
