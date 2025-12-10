use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// Standard JSON response wrapper
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: None,
        }
    }

    pub fn success_with_message(data: T, message: impl Into<String>) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: Some(message.into()),
        }
    }

    pub fn error(message: impl Into<String>) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            message: Some(message.into()),
        }
    }

    /// Create a paginated response
    pub fn paginated(data: T, total: u64, page: u32, per_page: u32) -> ApiResponse<PaginatedData<T>> {
        ApiResponse {
            success: true,
            data: Some(PaginatedData {
                items: data,
                pagination: PaginationMeta {
                    total,
                    page,
                    per_page,
                    total_pages: (total as f64 / per_page as f64).ceil() as u32,
                },
            }),
            message: None,
        }
    }

    /// Create a 201 Created response
    pub fn created(data: T, location: impl Into<String>) -> CreatedResponse<T> {
        CreatedResponse {
            data,
            location: location.into(),
        }
    }

    /// Create a 204 No Content response
    pub fn no_content() -> NoContentResponse {
        NoContentResponse
    }

    /// Create a 202 Accepted response
    pub fn accepted(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: Some("Request accepted for processing".to_string()),
        }
    }
}

/// Paginated data wrapper
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PaginatedData<T: Serialize> {
    pub items: T,
    pub pagination: PaginationMeta,
}

/// Pagination metadata
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PaginationMeta {
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
    pub total_pages: u32,
}

/// 201 Created response
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreatedResponse<T: Serialize> {
    pub data: T,
    pub location: String,
}

impl<T: Serialize> IntoResponse for CreatedResponse<T> {
    fn into_response(self) -> Response {
        let body = Json(self.data);
        let mut response = (StatusCode::CREATED, body).into_response();
        if let Ok(location) = self.location.parse() {
            response.headers_mut().insert(
                axum::http::header::LOCATION,
                location,
            );
        } else {
            tracing::warn!(location = %self.location, "Invalid Location header value in CreatedResponse");
        }
        response
    }
}

/// 204 No Content response
#[derive(Debug, Clone, Copy)]
pub struct NoContentResponse;

impl IntoResponse for NoContentResponse {
    fn into_response(self) -> Response {
        StatusCode::NO_CONTENT.into_response()
    }
}

impl<T: Serialize> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> Response {
        let status = if self.success {
            StatusCode::OK
        } else {
            StatusCode::BAD_REQUEST
        };

        (status, Json(self)).into_response()
    }
}

/// Convenience type alias for JSON responses
pub type JsonResponse<T> = Result<Json<T>, crate::error::TidewayError>;
