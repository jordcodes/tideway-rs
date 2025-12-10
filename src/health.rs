use axum::{
    Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Health check status
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Health check result for a single component
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ComponentHealth {
    pub name: String,
    pub status: HealthStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Overall health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HealthResponse {
    pub status: HealthStatus,
    pub checks: Vec<ComponentHealth>,
}

impl IntoResponse for HealthResponse {
    fn into_response(self) -> Response {
        let status_code = match self.status {
            HealthStatus::Healthy => StatusCode::OK,
            HealthStatus::Degraded => StatusCode::OK,
            HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
        };

        (status_code, Json(self)).into_response()
    }
}

/// Trait for implementing health checks
pub trait HealthCheck: Send + Sync {
    fn name(&self) -> &str;
    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ComponentHealth> + Send + '_>>;
}

/// Basic health check that always returns healthy
#[derive(Debug, Clone, Copy, Default)]
pub struct BasicHealthCheck;

impl HealthCheck for BasicHealthCheck {
    fn name(&self) -> &str {
        "application"
    }

    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ComponentHealth> + Send + '_>> {
        Box::pin(async {
            ComponentHealth {
                name: self.name().to_string(),
                status: HealthStatus::Healthy,
                message: Some("Application is running".to_string()),
            }
        })
    }
}

/// Health check manager that runs all registered checks
pub struct HealthChecker {
    checks: Vec<Arc<dyn HealthCheck>>,
}

impl HealthChecker {
    pub fn new() -> Self {
        Self {
            checks: vec![Arc::new(BasicHealthCheck)],
        }
    }

    pub fn with_check(mut self, check: Arc<dyn HealthCheck>) -> Self {
        self.checks.push(check);
        self
    }

    pub async fn check_health(&self) -> HealthResponse {
        let mut checks = Vec::new();
        let mut overall_status = HealthStatus::Healthy;

        for check in &self.checks {
            let result = check.check().await;

            match result.status {
                HealthStatus::Unhealthy => overall_status = HealthStatus::Unhealthy,
                HealthStatus::Degraded if overall_status == HealthStatus::Healthy => {
                    overall_status = HealthStatus::Degraded
                }
                _ => {}
            }

            checks.push(result);
        }

        HealthResponse {
            status: overall_status,
            checks,
        }
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Handler for the health endpoint
pub async fn health_handler() -> HealthResponse {
    let checker = HealthChecker::new();
    checker.check_health().await
}

/// Creates the health check router
pub fn health_routes() -> Router {
    Router::new().route("/health", get(health_handler))
}
