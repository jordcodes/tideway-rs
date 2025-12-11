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

#[cfg(test)]
mod tests {
    use super::*;

    // ============ HealthStatus tests ============

    #[test]
    fn test_health_status_serialization() {
        assert_eq!(serde_json::to_string(&HealthStatus::Healthy).unwrap(), "\"healthy\"");
        assert_eq!(serde_json::to_string(&HealthStatus::Degraded).unwrap(), "\"degraded\"");
        assert_eq!(serde_json::to_string(&HealthStatus::Unhealthy).unwrap(), "\"unhealthy\"");
    }

    #[test]
    fn test_health_status_deserialization() {
        assert_eq!(serde_json::from_str::<HealthStatus>("\"healthy\"").unwrap(), HealthStatus::Healthy);
        assert_eq!(serde_json::from_str::<HealthStatus>("\"degraded\"").unwrap(), HealthStatus::Degraded);
        assert_eq!(serde_json::from_str::<HealthStatus>("\"unhealthy\"").unwrap(), HealthStatus::Unhealthy);
    }

    #[test]
    fn test_health_status_equality() {
        assert_eq!(HealthStatus::Healthy, HealthStatus::Healthy);
        assert_ne!(HealthStatus::Healthy, HealthStatus::Degraded);
        assert_ne!(HealthStatus::Healthy, HealthStatus::Unhealthy);
    }

    // ============ ComponentHealth tests ============

    #[test]
    fn test_component_health_creation() {
        let health = ComponentHealth {
            name: "database".to_string(),
            status: HealthStatus::Healthy,
            message: Some("Connected".to_string()),
        };

        assert_eq!(health.name, "database");
        assert_eq!(health.status, HealthStatus::Healthy);
        assert_eq!(health.message, Some("Connected".to_string()));
    }

    #[test]
    fn test_component_health_serialization_with_message() {
        let health = ComponentHealth {
            name: "cache".to_string(),
            status: HealthStatus::Degraded,
            message: Some("High latency".to_string()),
        };

        let json = serde_json::to_string(&health).unwrap();
        assert!(json.contains("\"name\":\"cache\""));
        assert!(json.contains("\"status\":\"degraded\""));
        assert!(json.contains("\"message\":\"High latency\""));
    }

    #[test]
    fn test_component_health_serialization_without_message() {
        let health = ComponentHealth {
            name: "service".to_string(),
            status: HealthStatus::Healthy,
            message: None,
        };

        let json = serde_json::to_string(&health).unwrap();
        assert!(json.contains("\"name\":\"service\""));
        assert!(json.contains("\"status\":\"healthy\""));
        // message should be skipped when None
        assert!(!json.contains("message"));
    }

    // ============ HealthResponse tests ============

    #[test]
    fn test_health_response_creation() {
        let response = HealthResponse {
            status: HealthStatus::Healthy,
            checks: vec![
                ComponentHealth {
                    name: "app".to_string(),
                    status: HealthStatus::Healthy,
                    message: None,
                },
            ],
        };

        assert_eq!(response.status, HealthStatus::Healthy);
        assert_eq!(response.checks.len(), 1);
    }

    #[test]
    fn test_health_response_serialization() {
        let response = HealthResponse {
            status: HealthStatus::Degraded,
            checks: vec![
                ComponentHealth {
                    name: "db".to_string(),
                    status: HealthStatus::Healthy,
                    message: None,
                },
                ComponentHealth {
                    name: "cache".to_string(),
                    status: HealthStatus::Degraded,
                    message: Some("Slow".to_string()),
                },
            ],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"degraded\""));
        assert!(json.contains("\"checks\""));
        assert!(json.contains("\"db\""));
        assert!(json.contains("\"cache\""));
    }

    #[tokio::test]
    async fn test_health_response_into_response_healthy() {
        let response = HealthResponse {
            status: HealthStatus::Healthy,
            checks: vec![],
        };

        let http_response = response.into_response();
        assert_eq!(http_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_response_into_response_degraded() {
        let response = HealthResponse {
            status: HealthStatus::Degraded,
            checks: vec![],
        };

        let http_response = response.into_response();
        // Degraded still returns 200 OK
        assert_eq!(http_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_response_into_response_unhealthy() {
        let response = HealthResponse {
            status: HealthStatus::Unhealthy,
            checks: vec![],
        };

        let http_response = response.into_response();
        assert_eq!(http_response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // ============ BasicHealthCheck tests ============

    #[test]
    fn test_basic_health_check_name() {
        let check = BasicHealthCheck;
        assert_eq!(check.name(), "application");
    }

    #[tokio::test]
    async fn test_basic_health_check_returns_healthy() {
        let check = BasicHealthCheck;
        let result = check.check().await;

        assert_eq!(result.name, "application");
        assert_eq!(result.status, HealthStatus::Healthy);
        assert!(result.message.is_some());
        assert!(result.message.unwrap().contains("running"));
    }

    // ============ HealthChecker tests ============

    #[test]
    fn test_health_checker_new() {
        let checker = HealthChecker::new();
        // Should have the basic health check by default
        assert_eq!(checker.checks.len(), 1);
    }

    #[test]
    fn test_health_checker_default() {
        let checker = HealthChecker::default();
        assert_eq!(checker.checks.len(), 1);
    }

    // Custom health check for testing
    struct MockHealthCheck {
        name: String,
        status: HealthStatus,
        message: Option<String>,
    }

    impl HealthCheck for MockHealthCheck {
        fn name(&self) -> &str {
            &self.name
        }

        fn check(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ComponentHealth> + Send + '_>> {
            let name = self.name.clone();
            let status = self.status.clone();
            let message = self.message.clone();
            Box::pin(async move {
                ComponentHealth { name, status, message }
            })
        }
    }

    #[test]
    fn test_health_checker_with_check() {
        let checker = HealthChecker::new()
            .with_check(Arc::new(MockHealthCheck {
                name: "database".to_string(),
                status: HealthStatus::Healthy,
                message: None,
            }));

        assert_eq!(checker.checks.len(), 2);
    }

    #[test]
    fn test_health_checker_with_multiple_checks() {
        let checker = HealthChecker::new()
            .with_check(Arc::new(MockHealthCheck {
                name: "db".to_string(),
                status: HealthStatus::Healthy,
                message: None,
            }))
            .with_check(Arc::new(MockHealthCheck {
                name: "cache".to_string(),
                status: HealthStatus::Healthy,
                message: None,
            }))
            .with_check(Arc::new(MockHealthCheck {
                name: "queue".to_string(),
                status: HealthStatus::Healthy,
                message: None,
            }));

        assert_eq!(checker.checks.len(), 4); // 1 basic + 3 custom
    }

    #[tokio::test]
    async fn test_health_checker_all_healthy() {
        let checker = HealthChecker::new()
            .with_check(Arc::new(MockHealthCheck {
                name: "db".to_string(),
                status: HealthStatus::Healthy,
                message: None,
            }))
            .with_check(Arc::new(MockHealthCheck {
                name: "cache".to_string(),
                status: HealthStatus::Healthy,
                message: None,
            }));

        let response = checker.check_health().await;

        assert_eq!(response.status, HealthStatus::Healthy);
        assert_eq!(response.checks.len(), 3);
    }

    #[tokio::test]
    async fn test_health_checker_one_degraded() {
        let checker = HealthChecker::new()
            .with_check(Arc::new(MockHealthCheck {
                name: "db".to_string(),
                status: HealthStatus::Healthy,
                message: None,
            }))
            .with_check(Arc::new(MockHealthCheck {
                name: "cache".to_string(),
                status: HealthStatus::Degraded,
                message: Some("High latency".to_string()),
            }));

        let response = checker.check_health().await;

        assert_eq!(response.status, HealthStatus::Degraded);
        assert_eq!(response.checks.len(), 3);
    }

    #[tokio::test]
    async fn test_health_checker_one_unhealthy() {
        let checker = HealthChecker::new()
            .with_check(Arc::new(MockHealthCheck {
                name: "db".to_string(),
                status: HealthStatus::Unhealthy,
                message: Some("Connection refused".to_string()),
            }))
            .with_check(Arc::new(MockHealthCheck {
                name: "cache".to_string(),
                status: HealthStatus::Healthy,
                message: None,
            }));

        let response = checker.check_health().await;

        // Unhealthy takes precedence
        assert_eq!(response.status, HealthStatus::Unhealthy);
    }

    #[tokio::test]
    async fn test_health_checker_unhealthy_overrides_degraded() {
        let checker = HealthChecker::new()
            .with_check(Arc::new(MockHealthCheck {
                name: "service1".to_string(),
                status: HealthStatus::Degraded,
                message: None,
            }))
            .with_check(Arc::new(MockHealthCheck {
                name: "service2".to_string(),
                status: HealthStatus::Unhealthy,
                message: None,
            }));

        let response = checker.check_health().await;

        // Unhealthy takes precedence over degraded
        assert_eq!(response.status, HealthStatus::Unhealthy);
    }

    #[tokio::test]
    async fn test_health_checker_all_unhealthy() {
        let checker = HealthChecker::new()
            .with_check(Arc::new(MockHealthCheck {
                name: "db".to_string(),
                status: HealthStatus::Unhealthy,
                message: None,
            }))
            .with_check(Arc::new(MockHealthCheck {
                name: "cache".to_string(),
                status: HealthStatus::Unhealthy,
                message: None,
            }));

        let response = checker.check_health().await;

        assert_eq!(response.status, HealthStatus::Unhealthy);
    }

    #[tokio::test]
    async fn test_health_checker_checks_in_order() {
        let checker = HealthChecker::new()
            .with_check(Arc::new(MockHealthCheck {
                name: "first".to_string(),
                status: HealthStatus::Healthy,
                message: None,
            }))
            .with_check(Arc::new(MockHealthCheck {
                name: "second".to_string(),
                status: HealthStatus::Healthy,
                message: None,
            }));

        let response = checker.check_health().await;

        // Check order: basic (application), first, second
        assert_eq!(response.checks[0].name, "application");
        assert_eq!(response.checks[1].name, "first");
        assert_eq!(response.checks[2].name, "second");
    }

    // ============ health_handler tests ============

    #[tokio::test]
    async fn test_health_handler() {
        let response = health_handler().await;

        assert_eq!(response.status, HealthStatus::Healthy);
        assert!(!response.checks.is_empty());
        assert_eq!(response.checks[0].name, "application");
    }

    // ============ health_routes tests ============

    #[tokio::test]
    async fn test_health_routes_endpoint() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = health_routes();

        let response = app
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let health_response: HealthResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(health_response.status, HealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_health_routes_not_found() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = health_routes();

        let response = app
            .oneshot(Request::builder().uri("/not-health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
