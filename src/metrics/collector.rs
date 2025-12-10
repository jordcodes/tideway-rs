use prometheus::{
    HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Opts, Registry,
};
use std::sync::Arc;

/// Metrics collector for HTTP request metrics
#[derive(Clone)]
pub struct MetricsCollector {
    /// Total number of HTTP requests
    pub http_requests_total: IntCounterVec,

    /// HTTP request duration in seconds
    pub http_request_duration_seconds: HistogramVec,

    /// Number of HTTP requests currently in flight
    pub http_requests_in_flight: IntGauge,

    /// Prometheus registry
    registry: Arc<Registry>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        // HTTP requests total counter
        let http_requests_total = IntCounterVec::new(
            Opts::new("http_requests_total", "Total number of HTTP requests")
                .namespace("tideway"),
            &["method", "path", "status"],
        )?;

        // HTTP request duration histogram
        let http_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "http_request_duration_seconds",
                "HTTP request duration in seconds",
            )
            .namespace("tideway")
            .buckets(vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["method", "path"],
        )?;

        // HTTP requests in flight gauge
        let http_requests_in_flight = IntGauge::new(
            "http_requests_in_flight",
            "Number of HTTP requests currently in flight",
        )?;

        registry.register(Box::new(http_requests_total.clone()))?;
        registry.register(Box::new(http_request_duration_seconds.clone()))?;
        registry.register(Box::new(http_requests_in_flight.clone()))?;

        Ok(Self {
            http_requests_total,
            http_request_duration_seconds,
            http_requests_in_flight,
            registry: Arc::new(registry),
        })
    }

    /// Get the Prometheus registry
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Record an HTTP request
    pub fn record_request(
        &self,
        method: &str,
        path: &str,
        status: u16,
        duration: std::time::Duration,
    ) {
        // Normalize path (remove IDs, etc.)
        let normalized_path = normalize_path(path);

        // Increment request counter
        self.http_requests_total
            .with_label_values(&[method, &normalized_path, &status.to_string()])
            .inc();

        // Record duration
        self.http_request_duration_seconds
            .with_label_values(&[method, &normalized_path])
            .observe(duration.as_secs_f64());
    }

    /// Increment in-flight requests
    pub fn increment_in_flight(&self) {
        self.http_requests_in_flight.inc();
    }

    /// Decrement in-flight requests
    pub fn decrement_in_flight(&self) {
        self.http_requests_in_flight.dec();
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new().expect("Failed to create metrics collector")
    }
}

/// Normalize a path for metrics (remove IDs, etc.)
fn normalize_path(path: &str) -> String {
    // Simple normalization: replace numeric segments with :id
    // This prevents cardinality explosion from IDs in paths
    let parts: Vec<&str> = path.split('/').collect();
    let normalized: Vec<String> = parts
        .iter()
        .map(|part| {
            if part.parse::<u64>().is_ok() {
                ":id".to_string()
            } else if part.parse::<uuid::Uuid>().is_ok() {
                ":uuid".to_string()
            } else {
                part.to_string()
            }
        })
        .collect();
    normalized.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector_creation() {
        let collector = MetricsCollector::new();
        assert!(collector.is_ok());
    }

    #[test]
    fn test_path_normalization() {
        assert_eq!(normalize_path("/api/users/123"), "/api/users/:id");
        assert_eq!(normalize_path("/api/users"), "/api/users");
        assert_eq!(
            normalize_path("/api/users/550e8400-e29b-41d4-a716-446655440000"),
            "/api/users/:uuid"
        );
    }

    #[test]
    fn test_record_request() {
        let collector = MetricsCollector::new().unwrap();
        collector.record_request(
            "GET",
            "/api/users/123",
            200,
            std::time::Duration::from_millis(50),
        );
        // Verify metrics were recorded (we can't easily test the values without more setup)
    }
}
