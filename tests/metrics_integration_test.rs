#[cfg(feature = "metrics")]
mod tests {
    use std::sync::Arc;
    use tideway::testing::get as test_get;
    use tideway::{App, ConfigBuilder, MetricsCollector};

    #[tokio::test]
    async fn test_metrics_without_credentials_are_not_public() {
        let config = ConfigBuilder::new()
            .with_metrics(tideway::MetricsConfig::builder().enabled(true).build())
            .build()
            .unwrap();
        test_get(App::with_config(config).into_router(), "/metrics")
            .execute()
            .await
            .assert_not_found();
    }

    #[tokio::test]
    async fn test_metrics_reject_invalid_credentials() {
        for path in ["/metrics", "/private/metrics"] {
            let config = ConfigBuilder::new()
                .with_metrics(
                    tideway::MetricsConfig::builder()
                        .enabled(true)
                        .path(path)
                        .bearer_token("scrape-secret")
                        .build(),
                )
                .build()
                .unwrap();
            let app = App::with_config(config).into_router();
            test_get(app.clone(), path)
                .execute()
                .await
                .assert_unauthorized();
            for value in ["Bearer wrong", "Basic scrape-secret", "Bearer", "Bearer "] {
                test_get(app.clone(), path)
                    .header("Authorization", value)
                    .execute()
                    .await
                    .assert_unauthorized();
            }
            test_get(app.clone(), path)
                .header("Authorization", "Bearer scrape-secret")
                .execute()
                .await
                .assert_ok();
            test_get(app, "/health").execute().await.assert_ok();
        }
    }

    #[tokio::test]
    async fn test_empty_metrics_tokens_do_not_expose_route() {
        for token in ["", "   "] {
            let config = ConfigBuilder::new()
                .with_metrics(
                    tideway::MetricsConfig::builder()
                        .enabled(true)
                        .bearer_token(token)
                        .build(),
                )
                .build()
                .unwrap();
            test_get(App::with_config(config).into_router(), "/metrics")
                .execute()
                .await
                .assert_not_found();
        }
    }

    #[test]
    fn test_unknown_methods_have_bounded_cardinality() {
        let collector = MetricsCollector::new().unwrap();
        for i in 0..1000 {
            collector.record_request(
                &format!("CUSTOM-{i}"),
                "/test",
                200,
                std::time::Duration::ZERO,
            );
        }
        for family in collector.registry().gather() {
            if family.name() == "tideway_http_requests_total"
                || family.name() == "tideway_http_request_duration_seconds"
            {
                assert_eq!(family.get_metric().len(), 1);
                let metric = &family.get_metric()[0];
                let method = metric
                    .get_label()
                    .iter()
                    .find(|l| l.name() == "method")
                    .unwrap();
                assert_eq!(method.value(), "OTHER");
            }
        }
    }

    #[tokio::test]
    async fn test_metrics_collector_creation() {
        let collector = MetricsCollector::new();
        assert!(collector.is_ok());
    }

    #[tokio::test]
    async fn test_metrics_collector_recording() {
        let collector = Arc::new(MetricsCollector::new().unwrap());

        // Record some requests
        collector.record_request(
            "GET",
            "/api/test",
            200,
            std::time::Duration::from_millis(50),
        );
        collector.record_request(
            "POST",
            "/api/test",
            201,
            std::time::Duration::from_millis(100),
        );
        collector.record_request(
            "GET",
            "/api/test",
            404,
            std::time::Duration::from_millis(10),
        );

        // Increment in-flight
        collector.increment_in_flight();
        assert_eq!(collector.http_requests_in_flight.get(), 1);

        collector.decrement_in_flight();
        assert_eq!(collector.http_requests_in_flight.get(), 0);
    }

    #[tokio::test]
    async fn test_metrics_endpoint_returns_prometheus_format() {
        use tideway::MetricsConfig;

        let config = ConfigBuilder::new()
            .with_metrics(
                MetricsConfig::builder()
                    .enabled(true)
                    .path("/metrics")
                    .bearer_token("scrape-secret")
                    .build(),
            )
            .build()
            .unwrap();

        let app = App::with_config(config).into_router();

        let response = test_get(app, "/metrics")
            .header("Authorization", "Bearer scrape-secret")
            .execute()
            .await
            .assert_ok();

        // Verify it returns Prometheus text format
        let body = response.body_string().await;
        // Prometheus metrics should contain HELP and TYPE comments
        assert!(
            body.contains("# HELP") && body.contains("# TYPE"),
            "Expected Prometheus format, got: {}",
            body
        );
    }

    #[tokio::test]
    async fn test_metrics_endpoint_custom_path() {
        use tideway::MetricsConfig;

        let config = ConfigBuilder::new()
            .with_metrics(
                MetricsConfig::builder()
                    .enabled(true)
                    .path("/custom/metrics")
                    .bearer_token("scrape-secret")
                    .build(),
            )
            .build()
            .unwrap();

        let app = App::with_config(config).into_router();

        // Should be available at custom path
        test_get(app.clone(), "/custom/metrics")
            .header("Authorization", "Bearer scrape-secret")
            .execute()
            .await
            .assert_ok();

        // Should NOT be at default path
        test_get(app, "/metrics").execute().await.assert_not_found();
    }

    #[tokio::test]
    async fn test_metrics_endpoint_with_app_builder() {
        use tideway::MetricsConfig;

        let config = ConfigBuilder::new()
            .with_metrics(
                MetricsConfig::builder()
                    .enabled(true)
                    .path("/metrics")
                    .bearer_token("scrape-secret")
                    .build(),
            )
            .build()
            .unwrap();

        let app = App::builder().with_config(config).build().into_router();

        test_get(app, "/metrics")
            .header("Authorization", "Bearer scrape-secret")
            .execute()
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn test_metrics_endpoint_integration() {
        use tideway::MetricsConfig;

        let config = ConfigBuilder::new()
            .with_port(8080) // Use a valid port
            .with_metrics(
                MetricsConfig::builder()
                    .enabled(true)
                    .path("/metrics")
                    .bearer_token("scrape-secret")
                    .build(),
            )
            .build()
            .unwrap();

        let _router = App::with_config(config).into_router();
    }

    #[tokio::test]
    async fn test_metrics_path_normalization() {
        let collector = Arc::new(MetricsCollector::new().unwrap());

        // Record requests with IDs
        collector.record_request(
            "GET",
            "/api/users/123",
            200,
            std::time::Duration::from_millis(50),
        );
        collector.record_request(
            "GET",
            "/api/users/456",
            200,
            std::time::Duration::from_millis(60),
        );

        let gathered = collector.registry().gather();
        assert!(!gathered.is_empty());
    }

    #[tokio::test]
    async fn test_metrics_disabled() {
        use tideway::MetricsConfig;

        let config = ConfigBuilder::new()
            .with_metrics(MetricsConfig::builder().enabled(false).build())
            .build()
            .unwrap();

        let _router = App::with_config(config).into_router();
    }
}
