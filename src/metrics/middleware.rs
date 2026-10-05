use super::collector::MetricsCollector;
use axum::body::Body;
use axum::{
    extract::{MatchedPath, Request},
    response::Response,
};
use futures::future::BoxFuture;
use std::sync::Arc;
use std::time::Instant;
use tower::Service;

const UNMATCHED_ROUTE_LABEL: &str = "<unmatched>";

struct InFlightGuard(Arc<MetricsCollector>);

impl InFlightGuard {
    fn new(collector: Arc<MetricsCollector>) -> Self {
        collector.increment_in_flight();
        Self(collector)
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.decrement_in_flight();
    }
}

/// Build a Tower layer for metrics collection
pub fn build_metrics_layer(collector: Arc<MetricsCollector>) -> MetricsLayer {
    MetricsLayer { collector }
}

/// Tower layer for metrics collection
#[derive(Clone)]
pub struct MetricsLayer {
    collector: Arc<MetricsCollector>,
}

impl<S> tower::Layer<S> for MetricsLayer {
    type Service = MetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MetricsService {
            inner,
            collector: self.collector.clone(),
        }
    }
}

/// Tower service for metrics collection
#[derive(Clone)]
pub struct MetricsService<S> {
    inner: S,
    collector: Arc<MetricsCollector>,
}

impl<S> Service<Request> for MetricsService<S>
where
    S: Service<Request, Response = Response<Body>>,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let collector = self.collector.clone();
        let start = Instant::now();
        let method = req.method().to_string();
        let path = req
            .extensions()
            .get::<MatchedPath>()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| UNMATCHED_ROUTE_LABEL.to_string());

        // Create the guard before the future so even an unpolled cancellation is counted.
        let in_flight = InFlightGuard::new(collector.clone());

        let fut = self.inner.call(req);

        Box::pin(async move {
            // Keep cleanup tied to the future's lifetime, including cancellation.
            let _in_flight = in_flight;
            let result = fut.await;
            let duration = start.elapsed();

            match result {
                Ok(response) => {
                    let status = response.status().as_u16();
                    collector.record_request(&method, &path, status, duration);
                    Ok(response)
                }
                Err(error) => Err(error),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use prometheus::proto::MetricFamily;
    use tower::ServiceExt;

    #[test]
    fn test_metrics_layer_creation() {
        let collector = Arc::new(MetricsCollector::new().unwrap());
        let _layer = build_metrics_layer(collector);
    }

    #[tokio::test]
    async fn test_in_flight_decrements_when_unpolled_request_is_dropped() {
        use tower::Layer;

        let collector = Arc::new(MetricsCollector::new().unwrap());
        let mut service = build_metrics_layer(collector.clone()).layer(tower::service_fn(|_| {
            std::future::pending::<Result<Response, std::convert::Infallible>>()
        }));

        let request = service.call(Request::new(Body::empty()));
        assert_eq!(collector.http_requests_in_flight.get(), 1);
        drop(request);
        assert_eq!(collector.http_requests_in_flight.get(), 0);
    }

    #[tokio::test]
    async fn test_in_flight_tracks_concurrent_requests_across_cancellations() {
        use tower::Layer;

        let collector = Arc::new(MetricsCollector::new().unwrap());
        let mut service = build_metrics_layer(collector.clone()).layer(tower::service_fn(|_| {
            std::future::pending::<Result<Response, std::convert::Infallible>>()
        }));

        let mut active = service.call(Request::new(Body::empty()));
        assert!(futures::poll!(&mut active).is_pending());
        for _ in 0..10 {
            let mut cancelled = service.call(Request::new(Body::empty()));
            assert!(futures::poll!(&mut cancelled).is_pending());
            assert_eq!(collector.http_requests_in_flight.get(), 2);
            drop(cancelled);
            assert_eq!(collector.http_requests_in_flight.get(), 1);
        }
        drop(active);
        assert_eq!(collector.http_requests_in_flight.get(), 0);
    }

    #[tokio::test]
    async fn test_in_flight_decrements_once_on_success_and_error() {
        use tower::Layer;

        for fail in [false, true] {
            let collector = Arc::new(MetricsCollector::new().unwrap());
            let mut service = build_metrics_layer(collector.clone()).layer(tower::service_fn(
                move |_| async move {
                    if fail {
                        Err("service failed")
                    } else {
                        Ok(Response::new(Body::empty()))
                    }
                },
            ));

            let mut request = service.call(Request::new(Body::empty()));
            assert_eq!(collector.http_requests_in_flight.get(), 1);
            assert_eq!((&mut request).await.is_err(), fail);
            assert_eq!(collector.http_requests_in_flight.get(), 0);
            drop(request);
            assert_eq!(collector.http_requests_in_flight.get(), 0);
        }
    }

    #[tokio::test]
    async fn test_metrics_use_matched_path() {
        let collector = Arc::new(MetricsCollector::new().unwrap());
        let app = Router::new()
            .route("/users/{id}", get(|| async { "ok" }))
            .layer(build_metrics_layer(collector.clone()));

        let req = Request::builder()
            .method("GET")
            .uri("/users/123")
            .body(Body::empty())
            .unwrap();
        let _ = app.oneshot(req).await.unwrap();

        let metrics = collector.registry().gather();
        let family = find_metric_family(&metrics, "tideway_http_requests_total")
            .expect("metrics family not found");
        let metric = family.get_metric().first().expect("metric not recorded");
        let path = find_label_value(metric, "path").expect("path label missing");
        assert_eq!(path, "/users/{id}");
    }

    #[tokio::test]
    async fn test_metrics_unmatched_path_uses_constant_label() {
        let collector = Arc::new(MetricsCollector::new().unwrap());
        let app = Router::new()
            .route("/users/{id}", get(|| async { "ok" }))
            .layer(build_metrics_layer(collector.clone()));

        let req = Request::builder()
            .method("GET")
            .uri("/totally-random-path-123")
            .body(Body::empty())
            .unwrap();
        let _ = app.oneshot(req).await.unwrap();

        let metrics = collector.registry().gather();
        let family = find_metric_family(&metrics, "tideway_http_requests_total")
            .expect("metrics family not found");
        let metric = family
            .get_metric()
            .iter()
            .find(|m| find_label_value(m, "status").as_deref() == Some("404"))
            .expect("404 metric not recorded");
        let path = find_label_value(metric, "path").expect("path label missing");
        assert_eq!(path, UNMATCHED_ROUTE_LABEL);
    }

    fn find_metric_family<'a>(
        families: &'a [MetricFamily],
        name: &str,
    ) -> Option<&'a MetricFamily> {
        families.iter().find(|family| family.name() == name)
    }

    fn find_label_value(metric: &prometheus::proto::Metric, name: &str) -> Option<String> {
        metric
            .get_label()
            .iter()
            .find(|label| label.name() == name)
            .map(|label| label.value().to_string())
    }
}
