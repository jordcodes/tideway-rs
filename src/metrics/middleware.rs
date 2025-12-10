use super::collector::MetricsCollector;
use axum::{
    extract::Request,
    response::Response,
};
use axum::body::Body;
use futures::future::BoxFuture;
use std::sync::Arc;
use std::time::Instant;
use tower::Service;

/// Build a Tower layer for metrics collection
pub fn build_metrics_layer(
    collector: Arc<MetricsCollector>,
) -> MetricsLayer {
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
        let path = req.uri().path().to_string();

        // Increment in-flight requests
        collector.increment_in_flight();

        let fut = self.inner.call(req);

        Box::pin(async move {
            let response = fut.await?;
            let status = response.status().as_u16();
            let duration = start.elapsed();

            // Record metrics
            collector.record_request(&method, &path, status, duration);

            // Decrement in-flight requests
            collector.decrement_in_flight();

            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_layer_creation() {
        let collector = Arc::new(MetricsCollector::new().unwrap());
        let layer = build_metrics_layer(collector);
        // Just verify it compiles and can be created
        assert!(true);
    }
}
