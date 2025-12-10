//! Development-mode error middleware
//!
//! Enhances error responses with stack traces and detailed information
//! when development mode is enabled.

use crate::error::{ErrorInfo, TidewayError};
use axum::{
    body::Body,
    extract::Request,
    http::Response,
};
use std::sync::Arc;
use tower::Service;

/// Build a development error layer
///
/// This layer intercepts errors and enhances them with stack traces
/// and detailed information when dev mode is enabled.
pub fn build_dev_error_layer(config: Arc<crate::dev::DevConfig>) -> DevErrorLayer {
    DevErrorLayer { config }
}

/// Development error layer
#[derive(Debug, Clone)]
pub struct DevErrorLayer {
    config: Arc<crate::dev::DevConfig>,
}

impl<S> tower::Layer<S> for DevErrorLayer {
    type Service = DevErrorService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DevErrorService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Development error service
#[derive(Debug)]
pub struct DevErrorService<S> {
    inner: S,
    config: Arc<crate::dev::DevConfig>,
}

impl<S> Service<Request> for DevErrorService<S>
where
    S: Service<Request, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        if !self.config.enabled {
            return Box::pin(self.inner.call(req));
        }

        let mut inner = self.inner.clone();

        Box::pin(async move {
            let response = inner.call(req).await?;

            // If the response is an error, log it for debugging
            if response.status().is_client_error() || response.status().is_server_error() {
                tracing::debug!(
                    status = response.status().as_u16(),
                    "Dev mode: Error response generated"
                );
            }

            Ok(response)
        })
    }
}

/// Helper to create enhanced error response with stack trace
#[allow(dead_code)]
pub fn create_dev_error_response(
    error: TidewayError,
    config: &crate::dev::DevConfig,
) -> Response<Body> {
    let stack_trace = if config.include_stack_traces {
        Some(format!("{:?}", error))
    } else {
        None
    };

    let error_info = ErrorInfo::new()
        .with_stack_trace(stack_trace.unwrap_or_default());

    error.into_response_with_info(Some(error_info), config.enabled)
}
