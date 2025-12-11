use axum::response::Response;
use axum::body::Body;
use axum::http::StatusCode;
use crate::app::AppContext;

/// Handler for the /metrics endpoint
pub async fn metrics_handler(
    axum::extract::State(ctx): axum::extract::State<AppContext>,
) -> Result<Response<Body>, StatusCode> {
    use prometheus::Encoder;

    let collector = ctx.metrics_opt()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let encoder = prometheus::TextEncoder::new();
    let metric_families = collector.registry().gather();

    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Body::from(buffer))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(response)
}

