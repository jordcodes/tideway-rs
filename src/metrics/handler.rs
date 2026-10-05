use crate::app::AppContext;
use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;

/// Prometheus exposition handler. When mounting manually, protect this handler with authentication.
pub async fn metrics_handler(
    axum::extract::State(ctx): axum::extract::State<AppContext>,
) -> Result<Response<Body>, StatusCode> {
    use prometheus::Encoder;

    let collector = ctx.metrics_opt().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let encoder = prometheus::TextEncoder::new();
    let metric_families = collector.registry().gather();

    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Body::from(buffer))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(response)
}

/// Build the authenticated route used by App; authentication runs before gathering metrics.
pub(crate) fn authenticated_metrics_route(
    token: String,
) -> axum::routing::MethodRouter<AppContext> {
    use axum::{extract::Request, middleware::Next, response::IntoResponse};
    use subtle::ConstantTimeEq;

    axum::routing::get(metrics_handler).route_layer(axum::middleware::from_fn(
        move |request: Request, next: Next| {
            let authorized = request
                .headers()
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split_once(' '))
                .is_some_and(|(scheme, supplied)| {
                    scheme.eq_ignore_ascii_case("Bearer")
                        && !token.trim().is_empty()
                        && bool::from(supplied.as_bytes().ct_eq(token.as_bytes()))
                });
            async move {
                if authorized {
                    next.run(request).await
                } else {
                    (
                        StatusCode::UNAUTHORIZED,
                        [(axum::http::header::WWW_AUTHENTICATE, "Bearer")],
                    )
                        .into_response()
                }
            }
        },
    ))
}
