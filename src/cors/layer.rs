use super::config::CorsConfig;
use axum::http::{HeaderValue, Method};
use std::time::Duration;
use tower_http::cors::{Any, CorsLayer};

/// Build a tower-http CorsLayer from a CorsConfig
pub fn build_cors_layer(config: &CorsConfig) -> Option<CorsLayer> {
    if !config.enabled {
        return None;
    }
    if let Err(error) = config.validate() {
        tracing::error!(%error, "refusing invalid CORS configuration");
        return None;
    }

    let mut layer = CorsLayer::new();

    // A `*` anywhere in a list means "any". tower-http panics if a wildcard is
    // passed inside an origin list, so it must be mapped to `Any` explicitly.
    let has_wildcard = |values: &[String]| values.iter().any(|v| v.trim() == "*");

    // Configure allowed origins
    if config.allowed_origins.is_empty() {
        // No origins configured - don't set any allow_origin (most restrictive)
        // The layer will default to not allowing any origins
    } else if has_wildcard(&config.allowed_origins) {
        // Allow any origin
        layer = layer.allow_origin(Any);
    } else {
        // Allow specific origins
        let origins: Vec<HeaderValue> = config
            .allowed_origins
            .iter()
            .filter_map(|origin| origin.parse().ok())
            .collect();
        layer = layer.allow_origin(origins);
    }

    // Configure allowed methods
    if has_wildcard(&config.allowed_methods) {
        layer = layer.allow_methods(Any);
    } else {
        let methods: Vec<Method> = config
            .allowed_methods
            .iter()
            .filter_map(|m| m.parse().ok())
            .collect();

        if !methods.is_empty() {
            layer = layer.allow_methods(methods);
        }
    }

    // Configure allowed headers
    if has_wildcard(&config.allowed_headers) {
        layer = layer.allow_headers(Any);
    } else {
        let headers: Vec<_> = config
            .allowed_headers
            .iter()
            .filter_map(|h| h.parse().ok())
            .collect();
        if !headers.is_empty() {
            layer = layer.allow_headers(headers);
        }
    }

    // Configure exposed headers
    if has_wildcard(&config.exposed_headers) {
        layer = layer.expose_headers(Any);
    } else if !config.exposed_headers.is_empty() {
        let headers: Vec<_> = config
            .exposed_headers
            .iter()
            .filter_map(|h| h.parse().ok())
            .collect();
        if !headers.is_empty() {
            layer = layer.expose_headers(headers);
        }
    }

    // Configure credentials
    if config.allow_credentials {
        layer = layer.allow_credentials(true);
    }

    // Configure max age
    layer = layer.max_age(Duration::from_secs(config.max_age_seconds));

    Some(layer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_cors() {
        let config = CorsConfig {
            enabled: false,
            ..Default::default()
        };
        let layer = build_cors_layer(&config);
        assert!(layer.is_none());
    }

    #[test]
    fn test_default_config_disabled() {
        // SECURITY: Default config has CORS disabled
        let config = CorsConfig::default();
        let layer = build_cors_layer(&config);
        assert!(layer.is_none(), "CORS should be disabled by default");
    }

    #[test]
    fn test_permissive_cors() {
        let config = CorsConfig::permissive();
        let layer = build_cors_layer(&config);
        assert!(layer.is_some());
    }

    #[test]
    fn test_specific_origins() {
        let config = CorsConfig::builder()
            .enabled(true)
            .allow_origin("https://example.com")
            .build();
        let layer = build_cors_layer(&config);
        assert!(layer.is_some());
    }

    #[test]
    fn test_empty_origins_enabled() {
        // If explicitly enabled but no origins, still creates a layer
        let config = CorsConfig::builder().enabled(true).build();
        let layer = build_cors_layer(&config);
        assert!(layer.is_some());
    }

    /// Building the layer and wrapping a service is what happens at startup;
    /// tower-http runs its own panicking checks at both points.
    fn apply_layer(config: &CorsConfig) -> Option<CorsLayer> {
        use tower::Layer;
        let layer = build_cors_layer(config)?;
        let _ = layer.layer(tower::service_fn(|_: ()| async {
            Ok::<_, std::convert::Infallible>(())
        }));
        Some(layer)
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn test_wildcard_mixed_into_origins_does_not_panic() {
        let config = CorsConfig::builder()
            .enabled(true)
            .allow_origins(strings(&["https://example.com", "*"]))
            .build();
        assert!(apply_layer(&config).is_some());
    }

    #[test]
    fn test_wildcard_mixed_into_headers_does_not_panic() {
        let config = CorsConfig::builder()
            .enabled(true)
            .allow_origin("https://example.com")
            .allow_headers(strings(&["content-type", "*"]))
            .build();
        assert!(apply_layer(&config).is_some());
    }

    #[test]
    fn test_wildcard_methods_and_exposed_headers_do_not_panic() {
        let config = CorsConfig::builder()
            .enabled(true)
            .allow_origin("https://example.com")
            .allow_methods(strings(&["GET", "*"]))
            .expose_headers(strings(&["x-request-id", "*"]))
            .build();
        assert!(apply_layer(&config).is_some());
    }

    #[test]
    fn test_credentialed_wildcard_methods_or_exposed_headers_are_refused() {
        let methods = CorsConfig::builder()
            .enabled(true)
            .allow_origin("https://example.com")
            .allow_methods(strings(&["*"]))
            .allow_credentials(true)
            .build();
        assert!(apply_layer(&methods).is_none());

        let exposed = CorsConfig::builder()
            .enabled(true)
            .allow_origin("https://example.com")
            .expose_headers(strings(&["*"]))
            .allow_credentials(true)
            .build();
        assert!(apply_layer(&exposed).is_none());
    }

    #[test]
    fn test_invalid_credentialed_wildcard_is_refused() {
        let config = CorsConfig::builder()
            .enabled(true)
            .allow_any_origin()
            .allow_credentials(true)
            .build();
        assert!(build_cors_layer(&config).is_none());
    }
}
