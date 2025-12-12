use super::config::CorsConfig;
use axum::http::{HeaderValue, Method};
use std::time::Duration;
use tower_http::cors::{Any, CorsLayer};

/// Build a tower-http CorsLayer from a CorsConfig
pub fn build_cors_layer(config: &CorsConfig) -> Option<CorsLayer> {
    if !config.enabled {
        return None;
    }

    let mut layer = CorsLayer::new();

    // Configure allowed origins
    if config.allowed_origins.is_empty() {
        // No origins configured - don't set any allow_origin (most restrictive)
        // The layer will default to not allowing any origins
    } else if config.allowed_origins.len() == 1 && config.allowed_origins[0] == "*" {
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
    let methods: Vec<Method> = config
        .allowed_methods
        .iter()
        .filter_map(|m| m.parse().ok())
        .collect();

    if !methods.is_empty() {
        layer = layer.allow_methods(methods);
    }

    // Configure allowed headers
    if config.allowed_headers.len() == 1 && config.allowed_headers[0] == "*" {
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
    if !config.exposed_headers.is_empty() {
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
        let config = CorsConfig::builder()
            .enabled(true)
            .build();
        let layer = build_cors_layer(&config);
        assert!(layer.is_some());
    }
}
