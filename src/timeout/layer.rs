use super::config::TimeoutConfig;
use tower_http::timeout::TimeoutLayer;

/// Build a tower-http TimeoutLayer from a TimeoutConfig
pub fn build_timeout_layer(config: &TimeoutConfig) -> Option<TimeoutLayer> {
    if !config.enabled {
        return None;
    }

    Some(TimeoutLayer::new(config.duration()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_timeout() {
        let config = TimeoutConfig {
            enabled: false,
            ..Default::default()
        };
        let layer = build_timeout_layer(&config);
        assert!(layer.is_none());
    }

    #[test]
    fn test_enabled_timeout() {
        let config = TimeoutConfig {
            enabled: true,
            timeout_seconds: 60,
        };
        let layer = build_timeout_layer(&config);
        assert!(layer.is_some());
    }
}
