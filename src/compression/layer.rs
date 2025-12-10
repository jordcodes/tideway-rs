use super::config::{CompressionAlgorithm, CompressionConfig};
use tower_http::compression::CompressionLayer;

/// Build a tower-http CompressionLayer from a CompressionConfig
pub fn build_compression_layer(config: &CompressionConfig) -> Option<CompressionLayer> {
    if !config.enabled {
        return None;
    }

    let layer = match config.algorithm {
        CompressionAlgorithm::Gzip => {
            CompressionLayer::new().gzip(true)
        }
        CompressionAlgorithm::Brotli => {
            CompressionLayer::new()
                .br(true)
                .gzip(false)
        }
        CompressionAlgorithm::Both => {
            CompressionLayer::new()
                .br(true)
                .gzip(true)
        }
    };

    Some(layer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_compression() {
        let config = CompressionConfig {
            enabled: false,
            ..Default::default()
        };
        let layer = build_compression_layer(&config);
        assert!(layer.is_none());
    }

    #[test]
    fn test_gzip_only() {
        let config = CompressionConfig {
            enabled: true,
            algorithm: CompressionAlgorithm::Gzip,
            ..Default::default()
        };
        let layer = build_compression_layer(&config);
        assert!(layer.is_some());
    }

    #[test]
    fn test_brotli_only() {
        let config = CompressionConfig {
            enabled: true,
            algorithm: CompressionAlgorithm::Brotli,
            ..Default::default()
        };
        let layer = build_compression_layer(&config);
        assert!(layer.is_some());
    }

    #[test]
    fn test_both_algorithms() {
        let config = CompressionConfig {
            enabled: true,
            algorithm: CompressionAlgorithm::Both,
            ..Default::default()
        };
        let layer = build_compression_layer(&config);
        assert!(layer.is_some());
    }
}
