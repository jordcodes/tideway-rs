use serde::{Deserialize, Serialize};
use crate::utils::get_env_with_prefix;

/// Compression algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CompressionAlgorithm {
    /// Gzip compression
    Gzip,
    /// Brotli compression (better compression ratio, slower)
    Brotli,
    /// Both gzip and brotli (client chooses via Accept-Encoding)
    Both,
}

impl Default for CompressionAlgorithm {
    fn default() -> Self {
        Self::Both
    }
}

/// Compression configuration for Tideway applications
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CompressionConfig {
    /// Whether compression is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Compression algorithm to use
    #[serde(default)]
    pub algorithm: CompressionAlgorithm,

    /// Compression level (1-9, where 9 is maximum compression)
    /// Higher levels compress better but use more CPU
    #[serde(default = "default_compression_level")]
    pub level: u8,

    /// Quality level for brotli (1-11, where 11 is maximum)
    /// Only used when algorithm is Brotli or Both
    #[serde(default = "default_brotli_quality")]
    pub brotli_quality: u8,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            algorithm: CompressionAlgorithm::default(),
            level: default_compression_level(),
            brotli_quality: default_brotli_quality(),
        }
    }
}

impl CompressionConfig {
    /// Create a new CompressionConfig builder
    pub fn builder() -> CompressionConfigBuilder {
        CompressionConfigBuilder::new()
    }

    /// Load compression configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Some(enabled) = get_env_with_prefix("COMPRESSION_ENABLED") {
            config.enabled = enabled.parse().unwrap_or(true);
        }

        if let Some(algorithm) = get_env_with_prefix("COMPRESSION_ALGORITHM") {
            config.algorithm = match algorithm.to_lowercase().as_str() {
                "gzip" => CompressionAlgorithm::Gzip,
                "brotli" => CompressionAlgorithm::Brotli,
                "both" => CompressionAlgorithm::Both,
                _ => CompressionAlgorithm::default(),
            };
        }

        if let Some(level) = get_env_with_prefix("COMPRESSION_LEVEL") {
            if let Ok(l) = level.parse::<u8>() {
                config.level = l.clamp(1, 9);
            }
        }

        if let Some(quality) = get_env_with_prefix("COMPRESSION_BROTLI_QUALITY") {
            if let Ok(q) = quality.parse::<u8>() {
                config.brotli_quality = q.clamp(1, 11);
            }
        }

        config
    }
}

/// Builder for CompressionConfig
#[must_use = "builder does nothing until you call build()"]
pub struct CompressionConfigBuilder {
    config: CompressionConfig,
}

impl CompressionConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: CompressionConfig::default(),
        }
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    pub fn algorithm(mut self, algorithm: CompressionAlgorithm) -> Self {
        self.config.algorithm = algorithm;
        self
    }

    pub fn gzip(mut self) -> Self {
        self.config.algorithm = CompressionAlgorithm::Gzip;
        self
    }

    pub fn brotli(mut self) -> Self {
        self.config.algorithm = CompressionAlgorithm::Brotli;
        self
    }

    pub fn both(mut self) -> Self {
        self.config.algorithm = CompressionAlgorithm::Both;
        self
    }

    pub fn level(mut self, level: u8) -> Self {
        self.config.level = level.clamp(1, 9);
        self
    }

    pub fn brotli_quality(mut self, quality: u8) -> Self {
        self.config.brotli_quality = quality.clamp(1, 11);
        self
    }

    pub fn build(self) -> CompressionConfig {
        self.config
    }
}

impl Default for CompressionConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn default_enabled() -> bool {
    true
}

fn default_compression_level() -> u8 {
    6 // Balanced compression/speed
}

fn default_brotli_quality() -> u8 {
    4 // Balanced quality/speed for brotli
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CompressionConfig::default();
        assert!(config.enabled);
        assert_eq!(config.algorithm, CompressionAlgorithm::Both);
        assert_eq!(config.level, 6);
        assert_eq!(config.brotli_quality, 4);
    }

    #[test]
    fn test_builder() {
        let config = CompressionConfig::builder()
            .gzip()
            .level(9)
            .build();

        assert_eq!(config.algorithm, CompressionAlgorithm::Gzip);
        assert_eq!(config.level, 9);
    }

    #[test]
    fn test_level_clamping() {
        let config = CompressionConfig::builder()
            .level(15) // Too high
            .build();
        assert_eq!(config.level, 9);

        let config = CompressionConfig::builder()
            .level(0) // Too low
            .build();
        assert_eq!(config.level, 1);
    }

    #[test]
    fn test_brotli_quality_clamping() {
        let config = CompressionConfig::builder()
            .brotli_quality(15) // Too high
            .build();
        assert_eq!(config.brotli_quality, 11);

        let config = CompressionConfig::builder()
            .brotli_quality(0) // Too low
            .build();
        assert_eq!(config.brotli_quality, 1);
    }
}

