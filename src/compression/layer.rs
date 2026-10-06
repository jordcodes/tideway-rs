use super::config::{CompressionAlgorithm, CompressionConfig};
use axum::{
    body::HttpBody,
    http::{HeaderMap, Request, Response, header},
};
use std::task::{Context, Poll};
use tower::{Layer, Service};
use tower_http::compression::{
    Compression, CompressionBody, CompressionLevel, ResponseFuture, predicate::DefaultPredicate,
};

/// Compression layer with independent gzip and Brotli quality settings.
#[derive(Debug, Clone)]
pub struct ConfiguredCompressionLayer {
    config: CompressionConfig,
}

/// Build response compression using the configured algorithms and quality levels.
pub fn build_compression_layer(config: &CompressionConfig) -> Option<ConfiguredCompressionLayer> {
    config.enabled.then(|| ConfiguredCompressionLayer {
        config: config.clone(),
    })
}

impl<S> Layer<S> for ConfiguredCompressionLayer {
    type Service = ConfiguredCompression<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ConfiguredCompression {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Response compression service with per-algorithm quality settings.
#[derive(Debug, Clone)]
pub struct ConfiguredCompression<S> {
    inner: S,
    config: CompressionConfig,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ConfiguredCompression<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: HttpBody,
{
    type Response = Response<CompressionBody<ResBody>>;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future, DefaultPredicate>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let gzip = self.config.algorithm != CompressionAlgorithm::Brotli;
        let brotli = self.config.algorithm != CompressionAlgorithm::Gzip;
        let quality = if prefers_brotli(request.headers(), gzip, brotli) {
            self.config.brotli_quality.clamp(1, 11)
        } else {
            self.config.level.clamp(1, 9)
        };
        Compression::new(&mut self.inner)
            .gzip(gzip)
            .br(brotli)
            .no_deflate()
            .no_zstd()
            .quality(CompressionLevel::Precise(quality.into()))
            .call(request)
    }
}

// Match tower-http's negotiation to choose the quality; tower-http still owns
// compression eligibility and encoding negotiation. Brotli wins equal weights.
fn prefers_brotli(headers: &HeaderMap, gzip: bool, brotli: bool) -> bool {
    headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|entry| {
            let (encoding, weight) = match entry.split_once(';') {
                Some((encoding, weight)) => (encoding.trim(), parse_weight(weight.trim())?),
                None => (entry.trim(), 1000),
            };
            let preference = if brotli && encoding.eq_ignore_ascii_case("br") {
                2
            } else if gzip
                && (encoding.eq_ignore_ascii_case("gzip")
                    || encoding.eq_ignore_ascii_case("x-gzip"))
            {
                1
            } else if encoding.eq_ignore_ascii_case("identity") {
                0
            } else {
                return None;
            };
            (weight > 0).then_some((weight, preference))
        })
        .max()
        .is_some_and(|(_, preference)| preference == 2)
}

fn parse_weight(value: &str) -> Option<u16> {
    let value = value
        .strip_prefix("q=")
        .or_else(|| value.strip_prefix("Q="))?;
    let (integer, fraction) = value.split_once('.').unwrap_or((value, ""));
    if !matches!(integer, "0" | "1")
        || fraction.len() > 3
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let fraction = fraction
        .bytes()
        .zip([100, 10, 1])
        .map(|(b, scale)| u16::from(b - b'0') * scale)
        .sum::<u16>();
    let weight = if integer == "1" { 1000 } else { 0 } + fraction;
    (weight <= 1000).then_some(weight)
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
