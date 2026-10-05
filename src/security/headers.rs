use super::config::{ReferrerPolicy, SecurityConfig, XFrameOptions};
use axum::body::Body;
use axum::{
    extract::Request,
    http::{HeaderMap, HeaderValue, Response},
};
use futures::future::BoxFuture;
use std::sync::Arc;
use tower::Service;

/// Build a Tower layer that adds security headers to responses
pub fn build_security_headers_layer(config: &SecurityConfig) -> Option<SecurityHeadersLayer> {
    if !config.enabled {
        return None;
    }

    Some(SecurityHeadersLayer {
        headers: Arc::new(build_security_headers(config)),
    })
}

/// Tower layer that adds security headers
#[derive(Clone)]
pub struct SecurityHeadersLayer {
    headers: Arc<HeaderMap>,
}

impl<S> tower::Layer<S> for SecurityHeadersLayer {
    type Service = SecurityHeadersService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersService {
            inner,
            headers: self.headers.clone(),
        }
    }
}

/// Tower service that adds security headers
#[derive(Clone)]
pub struct SecurityHeadersService<S> {
    inner: S,
    headers: Arc<HeaderMap>,
}

impl<S> Service<Request> for SecurityHeadersService<S>
where
    S: Service<Request, Response = Response<Body>> + Send + 'static,
    S::Future: Send,
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
        let headers = self.headers.clone();
        let fut = self.inner.call(req);

        Box::pin(async move {
            let mut response = fut.await?;
            for (name, value) in headers.iter() {
                response.headers_mut().insert(name.clone(), value.clone());
            }
            Ok(response)
        })
    }
}

fn build_security_headers(config: &SecurityConfig) -> HeaderMap {
    let mut headers = HeaderMap::new();

    // HSTS
    if config.hsts_max_age > 0 {
        let mut hsts_value = format!("max-age={}", config.hsts_max_age);
        if config.hsts_include_subdomains {
            hsts_value.push_str("; includeSubDomains");
        }
        if config.hsts_preload {
            hsts_value.push_str("; preload");
        }
        if let Ok(header) = HeaderValue::from_str(&hsts_value) {
            headers.insert("strict-transport-security", header);
        }
    }

    // X-Content-Type-Options
    if config.nosniff {
        headers.insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
    }

    // X-Frame-Options
    if let Some(frame_options) = config.x_frame_options {
        let value = match frame_options {
            XFrameOptions::Deny => "DENY",
            XFrameOptions::SameOrigin => "SAMEORIGIN",
        };
        headers.insert("x-frame-options", HeaderValue::from_static(value));
    }

    // X-XSS-Protection (deprecated)
    if let Some(xss_protection) = config.xss_protection {
        let value = if xss_protection { "1; mode=block" } else { "0" };
        headers.insert("x-xss-protection", HeaderValue::from_static(value));
    }

    // Content-Security-Policy
    if let Some(ref csp) = config.content_security_policy
        && let Ok(header) = HeaderValue::from_str(csp)
    {
        headers.insert("content-security-policy", header);
    }

    // Referrer-Policy
    if let Some(referrer_policy) = config.referrer_policy {
        let value = match referrer_policy {
            ReferrerPolicy::NoReferrer => "no-referrer",
            ReferrerPolicy::SameOrigin => "same-origin",
            ReferrerPolicy::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
            ReferrerPolicy::StrictOrigin => "strict-origin",
            ReferrerPolicy::UnsafeUrl => "unsafe-url",
        };
        headers.insert("referrer-policy", HeaderValue::from_static(value));
    }

    // Permissions-Policy
    if let Some(ref permissions) = config.permissions_policy
        && let Ok(header) = HeaderValue::from_str(permissions)
    {
        headers.insert("permissions-policy", header);
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_and_services_share_prebuilt_headers() {
        use tower::Layer;
        let layer = build_security_headers_layer(&SecurityConfig::default()).unwrap();
        let service = layer.layer(());
        let clone = service.clone();
        assert!(Arc::ptr_eq(&layer.headers, &service.headers));
        assert!(Arc::ptr_eq(&service.headers, &clone.headers));
    }

    #[test]
    fn test_disabled_security() {
        let config = SecurityConfig {
            enabled: false,
            ..Default::default()
        };
        let layer = build_security_headers_layer(&config);
        assert!(layer.is_none());
    }

    #[test]
    fn test_hsts_header() {
        let config = SecurityConfig {
            enabled: true,
            hsts_max_age: 31536000,
            hsts_include_subdomains: true,
            ..Default::default()
        };
        let headers = build_security_headers(&config);
        assert!(headers.contains_key("strict-transport-security"));
    }

    #[test]
    fn test_nosniff_header() {
        let config = SecurityConfig {
            enabled: true,
            nosniff: true,
            ..Default::default()
        };
        let headers = build_security_headers(&config);
        assert_eq!(
            headers.get("x-content-type-options"),
            Some(&HeaderValue::from_static("nosniff"))
        );
    }
}
