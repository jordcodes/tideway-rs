use crate::error::TidewayError;
use axum::http::request::Parts;

/// Extracts bearer token from request headers
pub struct TokenExtractor;

impl TokenExtractor {
    /// Extract token from Authorization header
    pub fn from_header(parts: &Parts) -> Result<String, TidewayError> {
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| TidewayError::unauthorized("Missing authorization header"))?;

        if !auth_header.starts_with("Bearer ") {
            return Err(TidewayError::unauthorized(
                "Invalid authorization header format. Expected: Bearer <token>",
            ));
        }

        let token = auth_header.trim_start_matches("Bearer ").to_string();

        if token.is_empty() {
            return Err(TidewayError::unauthorized("Empty bearer token"));
        }

        Ok(token)
    }

    /// Extract token from cookie (optional, for session-based auth)
    pub fn from_cookie(parts: &Parts, cookie_name: &str) -> Result<String, TidewayError> {
        let cookie_header = parts
            .headers
            .get("cookie")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| TidewayError::unauthorized("Missing cookie header"))?;

        for cookie in cookie_header.split(';') {
            let cookie = cookie.trim();
            if let Some(value) = cookie.strip_prefix(&format!("{}=", cookie_name)) {
                return Ok(value.to_string());
            }
        }

        Err(TidewayError::unauthorized(format!(
            "Cookie '{}' not found",
            cookie_name
        )))
    }

    /// Extract token from query parameter (useful for WebSocket upgrades)
    pub fn from_query(parts: &Parts, param_name: &str) -> Result<String, TidewayError> {
        let query = parts
            .uri
            .query()
            .ok_or_else(|| TidewayError::unauthorized("No query parameters"))?;

        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                if key == param_name {
                    return Ok(value.to_string());
                }
            }
        }

        Err(TidewayError::unauthorized(format!(
            "Query parameter '{}' not found",
            param_name
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[test]
    fn test_extract_from_valid_bearer_header() {
        let req = Request::builder()
            .header("authorization", "Bearer test_token_123")
            .body(())
            .unwrap();

        let (parts, _) = req.into_parts();
        let token = TokenExtractor::from_header(&parts).unwrap();

        assert_eq!(token, "test_token_123");
    }

    #[test]
    fn test_extract_from_missing_header() {
        let req = Request::builder().body(()).unwrap();
        let (parts, _) = req.into_parts();

        let result = TokenExtractor::from_header(&parts);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_from_invalid_format() {
        let req = Request::builder()
            .header("authorization", "Basic credentials")
            .body(())
            .unwrap();

        let (parts, _) = req.into_parts();
        let result = TokenExtractor::from_header(&parts);

        assert!(result.is_err());
    }
}
