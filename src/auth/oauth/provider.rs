//! OAuth 2.0 / OpenID Connect provider configuration.

use crate::error::{Result, TidewayError};
use serde::Deserialize;
use std::fmt;

/// How a provider proves who the user is after the code exchange.
#[derive(Debug, Clone)]
pub enum ProviderKind {
    /// OpenID Connect: identity comes from a signed `id_token` verified against the
    /// provider's JWKS (signature, issuer, audience, expiry and nonce).
    Oidc {
        /// Accepted `iss` values.
        issuers: Vec<String>,
        /// JWKS endpoint used to verify `id_token` signatures.
        jwks_uri: String,
        /// Optional userinfo endpoint, used when the `id_token` carries no email.
        userinfo_url: Option<String>,
    },
    /// GitHub OAuth apps: identity comes from the REST API (`/user` and `/user/emails`).
    GitHub {
        /// API base URL (`https://api.github.com`, or a GitHub Enterprise API URL).
        api_base: String,
    },
}

/// Configuration for one sign-in provider.
///
/// Use the presets ([`Self::google`], [`Self::github`], [`Self::oidc`], [`Self::discover`])
/// and adjust with the builder methods.
#[derive(Clone)]
pub struct OAuthProvider {
    pub(crate) name: String,
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    pub(crate) redirect_uri: String,
    pub(crate) authorize_url: String,
    pub(crate) token_url: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) extra_authorize_params: Vec<(String, String)>,
    pub(crate) kind: ProviderKind,
}

impl OAuthProvider {
    /// Google sign-in (OpenID Connect).
    ///
    /// `redirect_uri` must exactly match an authorized redirect URI in the Google Cloud console.
    pub fn google(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            name: "google".to_string(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            authorize_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            scopes: vec!["openid".into(), "email".into(), "profile".into()],
            extra_authorize_params: Vec::new(),
            kind: ProviderKind::Oidc {
                issuers: vec![
                    "https://accounts.google.com".to_string(),
                    "accounts.google.com".to_string(),
                ],
                jwks_uri: "https://www.googleapis.com/oauth2/v3/certs".to_string(),
                userinfo_url: Some("https://openidconnect.googleapis.com/v1/userinfo".to_string()),
            },
        }
    }

    /// GitHub sign-in (OAuth app or GitHub App user authorization).
    ///
    /// Only a primary, verified email address from `/user/emails` is treated as the
    /// user's email, so the `user:email` scope is requested by default.
    pub fn github(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            name: "github".to_string(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            authorize_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            scopes: vec!["read:user".into(), "user:email".into()],
            extra_authorize_params: Vec::new(),
            kind: ProviderKind::GitHub {
                api_base: "https://api.github.com".to_string(),
            },
        }
    }

    /// A generic OpenID Connect provider with explicitly configured endpoints.
    #[allow(clippy::too_many_arguments)]
    pub fn oidc(
        name: impl Into<String>,
        issuer: impl Into<String>,
        authorize_url: impl Into<String>,
        token_url: impl Into<String>,
        jwks_uri: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            authorize_url: authorize_url.into(),
            token_url: token_url.into(),
            scopes: vec!["openid".into(), "email".into(), "profile".into()],
            extra_authorize_params: Vec::new(),
            kind: ProviderKind::Oidc {
                issuers: vec![issuer.into()],
                jwks_uri: jwks_uri.into(),
                userinfo_url: None,
            },
        }
    }

    /// Build a generic OpenID Connect provider from the issuer's discovery document
    /// (`{issuer}/.well-known/openid-configuration`).
    ///
    /// The discovered `issuer` must match the configured one exactly, as required by
    /// OpenID Connect Discovery.
    pub async fn discover(
        name: impl Into<String>,
        issuer: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<Self> {
        #[derive(Deserialize)]
        struct Discovery {
            issuer: String,
            authorization_endpoint: String,
            token_endpoint: String,
            jwks_uri: String,
            userinfo_endpoint: Option<String>,
        }

        let issuer = issuer.into();
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let http = super::flow::default_http_client()?;
        let response = http
            .get(&url)
            .send()
            .await
            .map_err(|e| TidewayError::internal(format!("OIDC discovery failed: {e}")))?;
        let discovery: Discovery = super::flow::read_json(response, "OIDC discovery").await?;
        if discovery.issuer != issuer {
            return Err(TidewayError::internal(format!(
                "OIDC discovery issuer mismatch: expected {issuer}, got {}",
                discovery.issuer
            )));
        }

        let mut provider = Self::oidc(
            name,
            discovery.issuer,
            discovery.authorization_endpoint,
            discovery.token_endpoint,
            discovery.jwks_uri,
            client_id,
            client_secret,
            redirect_uri,
        );
        if let ProviderKind::Oidc { userinfo_url, .. } = &mut provider.kind {
            *userinfo_url = discovery.userinfo_endpoint;
        }
        Ok(provider)
    }

    /// Provider name used in routes and stored identities (for example `google`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The provider kind.
    pub fn kind(&self) -> &ProviderKind {
        &self.kind
    }

    /// Rename the provider (useful for registering two tenants of the same provider).
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Replace the requested scopes.
    pub fn with_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Add an extra query parameter to the authorization URL
    /// (for example `prompt=select_account` or Google's `access_type=offline`).
    ///
    /// Parameters the flow controls (`state`, `nonce`, `code_challenge`, ...) cannot be overridden.
    pub fn with_authorize_param(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.extra_authorize_params.push((key.into(), value.into()));
        self
    }

    /// Override the authorization endpoint.
    pub fn with_authorize_url(mut self, url: impl Into<String>) -> Self {
        self.authorize_url = url.into();
        self
    }

    /// Override the token endpoint.
    pub fn with_token_url(mut self, url: impl Into<String>) -> Self {
        self.token_url = url.into();
        self
    }

    /// Override the OIDC JWKS endpoint (no-op for non-OIDC providers).
    pub fn with_jwks_uri(mut self, url: impl Into<String>) -> Self {
        if let ProviderKind::Oidc { jwks_uri, .. } = &mut self.kind {
            *jwks_uri = url.into();
        }
        self
    }

    /// Set the OIDC userinfo endpoint (no-op for non-OIDC providers).
    pub fn with_userinfo_url(mut self, url: impl Into<String>) -> Self {
        if let ProviderKind::Oidc { userinfo_url, .. } = &mut self.kind {
            *userinfo_url = Some(url.into());
        }
        self
    }

    /// Override the GitHub API base URL, e.g. for GitHub Enterprise (no-op for other providers).
    pub fn with_api_base(mut self, url: impl Into<String>) -> Self {
        if let ProviderKind::GitHub { api_base } = &mut self.kind {
            *api_base = url.into().trim_end_matches('/').to_string();
        }
        self
    }
}

impl fmt::Debug for OAuthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthProvider")
            .field("name", &self.name)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .field("authorize_url", &self.authorize_url)
            .field("token_url", &self.token_url)
            .field("scopes", &self.scopes)
            .field("kind", &self.kind)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_client_secret() {
        let provider = OAuthProvider::github("id", "super-secret", "https://app/cb");
        let debug = format!("{provider:?}");
        assert!(!debug.contains("super-secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn google_preset_is_oidc_with_both_issuer_spellings() {
        let provider = OAuthProvider::google("id", "secret", "https://app/cb");
        assert_eq!(provider.name(), "google");
        match provider.kind() {
            ProviderKind::Oidc { issuers, .. } => {
                assert!(issuers.contains(&"https://accounts.google.com".to_string()));
                assert!(issuers.contains(&"accounts.google.com".to_string()));
            }
            other => panic!("expected OIDC, got {other:?}"),
        }
    }
}
