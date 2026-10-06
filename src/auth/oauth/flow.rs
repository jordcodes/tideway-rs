//! OAuth 2.0 authorization-code flow with PKCE, OIDC `id_token` validation, and
//! account resolution against the application's user store.
//!
//! This module emits tracing events for security monitoring:
//! - `auth.oauth.started` - Authorization redirect issued
//! - `auth.oauth.denied` - Provider returned an error (user cancelled, etc.)
//! - `auth.oauth.failed` - State, code exchange, or identity verification failed
//! - `auth.oauth.linked` - Identity linked to an existing account
//! - `auth.oauth.signup` - New account created from an identity
//! - `auth.oauth.success` - Identity resolved to a user

use super::provider::{OAuthProvider, ProviderKind};
use super::state::{DEFAULT_STATE_TTL, OAuthStateStore, PendingAuthorization};
use crate::auth::jwt::{JwksClient, JwtVerifier};
use crate::auth::password::PasswordHasher;
use crate::auth::storage::UserStore;
use crate::error::{Result, TidewayError};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::StreamExt;
use jsonwebtoken::Algorithm;
use rand::RngCore;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use subtle::ConstantTimeEq;
use tokio::sync::OnceCell;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Tokens returned by the provider's token endpoint.
#[derive(Clone)]
pub struct OAuthTokens {
    /// Provider access token (for calling the provider's API).
    pub access_token: String,
    /// Provider refresh token, if one was issued.
    pub refresh_token: Option<String>,
    /// Access token lifetime reported by the provider.
    pub expires_in: Option<Duration>,
    /// Granted scopes, if reported.
    pub scope: Option<String>,
}

impl fmt::Debug for OAuthTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthTokens")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

/// A verified identity asserted by a provider.
#[derive(Debug, Clone)]
pub struct OAuthIdentity {
    /// Provider name (for example `google` or `github`).
    pub provider: String,
    /// Stable, provider-unique user identifier (`sub` for OIDC, numeric user ID for GitHub).
    ///
    /// Always key stored identities on `(provider, subject)`, never on email or username.
    pub subject: String,
    /// Normalized (trimmed, lowercase) email address, if the provider shared one.
    pub email: Option<String>,
    /// Whether the provider asserts that it verified `email`.
    pub email_verified: bool,
    /// Display name.
    pub name: Option<String>,
    /// Avatar URL.
    pub avatar_url: Option<String>,
    /// Provider tokens. Encrypt with [`super::OAuthTokenCipher`] before persisting.
    pub tokens: OAuthTokens,
}

impl OAuthIdentity {
    /// The email address, only if the provider verified it.
    pub fn verified_email(&self) -> Option<&str> {
        self.email.as_deref().filter(|_| self.email_verified)
    }
}

/// Storage for linking provider identities to application users.
///
/// Extends [`UserStore`] so social sign-in shares user lookup, lockout and MFA state with
/// password login. Back it with a table that has a unique constraint on
/// `(provider, subject)`.
#[async_trait]
pub trait SocialAccountStore: UserStore {
    /// Find the user linked to a provider identity.
    async fn find_by_identity(&self, provider: &str, subject: &str) -> Result<Option<Self::User>>;

    /// Link a provider identity to a user.
    async fn link_identity(&self, user: &Self::User, identity: &OAuthIdentity) -> Result<()>;

    /// Refresh stored profile data or tokens on each sign-in. Defaults to a no-op.
    async fn update_identity(&self, _user: &Self::User, _identity: &OAuthIdentity) -> Result<()> {
        Ok(())
    }

    /// Create a new user for a first-time social sign-in.
    ///
    /// `email` is the provider-verified address, so the user should be stored as verified.
    /// `password_hash` is an Argon2 hash of a random secret nobody knows: store it as the
    /// user's password hash so password login fails cleanly until the user sets a password
    /// through password reset. The identity is linked afterwards via [`Self::link_identity`].
    async fn create_user_from_identity(
        &self,
        identity: &OAuthIdentity,
        email: &str,
        password_hash: &str,
    ) -> Result<Self::User>;
}

/// When a first-time identity may be attached to an existing account with the same email.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccountLinking {
    /// Link when the provider verified the email and the existing account's email is
    /// verified too. Unverified local accounts are refused, which blocks account
    /// pre-hijacking (an attacker registering the victim's email with a password first).
    #[default]
    VerifiedEmail,
    /// Never link automatically; users must sign in and connect the provider explicitly.
    Never,
}

/// Configuration for [`OAuthFlow`].
#[derive(Debug, Clone)]
pub struct OAuthFlowConfig {
    /// How long a user has to complete sign-in at the provider.
    pub state_ttl: Duration,
    /// Whether first-time identities without a matching account create a new user.
    pub allow_signup: bool,
    /// Automatic account linking policy.
    pub account_linking: AccountLinking,
    /// Mark the state cookie `Secure` (HTTPS only). Disable only for plain-HTTP local development.
    pub secure_cookie: bool,
}

impl Default for OAuthFlowConfig {
    fn default() -> Self {
        Self {
            state_ttl: DEFAULT_STATE_TTL,
            allow_signup: true,
            account_linking: AccountLinking::default(),
            secure_cookie: true,
        }
    }
}

impl OAuthFlowConfig {
    /// Set how long a sign-in attempt stays valid.
    pub fn state_ttl(mut self, ttl: Duration) -> Self {
        self.state_ttl = ttl;
        self
    }

    /// Set whether the state cookie is marked `Secure`.
    pub fn secure_cookie(mut self, secure: bool) -> Self {
        self.secure_cookie = secure;
        self
    }

    /// Allow or forbid creating accounts from social sign-in.
    pub fn allow_signup(mut self, allow: bool) -> Self {
        self.allow_signup = allow;
        self
    }

    /// Set the automatic account linking policy.
    pub fn account_linking(mut self, policy: AccountLinking) -> Self {
        self.account_linking = policy;
        self
    }
}

/// Options for starting an authorization.
#[derive(Debug, Clone, Default)]
pub struct AuthorizeOptions {
    redirect_to: Option<String>,
    link_user_id: Option<String>,
}

impl AuthorizeOptions {
    /// Default options: sign in (or sign up), no post-login redirect.
    pub fn new() -> Self {
        Self::default()
    }

    /// Remember a same-origin path (for example `/dashboard`) to return to after sign-in.
    ///
    /// Absolute URLs and protocol-relative paths are rejected to prevent open redirects.
    pub fn redirect_to(mut self, path: impl Into<String>) -> Self {
        self.redirect_to = Some(path.into());
        self
    }

    /// Connect the provider to an already authenticated user instead of signing in.
    ///
    /// Only pass the ID of the user authenticated on the current request.
    pub fn link_to_user(mut self, user_id: impl Into<String>) -> Self {
        self.link_user_id = Some(user_id.into());
        self
    }
}

/// Where to send the browser to start sign-in.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    /// Provider authorization URL including `state`, PKCE challenge and (for OIDC) `nonce`.
    pub url: String,
    /// The raw `state` value. It must come back from the same browser on callback; see
    /// [`Self::state_cookie`].
    pub state: String,
    max_age: Duration,
    secure_cookie: bool,
}

/// Name of the cookie that binds an authorization to the browser that started it.
pub const OAUTH_STATE_COOKIE: &str = "tideway_oauth_state";

impl AuthorizationRequest {
    /// `Set-Cookie` value binding this authorization to the current browser.
    ///
    /// `HttpOnly` and `SameSite=Lax`, so it is sent on the provider's top-level redirect
    /// back to the app but cannot be read by scripts or attached by cross-site requests.
    pub fn state_cookie(&self) -> String {
        format!(
            "{OAUTH_STATE_COOKIE}={}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax{}",
            self.state,
            self.max_age.as_secs(),
            if self.secure_cookie { "; Secure" } else { "" }
        )
    }

    /// Redirect to the provider and set the state cookie.
    pub fn redirect(&self) -> axum::response::Response {
        use axum::response::IntoResponse;
        (
            [(axum::http::header::SET_COOKIE, self.state_cookie())],
            axum::response::Redirect::to(&self.url),
        )
            .into_response()
    }
}

/// Read the state cookie set by [`AuthorizationRequest::redirect`] from request headers.
pub fn state_from_cookies(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == OAUTH_STATE_COOKIE)
        .map(|(_, value)| value.to_string())
}

/// `Set-Cookie` value that removes the state cookie; send it from the callback response.
pub fn clear_state_cookie() -> String {
    format!("{OAUTH_STATE_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
}

/// Query parameters the provider sends to the redirect URI.
///
/// Use with `axum::extract::Query<OAuthCallbackParams>`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct OAuthCallbackParams {
    /// Authorization code.
    pub code: Option<String>,
    /// State value echoed back by the provider.
    pub state: Option<String>,
    /// Error code when the user denied access or the request failed.
    pub error: Option<String>,
    /// Human-readable error description.
    pub error_description: Option<String>,
}

/// Result of a successful callback.
#[derive(Debug, Clone)]
pub struct OAuthLoginOutcome<U> {
    /// The signed-in (or newly linked) user.
    pub user: U,
    /// The verified provider identity.
    pub identity: OAuthIdentity,
    /// Whether the account was created by this sign-in.
    pub is_new_user: bool,
    /// Whether the identity was newly linked to an existing account.
    pub linked: bool,
    /// Validated same-origin path requested when the flow started.
    pub redirect_to: Option<String>,
}

struct OidcEndpoints<'a> {
    issuers: &'a [String],
    jwks_uri: &'a str,
    userinfo_url: Option<&'a str>,
}

struct ProviderEntry {
    provider: OAuthProvider,
    id_token_verifier: OnceCell<JwtVerifier<IdTokenClaims>>,
}

/// Social sign-in via OAuth 2.0 (authorization code + PKCE) and OpenID Connect.
///
/// 1. [`Self::authorize`] creates a single-use `state`, PKCE verifier and OIDC nonce, stores
///    them in the [`OAuthStateStore`], and returns the provider URL to redirect to.
/// 2. [`Self::callback`] consumes the state, exchanges the code (with the PKCE verifier),
///    verifies the identity (signed `id_token` for OIDC, API lookups for GitHub), and
///    resolves it to a user via [`SocialAccountStore`].
///
/// Finish the login with [`crate::auth::LoginFlow::complete_external_login`] to issue JWTs
/// (honouring lockout and MFA), or create a cookie session for the returned user.
pub struct OAuthFlow<S, A> {
    providers: HashMap<String, Arc<ProviderEntry>>,
    state_store: S,
    accounts: A,
    http: Client,
    config: OAuthFlowConfig,
}

impl<S, A> OAuthFlow<S, A>
where
    S: OAuthStateStore,
    A: SocialAccountStore,
{
    /// Create a flow with no providers registered.
    pub fn new(state_store: S, accounts: A) -> Result<Self> {
        Ok(Self {
            providers: HashMap::new(),
            state_store,
            accounts,
            http: default_http_client()?,
            config: OAuthFlowConfig::default(),
        })
    }

    /// Register a provider. Registering a second provider with the same name replaces it.
    pub fn with_provider(mut self, provider: OAuthProvider) -> Self {
        self.providers.insert(
            provider.name.clone(),
            Arc::new(ProviderEntry {
                provider,
                id_token_verifier: OnceCell::new(),
            }),
        );
        self
    }

    /// Replace the configuration.
    pub fn with_config(mut self, config: OAuthFlowConfig) -> Self {
        self.config = config;
        self
    }

    /// Use a custom HTTP client for provider requests.
    ///
    /// Configure timeouts and disable redirects; token requests carry the client secret.
    pub fn with_http_client(mut self, http: Client) -> Self {
        self.http = http;
        self
    }

    /// Names of the registered providers.
    pub fn provider_names(&self) -> impl Iterator<Item = &str> {
        self.providers.keys().map(String::as_str)
    }

    /// The account store.
    pub fn accounts(&self) -> &A {
        &self.accounts
    }

    fn provider(&self, name: &str) -> Result<&Arc<ProviderEntry>> {
        self.providers
            .get(name)
            .ok_or_else(|| TidewayError::not_found("Unknown sign-in provider"))
    }

    /// Start sign-in: store a single-use state and return the provider redirect.
    pub async fn authorize(
        &self,
        provider: &str,
        options: AuthorizeOptions,
    ) -> Result<AuthorizationRequest> {
        let entry = self.provider(provider)?;
        let provider = &entry.provider;
        let redirect_to = options
            .redirect_to
            .map(|path| validate_redirect_path(&path).map(str::to_string))
            .transpose()?;

        let state = random_token();
        let pkce_verifier = random_token();
        let nonce = random_token();
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce_verifier.as_bytes()));
        let is_oidc = matches!(provider.kind, ProviderKind::Oidc { .. });

        let mut url = url::Url::parse(&provider.authorize_url).map_err(|e| {
            TidewayError::internal(format!("Invalid authorize URL for {}: {e}", provider.name))
        })?;
        {
            let mut query = url.query_pairs_mut();
            for (key, value) in &provider.extra_authorize_params {
                if !RESERVED_AUTHORIZE_PARAMS.contains(&key.as_str()) {
                    query.append_pair(key, value);
                }
            }
            query
                .append_pair("response_type", "code")
                .append_pair("client_id", &provider.client_id)
                .append_pair("redirect_uri", &provider.redirect_uri)
                .append_pair("scope", &provider.scopes.join(" "))
                .append_pair("state", &state)
                .append_pair("code_challenge", &code_challenge)
                .append_pair("code_challenge_method", "S256");
            if is_oidc {
                query.append_pair("nonce", &nonce);
            }
        }

        self.state_store
            .store(
                &hash_state(&state),
                PendingAuthorization {
                    provider: provider.name.clone(),
                    pkce_verifier,
                    nonce,
                    redirect_to,
                    link_user_id: options.link_user_id,
                },
                SystemTime::now() + self.config.state_ttl,
            )
            .await?;

        tracing::info!(target: "auth.oauth.started", provider = %provider.name, "OAuth authorization started");
        Ok(AuthorizationRequest {
            url: url.into(),
            state,
            max_age: self.config.state_ttl,
            secure_cookie: self.config.secure_cookie,
        })
    }

    /// Handle the provider redirect: validate state, exchange the code, verify the identity
    /// and resolve it to a user.
    ///
    /// `browser_state` is the state remembered by the browser that started the flow, usually
    /// [`state_from_cookies`]. It must equal the returned `state`; otherwise an attacker could
    /// make a victim's browser complete the attacker's sign-in (login CSRF) or attach the
    /// victim's provider account to the attacker's user.
    pub async fn callback(
        &self,
        provider: &str,
        params: OAuthCallbackParams,
        browser_state: Option<&str>,
    ) -> Result<OAuthLoginOutcome<A::User>> {
        let entry = self.provider(provider)?;
        let provider = &entry.provider;

        let state = params
            .state
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| TidewayError::bad_request("Missing sign-in state"))?;
        let same_browser = browser_state
            .is_some_and(|expected| bool::from(expected.as_bytes().ct_eq(state.as_bytes())));
        if !same_browser {
            tracing::warn!(target: "auth.oauth.failed", provider = %provider.name, reason = "browser_mismatch", "OAuth callback state does not match the browser's state cookie");
            return Err(TidewayError::unauthorized(
                "Sign-in attempt expired or is invalid. Please try again.",
            ));
        }
        let pending = self
            .state_store
            .consume(&hash_state(state))
            .await?
            .ok_or_else(|| {
                tracing::warn!(target: "auth.oauth.failed", provider = %provider.name, reason = "invalid_state", "OAuth callback with unknown or expired state");
                TidewayError::unauthorized("Sign-in attempt expired or is invalid. Please try again.")
            })?;
        if pending.provider != provider.name {
            tracing::warn!(target: "auth.oauth.failed", provider = %provider.name, reason = "provider_mismatch", "OAuth state issued for a different provider");
            return Err(TidewayError::unauthorized(
                "Sign-in attempt expired or is invalid. Please try again.",
            ));
        }

        if let Some(error) = params.error {
            tracing::info!(target: "auth.oauth.denied", provider = %provider.name, error = %error, description = ?params.error_description, "Provider returned an authorization error");
            return Err(TidewayError::unauthorized(format!(
                "Sign-in with {} was cancelled or denied",
                provider.name
            )));
        }
        let code = params
            .code
            .as_deref()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| TidewayError::bad_request("Missing authorization code"))?;

        let (tokens, id_token) = self.exchange_code(provider, code, &pending).await?;
        let identity = match &provider.kind {
            ProviderKind::Oidc {
                issuers,
                jwks_uri,
                userinfo_url,
            } => {
                let id_token = id_token
                    .ok_or_else(|| identity_failed(provider, "token response has no id_token"))?;
                let oidc = OidcEndpoints {
                    issuers,
                    jwks_uri,
                    userinfo_url: userinfo_url.as_deref(),
                };
                self.oidc_identity(entry, &oidc, &id_token, tokens, &pending)
                    .await?
            }
            ProviderKind::GitHub { api_base } => {
                self.github_identity(provider, api_base, tokens).await?
            }
        };

        self.resolve(identity, pending).await
    }

    async fn exchange_code(
        &self,
        provider: &OAuthProvider,
        code: &str,
        pending: &PendingAuthorization,
    ) -> Result<(OAuthTokens, Option<String>)> {
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: Option<String>,
            refresh_token: Option<String>,
            expires_in: Option<u64>,
            scope: Option<String>,
            id_token: Option<String>,
            error: Option<String>,
        }

        let response = self
            .http
            .post(&provider.token_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", provider.redirect_uri.as_str()),
                ("client_id", provider.client_id.as_str()),
                ("client_secret", provider.client_secret.as_str()),
                ("code_verifier", pending.pkce_verifier.as_str()),
            ])
            .send()
            .await
            .map_err(|e| exchange_failed(provider, format!("request error: {e}")))?;
        if !response.status().is_success() {
            return Err(exchange_failed(
                provider,
                format!("token endpoint returned {}", response.status()),
            ));
        }
        let body: TokenResponse = read_json(response, "OAuth token response")
            .await
            .map_err(|e| exchange_failed(provider, e.to_string()))?;
        // GitHub reports failures with 200 OK and an `error` field.
        if let Some(error) = body.error {
            return Err(exchange_failed(
                provider,
                format!("provider error: {error}"),
            ));
        }
        let access_token = body
            .access_token
            .filter(|t| !t.is_empty())
            .ok_or_else(|| exchange_failed(provider, "missing access_token".into()))?;

        let tokens = OAuthTokens {
            access_token,
            refresh_token: body.refresh_token,
            expires_in: body.expires_in.map(Duration::from_secs),
            scope: body.scope,
        };
        Ok((tokens, body.id_token))
    }

    async fn oidc_identity(
        &self,
        entry: &ProviderEntry,
        oidc: &OidcEndpoints<'_>,
        id_token: &str,
        tokens: OAuthTokens,
        pending: &PendingAuthorization,
    ) -> Result<OAuthIdentity> {
        let provider = &entry.provider;
        let OidcEndpoints {
            issuers,
            jwks_uri,
            userinfo_url,
        } = *oidc;

        let verifier = entry
            .id_token_verifier
            .get_or_try_init(|| async {
                Ok::<_, TidewayError>(
                    JwtVerifier::<IdTokenClaims>::from_jwks_url_with_client(
                        jwks_uri,
                        Algorithm::RS256,
                        JwksClient::with_http_client(self.http.clone()),
                    )
                    .await?
                    .with_issuers(issuers.iter().cloned())
                    .with_audience(provider.client_id.clone()),
                )
            })
            .await
            .map_err(|e| identity_failed(provider, &format!("JWKS unavailable: {e}")))?;

        let claims = verifier
            .verify(id_token)
            .await
            .map_err(|e| identity_failed(provider, &format!("invalid id_token: {e}")))?
            .claims;

        let nonce_matches = claims
            .nonce
            .as_deref()
            .is_some_and(|nonce| bool::from(nonce.as_bytes().ct_eq(pending.nonce.as_bytes())));
        if !nonce_matches {
            return Err(identity_failed(provider, "id_token nonce mismatch"));
        }
        if claims
            .azp
            .as_deref()
            .is_some_and(|azp| azp != provider.client_id)
        {
            return Err(identity_failed(provider, "id_token azp mismatch"));
        }
        if claims.sub.is_empty() {
            return Err(identity_failed(provider, "id_token has empty sub"));
        }

        let mut email = claims.email;
        let mut email_verified = claims.email_verified.unwrap_or(false);
        let mut name = claims.name;
        let mut picture = claims.picture;

        if email.is_none()
            && let Some(userinfo_url) = userinfo_url
        {
            let response = self
                .http
                .get(userinfo_url)
                .bearer_auth(&tokens.access_token)
                .send()
                .await
                .map_err(|e| identity_failed(provider, &format!("userinfo request error: {e}")))?;
            if !response.status().is_success() {
                return Err(identity_failed(
                    provider,
                    &format!("userinfo returned {}", response.status()),
                ));
            }
            let info: UserInfo = read_json(response, "OIDC userinfo")
                .await
                .map_err(|e| identity_failed(provider, &e.to_string()))?;
            // Userinfo responses are only trustworthy for the subject in the verified id_token.
            if info.sub != claims.sub {
                return Err(identity_failed(provider, "userinfo sub mismatch"));
            }
            email = info.email;
            email_verified = info.email_verified.unwrap_or(false);
            name = name.or(info.name);
            picture = picture.or(info.picture);
        }

        Ok(OAuthIdentity {
            provider: provider.name.clone(),
            subject: claims.sub,
            email: email.map(|e| normalize_email(&e)),
            email_verified,
            name,
            avatar_url: picture,
            tokens,
        })
    }

    async fn github_identity(
        &self,
        provider: &OAuthProvider,
        api_base: &str,
        tokens: OAuthTokens,
    ) -> Result<OAuthIdentity> {
        #[derive(Deserialize)]
        struct GitHubUser {
            id: u64,
            login: String,
            name: Option<String>,
            avatar_url: Option<String>,
        }
        #[derive(Deserialize)]
        struct GitHubEmail {
            email: String,
            primary: bool,
            verified: bool,
        }

        let user_response = self
            .github_get(api_base, "/user", &tokens.access_token)
            .await
            .map_err(|e| identity_failed(provider, &e))?;
        if !user_response.status().is_success() {
            return Err(identity_failed(
                provider,
                &format!("GET /user returned {}", user_response.status()),
            ));
        }
        let user: GitHubUser = read_json(user_response, "GitHub user")
            .await
            .map_err(|e| identity_failed(provider, &e.to_string()))?;

        // `/user.email` is the public profile email and is not guaranteed verified; only
        // trust a primary address that GitHub reports as verified.
        let email = match self
            .github_get(api_base, "/user/emails", &tokens.access_token)
            .await
        {
            Ok(response) if response.status().is_success() => {
                read_json::<Vec<GitHubEmail>>(response, "GitHub emails")
                    .await
                    .map_err(|e| identity_failed(provider, &e.to_string()))?
                    .into_iter()
                    .find(|e| e.primary && e.verified)
                    .map(|e| normalize_email(&e.email))
            }
            Ok(response) => {
                tracing::warn!(provider = %provider.name, status = %response.status(), "GitHub /user/emails unavailable; is the user:email scope granted?");
                None
            }
            Err(error) => {
                tracing::warn!(provider = %provider.name, error = %error, "GitHub /user/emails request failed");
                None
            }
        };

        Ok(OAuthIdentity {
            provider: provider.name.clone(),
            subject: user.id.to_string(),
            email_verified: email.is_some(),
            email,
            name: user.name.or(Some(user.login)),
            avatar_url: user.avatar_url,
            tokens,
        })
    }

    async fn github_get(
        &self,
        api_base: &str,
        path: &str,
        access_token: &str,
    ) -> std::result::Result<reqwest::Response, String> {
        self.http
            .get(format!("{api_base}{path}"))
            .bearer_auth(access_token)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .map_err(|e| format!("GET {path} failed: {e}"))
    }

    async fn resolve(
        &self,
        identity: OAuthIdentity,
        pending: PendingAuthorization,
    ) -> Result<OAuthLoginOutcome<A::User>> {
        let accounts = &self.accounts;
        let existing = accounts
            .find_by_identity(&identity.provider, &identity.subject)
            .await?;

        // Connecting a provider to the signed-in user.
        if let Some(link_user_id) = pending.link_user_id {
            let user = accounts
                .find_by_id(&link_user_id)
                .await?
                .ok_or_else(|| TidewayError::unauthorized("User not found"))?;
            let linked = match existing {
                Some(owner) if accounts.user_id(&owner) != link_user_id => {
                    return Err(TidewayError::conflict(format!(
                        "This {} account is already connected to another user",
                        identity.provider
                    )));
                }
                Some(_) => {
                    accounts.update_identity(&user, &identity).await?;
                    false
                }
                None => {
                    accounts.link_identity(&user, &identity).await?;
                    tracing::info!(target: "auth.oauth.linked", provider = %identity.provider, user_id = %link_user_id, mode = "explicit", "Identity connected to signed-in user");
                    true
                }
            };
            return Ok(OAuthLoginOutcome {
                user,
                identity,
                is_new_user: false,
                linked,
                redirect_to: pending.redirect_to,
            });
        }

        let (user, is_new_user, linked) = if let Some(user) = existing {
            accounts.update_identity(&user, &identity).await?;
            (user, false, false)
        } else {
            let email = identity.verified_email().ok_or_else(|| {
                TidewayError::forbidden(format!(
                    "Your {} account has no verified email address",
                    identity.provider
                ))
            })?;

            if let Some(user) = accounts.find_by_email(email).await? {
                let may_link = self.config.account_linking == AccountLinking::VerifiedEmail
                    && accounts.is_verified(&user).await?;
                if !may_link {
                    return Err(TidewayError::conflict(format!(
                        "An account with this email already exists. Sign in with your password, then connect {} from your account settings.",
                        identity.provider
                    )));
                }
                accounts.link_identity(&user, &identity).await?;
                tracing::info!(target: "auth.oauth.linked", provider = %identity.provider, user_id = %accounts.user_id(&user), mode = "verified_email", "Identity linked to existing account");
                (user, false, true)
            } else {
                if !self.config.allow_signup {
                    return Err(TidewayError::forbidden(
                        "No account exists for this email address",
                    ));
                }
                let password_hash = PasswordHasher::default()
                    .hash_async(&random_token())
                    .await?;
                let user = accounts
                    .create_user_from_identity(&identity, email, &password_hash)
                    .await?;
                accounts.link_identity(&user, &identity).await?;
                tracing::info!(target: "auth.oauth.signup", provider = %identity.provider, user_id = %accounts.user_id(&user), "Account created from social sign-in");
                (user, true, false)
            }
        };

        if let Some(until) = accounts.is_locked(&user).await?
            && until > SystemTime::now()
        {
            tracing::warn!(target: "auth.oauth.failed", provider = %identity.provider, user_id = %accounts.user_id(&user), reason = "locked", "Social sign-in blocked: account locked");
            return Err(TidewayError::forbidden(
                "Account temporarily locked. Try again later.",
            ));
        }

        tracing::info!(target: "auth.oauth.success", provider = %identity.provider, user_id = %accounts.user_id(&user), is_new_user, "Social sign-in resolved");
        Ok(OAuthLoginOutcome {
            user,
            identity,
            is_new_user,
            linked,
            redirect_to: pending.redirect_to,
        })
    }
}

const RESERVED_AUTHORIZE_PARAMS: &[&str] = &[
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method",
    "nonce",
];

#[derive(Clone, Deserialize)]
struct IdTokenClaims {
    sub: String,
    nonce: Option<String>,
    azp: Option<String>,
    email: Option<String>,
    #[serde(default, deserialize_with = "lenient_bool")]
    email_verified: Option<bool>,
    name: Option<String>,
    picture: Option<String>,
}

#[derive(Deserialize)]
struct UserInfo {
    sub: String,
    email: Option<String>,
    #[serde(default, deserialize_with = "lenient_bool")]
    email_verified: Option<bool>,
    name: Option<String>,
    picture: Option<String>,
}

/// Some providers encode `email_verified` as the string `"true"`.
fn lenient_bool<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Option<bool>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BoolOrString {
        Bool(bool),
        String(String),
    }
    Ok(match Option::<BoolOrString>::deserialize(d)? {
        Some(BoolOrString::Bool(b)) => Some(b),
        Some(BoolOrString::String(s)) => Some(s.eq_ignore_ascii_case("true")),
        None => None,
    })
}

pub(crate) fn default_http_client() -> Result<Client> {
    Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("tideway/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| TidewayError::internal(format!("Failed to build OAuth HTTP client: {e}")))
}

/// Read a JSON body with a size cap.
pub(crate) async fn read_json<T: DeserializeOwned>(
    response: reqwest::Response,
    context: &str,
) -> Result<T> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
    {
        return Err(TidewayError::internal(format!("{context} is too large")));
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| TidewayError::internal(format!("Failed to read {context}: {e}")))?;
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(TidewayError::internal(format!("{context} is too large")));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|e| TidewayError::internal(format!("Invalid {context}: {e}")))
}

fn exchange_failed(provider: &OAuthProvider, detail: String) -> TidewayError {
    tracing::warn!(target: "auth.oauth.failed", provider = %provider.name, reason = "code_exchange", detail = %detail, "OAuth code exchange failed");
    TidewayError::unauthorized(format!("Sign-in with {} failed", provider.name))
}

fn identity_failed(provider: &OAuthProvider, detail: &str) -> TidewayError {
    tracing::warn!(target: "auth.oauth.failed", provider = %provider.name, reason = "identity", detail = %detail, "OAuth identity verification failed");
    TidewayError::unauthorized(format!("Sign-in with {} failed", provider.name))
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn hash_state(state: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(state.as_bytes()))
}

fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Accept only same-origin absolute paths such as `/dashboard?tab=1`.
pub fn validate_redirect_path(path: &str) -> Result<&str> {
    let valid = path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains('\\')
        && !path.chars().any(char::is_control);
    if valid {
        Ok(path)
    } else {
        Err(TidewayError::bad_request(
            "redirect_to must be a same-origin path starting with '/'",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_cookie_round_trips_through_cookie_header() {
        let request = AuthorizationRequest {
            url: "https://provider/authorize".into(),
            state: "abc123".into(),
            max_age: Duration::from_secs(600),
            secure_cookie: true,
        };
        let cookie = request.state_cookie();
        for attribute in [
            "HttpOnly",
            "SameSite=Lax",
            "Secure",
            "Max-Age=600",
            "Path=/",
        ] {
            assert!(cookie.contains(attribute), "{cookie} missing {attribute}");
        }

        let response = request.redirect();
        assert_eq!(
            response.headers()[axum::http::header::SET_COOKIE],
            cookie.as_str()
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("other=1; {OAUTH_STATE_COOKIE}=abc123; x=y")
                .parse()
                .unwrap(),
        );
        assert_eq!(state_from_cookies(&headers).as_deref(), Some("abc123"));
        assert_eq!(state_from_cookies(&axum::http::HeaderMap::new()), None);
        assert!(clear_state_cookie().contains("Max-Age=0"));
    }

    #[test]
    fn redirect_paths_reject_open_redirects() {
        assert!(validate_redirect_path("/dashboard?tab=1").is_ok());
        for bad in [
            "https://evil.example",
            "//evil.example",
            "/\\evil.example",
            "/foo\nbar",
            "dashboard",
            "",
        ] {
            assert!(
                validate_redirect_path(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn tokens_debug_is_redacted() {
        let tokens = OAuthTokens {
            access_token: "at-secret".into(),
            refresh_token: Some("rt-secret".into()),
            expires_in: None,
            scope: None,
        };
        let debug = format!("{tokens:?}");
        assert!(!debug.contains("at-secret"));
        assert!(!debug.contains("rt-secret"));
    }

    #[test]
    fn email_verified_accepts_string_encoding() {
        let claims: IdTokenClaims = serde_json::from_value(serde_json::json!({
            "sub": "1", "email_verified": "true"
        }))
        .unwrap();
        assert_eq!(claims.email_verified, Some(true));
        let claims: IdTokenClaims =
            serde_json::from_value(serde_json::json!({ "sub": "1" })).unwrap();
        assert_eq!(claims.email_verified, None);
    }
}
