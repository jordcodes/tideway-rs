//! Social login via OAuth 2.0 and OpenID Connect (Google, GitHub, any OIDC provider).
//!
//! Requires the `auth-oauth` feature.
//!
//! - Authorization code flow with PKCE (S256), single-use `state` bound to the browser by an
//!   HttpOnly cookie, and OIDC `nonce`.
//! - OIDC `id_token`s are verified against the provider JWKS (signature, `iss`, `aud`,
//!   `exp`, `nonce`, `azp`).
//! - GitHub identities use the numeric user ID and only a primary, verified email.
//! - Identities resolve to users through [`SocialAccountStore`] (an extension of
//!   [`crate::auth::UserStore`]), creating or linking accounts by verified email.
//! - Finish with [`crate::auth::LoginFlow::complete_external_login`] to issue JWTs while
//!   honouring lockout and MFA, or start a cookie session for the user.
//!
//! # Example
//!
//! ```rust,ignore
//! use axum::extract::{Path, Query, State};
//! use tideway::auth::oauth::{
//!     AuthorizeOptions, InMemoryOAuthStateStore, OAuthCallbackParams, OAuthFlow, OAuthProvider,
//! };
//!
//! let oauth = OAuthFlow::new(InMemoryOAuthStateStore::new(), accounts)?
//!     .with_provider(OAuthProvider::google(google_id, google_secret, "https://app.example/auth/google/callback"))
//!     .with_provider(OAuthProvider::github(github_id, github_secret, "https://app.example/auth/github/callback"));
//!
//! async fn start(State(app): State<AppState>, Path(provider): Path<String>) -> Result<Response> {
//!     // Redirects to the provider and sets the browser-binding state cookie.
//!     Ok(app.oauth.authorize(&provider, AuthorizeOptions::new()).await?.redirect())
//! }
//!
//! async fn callback(
//!     State(app): State<AppState>,
//!     Path(provider): Path<String>,
//!     headers: HeaderMap,
//!     Query(params): Query<OAuthCallbackParams>,
//! ) -> Result<impl IntoResponse> {
//!     let browser_state = state_from_cookies(&headers);
//!     let outcome = app.oauth.callback(&provider, params, browser_state.as_deref()).await?;
//!     let login = app.login.complete_external_login(&outcome.user, false).await?;
//!     Ok(([(SET_COOKIE, clear_state_cookie())], LoginHttpResponse::from(login)))
//! }
//! ```

mod cipher;
mod flow;
mod provider;
mod state;

pub use cipher::OAuthTokenCipher;
pub use flow::{
    AccountLinking, AuthorizationRequest, AuthorizeOptions, OAUTH_STATE_COOKIE,
    OAuthCallbackParams, OAuthFlow, OAuthFlowConfig, OAuthIdentity, OAuthLoginOutcome, OAuthTokens,
    SocialAccountStore, clear_state_cookie, state_from_cookies, validate_redirect_path,
};
pub use provider::{OAuthProvider, ProviderKind};
pub use state::{InMemoryOAuthStateStore, OAuthStateStore, PendingAuthorization};
