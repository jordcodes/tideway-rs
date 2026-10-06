//! End-to-end tests for social login (OAuth 2.0 / OpenID Connect).
//!
//! A local mock provider serves the token endpoint, JWKS, and GitHub-style API so the full
//! authorize → callback → account resolution → token issuance path runs for real.

use async_trait::async_trait;
use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tideway::auth::oauth::{
    AccountLinking, AuthorizeOptions, InMemoryOAuthStateStore, OAuthCallbackParams, OAuthFlow,
    OAuthFlowConfig, OAuthIdentity, OAuthProvider, OAuthTokenCipher, SocialAccountStore,
    state_from_cookies,
};
use tideway::auth::{
    LoginFlow, LoginFlowConfig, LoginRequest, LoginResponse, MfaTokenStore, TokenIssuance,
    TokenIssuer, UserStore,
};
use tideway::{Result, TidewayError};

const CLIENT_ID: &str = "client-123";
const CLIENT_SECRET: &str = "secret-xyz";
const REDIRECT_URI: &str = "https://app.example/auth/callback";
const GOOD_CODE: &str = "good-code";

// =============================================================================
// Mock provider
// =============================================================================

#[derive(Default)]
struct MockState {
    /// PKCE challenge and nonce captured from the authorize URL, keyed by code.
    code_challenge: Option<String>,
    nonce: Option<String>,
    /// Overrides merged into the id_token claims.
    claim_overrides: Value,
    github_emails: Value,
    token_requests: usize,
}

struct MockProvider {
    base: String,
    state: Arc<Mutex<MockState>>,
}

struct SigningKey {
    encoding: EncodingKey,
    jwk: Value,
}

fn signing_key() -> &'static SigningKey {
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::traits::PublicKeyParts;
    static KEY: std::sync::OnceLock<SigningKey> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let private = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
        SigningKey {
            encoding: EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
            jwk: json!({
                "kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
                "n": URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
                "e": URL_SAFE_NO_PAD.encode(private.e().to_bytes_be()),
            }),
        }
    })
}

async fn start_mock() -> MockProvider {
    let state = Arc::new(Mutex::new(MockState {
        claim_overrides: json!({}),
        github_emails: json!([
            { "email": "octo@example.com", "primary": true, "verified": true }
        ]),
        ..Default::default()
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());

    let issuer = base.clone();
    let app = Router::new()
        .route(
            "/token",
            post(
                move |State(state): State<Arc<Mutex<MockState>>>,
                      Form(form): Form<HashMap<String, String>>| {
                    let issuer = issuer.clone();
                    async move { token_endpoint(state, form, issuer) }
                },
            ),
        )
        .route(
            "/jwks",
            get(|| async { Json(json!({ "keys": [signing_key().jwk.clone()] })) }),
        )
        .route(
            "/api/user",
            get(|headers: HeaderMap| async move {
                if !authorized(&headers) {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                Json(json!({ "id": 4242, "login": "octocat", "name": null, "avatar_url": "https://avatars/4242" }))
                    .into_response()
            }),
        )
        .route(
            "/api/user/emails",
            get(
                |State(state): State<Arc<Mutex<MockState>>>, headers: HeaderMap| async move {
                    if !authorized(&headers) {
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                    Json(state.lock().unwrap().github_emails.clone()).into_response()
                },
            ),
        )
        .with_state(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    MockProvider { base, state }
}

fn authorized(headers: &HeaderMap) -> bool {
    headers.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer provider-access")
}

fn token_endpoint(
    state: Arc<Mutex<MockState>>,
    form: HashMap<String, String>,
    issuer: String,
) -> axum::response::Response {
    let mut state = state.lock().unwrap();
    state.token_requests += 1;
    let field = |k: &str| form.get(k).map(String::as_str);

    if field("grant_type") != Some("authorization_code")
        || field("code") != Some(GOOD_CODE)
        || field("client_id") != Some(CLIENT_ID)
        || field("client_secret") != Some(CLIENT_SECRET)
        || field("redirect_uri") != Some(REDIRECT_URI)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_grant" })),
        )
            .into_response();
    }
    // PKCE: the verifier must hash to the challenge sent in the authorize request.
    let verifier = field("code_verifier").unwrap_or_default();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    if state.code_challenge.as_deref() != Some(challenge.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_grant", "error_description": "PKCE" })),
        )
            .into_response();
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut claims = json!({
        "iss": issuer,
        "aud": CLIENT_ID,
        "sub": "google-sub-1",
        "exp": now + 600,
        "iat": now,
        "nonce": state.nonce,
        "email": "Alice@Example.com",
        "email_verified": true,
        "name": "Alice",
    });
    for (k, v) in state.claim_overrides.as_object().unwrap() {
        claims[k] = v.clone();
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("k1".into());
    let id_token = jsonwebtoken::encode(&header, &claims, &signing_key().encoding).unwrap();

    Json(json!({
        "access_token": "provider-access",
        "refresh_token": "provider-refresh",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token,
    }))
    .into_response()
}

impl MockProvider {
    fn oidc(&self) -> OAuthProvider {
        OAuthProvider::oidc(
            "google",
            &self.base,
            format!("{}/authorize", self.base),
            format!("{}/token", self.base),
            format!("{}/jwks", self.base),
            CLIENT_ID,
            CLIENT_SECRET,
            REDIRECT_URI,
        )
    }

    fn github(&self) -> OAuthProvider {
        OAuthProvider::github(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI)
            .with_authorize_url(format!("{}/authorize", self.base))
            .with_token_url(format!("{}/token", self.base))
            .with_api_base(format!("{}/api", self.base))
    }

    /// Simulate the user approving at the provider: capture PKCE/nonce, return callback params.
    fn approve(&self, authorize_url: &str) -> OAuthCallbackParams {
        let url = url::Url::parse(authorize_url).unwrap();
        let q: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["client_id"], CLIENT_ID);
        assert_eq!(q["redirect_uri"], REDIRECT_URI);
        assert_eq!(q["code_challenge_method"], "S256");
        let mut state = self.state.lock().unwrap();
        state.code_challenge = Some(q["code_challenge"].clone());
        state.nonce = q.get("nonce").cloned();
        OAuthCallbackParams {
            code: Some(GOOD_CODE.into()),
            state: Some(q["state"].clone()),
            ..Default::default()
        }
    }

    fn override_claims(&self, overrides: Value) {
        self.state.lock().unwrap().claim_overrides = overrides;
    }
}

// =============================================================================
// Application user store
// =============================================================================

#[derive(Clone, Debug)]
struct User {
    id: String,
    email: String,
    password_hash: String,
    verified: bool,
    locked_until: Option<SystemTime>,
    mfa_enabled: bool,
}

/// (provider, subject) -> (user id, encrypted access token)
type IdentityTable = HashMap<(String, String), (String, String)>;

#[derive(Clone, Default)]
struct Accounts {
    users: Arc<Mutex<Vec<User>>>,
    identities: Arc<Mutex<IdentityTable>>,
    cipher: Option<OAuthTokenCipher>,
}

impl Accounts {
    fn new() -> Self {
        Self {
            cipher: Some(
                OAuthTokenCipher::from_base64(
                    &base64::engine::general_purpose::STANDARD.encode([3u8; 32]),
                )
                .unwrap(),
            ),
            ..Default::default()
        }
    }

    fn add(&self, email: &str, verified: bool) -> String {
        let id = format!("user-{}", self.users.lock().unwrap().len() + 1);
        self.users.lock().unwrap().push(User {
            id: id.clone(),
            email: email.into(),
            password_hash: tideway::auth::PasswordHasher::default()
                .hash("pw-123456789")
                .unwrap(),
            verified,
            locked_until: None,
            mfa_enabled: false,
        });
        id
    }

    fn update(&self, id: &str, f: impl FnOnce(&mut User)) {
        f(self
            .users
            .lock()
            .unwrap()
            .iter_mut()
            .find(|u| u.id == id)
            .unwrap());
    }

    fn user_count(&self) -> usize {
        self.users.lock().unwrap().len()
    }
}

#[async_trait]
impl UserStore for Accounts {
    type User = User;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        Ok(self
            .users
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.email == email)
            .cloned())
    }
    async fn find_by_id(&self, id: &str) -> Result<Option<User>> {
        Ok(self
            .users
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.id == id)
            .cloned())
    }
    fn user_id(&self, user: &User) -> String {
        user.id.clone()
    }
    fn user_email(&self, user: &User) -> String {
        user.email.clone()
    }
    async fn get_password_hash(&self, user: &User) -> Result<String> {
        Ok(user.password_hash.clone())
    }
    async fn update_password_hash(&self, _: &User, _: &str) -> Result<()> {
        Ok(())
    }
    async fn is_verified(&self, user: &User) -> Result<bool> {
        Ok(user.verified)
    }
    async fn mark_verified(&self, _: &User) -> Result<()> {
        Ok(())
    }
    async fn is_locked(&self, user: &User) -> Result<Option<SystemTime>> {
        Ok(user.locked_until)
    }
    async fn record_failed_attempt(&self, _: &User) -> Result<()> {
        Ok(())
    }
    async fn clear_failed_attempts(&self, _: &User) -> Result<()> {
        Ok(())
    }
    async fn has_mfa_enabled(&self, user: &User) -> Result<bool> {
        Ok(user.mfa_enabled)
    }
    #[cfg(feature = "auth-mfa")]
    async fn get_totp_secret(&self, _: &User) -> Result<Option<String>> {
        Ok(None)
    }
    #[cfg(feature = "auth-mfa")]
    async fn get_backup_codes(&self, _: &User) -> Result<Vec<String>> {
        Ok(vec!["code".into()])
    }
    #[cfg(feature = "auth-mfa")]
    async fn remove_backup_code(&self, _: &User, _: usize) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl SocialAccountStore for Accounts {
    async fn find_by_identity(&self, provider: &str, subject: &str) -> Result<Option<User>> {
        let user_id = self
            .identities
            .lock()
            .unwrap()
            .get(&(provider.to_string(), subject.to_string()))
            .map(|(id, _)| id.clone());
        match user_id {
            Some(id) => self.find_by_id(&id).await,
            None => Ok(None),
        }
    }

    async fn link_identity(&self, user: &User, identity: &OAuthIdentity) -> Result<()> {
        let encrypted = self.cipher.as_ref().unwrap().encrypt(
            &identity.provider,
            &identity.subject,
            &identity.tokens.access_token,
        )?;
        let key = (identity.provider.clone(), identity.subject.clone());
        let mut identities = self.identities.lock().unwrap();
        if identities.contains_key(&key) {
            return Err(TidewayError::conflict("identity already linked"));
        }
        identities.insert(key, (user.id.clone(), encrypted));
        Ok(())
    }

    async fn create_user_from_identity(
        &self,
        _identity: &OAuthIdentity,
        email: &str,
        password_hash: &str,
    ) -> Result<User> {
        let id = format!("user-{}", self.user_count() + 1);
        let user = User {
            id,
            email: email.into(),
            password_hash: password_hash.into(),
            verified: true,
            locked_until: None,
            mfa_enabled: false,
        };
        self.users.lock().unwrap().push(user.clone());
        Ok(user)
    }
}

struct Issuer;
impl TokenIssuer for Issuer {
    type User = User;
    fn issue(&self, user: &User, _remember_me: bool) -> Result<TokenIssuance> {
        Ok(TokenIssuance {
            access_token: format!("access-for-{}", user.id),
            refresh_token: "refresh".into(),
            expires_in: 900,
            family: "family".into(),
        })
    }
}

#[derive(Default)]
struct MfaTokens(Mutex<HashMap<String, String>>);
#[async_trait]
impl MfaTokenStore for MfaTokens {
    async fn store(&self, token: &str, user_id: &str, _ttl: Duration) -> Result<()> {
        self.0.lock().unwrap().insert(token.into(), user_id.into());
        Ok(())
    }
    async fn consume(&self, token: &str) -> Result<Option<String>> {
        Ok(self.0.lock().unwrap().remove(token))
    }
}

fn flow(
    mock: &MockProvider,
    accounts: &Accounts,
    config: OAuthFlowConfig,
) -> OAuthFlow<InMemoryOAuthStateStore, Accounts> {
    OAuthFlow::new(InMemoryOAuthStateStore::new(), accounts.clone())
        .unwrap()
        .with_provider(mock.oidc())
        .with_provider(mock.github())
        .with_config(config)
}

fn login_flow(accounts: &Accounts) -> LoginFlow<Accounts, MfaTokens, Issuer> {
    LoginFlow::new(
        accounts.clone(),
        MfaTokens::default(),
        Issuer,
        LoginFlowConfig::new("test"),
    )
}

fn status(err: &TidewayError) -> StatusCode {
    match err {
        TidewayError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
        TidewayError::Forbidden(_) => StatusCode::FORBIDDEN,
        TidewayError::Conflict(_) => StatusCode::CONFLICT,
        TidewayError::BadRequest(_) => StatusCode::BAD_REQUEST,
        TidewayError::NotFound(_) => StatusCode::NOT_FOUND,
        other => panic!("unexpected error: {other:?}"),
    }
}

/// Complete a callback from the browser that started the flow (state cookie present).
async fn callback(
    oauth: &OAuthFlow<InMemoryOAuthStateStore, Accounts>,
    provider: &str,
    params: OAuthCallbackParams,
) -> Result<tideway::auth::oauth::OAuthLoginOutcome<User>> {
    let browser_state = params.state.clone();
    oauth
        .callback(provider, params, browser_state.as_deref())
        .await
}

// =============================================================================
// Tests
// =============================================================================

#[tokio::test]
async fn oidc_sign_in_creates_verified_user_and_issues_app_tokens() {
    let mock = start_mock().await;
    let accounts = Accounts::new();
    let oauth = flow(&mock, &accounts, OAuthFlowConfig::default());

    let request = oauth
        .authorize("google", AuthorizeOptions::new().redirect_to("/dashboard"))
        .await
        .unwrap();
    let params = mock.approve(&request.url);
    assert!(
        mock.state.lock().unwrap().nonce.is_some(),
        "OIDC requests carry a nonce"
    );

    let outcome = callback(&oauth, "google", params).await.unwrap();
    assert!(outcome.is_new_user);
    assert_eq!(outcome.user.email, "alice@example.com");
    assert!(outcome.user.verified);
    assert_eq!(outcome.identity.subject, "google-sub-1");
    assert_eq!(outcome.redirect_to.as_deref(), Some("/dashboard"));

    // Provider tokens are stored encrypted, never in plaintext.
    let stored = accounts.identities.lock().unwrap()[&("google".into(), "google-sub-1".into())]
        .1
        .clone();
    assert!(!stored.contains("provider-access"));
    assert_eq!(
        accounts
            .cipher
            .as_ref()
            .unwrap()
            .decrypt("google", "google-sub-1", &stored)
            .unwrap(),
        "provider-access"
    );

    // Integrates with existing token issuance.
    let response = login_flow(&accounts)
        .complete_external_login(&outcome.user, false)
        .await
        .unwrap();
    match response {
        LoginResponse::Success { access_token, .. } => {
            assert_eq!(access_token, format!("access-for-{}", outcome.user.id))
        }
        _ => panic!("expected tokens"),
    }

    // Social-only users cannot log in with a password (and do not cause a 500).
    let password_login = login_flow(&accounts)
        .login(LoginRequest {
            email: "alice@example.com".into(),
            password: "".into(),
            mfa_code: None,
            remember_me: false,
        })
        .await
        .unwrap();
    assert!(matches!(password_login, LoginResponse::Error { .. }));

    // Signing in again resolves to the same account.
    let request = oauth
        .authorize("google", AuthorizeOptions::new())
        .await
        .unwrap();
    let again = callback(&oauth, "google", mock.approve(&request.url))
        .await
        .unwrap();
    assert!(!again.is_new_user);
    assert_eq!(again.user.id, outcome.user.id);
    assert_eq!(accounts.user_count(), 1);
}

#[tokio::test]
async fn state_is_single_use() {
    let mock = start_mock().await;
    let accounts = Accounts::new();
    let oauth = flow(&mock, &accounts, OAuthFlowConfig::default());

    let request = oauth
        .authorize("google", AuthorizeOptions::new())
        .await
        .unwrap();
    let params = mock.approve(&request.url);
    callback(&oauth, "google", params.clone()).await.unwrap();

    let replay = callback(&oauth, "google", params).await.unwrap_err();
    assert_eq!(status(&replay), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn forged_or_cross_provider_state_is_rejected_before_code_exchange() {
    let mock = start_mock().await;
    let accounts = Accounts::new();
    let oauth = flow(&mock, &accounts, OAuthFlowConfig::default());

    let forged = OAuthCallbackParams {
        code: Some(GOOD_CODE.into()),
        state: Some("attacker-state".into()),
        ..Default::default()
    };
    assert_eq!(
        status(&callback(&oauth, "google", forged).await.unwrap_err()),
        StatusCode::UNAUTHORIZED
    );

    let request = oauth
        .authorize("google", AuthorizeOptions::new())
        .await
        .unwrap();
    let params = mock.approve(&request.url);
    assert_eq!(
        status(&callback(&oauth, "github", params).await.unwrap_err()),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(mock.state.lock().unwrap().token_requests, 0);
}

#[tokio::test]
async fn callback_from_another_browser_is_rejected() {
    // Login CSRF: the attacker starts sign-in and lures the victim to the callback URL.
    let mock = start_mock().await;
    let accounts = Accounts::new();
    let oauth = flow(&mock, &accounts, OAuthFlowConfig::default());

    let request = oauth
        .authorize("google", AuthorizeOptions::new())
        .await
        .unwrap();
    let params = mock.approve(&request.url);
    for victim_cookie in [None, Some("victims-own-state")] {
        let err = oauth
            .callback("google", params.clone(), victim_cookie)
            .await
            .unwrap_err();
        assert_eq!(status(&err), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(mock.state.lock().unwrap().token_requests, 0);
    assert_eq!(accounts.user_count(), 0);

    // The browser holding the state cookie can still finish.
    let mut headers = HeaderMap::new();
    headers.insert(
        "cookie",
        request
            .state_cookie()
            .split(';')
            .next()
            .unwrap()
            .parse()
            .unwrap(),
    );
    let browser_state = state_from_cookies(&headers);
    oauth
        .callback("google", params, browser_state.as_deref())
        .await
        .unwrap();
}

#[tokio::test]
async fn id_token_with_wrong_nonce_audience_or_issuer_is_rejected() {
    for overrides in [
        json!({ "nonce": "replayed-nonce" }),
        json!({ "aud": "someone-else" }),
        json!({ "iss": "https://evil.example" }),
        json!({ "exp": 1 }),
    ] {
        let mock = start_mock().await;
        let accounts = Accounts::new();
        let oauth = flow(&mock, &accounts, OAuthFlowConfig::default());
        mock.override_claims(overrides.clone());

        let request = oauth
            .authorize("google", AuthorizeOptions::new())
            .await
            .unwrap();
        let err = callback(&oauth, "google", mock.approve(&request.url))
            .await
            .unwrap_err();
        assert_eq!(status(&err), StatusCode::UNAUTHORIZED, "{overrides}");
        assert_eq!(accounts.user_count(), 0, "{overrides}");
    }
}

#[tokio::test]
async fn pkce_verifier_must_match_challenge() {
    let mock = start_mock().await;
    let accounts = Accounts::new();
    let oauth = flow(&mock, &accounts, OAuthFlowConfig::default());

    let request = oauth
        .authorize("google", AuthorizeOptions::new())
        .await
        .unwrap();
    let params = mock.approve(&request.url);
    // Simulate an intercepted code redeemed against a different authorization request.
    mock.state.lock().unwrap().code_challenge = Some("other-challenge".into());

    let err = callback(&oauth, "google", params).await.unwrap_err();
    assert_eq!(status(&err), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unverified_oidc_email_cannot_create_or_link_accounts() {
    let mock = start_mock().await;
    let accounts = Accounts::new();
    accounts.add("alice@example.com", true);
    let oauth = flow(&mock, &accounts, OAuthFlowConfig::default());
    mock.override_claims(json!({ "email_verified": false }));

    let request = oauth
        .authorize("google", AuthorizeOptions::new())
        .await
        .unwrap();
    let err = callback(&oauth, "google", mock.approve(&request.url))
        .await
        .unwrap_err();
    assert_eq!(status(&err), StatusCode::FORBIDDEN);
    assert!(accounts.identities.lock().unwrap().is_empty());
}

#[tokio::test]
async fn github_sign_in_uses_numeric_id_and_primary_verified_email() {
    let mock = start_mock().await;
    let accounts = Accounts::new();
    let oauth = flow(&mock, &accounts, OAuthFlowConfig::default());

    let request = oauth
        .authorize("github", AuthorizeOptions::new())
        .await
        .unwrap();
    assert!(!request.url.contains("nonce="), "GitHub is not OIDC");
    let outcome = callback(&oauth, "github", mock.approve(&request.url))
        .await
        .unwrap();

    assert!(outcome.is_new_user);
    assert_eq!(outcome.identity.subject, "4242");
    assert_eq!(outcome.identity.name.as_deref(), Some("octocat"));
    assert_eq!(outcome.user.email, "octo@example.com");
}

#[tokio::test]
async fn github_without_verified_email_cannot_sign_up() {
    let mock = start_mock().await;
    mock.state.lock().unwrap().github_emails = json!([
        { "email": "octo@example.com", "primary": true, "verified": false },
        { "email": "other@example.com", "primary": false, "verified": true }
    ]);
    let accounts = Accounts::new();
    let oauth = flow(&mock, &accounts, OAuthFlowConfig::default());

    let request = oauth
        .authorize("github", AuthorizeOptions::new())
        .await
        .unwrap();
    let err = callback(&oauth, "github", mock.approve(&request.url))
        .await
        .unwrap_err();
    assert_eq!(status(&err), StatusCode::FORBIDDEN);
    assert_eq!(accounts.user_count(), 0);
}

#[tokio::test]
async fn links_to_existing_verified_account_by_email() {
    let mock = start_mock().await;
    let accounts = Accounts::new();
    let existing = accounts.add("octo@example.com", true);
    let oauth = flow(&mock, &accounts, OAuthFlowConfig::default());

    let request = oauth
        .authorize("github", AuthorizeOptions::new())
        .await
        .unwrap();
    let outcome = callback(&oauth, "github", mock.approve(&request.url))
        .await
        .unwrap();
    assert_eq!(outcome.user.id, existing);
    assert!(outcome.linked);
    assert!(!outcome.is_new_user);
    assert_eq!(accounts.user_count(), 1);
}

#[tokio::test]
async fn refuses_to_link_unverified_local_account_or_when_linking_disabled() {
    // An attacker pre-registered the victim's email but never verified it.
    let mock = start_mock().await;
    let accounts = Accounts::new();
    accounts.add("octo@example.com", false);
    let oauth = flow(&mock, &accounts, OAuthFlowConfig::default());
    let request = oauth
        .authorize("github", AuthorizeOptions::new())
        .await
        .unwrap();
    let err = callback(&oauth, "github", mock.approve(&request.url))
        .await
        .unwrap_err();
    assert_eq!(status(&err), StatusCode::CONFLICT);
    assert!(accounts.identities.lock().unwrap().is_empty());

    let accounts = Accounts::new();
    accounts.add("octo@example.com", true);
    let oauth = flow(
        &mock,
        &accounts,
        OAuthFlowConfig::default().account_linking(AccountLinking::Never),
    );
    let request = oauth
        .authorize("github", AuthorizeOptions::new())
        .await
        .unwrap();
    let err = callback(&oauth, "github", mock.approve(&request.url))
        .await
        .unwrap_err();
    assert_eq!(status(&err), StatusCode::CONFLICT);
}

#[tokio::test]
async fn signup_can_be_disabled() {
    let mock = start_mock().await;
    let accounts = Accounts::new();
    let oauth = flow(
        &mock,
        &accounts,
        OAuthFlowConfig::default().allow_signup(false),
    );
    let request = oauth
        .authorize("github", AuthorizeOptions::new())
        .await
        .unwrap();
    let err = callback(&oauth, "github", mock.approve(&request.url))
        .await
        .unwrap_err();
    assert_eq!(status(&err), StatusCode::FORBIDDEN);
    assert_eq!(accounts.user_count(), 0);
}

#[tokio::test]
async fn explicit_connect_links_to_signed_in_user_and_rejects_identity_owned_by_another() {
    let mock = start_mock().await;
    let accounts = Accounts::new();
    // Different email from the provider: explicit linking does not depend on email.
    let me = accounts.add("me@example.com", true);
    let other = accounts.add("other@example.com", true);
    let oauth = flow(&mock, &accounts, OAuthFlowConfig::default());

    let request = oauth
        .authorize("github", AuthorizeOptions::new().link_to_user(&me))
        .await
        .unwrap();
    let outcome = callback(&oauth, "github", mock.approve(&request.url))
        .await
        .unwrap();
    assert_eq!(outcome.user.id, me);
    assert!(outcome.linked);

    let request = oauth
        .authorize("github", AuthorizeOptions::new().link_to_user(&other))
        .await
        .unwrap();
    let err = callback(&oauth, "github", mock.approve(&request.url))
        .await
        .unwrap_err();
    assert_eq!(status(&err), StatusCode::CONFLICT);
}

#[tokio::test]
async fn provider_error_consumes_state_and_is_reported() {
    let mock = start_mock().await;
    let accounts = Accounts::new();
    let oauth = flow(&mock, &accounts, OAuthFlowConfig::default());

    let request = oauth
        .authorize("google", AuthorizeOptions::new())
        .await
        .unwrap();
    let mut params = mock.approve(&request.url);
    params.code = None;
    params.error = Some("access_denied".into());
    let err = callback(&oauth, "google", params.clone())
        .await
        .unwrap_err();
    assert_eq!(status(&err), StatusCode::UNAUTHORIZED);
    assert_eq!(mock.state.lock().unwrap().token_requests, 0);
}

#[tokio::test]
async fn rejects_open_redirects_and_unknown_providers() {
    let mock = start_mock().await;
    let accounts = Accounts::new();
    let oauth = flow(&mock, &accounts, OAuthFlowConfig::default());

    let err = oauth
        .authorize(
            "google",
            AuthorizeOptions::new().redirect_to("https://evil.example"),
        )
        .await
        .unwrap_err();
    assert_eq!(status(&err), StatusCode::BAD_REQUEST);

    let err = oauth
        .authorize("myspace", AuthorizeOptions::new())
        .await
        .unwrap_err();
    assert_eq!(status(&err), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn locked_accounts_cannot_sign_in() {
    let mock = start_mock().await;
    let accounts = Accounts::new();
    let id = accounts.add("octo@example.com", true);
    let oauth = flow(&mock, &accounts, OAuthFlowConfig::default());
    let request = oauth
        .authorize("github", AuthorizeOptions::new())
        .await
        .unwrap();
    callback(&oauth, "github", mock.approve(&request.url))
        .await
        .unwrap();

    accounts.update(&id, |u| {
        u.locked_until = Some(SystemTime::now() + Duration::from_secs(600))
    });
    let request = oauth
        .authorize("github", AuthorizeOptions::new())
        .await
        .unwrap();
    let err = callback(&oauth, "github", mock.approve(&request.url))
        .await
        .unwrap_err();
    assert_eq!(status(&err), StatusCode::FORBIDDEN);

    let user = accounts.find_by_id(&id).await.unwrap().unwrap();
    let response = login_flow(&accounts)
        .complete_external_login(&user, false)
        .await
        .unwrap();
    assert!(matches!(response, LoginResponse::Error { .. }));
}

#[tokio::test]
async fn external_login_still_requires_mfa() {
    let accounts = Accounts::new();
    let id = accounts.add("mfa@example.com", true);
    accounts.update(&id, |u| u.mfa_enabled = true);
    let user = accounts.find_by_id(&id).await.unwrap().unwrap();

    let response = login_flow(&accounts)
        .complete_external_login(&user, false)
        .await
        .unwrap();
    #[cfg(feature = "auth-mfa")]
    assert!(matches!(response, LoginResponse::MfaRequired { .. }));
    #[cfg(not(feature = "auth-mfa"))]
    assert!(matches!(response, LoginResponse::Error { .. }));
}
