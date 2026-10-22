# Authentication

Tideway provides a complete authentication system with password hashing, JWT tokens, MFA, and common auth flows.

## Features

- **Password Hashing**: Argon2id with automatic rehashing
- **JWT Tokens**: Access and refresh tokens with rotation
- **MFA**: TOTP (Google Authenticator) and backup codes
- **Social Login**: Google, GitHub, and any OpenID Connect provider via OAuth 2.0 + PKCE (opt-in)
- **Auth Flows**: Login, registration, password reset/change, email verification
- **Breach Checking**: HaveIBeenPwned integration (opt-in)
- **Session Management**: List and revoke active sessions
- **Trusted Devices**: Remember devices to skip MFA on subsequent logins
- **API Keys**: Hashed, scoped, revocable organization keys with last-used tracking
- **Account Lockout**: Progressive delays, notifications, admin unlock
- **Account Deletion**: GDPR-compliant deletion with grace period
- **Admin Impersonation**: Act as users for support with full audit trail
- **Security Events**: Comprehensive tracing for monitoring

## Quick Start

Enable the auth features in your `Cargo.toml`:

```toml
[dependencies]
tideway = { version = "0.9.0", features = ["auth", "auth-mfa"] }
```

### Basic Login Flow

```rust
use tideway::auth::{
    flows::{LoginFlow, LoginFlowConfig, LoginRequest},
    JwtIssuer, JwtIssuerConfig,
};

// Configure JWT issuer
let jwt_config = JwtIssuerConfig::with_secure_secret(&jwt_secret, "my-app")?;
let jwt_issuer = JwtIssuer::new(jwt_config)?;

// Create login flow
let config = LoginFlowConfig::new("MyApp")
    .require_verification(true);

let flow = LoginFlow::new(
    user_store,      // implements UserStore
    mfa_token_store, // implements MfaTokenStore
    token_issuer,    // implements TokenIssuer
    config,
)
.with_refresh_store(refresh_store); // implements RefreshTokenStore

// Handle login
let response = flow.login(LoginRequest {
    email: "user@example.com".to_string(),
    password: "password123".to_string(),
    remember_me: false,
    mfa_code: None,
}).await?;

match response {
    LoginResponse::Success { access_token, refresh_token, expires_in, .. } => {
        // Return tokens to client
    }
    LoginResponse::MfaRequired { mfa_token, .. } => {
        // Prompt for MFA code
    }
    LoginResponse::Error { message } => {
        // Handle error
    }
}
```

## Testing With `test-auth-bypass`

For integration tests, enable the test-only bypass feature:

```toml
[dependencies]
tideway = { version = "0.9.0", features = ["auth", "test-auth-bypass"] }
```

Then use `TestHost` or the lower-level request DSL to inject either a synthetic
user id or a full claims object:

```rust,ignore
use tideway::testing::TestHost;

let host = TestHost::new(app);

host.scenario(|scenario| {
    scenario.get("/api/me");
    scenario.with_test_user("user-123");
}).await;

host.scenario(|scenario| {
    scenario.get("/api/admin");
    scenario.with_test_claims(&MyClaims {
        sub: "admin-1".into(),
        role: "admin".into(),
    });
    scenario.status_code_should_be(200);
}).await;
```

`with_test_user(...)` calls `AuthProvider::test_claims(...)`, so your provider
should override that method when this feature is enabled. `with_test_claims(...)`
skips token verification and deserializes the supplied claims payload directly.

## Storage Traits

Implement these traits to connect the auth system to your database.

### UserStore

Core user operations for authentication:

```rust
use tideway::auth::storage::UserStore;
use async_trait::async_trait;

#[async_trait]
impl UserStore for MyUserStore {
    type User = MyUser;

    // Required: Find user by email (case-insensitive)
    async fn find_by_email(&self, email: &str) -> Result<Option<Self::User>>;

    // Required: Find user by ID
    async fn find_by_id(&self, id: &str) -> Result<Option<Self::User>>;

    // Required: Extract user ID as string
    fn user_id(&self, user: &Self::User) -> String;

    // Required: Extract user email
    fn user_email(&self, user: &Self::User) -> String;

    // Optional: Extract user name (default returns None)
    fn user_name(&self, user: &Self::User) -> Option<String>;

    // Required: Get password hash for verification
    async fn get_password_hash(&self, user: &Self::User) -> Result<String>;

    // Required: Update password hash (for rehashing)
    async fn update_password_hash(&self, user: &Self::User, hash: &str) -> Result<()>;

    // Required: Check if email is verified
    async fn is_verified(&self, user: &Self::User) -> Result<bool>;

    // Required: Mark email as verified
    async fn mark_verified(&self, user: &Self::User) -> Result<()>;

    // Required: Check if account is locked, return unlock time
    async fn is_locked(&self, user: &Self::User) -> Result<Option<SystemTime>>;

    // Required: Record failed login attempt (implement lockout logic)
    async fn record_failed_attempt(&self, user: &Self::User) -> Result<()>;

    // Required: Clear failed attempts on successful login
    async fn clear_failed_attempts(&self, user: &Self::User) -> Result<()>;

    // Required: Check if MFA is enabled
    async fn has_mfa_enabled(&self, user: &Self::User) -> Result<bool>;

    // MFA methods (only with auth-mfa feature)
    #[cfg(feature = "auth-mfa")]
    async fn get_totp_secret(&self, user: &Self::User) -> Result<Option<String>>;

    #[cfg(feature = "auth-mfa")]
    async fn get_backup_codes(&self, user: &Self::User) -> Result<Vec<String>>;

    #[cfg(feature = "auth-mfa")]
    async fn remove_backup_code(&self, user: &Self::User, index: usize) -> Result<()>;
}
```

### UserCreator

User registration:

```rust
use tideway::auth::storage::UserCreator;

#[async_trait]
impl UserCreator for MyUserStore {
    type User = MyUser;

    // Extract user ID from created user
    fn user_id(&self, user: &Self::User) -> String;

    // Check if email is already registered
    async fn email_exists(&self, email: &str) -> Result<bool>;

    // Create new user with hashed password
    async fn create_user(
        &self,
        email: &str,
        password_hash: &str,
        name: Option<&str>,
    ) -> Result<Self::User>;

    // Send verification email (integrate with your email service)
    async fn send_verification_email(&self, user: &Self::User) -> Result<()>;
}
```

### RefreshTokenStore

Token rotation and revocation:

```rust
use tideway::auth::storage::RefreshTokenStore;

#[async_trait]
impl RefreshTokenStore for MyTokenStore {
    // Check if token family has been revoked
    async fn is_family_revoked(&self, family: &str) -> Result<bool>;

    // Get current generation for reuse detection
    async fn get_family_generation(&self, family: &str) -> Result<Option<u32>>;

    // Update generation after successful refresh
    async fn set_family_generation(&self, family: &str, generation: u32) -> Result<()>;

    // Revoke a specific token family (logout)
    async fn revoke_family(&self, family: &str) -> Result<()>;

    // Revoke all tokens for a user (password change, security event)
    async fn revoke_all_for_user(&self, user_id: &str) -> Result<()>;

    // Associate new token family with user
    async fn associate_family_with_user(&self, family: &str, user_id: &str) -> Result<()>;
}
```

### MfaTokenStore

Temporary MFA challenge tokens:

```rust
use tideway::auth::storage::MfaTokenStore;

#[async_trait]
impl MfaTokenStore for MyMfaStore {
    // Store MFA token with TTL (typically 5 minutes)
    async fn store(&self, token: &str, user_id: &str, ttl: Duration) -> Result<()>;

    // Consume token (one-time use), return user_id if valid
    async fn consume(&self, token: &str) -> Result<Option<String>>;
}
```

**Note:** Use Redis or similar for MfaTokenStore in production for proper TTL handling.

### PasswordResetStore

Password reset flow:

```rust
use tideway::auth::storage::PasswordResetStore;

#[async_trait]
impl PasswordResetStore for MyResetStore {
    type User = MyUser;

    async fn find_by_email(&self, email: &str) -> Result<Option<Self::User>>;
    fn user_id(&self, user: &Self::User) -> String;

    // Store hashed reset token with expiration
    async fn store_reset_token(
        &self,
        user_id: &str,
        token_hash: &str,
        expires: SystemTime,
    ) -> Result<()>;

    // Legacy primitive retained for compatibility
    async fn consume_reset_token(&self, token_hash: &str) -> Result<Option<String>>;

    // Non-consuming preflight; complete_password_reset must revalidate after hashing
    async fn is_reset_token_valid(&self, token_hash: &str) -> Result<bool>;

    // Delete a newly stored token if delivery fails; do not invalidate older links when storing
    async fn discard_reset_token(&self, token_hash: &str) -> Result<()>;

    // Update user's password
    async fn update_password(&self, user_id: &str, hash: &str) -> Result<()>;

    // Invalidate all sessions (revoke refresh tokens)
    async fn invalidate_sessions(&self, user_id: &str) -> Result<()>;

    // Implementations must perform this lifecycle atomically:
    // claim the token, update the password, clear login/MFA lockout state,
    // invalidate all reset tokens, advance session_version, and revoke refresh sessions.
    async fn complete_password_reset(
        &self,
        token_hash: &str,
        password_hash: &str,
    ) -> Result<Option<String>>;

    // Send reset email with token
    async fn send_reset_email(
        &self,
        user: &Self::User,
        token: &str,
        expires_in: Duration,
    ) -> Result<()>;
}
```

Reset-token storage uses delivery-safe multiple-token semantics: requesting a new link must not
invalidate older links. Each link is individually single-use, and the first successful reset
invalidates every outstanding reset token for that user. If email-provider acceptance fails, the
new token is discarded while existing delivered links remain usable.

Tideway 0.8 requires `PasswordResetStore` implementations to provide the non-consuming token
preflight, delivery-failure cleanup, and atomic completion operation. Newly generated SeaORM stores
perform the password update, login/MFA lockout clearing, reset-token invalidation, session-version
advance, and refresh-session revocation in one transaction.

Generated auth modules expose `GET /auth/password-policy`, sourced from the same `PasswordPolicy`
used for registration and reset validation. Configure all three with
`AuthModule::with_password_policy`. Client errors include stable codes such as
`password_reset.invalid_or_expired_token`, `password_policy.too_short`, and
`password_policy.too_long`; display text remains intended for people rather than client branching.

Password length limits count Unicode scalar values rather than UTF-8 bytes. This keeps API
validation and the metadata contract aligned for non-ASCII passwords.

On successful reset, generated database stores increment `users.session_version` in the same
transaction as the password and lockout updates. Access-token issuance embeds that version and the
generated authentication provider compares it with the current user row. Refresh-family revocation
therefore blocks refresh immediately, while the version check also rejects access JWTs that were
issued before the reset.

### VerificationStore

Email verification:

```rust
use tideway::auth::storage::VerificationStore;

#[async_trait]
impl VerificationStore for MyVerificationStore {
    async fn store_verification_token(
        &self,
        user_id: &str,
        token_hash: &str,
        expires: SystemTime,
    ) -> Result<()>;

    async fn consume_verification_token(&self, token_hash: &str) -> Result<Option<String>>;

    async fn mark_user_verified(&self, user_id: &str) -> Result<()>;

    // Used by `EmailVerificationFlow::resend_for_user`; resends always go to
    // the account's stored address, never one from the request.
    async fn verification_email(&self, user_id: &str) -> Result<Option<String>>;

    async fn send_verification_email(
        &self,
        user_id: &str,
        email: &str,
        token: &str,
        expires_in: Duration,
    ) -> Result<()>;
}
```

## Password Hashing

Tideway uses Argon2id with secure defaults:

```rust
use tideway::auth::password::{PasswordHasher, PasswordPolicy};

// Create hasher with default config
let hasher = PasswordHasher::default();

// Hash a password
let hash = hasher.hash("user_password")?;

// Verify a password
if hasher.verify("user_password", &hash)? {
    println!("Password correct");
}

// Check if rehashing is needed (algorithm upgrade)
if hasher.needs_rehash(&hash)? {
    let new_hash = hasher.hash("user_password")?;
    // Update stored hash
}
```

### Password Policies

```rust
use tideway::auth::password::PasswordPolicy;

// Modern policy (recommended): 8+ chars, checks common passwords
let policy = PasswordPolicy::modern();

// Strict policy: 12+ chars, uppercase, lowercase, digit, special char
let policy = PasswordPolicy::strict();

// Custom policy
let policy = PasswordPolicy::new()
    .min_length(10)
    .require_uppercase()
    .require_digit();

// Validate password
policy.check("MyPassword123!")?;
```

## Password Change

For authenticated users who want to change their password (not forgot password).

### PasswordChangeStore Trait

```rust
use tideway::auth::flows::{PasswordChangeStore};
use async_trait::async_trait;

#[async_trait]
impl PasswordChangeStore for MyStore {
    // Get current password hash by user ID
    async fn get_password_hash(&self, user_id: &str) -> Result<Option<String>>;

    // Update password hash
    async fn update_password(&self, user_id: &str, hash: &str) -> Result<()>;

    // Invalidate other sessions (keep current session active)
    async fn invalidate_other_sessions(
        &self,
        user_id: &str,
        except_session_id: Option<&str>,
    ) -> Result<usize>;
}
```

### PasswordChangeFlow

```rust
use tideway::auth::flows::{PasswordChangeFlow, PasswordChangeRequest};

let flow = PasswordChangeFlow::new(store);

// User is authenticated - we have user_id from JWT
// current_session_id from token family keeps this session active
flow.change_password(
    "user-123",
    PasswordChangeRequest {
        current_password: "old-password".to_string(),
        new_password: "new-secure-password".to_string(),
    },
    Some("current-session-id"),
).await?;
```

### Configuration

```rust
use tideway::auth::flows::{PasswordChangeFlow, PasswordChangeConfig, PasswordPolicy};

let flow = PasswordChangeFlow::new(store)
    .with_policy(PasswordPolicy::strict())  // Require strong password
    .without_session_invalidation();        // Don't log out other devices
```

### Security Features

- **Current password verification**: Must know current password to change it
- **Password policy enforcement**: New password must meet requirements
- **Same password prevention**: Cannot set new password same as current
- **Session invalidation**: Logs out all other devices by default
- **Guess limiting**: Current-password attempts are limited per user (5 per 15 minutes by
  default), so a stolen session cannot be used to guess the password. Pass a shared limiter with
  `.with_rate_limiter(AuthRateLimiter::new(config))`, or `.without_rate_limiter()` only when an
  equivalent per-account limit is enforced elsewhere. The limiter is in-process; multi-replica
  deployments need a shared limit as well.

### Password Change Events

| Target | Level | Description |
|--------|-------|-------------|
| `auth.password.change_failed` | WARN | Wrong current password |
| `auth.password.change_failed` | INFO | Weak new password or same password |
| `auth.password.changed` | INFO | Password changed successfully |
| `auth.reauth.rate_limited` | WARN | Too many current-password attempts for the user |

## Password Breach Checking

Check passwords against the HaveIBeenPwned database to prevent use of compromised passwords.

Requires `auth-breach` feature:

```toml
[dependencies]
tideway = { version = "0.9.0", features = ["auth", "auth-breach"] }
```

### Basic Usage

```rust
use tideway::auth::BreachChecker;

let checker = BreachChecker::hibp();

// Check if password has been breached
let result = checker.check("password123").await?;
match result {
    Some(count) => println!("Found in {} breaches!", count),
    None => println!("Password not found in breaches"),
}

// Validate (returns error if breached)
checker.validate("my-password").await?;
```

### Configuration

```rust
use tideway::auth::BreachChecker;
use std::time::Duration;

let checker = BreachChecker::hibp()
    .with_timeout(Duration::from_secs(5))  // API timeout
    .with_min_breach_count(10)             // Only block if seen 10+ times
    .with_fail_open(true);                 // Don't block on API errors
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `timeout` | 3 seconds | API request timeout |
| `min_breach_count` | 1 | Minimum breaches to block |
| `fail_open` | `true` | Allow password if API fails |

### Privacy

Uses k-anonymity: only the first 5 characters of the SHA-1 hash are sent to the API. The full password hash never leaves your server.

### Integration with Registration

```rust
async fn register(req: RegisterRequest) -> Result<()> {
    // Check policy first (fast, no network)
    let policy = PasswordPolicy::modern();
    policy.check(&req.password)?;

    // Then check breaches (requires network)
    let checker = BreachChecker::hibp();
    checker.validate(&req.password).await?;

    // Continue with registration...
}
```

### Tracing Events

| Target | Level | Description |
|--------|-------|-------------|
| `auth.breach.api_error` | WARN | API request failed |
| `auth.breach.password_blocked` | INFO | Password rejected (breached) |

## JWT Configuration

```rust
use std::time::Duration;
use tideway::auth::{AccessTokenClaims, JwtAuth, JwtAuthConfig, TokenSubject};

let jwt_issuer_id = "my-api";
let jwt_audience = "my-api";

// HMAC-SHA256 (symmetric)
let secret = "a-random-secret-of-at-least-32-bytes";
let config = JwtAuthConfig::with_secure_secret(secret, jwt_issuer_id)?
    .audience(jwt_audience)
    .access_token_ttl(Duration::from_secs(900))      // 15 minutes
    .refresh_token_ttl(Duration::from_secs(604800))  // 7 days
    .remember_me_ttl(Duration::from_secs(2592000)); // 30 days

let jwt = JwtAuth::new(config)?;
let issuer = jwt.issuer();
let verifier = jwt.verifier::<AccessTokenClaims>()?;

// Issue tokens
let subject = TokenSubject::new("user-123")
    .with_email("user@example.com")
    .with_name("John Doe")
    .with_claim("role", "admin");

let tokens = issuer.issue(subject, false)?; // false = don't remember me
```

The returned verifier inherits the algorithm, verification key, issuer, and audience. Pass
`verifier.clone()` to protected modules. Audience validation prevents a token issued for one
service from being accepted by another service that shares signing infrastructure.
For RS256, `JwtAuthConfig::with_rsa_key_pair` validates both PEM values and confirms that the
public key verifies signatures from the private key before startup succeeds.

New CLI scaffolds expose `JWT_ISSUER` and `JWT_AUDIENCE`, default both to the Cargo package name,
and construct a paired `JwtAuth` issuer and access-token verifier at startup. Keep these
security identifiers separate from a human-readable `APP_NAME` and pass the configured verifier to
protected modules instead of reconstructing it from the raw secret. Existing applications that add
or change issuer/audience validation will invalidate incompatible tokens, so preserve established
production values and deploy issuance and verification together.

## Auth Extractors

Tideway provides extractors for common authentication patterns:

```rust,ignore
use tideway::auth::{AuthUser, OptionalAuth, RequireAdmin, Claims, ClaimsRef};

async fn me(AuthUser(user): AuthUser<MyAuthProvider>) -> Json<UserResponse> {
    Json(UserResponse::from(user))
}

async fn maybe_me(OptionalAuth(user): OptionalAuth<MyAuthProvider>) -> Json<Response> {
    Json(Response { user })
}

async fn admin_only(RequireAdmin(user): RequireAdmin<MyAuthProvider>) -> Json<AdminResponse> {
    Json(AdminResponse::from(user))
}
```

If you only need JWT claims, use `Claims` or `ClaimsRef`:

```rust,ignore
async fn whoami(ClaimsRef(claims): ClaimsRef<MyAuthProvider>) -> String {
    format!("user_id={}", claims.sub)
}
```

`ClaimsRef` reuses cached claims when available (e.g., after auth middleware), avoiding
duplicate token verification within the same request.

Both run `AuthProvider::validate_claims` after verifying the token. By default it calls
`load_user` and `validate_user`, so `session_version` revocation and banned-user checks apply to
claims-only handlers just as they do to `AuthUser`. If your `verify_token` already enforces
revocation and you want to skip the user lookup, override `validate_claims`.

## MFA (Multi-Factor Authentication)

Requires `auth-mfa` feature.

New API scaffolds provide a production-safe database-backed MFA flow:

- `POST /auth/mfa/setup` reauthenticates with the current password and returns a
  TOTP secret, URI, and QR code with `Cache-Control: no-store`.
- `POST /auth/mfa/enable` reauthenticates, verifies the first TOTP code, and
  returns recovery codes once.
- `POST /auth/mfa/verify` consumes a short-lived, one-time database challenge.
- `DELETE /auth/mfa` requires both the current password and a valid TOTP code.

Set `MFA_ENCRYPTION_KEY` to an independent base64-encoded 32-byte random key:

```bash
openssl rand -base64 32
```

Do not reuse `JWT_SECRET`. The generated store encrypts TOTP secrets with
AES-256-GCM and binds each ciphertext to its user ID. Recovery codes are
Argon2id-hashed and consumed atomically. Successful TOTP time steps are also
recorded with an atomic conditional update so a code cannot be replayed during
its validity window. Losing the encryption key prevents existing TOTP secrets
from being recovered, so manage and rotate it as a production secret with a
deliberate migration plan.

### TOTP Setup

```rust
use tideway::auth::mfa::{TotpManager, TotpConfig};

let totp = TotpManager::new(TotpConfig::new("MyApp"));

// Generate setup for user
let setup = totp.generate_setup("user@example.com")?;

// setup.secret - Store this securely
// setup.uri - For QR code generation
// setup.qr_code_svg - SVG QR code (if qr feature enabled)

// Verify code from authenticator app
if totp.verify(&setup.secret, "123456", "user@example.com")? {
    println!("Code valid");
}
```

### Backup Codes

```rust
use tideway::auth::mfa::BackupCodeGenerator;

let generator = BackupCodeGenerator::default();
let codes = generator.generate();

// codes.codes - Vec of 10 plaintext random codes
// codes.display_codes() - Formatted plaintext codes to show user ONCE

// Hash before persistence; this runs Argon2id off the async runtime.
let hash = BackupCodeGenerator::hash(&codes.codes[0]).await?;
assert!(BackupCodeGenerator::verify_hash(&codes.codes[0], &hash).await?);

// Verify backup code (returns index if valid)
if let Some(index) = BackupCodeGenerator::verify("ABCD-1234", &in_memory_plaintext_codes) {
    // Remove used code
    stored_codes.remove(index);
}
```

## Social Login (OAuth 2.0 / OpenID Connect)

Requires the `auth-oauth` feature:

```toml
[dependencies]
tideway = { version = "0.9.0", features = ["auth", "auth-oauth"] }
```

`tideway::auth::oauth` implements the authorization-code flow with PKCE for Google, GitHub,
and any OpenID Connect provider (Microsoft Entra ID, Okta, Auth0, Keycloak, ...).

### Providers

```rust
use tideway::auth::oauth::{InMemoryOAuthStateStore, OAuthFlow, OAuthProvider};

let oauth = OAuthFlow::new(InMemoryOAuthStateStore::new(), accounts.clone())?
    .with_provider(OAuthProvider::google(
        env("GOOGLE_CLIENT_ID"),
        env("GOOGLE_CLIENT_SECRET"),
        "https://app.example.com/auth/google/callback",
    ))
    .with_provider(OAuthProvider::github(
        env("GITHUB_CLIENT_ID"),
        env("GITHUB_CLIENT_SECRET"),
        "https://app.example.com/auth/github/callback",
    ))
    // Any OIDC issuer, configured from its discovery document:
    .with_provider(
        OAuthProvider::discover("okta", "https://example.okta.com", id, secret, redirect).await?,
    );
```

Use `with_scopes`, `with_authorize_param("prompt", "select_account")`, or `with_name` to customize
a provider. `InMemoryOAuthStateStore` only works for a single instance; implement
`OAuthStateStore` on Redis or your database when running several instances.

`authorize` needs no authentication and stores an entry per call, so put a per-IP rate limit on
the route that starts sign-in. `InMemoryOAuthStateStore` holds at most 100,000 pending
authorizations; when full it evicts the oldest rather than refusing new sign-ins. Give a shared
store an equivalent bound and eviction policy.

### SocialAccountStore

`SocialAccountStore` extends `UserStore`, so social sign-in shares user lookup, lockout, and MFA
state with password login. Store identities in a table with a unique `(provider, subject)` key:

```rust
use tideway::auth::oauth::{OAuthIdentity, SocialAccountStore};

#[async_trait]
impl SocialAccountStore for MyUserStore {
    async fn find_by_identity(&self, provider: &str, subject: &str) -> Result<Option<User>>;

    // Insert into user_identities (user_id, provider, subject, ...).
    async fn link_identity(&self, user: &User, identity: &OAuthIdentity) -> Result<()>;

    // Optional: refresh stored profile data / tokens on every sign-in.
    async fn update_identity(&self, user: &User, identity: &OAuthIdentity) -> Result<()>;

    // Create a user with the provider-verified email, marked as verified. `password_hash` is the
    // hash of a random secret, so password login fails until the user resets their password.
    async fn create_user_from_identity(
        &self,
        identity: &OAuthIdentity,
        email: &str,
        password_hash: &str,
    ) -> Result<User>;
}
```

```sql
CREATE TABLE user_identities (
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access_token_encrypted TEXT,
    refresh_token_encrypted TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, subject)
);
```

Sign-in does not need the provider's tokens. If you persist them to call the provider's API later,
encrypt them with `OAuthTokenCipher` (AES-256-GCM, bound to the provider and subject):

```rust
let cipher = OAuthTokenCipher::from_env("OAUTH_TOKEN_KEY")?; // base64 32-byte key
let encrypted = cipher.encrypt(&identity.provider, &identity.subject, &identity.tokens.access_token)?;
```

### Routes

```rust
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, header::SET_COOKIE};
use tideway::auth::LoginHttpResponse;
use tideway::auth::oauth::{
    AuthorizeOptions, OAuthCallbackParams, clear_state_cookie, state_from_cookies,
};

// GET /auth/:provider
async fn start(State(app): State<AppState>, Path(provider): Path<String>) -> Result<Response> {
    let request = app.oauth.authorize(&provider, AuthorizeOptions::new()).await?;
    // Redirects to the provider and sets the HttpOnly state cookie.
    Ok(request.redirect())
}

// GET /auth/:provider/callback
async fn callback(
    State(app): State<AppState>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Query(params): Query<OAuthCallbackParams>,
) -> Result<impl IntoResponse> {
    let browser_state = state_from_cookies(&headers);
    let outcome = app.oauth.callback(&provider, params, browser_state.as_deref()).await?;
    // Issues JWTs like a password login; returns an MFA challenge if MFA is enabled.
    let login = app.login.complete_external_login(&outcome.user, false).await?;
    Ok(([(SET_COOKIE, clear_state_cookie())], LoginHttpResponse::from(login)))
}
```

The callback only succeeds in the browser that started the flow: `state` must match the
`tideway_oauth_state` cookie (`HttpOnly`, `SameSite=Lax`, `Secure`). This blocks login CSRF and
attackers attaching a victim's provider account to their own user. For plain-HTTP local
development, set `OAuthFlowConfig::secure_cookie(false)`. Clients that cannot use cookies (native
apps) must store `AuthorizationRequest::state` themselves and pass it back as `browser_state`.

For cookie sessions, create the session for `outcome.user` instead of calling
`complete_external_login`, and check `has_mfa_enabled` yourself if you use MFA.

`AuthorizeOptions::redirect_to("/dashboard")` round-trips a same-origin path through
`outcome.redirect_to` (absolute and protocol-relative URLs are rejected). To let a signed-in user
connect another provider, use `AuthorizeOptions::new().link_to_user(current_user_id)`.

### Account Resolution

On callback, the identity is resolved in this order:

1. An identity already linked to a user signs that user in.
2. Otherwise, if the provider **verified** the email and a local account with that email exists,
   the identity is linked when the local account is also verified
   (`AccountLinking::VerifiedEmail`, the default). Unverified local accounts are refused with
   `409 Conflict` to prevent account pre-hijacking. Set `AccountLinking::Never` to require
   explicit linking.
3. Otherwise a new verified user is created (disable with `OAuthFlowConfig::allow_signup(false)`).

Identities without a provider-verified email can only sign in to accounts they are already linked
to. Locked accounts are refused.

### Security Properties

- Single-use, hashed `state` that expires after 10 minutes, is bound to the provider, and must
  match the browser's HttpOnly state cookie (CSRF and login-CSRF protection).
- PKCE (`S256`) on every request, including GitHub.
- OIDC `id_token` verified against the provider JWKS: RS256 signature, `iss`, `aud`, `exp`,
  `nonce`, and `azp`.
- Identities keyed on the stable subject (`sub`, or GitHub's numeric user ID), never on email or
  username. GitHub emails are only trusted when primary and verified.
- Client secrets, provider tokens, PKCE verifiers, and nonces are redacted from `Debug` output.
- Provider HTTP calls have timeouts, a 1 MiB response limit, and do not follow redirects.

### Social Login Events

| Target | Description |
|--------|-------------|
| `auth.oauth.started` | Authorization redirect issued |
| `auth.oauth.denied` | Provider returned an error (user cancelled) |
| `auth.oauth.failed` | Invalid state, failed code exchange, or invalid identity |
| `auth.oauth.linked` | Identity linked to an existing account |
| `auth.oauth.signup` | Account created from social sign-in |
| `auth.oauth.success` | Identity resolved to a user |

## Token Refresh

```rust
use tideway::auth::TokenRefreshFlow;

let flow = TokenRefreshFlow::new(
    jwt_issuer,
    refresh_token_store,
    user_loader, // implements UserLoader trait
    jwt_secret.as_bytes(),
);

// Refresh tokens
let new_tokens = flow.refresh(&old_refresh_token).await?;

// Logout (revoke token family)
flow.revoke(&refresh_token).await?;

// Security event (revoke all user tokens)
flow.revoke_all("user-123").await?;
```

## Session Management

Track active sessions and allow users to view/revoke their logins across devices.

### SessionStore Trait

```rust
use tideway::auth::sessions::{SessionStore, SessionInfo, SessionMetadata};
use async_trait::async_trait;

#[async_trait]
impl SessionStore for MySessionStore {
    // Create session on login
    async fn create_session(
        &self,
        session_id: &str,  // Same as token family ID
        user_id: &str,
        metadata: SessionMetadata,
    ) -> Result<()>;

    // Update last_used_at on token refresh
    async fn touch_session(&self, session_id: &str) -> Result<()>;

    // Get single session
    async fn get_session(&self, session_id: &str) -> Result<Option<SessionInfo>>;

    // List all active sessions for user (newest first)
    async fn list_sessions(&self, user_id: &str) -> Result<Vec<SessionInfo>>;

    // Revoke specific session (logout device)
    async fn revoke_session(&self, session_id: &str) -> Result<bool>;

    // Revoke all sessions (logout everywhere)
    async fn revoke_all_sessions(&self, user_id: &str) -> Result<usize>;

    // Revoke all except current (logout other devices)
    async fn revoke_other_sessions(
        &self,
        user_id: &str,
        except_session_id: &str,
    ) -> Result<usize>;
}
```

### SessionManager

High-level session operations with tracing:

```rust
use std::sync::Arc;
use tideway::auth::sessions::{SessionManager, SessionMetadata};

// Share one refresh token store with TokenRefreshFlow so revoking a session
// also revokes its refresh token family.
let token_store = Arc::new(my_token_store);
let manager = SessionManager::new(session_store)
    .with_refresh_token_store(token_store.clone());
let refresh_flow = TokenRefreshFlow::new(issuer, token_store, user_loader, secret);

// Create session on login (session ID = refresh token family)
let metadata = SessionMetadata::new()
    .with_ip("192.168.1.1")
    .with_user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X) Chrome/120.0.0.0");

manager.create_session("family-123", "user-456", metadata).await?;

// List sessions (marks current session)
let sessions = manager.list_sessions("user-456", Some("family-123")).await?;

for session in sessions {
    println!(
        "{}: {} - {} {}",
        session.device_info.unwrap_or_default(),  // "Chrome on macOS"
        session.ip_address.unwrap_or_default(),
        if session.is_current { "(current)" } else { "" },
        humanize_time(session.last_used_at),
    );
}

// Logout specific device
manager.revoke_session("user-456", "family-789").await?;

// Logout all other devices
manager.revoke_other_sessions("user-456", "family-123").await?;
```

> **Important:** Without `with_refresh_token_store`, revoking a session only hides it from
> session listings. Its refresh token keeps minting access tokens until it expires.
> With a token store attached, `revoke_session`, `revoke_other_sessions`,
> `revoke_all_sessions`, and session-limit eviction all revoke the matching refresh token
> families first.

### Session Limits

Limit concurrent sessions per user (e.g., max 5 devices):

```rust
use tideway::auth::sessions::{SessionManager, SessionLimitConfig};

// Limit to 5 sessions, revoke oldest when exceeded (default)
let manager = SessionManager::new(session_store)
    .with_session_limit(SessionLimitConfig::new(5));

// Or reject new logins when at limit
let manager = SessionManager::new(session_store)
    .with_session_limit(SessionLimitConfig::new(3).reject_new());
```

When a session is created and the limit is exceeded:

```rust
let result = manager.create_session("session-id", "user-id", metadata).await?;

if result.created {
    // Session was created
    if !result.evicted_sessions.is_empty() {
        println!("Evicted {} old sessions", result.evicted_sessions.len());
    }
} else {
    // Session was rejected (reject_new mode)
    return Err("Too many active sessions".into());
}
```

### Overflow Behaviors

| Behavior | Description |
|----------|-------------|
| `RevokeOldest` (default) | Automatically revokes oldest session(s) to make room |
| `RejectNew` | Rejects the new login, user must manually revoke a session |

### SessionInfo

Information returned for each session:

```rust
pub struct SessionInfo {
    pub id: String,              // Session/family ID
    pub user_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub device_info: Option<String>,  // Parsed: "Chrome on macOS"
    pub location: Option<String>,     // From geolocation service
    pub created_at: SystemTime,
    pub last_used_at: SystemTime,
    pub is_current: bool,             // Set by SessionManager
}
```

### Session Events

| Target | Level | Description |
|--------|-------|-------------|
| `auth.session.created` | INFO | New session created on login |
| `auth.session.revoked` | INFO | Session explicitly revoked |
| `auth.session.revoke_all` | WARN | All sessions revoked for user |
| `auth.session.revoke_others` | INFO | Other sessions revoked |
| `auth.session.limit_exceeded` | WARN | Session limit exceeded (reject mode) |
| `auth.session.evicted` | INFO | Session evicted due to limit |

## Trusted Devices

Allow users to mark devices as "trusted" after MFA to skip MFA on subsequent logins.

### TrustedDeviceStore Trait

```rust
use tideway::auth::trusted_device::{TrustedDeviceStore, TrustedDevice, DeviceFingerprint};
use async_trait::async_trait;

#[async_trait]
impl TrustedDeviceStore for MyTrustedDeviceStore {
    // Store a new trusted device
    async fn store_trusted_device(&self, device: &TrustedDevice) -> Result<()>;

    // Find by user and token hash
    async fn find_by_token_hash(
        &self,
        user_id: &str,
        token_hash: &str,
    ) -> Result<Option<TrustedDevice>>;

    // List all trusted devices for a user
    async fn list_trusted_devices(&self, user_id: &str) -> Result<Vec<TrustedDevice>>;

    // Update last_used_at timestamp
    async fn touch_trusted_device(&self, device_id: &str) -> Result<()>;

    // Revoke specific device
    async fn revoke_trusted_device(&self, device_id: &str) -> Result<bool>;

    // Revoke all trusted devices for user
    async fn revoke_all_trusted_devices(&self, user_id: &str) -> Result<usize>;

    // Remove expired trusted devices
    async fn cleanup_expired(&self) -> Result<usize>;
}
```

### TrustedDeviceManager

High-level trusted device operations with tracing:

```rust
use tideway::auth::trusted_device::{
    TrustedDeviceManager, TrustedDeviceConfig, DeviceFingerprint
};

// Configure
let config = TrustedDeviceConfig::new()
    .trust_duration(Duration::from_secs(30 * 24 * 60 * 60)) // 30 days
    .max_devices_per_user(10)
    .validate_fingerprint(false); // Don't require exact IP match

let manager = TrustedDeviceManager::new(trusted_device_store, config);

// After MFA success, trust the device
let fingerprint = DeviceFingerprint::new()
    .with_ip("192.168.1.1")
    .with_user_agent("Mozilla/5.0 (Macintosh) Chrome/120.0.0.0");

let trust_token = manager.trust_device("user-123", fingerprint).await?;
// Return trust_token to client (set as secure cookie)

// On next login, check if device is trusted
let is_trusted = manager.is_trusted("user-123", &trust_token, None).await?;
if is_trusted {
    // Skip MFA, proceed directly to token issuance
}
```

### Integration with Login Flow

```rust
async fn login_handler(req: LoginRequest) -> Result<LoginResponse> {
    // Check credentials...

    if user_has_mfa_enabled {
        // Check if device is trusted first
        if let Some(trust_token) = req.trust_token {
            let fingerprint = DeviceFingerprint::new()
                .with_ip(client_ip)
                .with_user_agent(user_agent);

            if manager.is_trusted(&user_id, &trust_token, Some(fingerprint)).await? {
                // Skip MFA, issue tokens directly
                return Ok(issue_tokens(user_id));
            }
        }

        // Device not trusted, require MFA
        return Ok(LoginResponse::MfaRequired { .. });
    }

    Ok(issue_tokens(user_id))
}

async fn verify_mfa_handler(req: MfaVerifyRequest) -> Result<LoginResponse> {
    // Verify MFA code...

    // Optionally trust this device
    if req.trust_this_device {
        let fingerprint = DeviceFingerprint::new()
            .with_ip(client_ip)
            .with_user_agent(user_agent);

        let trust_token = manager.trust_device(&user_id, fingerprint).await?;
        // Include trust_token in response for client to store
    }

    Ok(issue_tokens(user_id))
}
```

### Managing Trusted Devices

```rust
// List user's trusted devices
let devices = manager.list_devices("user-123").await?;

for device in devices {
    println!(
        "{}: {} - Last used: {:?}",
        device.device_name.unwrap_or_default(), // "Chrome on macOS"
        device.ip_address.unwrap_or_default(),
        device.last_used_at,
    );
}

// Revoke specific device
manager.revoke_device("user-123", "device-id").await?;

// Revoke all trusted devices (security event, password change)
manager.revoke_all_devices("user-123").await?;
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `trust_duration` | 30 days | How long a device stays trusted |
| `max_devices_per_user` | 10 | Maximum trusted devices (oldest evicted) |
| `validate_fingerprint` | `false` | Require IP/UA to match when verifying |

### Fingerprint Validation

When `validate_fingerprint` is enabled:

```rust
let config = TrustedDeviceConfig::new()
    .validate_fingerprint(true);

// Trust token will only work from same IP/user agent
// Useful for high-security applications, but may cause issues
// with dynamic IPs or browser updates
```

### Security Notes

- **Token hashing**: Trust tokens are hashed with SHA-256 before storage
- **Token entropy**: Tokens are 256-bit random values
- **Ownership verification**: Can only revoke devices belonging to the user
- **Automatic eviction**: Oldest device evicted when limit reached
- **Input validation**: IP and user agent are truncated to prevent DoS

### Trusted Device Events

| Target | Level | Description |
|--------|-------|-------------|
| `auth.trusted_device.created` | INFO | Device marked as trusted |
| `auth.trusted_device.verified` | DEBUG | Trust token verified |
| `auth.trusted_device.expired` | DEBUG | Trust token expired |
| `auth.trusted_device.fingerprint_mismatch` | WARN | IP/UA mismatch (when validating) |
| `auth.trusted_device.revoked` | INFO | Specific device revoked |
| `auth.trusted_device.revoke_all` | WARN | All devices revoked |
| `auth.trusted_device.evicted` | INFO | Device evicted due to limit |
| `auth.trusted_device.cleanup` | INFO | Expired devices cleaned up |

### Database Schema

```sql
CREATE TABLE trusted_devices (
    id VARCHAR(255) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    token_hash VARCHAR(64) NOT NULL,     -- SHA-256 hex
    device_name VARCHAR(255),            -- Parsed: "Chrome on macOS"
    ip_address VARCHAR(45),
    user_agent TEXT,
    trusted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_trusted_devices_user ON trusted_devices(user_id);
CREATE INDEX idx_trusted_devices_lookup ON trusted_devices(user_id, token_hash);
CREATE INDEX idx_trusted_devices_expiry ON trusted_devices(expires_at);
```

## API Keys

Organization-scoped API keys (personal access tokens) for machine-to-machine access.
Keys look like `tw_<id>_<secret>`; only a SHA-256 hash is stored and the plaintext is
returned once at creation.

### ApiKeyStore Trait

```rust
#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    async fn create_api_key(&self, key: &ApiKey) -> Result<()>;
    async fn find_api_key(&self, id: &str) -> Result<Option<ApiKey>>;
    async fn list_api_keys(&self, organization_id: &str) -> Result<Vec<ApiKey>>;
    async fn touch_api_key(&self, id: &str, used_at: SystemTime) -> Result<()>;
    async fn revoke_api_key(&self, id: &str, revoked_at: SystemTime) -> Result<bool>;
    // Default implementation provided:
    async fn revoke_all_api_keys(&self, organization_id: &str, revoked_at: SystemTime) -> Result<usize>;
}
```

`InMemoryApiKeyStore` is available under `test-auth-bypass` for tests. For production, enable
`api-keys-seaorm` and use `SeaOrmApiKeyStore::new(db)`; `tideway add api-keys` generates the
`api_keys` migration it expects.

### Scaffolding with the CLI

```bash
tideway add api-keys --wire
```

This adds the migration and, for apps with the DB-backed organizations scaffold, owner/admin-only
management routes (`GET/POST /organizations/{org_id}/api-keys`,
`DELETE /organizations/{org_id}/api-keys/{key_id}`). Creating a key returns the plaintext once in
the `key` field. `--wire` also installs the key manager as a global `ApiKeyExtension`, so your own
handlers can accept keys with `ApiKeyAuth` or `Principal<P>`.

### Issuing, Listing, and Revoking

```rust
use tideway::auth::{ApiKeyConfig, ApiKeyManager, NewApiKey};

let manager = ApiKeyManager::new(store, ApiKeyConfig::default()
    .max_keys_per_organization(25)
    .default_ttl(Duration::from_secs(365 * 24 * 60 * 60)));

// Only members whose role can manage org settings (owners/admins by default) may manage keys.
manager.authorize_management(&membership_store, org_id, &user.id).await?; // 403 otherwise

let created = manager
    .create(NewApiKey::new(org_id, "CI deploy")
        .scopes(["projects:read", "deployments:*"])
        .created_by(&user.id))
    .await?;
// Return `created.plaintext` once; it cannot be recovered later.

let keys = manager.list(org_id).await?;           // includes revoked keys
manager.revoke(org_id, &key_id).await?;           // false if not in this org
manager.revoke_all(org_id).await?;                // e.g. on org deletion
```

### Protecting Routes

Install the manager as an extension, then use `ApiKeyAuth` for API-key-only routes or
`Principal<P>` to accept either a JWT user (via your `AuthProvider`) or an API key:

```rust
use tideway::auth::{ApiKeyAuth, ApiKeyExtension, Principal};

let app = Router::new()
    .route("/projects", get(list_projects))
    .layer(Extension(ApiKeyExtension::new(manager)))
    .layer(Extension(my_auth_provider));

async fn list_projects(principal: Principal<MyAuthProvider>) -> Result<Json<Vec<Project>>> {
    let org_id = match &principal {
        Principal::User(user) => user.current_org_id.clone(),
        Principal::ApiKey(key) => {
            key.require_scope("projects:read")?; // 403 if missing
            key.organization_id.clone()
        }
    };
    // ...
}
```

Keys are accepted from `X-API-Key: <key>` or `Authorization: Bearer <key>`. A bearer
token with the key prefix is treated as an API key; anything else falls through to
JWT authentication. Unknown, tampered, revoked, and expired keys all return the same
401 response.

Scopes match exactly, via `*` (everything), or via `resource:*` (any `resource:<action>`).

`authorize_management` (with the `organizations` feature) treats API keys as an organization
setting: it requires a membership whose role passes `MembershipStore::can_manage_settings`. Apps
using the generated `RequestActor` get the same rule via `require_org_role(&["owner", "admin"])` in
the scaffolded routes.

`last_used_at` is updated on successful authentication, throttled by
`ApiKeyConfig::last_used_update_interval` (default 60 seconds).

### API Key Events

| Target | Level | Description |
|--------|-------|-------------|
| `auth.api_key.created` | INFO | Key created |
| `auth.api_key.revoked` | INFO | Key revoked |
| `auth.api_key.revoke_all` | WARN | All keys revoked for an organization |
| `auth.api_key.inactive` | DEBUG | Revoked or expired key presented |
| `auth.api_key.touch_failed` | WARN | Failed to record last-used timestamp |

### Database Schema

`SeaOrmApiKeyStore` expects this table (timestamps are Unix seconds; `scopes` is a JSON array):

```sql
CREATE TABLE api_keys (
    id VARCHAR(32) PRIMARY KEY,           -- public key ID (hex)
    organization_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(64) NOT NULL,        -- SHA-256 hex of the full key
    scopes TEXT NOT NULL,                 -- JSON array, e.g. ["projects:read"]
    created_by VARCHAR(255),
    created_at BIGINT NOT NULL,
    expires_at BIGINT,
    last_used_at BIGINT,
    revoked_at BIGINT
);

CREATE INDEX idx_api_keys_organization ON api_keys(organization_id);
```

### Reuse Detection

The refresh flow automatically detects token reuse attacks:

1. Each refresh token has a generation number
2. On refresh, generation increments and old token becomes invalid
3. If an old-generation token is used, the entire token family is revoked
4. This protects against token theft scenarios

## Security Events (Tracing)

All auth operations emit structured tracing events for security monitoring:

### Login Events

| Target | Level | Description |
|--------|-------|-------------|
| `auth.login.failed` | WARN | Failed login (user not found, wrong password) |
| `auth.login.locked` | WARN | Login blocked due to account lockout |
| `auth.login.unverified` | INFO | Login blocked due to unverified email |
| `auth.login.success` | INFO | Successful login |
| `auth.login.mfa_required` | INFO | MFA challenge issued |

### MFA Events

| Target | Level | Description |
|--------|-------|-------------|
| `auth.mfa.failed` | WARN | Invalid MFA code |
| `auth.mfa.success` | INFO | MFA verification successful |
| `auth.mfa.backup_used` | INFO | Backup code consumed |
| `auth.mfa.backup_low` | WARN | 2 or fewer backup codes remaining |

### Token Events

| Target | Level | Description |
|--------|-------|-------------|
| `auth.token.refresh` | INFO | Token refreshed successfully |
| `auth.token.reuse_detected` | ERROR | **CRITICAL**: Token reuse attack detected |
| `auth.token.revoked` | INFO | Token family revoked (logout) |
| `auth.token.revoke_all` | WARN | All user tokens revoked |
| `auth.token.invalid` | WARN | Invalid token presented |

### Password Events

| Target | Level | Description |
|--------|-------|-------------|
| `auth.password.rehashed` | INFO | Password hash upgraded |
| `auth.password.reset_requested` | INFO | Reset email sent |
| `auth.password.reset_completed` | INFO | Password successfully reset |
| `auth.password.reset_failed` | WARN | Reset failed (invalid token, weak password) |

### Registration Events

| Target | Level | Description |
|--------|-------|-------------|
| `auth.register.success` | INFO | User registered |
| `auth.register.failed` | INFO | Registration failed |
| `auth.register.verification_email_failed` | WARN | Failed to send verification email |
| `auth.register.existing_account_notice_failed` | WARN | Failed to notify an existing account owner |

### Email Verification Events

| Target | Level | Description |
|--------|-------|-------------|
| `auth.email.verification_sent` | INFO | Verification email sent |
| `auth.email.verified` | INFO | Email verified |
| `auth.email.verification_failed` | WARN | Invalid or expired token |

### Filtering Events

```rust
// In your tracing subscriber setup, filter by target:
tracing_subscriber::fmt()
    .with_env_filter("auth=info") // All auth events
    .with_env_filter("auth.token.reuse_detected=error") // Critical only
    .init();
```

## Public Registration Policy

Generated applications treat public account creation as an explicit product decision. The
`/auth/register` route is not mounted unless `ALLOW_PUBLIC_REGISTRATION=true`. Private B2B and
invitation-only products should leave it disabled. Self-service products should enable it only
after configuring endpoint limits, email verification, and abuse monitoring.

Changing the environment value requires an application restart because route topology and the
OpenAPI document are built at startup.

The generated Vue `RegisterForm` remains hidden unless its `registrationEnabled` prop is `true`
or the frontend build has `VITE_ALLOW_PUBLIC_REGISTRATION=true`. Set the frontend flag alongside
the backend flag for an intentional self-service flow. The frontend setting controls presentation
only; the backend route policy remains the security boundary.

## Authentication Endpoint Rate Limiting

Generated routes apply separate trusted-proxy-aware per-IP policies before expensive work:

| Endpoint | Generated default | Purpose |
| --- | --- | --- |
| Login | 5 attempts per 15 minutes | Slow credential guessing and password hashing abuse. |
| Registration | 5 attempts per hour | Protect password hashing and account/database creation. |
| Refresh | 60 attempts per minute | Bound token parsing and refresh-family database work. |
| Password reset / verification resend | 5 requests per hour per IP and email | Bound email delivery and enumeration abuse. |

Logout remains outside ordinary authentication throttling so a client can revoke a session while
other authentication endpoints are limited. The generated in-process limiter is a safe single-node
default; multi-replica deployments should replace it or enforce an equivalent shared policy at a
trusted gateway.

### Login Flow Rate Limiting

Protect against brute force attacks with IP-based rate limiting on login attempts.

### Basic Setup

```rust
use tideway::auth::flows::{LoginFlow, LoginRateLimiter, LoginRateLimitConfig};

// Create rate limiter with default config (5 attempts per 15 minutes)
let rate_limiter = LoginRateLimiter::new(LoginRateLimitConfig::default());

// Add to login flow
let flow = LoginFlow::new(user_store, mfa_store, token_issuer, config)
    .with_rate_limiter(rate_limiter);
```

### Configuration Presets

```rust
use tideway::auth::flows::LoginRateLimitConfig;

// Default: 5 attempts per 15 minutes
let config = LoginRateLimitConfig::default();

// Strict: 3 attempts per 30 minutes (high-security apps)
let config = LoginRateLimitConfig::strict();

// Lenient: 10 attempts per 15 minutes (user-facing apps)
let config = LoginRateLimitConfig::lenient();

// Custom
let config = LoginRateLimitConfig::new(
    7,    // max_attempts
    600,  // window_seconds (10 minutes)
);
```

### Using with IP Address

```rust
use axum::extract::ConnectInfo;
use std::net::SocketAddr;

async fn login_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(flow): State<LoginFlow<...>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    // Pass client IP for rate limiting
    let response = flow.login_with_ip(req, Some(addr.ip().to_string())).await?;
    Ok(Json(response))
}
```

### Behind a Proxy

When behind a reverse proxy, resolve the client IP through an explicit proxy
allowlist. Never read `X-Forwarded-For` directly from an internet-facing request:

```rust
async fn login_handler(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Extension(client_ips): Extension<Arc<ClientIpResolver>>,
    State(flow): State<LoginFlow<...>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    // Construct ClientIpResolver once at startup from known proxy IPs/CIDRs.
    let client_ip = client_ips.resolve(peer.ip(), &headers).to_string();

    let response = flow.login_with_ip(req, Some(client_ip)).await?;
    Ok(Json(response))
}
```

### Rate Limit Events

| Target | Level | Description |
|--------|-------|-------------|
| `auth.login.rate_limited` | WARN | Login blocked due to rate limiting |
| `auth.endpoint.rate_limited` | WARN | Registration or refresh blocked due to rate limiting |
| `auth.reauth.rate_limited` | WARN | Password change or account deletion blocked after too many current-password attempts |

### How It Works

1. **IP-based tracking**: Each IP address has its own rate limit bucket
2. **GCRA algorithm**: Uses governor crate's Generic Cell Rate Algorithm for accurate limiting
3. **Automatic cleanup**: Stale entries are periodically removed to prevent memory growth
4. **Complements user lockout**: Works alongside `record_failed_attempt()` for defense in depth

## Account Lockout

Comprehensive account lockout with progressive delays, notifications, and admin unlock.

### LockoutPolicy

```rust
use tideway::auth::lockout::{LockoutPolicy, LockoutManager};
use std::time::Duration;

// Default: 5 attempts, 15 min lockout
let policy = LockoutPolicy::new();

// Strict: 3 attempts, 30 min lockout, notifications, IP tracking
let policy = LockoutPolicy::strict();

// Lenient: 10 attempts, 5 min lockout
let policy = LockoutPolicy::lenient();

// Custom
let policy = LockoutPolicy::new()
    .max_attempts(5)
    .lockout_duration(Duration::from_secs(900))
    .progressive_delays(vec![0, 0, 0, 60, 300])  // Delays per attempt
    .with_notifications()
    .track_by_ip(true);
```

### Progressive Delays

Instead of immediate lockout, add delays before full lockout:

```rust
// vec![0, 0, 0, 60, 300] means:
// Attempt 1: No delay
// Attempt 2: No delay
// Attempt 3: No delay
// Attempt 4: 60 second delay before retry
// Attempt 5: 300 second delay before retry
// Attempt 6+: Full lockout

let policy = LockoutPolicy::new()
    .max_attempts(6)
    .progressive_delays(vec![0, 0, 0, 60, 300]);
```

### LockoutStore Trait

```rust
use tideway::auth::lockout::{LockoutStore, LockoutStatus};
use async_trait::async_trait;

#[async_trait]
impl LockoutStore for MyStore {
    // Get failed attempt count
    async fn get_failed_attempts(&self, user_id: &str) -> Result<u32>;

    // Get current lockout status
    async fn get_lockout_status(&self, user_id: &str) -> Result<Option<LockoutStatus>>;

    // Increment failed attempts
    async fn increment_failed_attempts(&self, user_id: &str) -> Result<u32>;

    // Lock the account
    async fn set_lockout(&self, user_id: &str, until: SystemTime) -> Result<()>;

    // Set delay before next attempt
    async fn set_delay(&self, user_id: &str, until: SystemTime) -> Result<()>;

    // Clear all lockout state
    async fn clear_lockout(&self, user_id: &str) -> Result<()>;

    // Optional: Get email for notifications
    async fn get_user_email(&self, user_id: &str) -> Result<Option<String>>;

    // Optional: Send lockout notification
    async fn send_lockout_notification(
        &self,
        user_id: &str,
        email: &str,
        locked_until: SystemTime,
    ) -> Result<()>;

    // Optional: Send unlock notification
    async fn send_unlock_notification(&self, user_id: &str, email: &str) -> Result<()>;

    // IP tracking methods (optional, for track_by_ip)
    async fn increment_failed_attempts_by_ip(&self, ip: &str) -> Result<u32>;
    async fn set_lockout_by_ip(&self, ip: &str, until: SystemTime) -> Result<()>;
    async fn is_ip_locked(&self, ip: &str) -> Result<Option<SystemTime>>;
}
```

### LockoutManager Usage

```rust
use tideway::auth::lockout::{LockoutManager, LockoutPolicy};

let manager = LockoutManager::new(store, LockoutPolicy::strict());

// Check if user can attempt login
if let Some(status) = manager.check_can_attempt("user-123", Some("1.2.3.4")).await? {
    if status.is_locked {
        return Err(format!("Account locked for {} seconds", status.remaining_wait_seconds()));
    }
    if let Some(delay) = status.delay_seconds {
        return Err(format!("Please wait {} seconds", delay));
    }
}

// Record failed attempt
let result = manager.record_failed_attempt("user-123", Some("1.2.3.4")).await?;
if result.just_locked {
    // Account was just locked
}
if !result.can_retry_now() {
    println!("Wait {} seconds", result.wait_seconds());
}

// Clear the account's lockout on successful login. The shared per-IP count is kept, so one
// account's success cannot refund guesses spent against other accounts; it restarts once the
// IP lockout expires.
manager.record_successful_login("user-123", Some("1.2.3.4")).await?;

// Admin unlock
manager.admin_unlock("user-123", "admin-456").await?;
```

### Integration with LoginFlow

Reserve the attempt with `begin_attempt` before verifying the password. It counts the attempt
up front, so concurrent requests for one account cannot all slip past a stale count
(`check_can_attempt` followed by `record_failed_attempt` can).

```rust
async fn login_handler(
    State(lockout): State<LockoutManager<...>>,
    State(login): State<LoginFlow<...>>,
    client_ip: Option<String>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    let user_id = get_user_id_by_email(&req.email).await?;
    let ip = client_ip.as_deref();

    if let Some(status) = lockout.begin_attempt(&user_id, ip).await? {
        return Ok(Json(LoginResponse::error(format!(
            "Too many failed attempts. Try again in {} seconds.",
            status.remaining_wait_seconds()
        ))));
    }

    match login.login(req).await {
        // The password was correct (an MFA challenge still follows for MfaRequired).
        Ok(response @ (LoginResponse::Success { .. } | LoginResponse::MfaRequired { .. })) => {
            // Clears the reserved attempt along with earlier failures.
            lockout.record_successful_login(&user_id, ip).await?;
            Ok(Json(response))
        }
        Ok(response) => {
            lockout.finish_failed_attempt(&user_id, ip).await?;
            Ok(Json(response))
        }
        Err(e) => Err(e),
    }
}
```

The attempt that reaches `max_attempts` locks the account before its password is checked; if
that password is correct, `record_successful_login` unlocks it again.

### Lockout Events

| Target | Level | Description |
|--------|-------|-------------|
| `auth.lockout.blocked` | DEBUG | Login blocked by existing lockout |
| `auth.lockout.ip_blocked` | DEBUG | Login blocked by IP lockout |
| `auth.lockout.account_locked` | WARN | Account locked (max attempts reached) |
| `auth.lockout.ip_locked` | WARN | IP address locked |
| `auth.lockout.delay_applied` | INFO | Progressive delay applied |
| `auth.lockout.cleared` | DEBUG | Lockout cleared on success |
| `auth.lockout.admin_unlock` | WARN | Account unlocked by admin |
| `auth.lockout.notification_sent` | INFO | Lockout email notification sent |

### Rate Limiting vs Lockout

| Feature | Rate Limiting | Account Lockout |
|---------|--------------|-----------------|
| Tracks by | IP address | User account (+ optional IP) |
| Purpose | Prevent brute force | Protect specific accounts |
| State | In-memory | Persistent (database) |
| Reset | Automatic (time window) | Account: on successful login. IP: when the IP lockout expires |
| Progressive | No | Yes (configurable delays) |
| Notifications | No | Yes (email) |

**Best practice**: Use both together for defense in depth.

## Account Deletion

GDPR-compliant account deletion with cascading cleanup and optional grace period.

### DeletionConfig

```rust
use tideway::auth::deletion::{AccountDeletionFlow, DeletionConfig};
use std::time::Duration;

// Default: 7-day grace period, soft delete, requires password
let config = DeletionConfig::new();

// Immediate hard deletion
let config = DeletionConfig::immediate();

// Custom configuration
let config = DeletionConfig::new()
    .grace_period(Some(Duration::from_secs(14 * 24 * 60 * 60))) // 14 days
    .require_password(true)
    .send_confirmation_email(true)
    .send_deletion_email(true)
    .hard_delete(false);  // Soft delete (anonymize)
```

### AccountDeletionStore Trait

```rust
use tideway::auth::deletion::{AccountDeletionStore, PendingDeletion};
use async_trait::async_trait;

#[async_trait]
impl AccountDeletionStore for MyStore {
    // Required: Password verification
    async fn get_password_hash(&self, user_id: &str) -> Result<Option<String>>;
    async fn get_user_email(&self, user_id: &str) -> Result<Option<String>>;
    async fn user_exists(&self, user_id: &str) -> Result<bool>;

    // Required: Scheduling
    async fn schedule_deletion(&self, user_id: &str, scheduled_for: SystemTime, reason: Option<&str>) -> Result<()>;
    async fn cancel_deletion(&self, user_id: &str) -> Result<bool>;
    async fn get_pending_deletion(&self, user_id: &str) -> Result<Option<PendingDeletion>>;
    async fn get_due_deletions(&self) -> Result<Vec<PendingDeletion>>;

    // Required: Deletion
    async fn soft_delete_user(&self, user_id: &str) -> Result<()>;
    async fn hard_delete_user(&self, user_id: &str) -> Result<()>;

    // Optional: Cleanup (have default no-op implementations)
    async fn revoke_all_sessions(&self, user_id: &str) -> Result<usize>;
    async fn revoke_all_refresh_tokens(&self, user_id: &str) -> Result<usize>;
    async fn remove_all_trusted_devices(&self, user_id: &str) -> Result<usize>;
    async fn clear_mfa(&self, user_id: &str) -> Result<bool>;
    async fn clear_lockout(&self, user_id: &str) -> Result<bool>;

    // Optional: Notifications
    async fn send_confirmation_email(&self, user_id: &str, email: &str, scheduled_for: SystemTime) -> Result<()>;
    async fn send_deletion_notification(&self, email: &str) -> Result<()>;
}
```

If any cleanup method returns an error, the deletion is aborted before the account is
deleted, so sessions and tokens can never outlive the account. `request_deletion` returns the
error; `process_due_deletions` logs it (`auth.deletion.cleanup_failed`) and leaves the
deletion pending so the next run retries it. Keep cleanup methods idempotent.

### Usage

```rust
use tideway::auth::deletion::{AccountDeletionFlow, DeletionConfig, DeletionRequest};

let flow = AccountDeletionFlow::new(store, DeletionConfig::default());

// Request deletion (user-initiated). `user_id` must be the authenticated
// user's ID from your session/JWT, never a value from the request body.
let result = flow.request_deletion(DeletionRequest {
    user_id: authenticated_user_id,
    password: Some("current-password".to_string()),
    reason: Some("No longer using the service".to_string()),
}).await?;

// In an HTTP handler, deserialize the client body into `DeletionRequestBody`
// (password + reason only; unknown fields such as `user_id` are rejected) and
// attach the authenticated user's ID:
let result = flow.request_deletion(body.into_request(authenticated_user_id)).await?;

match result {
    DeletionResult::Scheduled { scheduled_for, .. } => {
        // Account will be deleted at scheduled_for timestamp
        // User received confirmation email with cancellation link
    }
    DeletionResult::Deleted { .. } => {
        // Account deleted immediately (no grace period)
    }
    _ => {}
}

// Cancel scheduled deletion
flow.cancel_deletion("user-123").await?;

// Check pending deletion status
if let Some(pending) = flow.get_pending_deletion("user-123").await? {
    println!("Deletion scheduled for {:?}", pending.scheduled_for);
}
```

When `require_password` is set, password attempts are limited per user (5 per 15 minutes by
default) and further attempts return `TooManyRequests`. Use `.with_rate_limiter(...)` to share a
limiter with other flows, or `.without_rate_limiter()` only when an equivalent per-account limit is
enforced elsewhere.

### Processing Scheduled Deletions

Run from a scheduled job (e.g., cron, background worker):

```rust
// Process all due deletions
let processed = flow.process_due_deletions().await?;
println!("Processed {} deletions", processed);
```

### Soft Delete vs Hard Delete

| Mode | Description | Use Case |
|------|-------------|----------|
| **Soft Delete** | Anonymizes user data, keeps record | GDPR compliance, audit trails |
| **Hard Delete** | Completely removes user from database | When no audit trail needed |

Soft delete typically:
- Replaces email with `deleted-{user_id}@deleted.local`
- Clears personal data fields
- Keeps record for referential integrity

### Cascading Cleanup

Account deletion automatically cleans up:
- All active sessions
- All refresh tokens
- All trusted devices
- MFA settings (TOTP secret, backup codes)
- Lockout state

### Deletion Events

| Target | Level | Description |
|--------|-------|-------------|
| `auth.deletion.scheduled` | INFO | Deletion scheduled (grace period) |
| `auth.deletion.cancelled` | INFO | Scheduled deletion cancelled |
| `auth.deletion.completed` | WARN | Account deleted |
| `auth.deletion.user_not_found` | WARN | Deletion requested for non-existent user |
| `auth.deletion.password_invalid` | WARN | Deletion rejected: wrong password |
| `auth.reauth.rate_limited` | WARN | Deletion blocked after too many password attempts |
| `auth.deletion.process_failed` | ERROR | Failed to process scheduled deletion |
| `auth.deletion.batch_processed` | INFO | Batch of scheduled deletions processed |

### Database Schema

```sql
-- Pending deletions table
CREATE TABLE pending_deletions (
    user_id UUID PRIMARY KEY REFERENCES users(id),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scheduled_for TIMESTAMPTZ NOT NULL,
    reason TEXT
);

CREATE INDEX idx_pending_deletions_scheduled ON pending_deletions(scheduled_for);

-- For soft delete, add to users table:
ALTER TABLE users ADD COLUMN deleted_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN deletion_reason TEXT;
```

### GDPR Compliance Notes

1. **Right to erasure**: Use `AccountDeletionFlow` for user-initiated deletion
2. **Grace period**: Recommended 7-14 days for accidental deletion recovery
3. **Data portability**: Export user data before deletion (implement separately)
4. **Audit log**: Keep deletion records for compliance (use soft delete)
5. **Third-party data**: Ensure cascading cleanup reaches all user data

## Admin Impersonation

Allow administrators to temporarily act as another user for debugging and support purposes.

### ImpersonationConfig

```rust
use tideway::auth::impersonation::{ImpersonationManager, ImpersonationConfig, BlockedAction};
use std::time::Duration;

// Default: 1 hour, reason required, blocks destructive actions
let config = ImpersonationConfig::new();

// Strict: notify user, shorter duration
let config = ImpersonationConfig::strict();

// Permissive: 4 hours, no reason required (internal tools)
let config = ImpersonationConfig::permissive();

// Custom configuration
let config = ImpersonationConfig::new()
    .max_duration(Duration::from_secs(30 * 60))  // 30 minutes
    .notify_user(true)                            // Email user on start
    .notify_on_end(true)                          // Email user on end
    .allow_admin_impersonation(false)             // Can't impersonate other admins (never overrides user opt-out)
    .require_reason(true)                         // Must provide reason
    .blocked_actions(vec![
        BlockedAction::DeleteAccount,
        BlockedAction::ChangePassword,
        BlockedAction::ChangeMfa,
        BlockedAction::ChangeEmail,
        BlockedAction::ModifyBilling,
    ]);
```

### ImpersonationStore Trait

```rust
use tideway::auth::impersonation::{ImpersonationStore, ImpersonationSession, ImpersonationAuditEntry};
use async_trait::async_trait;

#[async_trait]
impl ImpersonationStore for MyStore {
    // Required: Permission checks
    async fn is_admin(&self, user_id: &str) -> Result<bool>;
    // Per-user eligibility (e.g. opt-out). Always enforced, even with
    // `allow_admin_impersonation(true)`. Don't return false just because the
    // user is an admin; admin targets are gated via `is_admin` + config.
    async fn can_be_impersonated(&self, user_id: &str) -> Result<bool>;
    async fn user_exists(&self, user_id: &str) -> Result<bool>;
    async fn get_user_email(&self, user_id: &str) -> Result<Option<String>>;

    // Required: Session management
    async fn create_session(&self, session: &ImpersonationSession) -> Result<()>;
    async fn get_session(&self, session_id: &str) -> Result<Option<ImpersonationSession>>;
    async fn get_session_for_user(&self, target_user_id: &str) -> Result<Option<ImpersonationSession>>;
    async fn get_sessions_by_admin(&self, admin_id: &str) -> Result<Vec<ImpersonationSession>>;
    async fn end_session(&self, session_id: &str) -> Result<bool>;
    async fn end_sessions_for_user(&self, target_user_id: &str) -> Result<usize>;

    // Required: Audit logging
    async fn record_audit(&self, entry: &ImpersonationAuditEntry) -> Result<()>;
    async fn get_audit_log(&self, user_id: &str, limit: usize) -> Result<Vec<ImpersonationAuditEntry>>;

    // Optional: Notifications (has default no-op)
    async fn send_notification(&self, email: &str, admin_id: &str, event: &ImpersonationEvent) -> Result<()>;
}
```

### Usage

```rust
use tideway::auth::impersonation::{ImpersonationManager, ImpersonationConfig, ImpersonationRequest};

let manager = ImpersonationManager::new(store, ImpersonationConfig::default());

// Start impersonation. `admin_id` must be the authenticated admin's ID from
// your session/JWT, never a value from the request body.
let session = manager.start_impersonation(ImpersonationRequest {
    admin_id: authenticated_admin_id,
    target_user_id: "user-456".to_string(),
    reason: Some("Support ticket #789".to_string()),
    duration: None,  // Use config default
}).await?;

// In an HTTP handler, deserialize the client body into `ImpersonationRequestBody`
// (`target_user_id`, `reason`, `duration_secs`; unknown fields such as `admin_id`
// are rejected) and attach the authenticated admin's ID:
let session = manager.start_impersonation(body.into_request(authenticated_admin_id)).await?;

// Issue an access token with the impersonation claims (imp_session, imp_admin,
// imp_blocked) that expires with the session. Don't issue a refresh token.
let subject = TokenSubject::new(&session.target_user_id)
    .with_custom(ImpersonationClaims::from_session(&session));
let (access_token, _) = issuer.issue_access_token_expiring_at(subject, session.expires_at)?;

// On each request, read the claims and reject the token once its session has
// ended or expired.
let data = verifier
    .with_claims::<AccessTokenClaims<ImpersonationClaims>>()
    .verify_access_token(&access_token)
    .await?;
if let Some(claims) = data.claims.custom {
    manager.validate_session(&claims.imp_session, None).await?;
}

// Validate session and check if action is allowed
let session = manager.validate_session(&session.session_id, Some("view_profile")).await?;

// This would fail - blocked action
let result = manager.validate_session(&session.session_id, Some("delete_account")).await;
// Returns Err(Forbidden("Action 'delete_account' is not allowed during impersonation"))

// End impersonation
manager.end_impersonation(&session.session_id).await?;

// When an admin logs out or loses admin access, end everything they started
manager.end_all_for_admin(&admin_id).await?;
```

`validate_session` also re-checks `ImpersonationStore::is_admin` for the session's admin and
ends the session if it fails, so demoting an admin cuts off their impersonation tokens on the
next request.

### Blocked Actions

During impersonation, certain actions are blocked by default:

| Action | Description |
|--------|-------------|
| `delete_account` | Account deletion |
| `change_password` | Password changes |
| `change_mfa` | MFA settings |
| `change_email` | Email changes |
| `modify_billing` | Payment/billing (strict mode) |
| `export_data` | Data export (strict mode) |

Use `BlockedAction::Custom("action_name")` for app-specific restrictions.

### UI Integration

Detect impersonation in your frontend using JWT claims:

```typescript
// In your frontend
const token = decodeJwt(accessToken);

if (token.imp_session) {
  // Show impersonation banner
  showBanner(`Admin ${token.imp_admin} is viewing as this user`);

  // Disable blocked actions
  const blockedActions = token.imp_blocked;
  disableButtons(blockedActions);
}
```

### Impersonation Events

| Event | Description |
|-------|-------------|
| `auth.impersonation.started` | Session started |
| `auth.impersonation.ended` | Session ended normally |
| `auth.impersonation.expired` | Session expired |
| `auth.impersonation.blocked` | Blocked action attempted |
| `auth.impersonation.rejected` | Start rejected (not admin, already impersonated, etc.) |

### Database Schema

```sql
CREATE TABLE impersonation_sessions (
    session_id VARCHAR(255) PRIMARY KEY,
    admin_id UUID NOT NULL REFERENCES users(id),
    target_user_id UUID NOT NULL REFERENCES users(id),
    reason TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    ended_at TIMESTAMPTZ
);

CREATE INDEX idx_imp_sessions_admin ON impersonation_sessions(admin_id);
CREATE INDEX idx_imp_sessions_target ON impersonation_sessions(target_user_id);
CREATE INDEX idx_imp_sessions_active ON impersonation_sessions(target_user_id)
    WHERE ended_at IS NULL;

CREATE TABLE impersonation_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event VARCHAR(50) NOT NULL,
    session_id VARCHAR(255) NOT NULL,
    admin_id UUID NOT NULL,
    target_user_id UUID NOT NULL,
    reason TEXT,
    metadata TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_imp_audit_admin ON impersonation_audit(admin_id);
CREATE INDEX idx_imp_audit_target ON impersonation_audit(target_user_id);
```

### Security Notes

1. **Only admins can impersonate**: `is_admin()` is checked at start and on every
   `validate_session`
2. **Cannot impersonate admins by default**: Prevent privilege escalation
3. **Cannot impersonate yourself**: Self-impersonation is blocked
4. **One impersonation per user**: Can't have multiple admins on same user
5. **Full audit trail**: Every action is logged with timestamp and reason
6. **Time-limited sessions**: Auto-expire after configured duration
7. **Explicit end required**: Call `end_all_for_admin` from your admin logout handler;
   sessions otherwise last until they expire or are ended

## Security Best Practices

### Password Storage

1. **Use Argon2id** (default) - resistant to GPU and side-channel attacks
2. **Enable auto-rehashing** - transparently upgrades old hashes
3. **Enforce password policy** - use `PasswordPolicy::modern()` at minimum

### Token Security

1. **Short access token TTL** - 15 minutes recommended
2. **Longer refresh token TTL** - 7 days, with rotation
3. **Enable reuse detection** - use `RefreshTokenStore`
4. **Revoke on password change** - call `revoke_all_for_user`

### Account Protection

1. **Implement lockout** - 5 failed attempts, 15 minute lockout
2. **Require email verification** - set `require_verification(true)`
3. **Enable MFA** - encourage TOTP setup
4. **Monitor security events** - alert on `auth.token.reuse_detected`
5. **Enable login rate limiting** - use `with_rate_limiter()` to protect against brute force

### Email Enumeration Prevention

The auth flows prevent email enumeration:
- Login returns same error for "user not found" and "wrong password"
- Login returns that same error for a locked account whatever password is sent, so a lockout
  cannot confirm a guess. Tell users about a lock out of band (for example a lockout email)
- `RegistrationFlow::register` returns the created user, so it reveals whether an email is
  already registered (an existing email gets "Registration failed"). Where that matters, call
  `register_without_enumeration` instead: it returns `Ok(())` for new and existing emails alike,
  hashes the password in both cases, and calls `UserCreator::notify_existing_account` so the
  owner can be emailed. Answer with the same "check your email" response and do not log the
  user in from registration
- Password reset always returns success (even for non-existent emails)

Internal logs capture the actual reason for debugging.

## Database Schema

The API starter generates these auth migrations:

- `m001_create_users.rs` - Users table
- `m002_create_refresh_tokens.rs` - Refresh-token families
- `m003_create_auth_tokens.rs` - One-time email, reset, and MFA challenge tokens
- `m004_create_mfa.rs` - Encrypted TOTP state and hashed recovery codes (when
  `auth-mfa` is enabled)

Additional session-management integrations may add a sessions migration.

### Sessions Table Schema

```sql
CREATE TABLE sessions (
    id VARCHAR(255) PRIMARY KEY,      -- Same as token family ID
    user_id UUID NOT NULL REFERENCES users(id),
    ip_address VARCHAR(45),           -- IPv4 or IPv6
    user_agent TEXT,
    device_info VARCHAR(255),         -- Parsed: "Chrome on macOS"
    location VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ            -- NULL if active
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_user_active ON sessions(user_id) WHERE revoked_at IS NULL;
```

## Complete Example

See `examples/seaorm_auth.rs` for a complete working example with:
- All storage trait implementations
- HTTP endpoints for register, login, refresh
- Token rotation and MFA support

## Future Enhancements

The following features are not currently implemented but may be added in future versions:

| Feature | Description | Use Case |
|---------|-------------|----------|
| **Password History** | Prevent reuse of last N passwords | Enterprise compliance (SOC2, HIPAA) |
| **Magic Links** | Passwordless login via email link | Improved UX, reduced friction |
| **API Keys** | Long-lived tokens with scopes for service-to-service auth | Developer APIs, integrations |
| **Login Notifications** | Email alerts on new device/location login | Security-conscious users |
| **Remember Me Tokens** | Persistent login across browser sessions | Long-lived user sessions |

Note: Password expiry (forced rotation) is intentionally not planned, as [NIST guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html) now recommend against mandatory periodic password changes.
