# Authentication

Tideway provides a complete authentication system with password hashing, JWT tokens, MFA, and common auth flows.

## Features

- **Password Hashing**: Argon2id with automatic rehashing
- **JWT Tokens**: Access and refresh tokens with rotation
- **MFA**: TOTP (Google Authenticator) and backup codes
- **Auth Flows**: Login, registration, password reset, email verification
- **Security Events**: Comprehensive tracing for monitoring

## Quick Start

Enable the auth features in your `Cargo.toml`:

```toml
[dependencies]
tideway = { version = "0.7", features = ["auth", "auth-mfa"] }
```

### Basic Login Flow

```rust
use tideway::auth::{
    flows::{LoginFlow, LoginFlowConfig, LoginRequest},
    JwtIssuer, JwtIssuerConfig,
};

// Configure JWT issuer
let jwt_config = JwtIssuerConfig::with_secret(&jwt_secret, "my-app");
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

    // Consume token, return user_id if valid and not expired
    async fn consume_reset_token(&self, token_hash: &str) -> Result<Option<String>>;

    // Update user's password
    async fn update_password(&self, user_id: &str, hash: &str) -> Result<()>;

    // Invalidate all sessions (revoke refresh tokens)
    async fn invalidate_sessions(&self, user_id: &str) -> Result<()>;

    // Send reset email with token
    async fn send_reset_email(
        &self,
        user: &Self::User,
        token: &str,
        expires_in: Duration,
    ) -> Result<()>;
}
```

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

## JWT Configuration

```rust
use tideway::auth::{JwtIssuer, JwtIssuerConfig};

// HMAC-SHA256 (symmetric)
let config = JwtIssuerConfig::with_secret("your-secret-key", "my-app")
    .access_token_ttl(Duration::from_secs(900))      // 15 minutes
    .refresh_token_ttl(Duration::from_secs(604800))  // 7 days
    .remember_me_ttl(Duration::from_secs(2592000)); // 30 days

let issuer = JwtIssuer::new(config)?;

// Issue tokens
let subject = TokenSubject::new("user-123")
    .with_email("user@example.com")
    .with_name("John Doe")
    .with_claim("role", "admin");

let tokens = issuer.issue(subject, false)?; // false = don't remember me
```

## MFA (Multi-Factor Authentication)

Requires `auth-mfa` feature.

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

// codes.codes - Vec of 10 hashed backup codes to store
// codes.display_codes - Plain codes to show user ONCE

// Verify backup code (returns index if valid)
if let Some(index) = BackupCodeGenerator::verify("ABCD-1234", &stored_codes) {
    // Remove used code
    stored_codes.remove(index);
}
```

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

## Login Rate Limiting

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

When behind a reverse proxy, extract the real client IP from headers:

```rust
async fn login_handler(
    headers: HeaderMap,
    State(flow): State<LoginFlow<...>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    // Extract from X-Forwarded-For (trust your proxy!)
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string());

    let response = flow.login_with_ip(req, client_ip).await?;
    Ok(Json(response))
}
```

### Rate Limit Events

| Target | Level | Description |
|--------|-------|-------------|
| `auth.login.rate_limited` | WARN | Login blocked due to rate limiting |

### How It Works

1. **IP-based tracking**: Each IP address has its own rate limit bucket
2. **GCRA algorithm**: Uses governor crate's Generic Cell Rate Algorithm for accurate limiting
3. **Automatic cleanup**: Stale entries are periodically removed to prevent memory growth
4. **Complements user lockout**: Works alongside `record_failed_attempt()` for defense in depth

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
- Registration returns generic "Registration failed" for existing emails
- Password reset always returns success (even for non-existent emails)

Internal logs capture the actual reason for debugging.

## Database Schema

See `examples/auth_migrations/` for SeaORM migration examples:

- `m001_create_users.rs` - Users table
- `m002_create_refresh_tokens.rs` - Token families
- `m003_create_mfa.rs` - MFA configuration
- `m004_create_verification_tokens.rs` - Email/reset tokens

## Complete Example

See `examples/seaorm_auth.rs` for a complete working example with:
- All storage trait implementations
- HTTP endpoints for register, login, refresh
- Token rotation and MFA support
