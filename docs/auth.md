# Authentication

Tideway provides a complete authentication system with password hashing, JWT tokens, MFA, and common auth flows.

## Features

- **Password Hashing**: Argon2id with automatic rehashing
- **JWT Tokens**: Access and refresh tokens with rotation
- **MFA**: TOTP (Google Authenticator) and backup codes
- **Auth Flows**: Login, registration, password reset/change, email verification
- **Breach Checking**: HaveIBeenPwned integration (opt-in)
- **Session Management**: List and revoke active sessions
- **Trusted Devices**: Remember devices to skip MFA on subsequent logins
- **Account Lockout**: Progressive delays, notifications, admin unlock
- **Account Deletion**: GDPR-compliant deletion with grace period
- **Admin Impersonation**: Act as users for support with full audit trail
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

### Password Change Events

| Target | Level | Description |
|--------|-------|-------------|
| `auth.password.change_failed` | WARN | Wrong current password |
| `auth.password.change_failed` | INFO | Weak new password or same password |
| `auth.password.changed` | INFO | Password changed successfully |

## Password Breach Checking

Check passwords against the HaveIBeenPwned database to prevent use of compromised passwords.

Requires `auth-breach` feature:

```toml
[dependencies]
tideway = { version = "0.7", features = ["auth", "auth-breach"] }
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
use tideway::auth::sessions::{SessionManager, SessionMetadata};

let manager = SessionManager::new(session_store);

// Create session on login
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

// Clear on successful login
manager.record_successful_login("user-123", Some("1.2.3.4")).await?;

// Admin unlock
manager.admin_unlock("user-123", "admin-456").await?;
```

### Integration with LoginFlow

```rust
async fn login_handler(
    State(lockout): State<LockoutManager<...>>,
    State(login): State<LoginFlow<...>>,
    client_ip: Option<String>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    let user_id = get_user_id_by_email(&req.email).await?;

    // Check lockout before attempting login
    if let Some(status) = lockout.check_can_attempt(&user_id, client_ip.as_deref()).await? {
        return Ok(Json(LoginResponse::error(format!(
            "Too many failed attempts. Try again in {} seconds.",
            status.remaining_wait_seconds()
        ))));
    }

    // Attempt login
    match login.login(req).await {
        Ok(response) => {
            lockout.record_successful_login(&user_id, client_ip.as_deref()).await?;
            Ok(Json(response))
        }
        Err(e) if is_auth_error(&e) => {
            let result = lockout.record_failed_attempt(&user_id, client_ip.as_deref()).await?;
            if result.just_locked {
                Ok(Json(LoginResponse::error("Account locked due to too many failed attempts")))
            } else if !result.can_retry_now() {
                Ok(Json(LoginResponse::error(format!(
                    "Please wait {} seconds before retrying",
                    result.wait_seconds()
                ))))
            } else {
                Ok(Json(LoginResponse::error("Invalid credentials")))
            }
        }
        Err(e) => Err(e),
    }
}
```

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
| Reset | Automatic (time window) | On successful login |
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

### Usage

```rust
use tideway::auth::deletion::{AccountDeletionFlow, DeletionConfig, DeletionRequest};

let flow = AccountDeletionFlow::new(store, DeletionConfig::default());

// Request deletion (user-initiated)
let result = flow.request_deletion(DeletionRequest {
    user_id: "user-123".to_string(),
    password: Some("current-password".to_string()),
    reason: Some("No longer using the service".to_string()),
}).await?;

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
    .allow_admin_impersonation(false)             // Can't impersonate other admins
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

// Start impersonation
let session = manager.start_impersonation(ImpersonationRequest {
    admin_id: "admin-123".to_string(),
    target_user_id: "user-456".to_string(),
    reason: Some("Support ticket #789".to_string()),
    duration: None,  // Use config default
}).await?;

// Include impersonation info in JWT claims
let claims = ImpersonationClaims::from_session(&session);
// Add to your JWT: imp_session, imp_admin, imp_blocked

// Validate session and check if action is allowed
let session = manager.validate_session(&session.session_id, Some("view_profile")).await?;

// This would fail - blocked action
let result = manager.validate_session(&session.session_id, Some("delete_account")).await;
// Returns Err(Forbidden("Action 'delete_account' is not allowed during impersonation"))

// End impersonation
manager.end_impersonation(&session.session_id).await?;
```

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

1. **Only admins can impersonate**: Check `is_admin()` before allowing
2. **Cannot impersonate admins by default**: Prevent privilege escalation
3. **Cannot impersonate yourself**: Self-impersonation is blocked
4. **One impersonation per user**: Can't have multiple admins on same user
5. **Full audit trail**: Every action is logged with timestamp and reason
6. **Time-limited sessions**: Auto-expire after configured duration
7. **Explicit end required**: Sessions don't persist across admin logout

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
- `m005_create_sessions.rs` - Active sessions (for session management)

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
| **OAuth/Social Login** | Google, GitHub, Apple sign-in | Consumer apps, reduced registration friction |
| **API Keys** | Long-lived tokens with scopes for service-to-service auth | Developer APIs, integrations |
| **Login Notifications** | Email alerts on new device/location login | Security-conscious users |
| **Remember Me Tokens** | Persistent login across browser sessions | Long-lived user sessions |

Note: Password expiry (forced rotation) is intentionally not planned, as [NIST guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html) now recommend against mandatory periodic password changes.
