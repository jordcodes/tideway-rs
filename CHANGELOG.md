# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.1] - 2025-12-12

### Fixed

- **Compilation fix**: Updated `tower-http` minimum version to 0.6.7 to ensure `TimeoutLayer::with_status_code()` method is available. Version 0.7.0 would fail to compile with older tower-http versions.

## [0.7.0] - 2025-12-12

### Security

This release contains important security hardening for enterprise deployments.

- **ConsoleMailer now redacts email content by default.** Email body content is no longer printed to stdout to prevent sensitive data (tokens, PII, verification links) from being captured in container logs.

- **Webhook signature prefix is now strictly enforced.** When using `HmacSha256Verifier::new_with_prefix()`, signatures missing the required prefix are now rejected instead of silently accepting unprefixed signatures.

- **Database credentials protected in all output.** Both `Debug` and `Serialize` implementations for `DatabaseConfig` now redact the password, preventing credential leakage in logs, JSON serialization, and error messages.

- **JWT warning spam eliminated.** Security warnings for missing issuer/audience validation now fire only once per verifier instance using `OnceLock`.

### Added

- `RedisJobQueue::shutdown()` - Gracefully stop the background scheduler task
- `RedisJobQueue::ping()` - Async health check that updates cached status
- `InMemoryJobQueue::shutdown()` - Gracefully stop the background scheduler task
- `InMemoryJobQueue::with_history_limit()` - Create queue with custom completed/failed history size
- `RedisCache::ping()` - Async health check that updates cached status
- `SeaOrmPool::ping()` - Async health check that updates cached status
- `ConnectionManager::reconcile_counter()` - Detect and correct connection counter drift
- `ConsoleMailer::with_full_output()` - Opt-in to see full email content (development only)
- Configuration validation warnings for invalid environment variables (compression, timeout, session configs)

### Changed

- **BREAKING**: `ConsoleMailer` now redacts email body content by default. Use `.with_full_output(true)` to see full content.
- **BREAKING**: `HmacSha256Verifier::new_with_prefix()` now rejects signatures missing the required prefix (was silently accepting).
- `InMemoryJobQueue` completed/failed lists are now bounded (default 10,000) to prevent unbounded memory growth.
- `is_healthy()` methods on `RedisCache`, `RedisJobQueue`, `InMemoryJobQueue`, and `SeaOrmPool` now return cached status from `ping()` instead of blocking.
- Database pool configuration now validates limits: `max_connections` (1-1000), `connect_timeout` (1-300 seconds).
- Signal handlers in `App::serve()` use fallback instead of panicking on failure.
- Shutdown grace period increased from 2 to 5 seconds.

### Fixed

- **Blocking I/O in async context**: `InMemoryJobQueue::is_healthy()` used `blocking_lock()` which could deadlock the async runtime. Now uses `AtomicBool`.
- **Resource leak**: Background scheduler tasks in `RedisJobQueue` and `InMemoryJobQueue` now have proper shutdown mechanisms.
- **Unbounded memory growth**: `InMemoryJobQueue` completed/failed job lists now have configurable size limits.
- **Panic in production**: Removed `expect()` calls in `App::serve()` that could panic on invalid config or signal handler failures.
- **WebSocket connection counter drift**: Added `reconcile_counter()` to detect and correct atomic counter drift.

### Migration Guide

#### ConsoleMailer (Breaking Change)

If you use `ConsoleMailer` for development and need to see full email content:

```rust
// Before (0.6.x) - full content shown by default
let mailer = ConsoleMailer::new();

// After (0.7.0) - content redacted by default
let mailer = ConsoleMailer::new();  // Shows: "[TEXT] 42 bytes [REDACTED]"

// To see full content (development only):
let mailer = ConsoleMailer::new().with_full_output(true);
```

#### Webhook Signature Verification (Breaking Change)

If you use `HmacSha256Verifier::new_with_prefix()`, signatures **must** now include the prefix:

```rust
// Verifier configured with prefix
let verifier = HmacSha256Verifier::new_with_prefix(secret, "sha256=");

// Before (0.6.x) - both would pass:
verifier.verify_signature(payload, "sha256=abc123...").await  // OK
verifier.verify_signature(payload, "abc123...").await         // Also OK (wrong!)

// After (0.7.0) - prefix is required:
verifier.verify_signature(payload, "sha256=abc123...").await  // OK
verifier.verify_signature(payload, "abc123...").await         // FAILS (correct!)
```

#### Job Queue Shutdown (Recommended)

For clean resource cleanup, call `shutdown()` before dropping job queues:

```rust
// Redis job queue
let queue = RedisJobQueue::new("redis://localhost", None, 3, 5)?;
// ... use queue ...
queue.shutdown().await;  // NEW: Clean shutdown

// In-memory job queue
let queue = InMemoryJobQueue::new(3, 60);
// ... use queue ...
queue.shutdown().await;  // NEW: Clean shutdown
```

#### Health Check Pattern (Recommended)

For accurate health status, run periodic `ping()` calls:

```rust
// Database pool
let pool = SeaOrmPool::from_config(&config).await?;
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        pool.ping().await;  // Updates cached health status
    }
});

// is_healthy() now returns cached status (non-blocking)
if pool.is_healthy() { /* ... */ }
```

## [0.6.0] - 2025-12-12

### Security

**Cookie sessions are now properly encrypted.** Previously, session data was stored as plaintext JSON despite having an encryption key configured. This version implements authenticated encryption using XChaCha20-Poly1305 via the `cookie` crate's private cookies.

### Changed
- **BREAKING**: Cookie session encryption key must now be 64 bytes (128 hex characters), not 32 bytes. Generate with: `openssl rand -hex 64`
- Session cookies are now encrypted and authenticated - tampered cookies are rejected
- Added `encrypt()` and `decrypt()` public methods to `CookieSessionStore` for direct use
- Updated session documentation with correct key size requirements

### Migration Guide

If you were using cookie sessions, regenerate your encryption key:

```bash
# Old (no longer works):
# openssl rand -hex 32

# New (required):
openssl rand -hex 64
export SESSION_ENCRYPTION_KEY=your-128-char-hex-key
```

**Important:** Existing sessions will be invalidated when you upgrade, as the encryption format has changed.

## [0.5.0] - 2025-12-12

### Security

This release contains important security fixes. Users are strongly encouraged to upgrade.

- **Webhook HMAC verification**: Implemented proper HMAC-SHA256 signature verification with timing-safe comparison using the `subtle` crate. Previously, the webhook verifier accepted any non-empty signature.

- **Session encryption key requirement**: Cookie sessions now require an explicit encryption key. Without it, `CookieSessionStore::new()` returns an error. Use `allow_insecure_key: true` for development only.

- **Error information disclosure (CWE-209)**: Server errors (5xx) now hide internal details in production, preventing leakage of database credentials, internal hostnames, SQL queries, and stack traces.

- **Rate limiter IP spoofing**: Added `trust_proxy` configuration (default: `false`). X-Forwarded-For headers are now ignored by default to prevent IP spoofing attacks.

- **CORS disabled by default**: CORS is now disabled by default and must be explicitly enabled.

### Added
- `HmacSha256Verifier` for webhook signature verification with support for hex, base64, and prefixed signatures
- `trust_proxy` configuration for rate limiting
- `allow_insecure_key` configuration for session development mode
- `safe_message()` method on `TidewayError` for production-safe error messages
- Comprehensive test suite (200+ tests)
- Webhook documentation (`docs/webhooks.md`)

### Changed
- **BREAKING**: CORS `enabled` now defaults to `false` (was `true`)
- **BREAKING**: Rate limiter `trust_proxy` defaults to `false` - X-Forwarded-For is no longer trusted by default
- **BREAKING**: Cookie sessions require `encryption_key` or `allow_insecure_key: true`
- Session encryption key error now returns `Result` instead of panicking
- Updated `sessions.md`, `rate_limiting.md`, and `error_handling.md` documentation

### Dependencies
- Added `subtle` crate for timing-safe cryptographic operations
- `hmac` and `sha2` crates (already present) now used for webhook verification

### Migration Guide

#### CORS Configuration

CORS is now disabled by default. To enable:

```rust
// Option 1: Use permissive() for development
let cors = CorsConfig::permissive();

// Option 2: Explicitly enable with origins
let cors = CorsConfig::builder()
    .enabled(true)
    .allow_origin("https://example.com")
    .build();
```

#### Session Configuration

Cookie sessions now require a 64-byte encryption key (128 hex characters):

```bash
# Generate a key
openssl rand -hex 64

# Set environment variable
export SESSION_ENCRYPTION_KEY=your-128-char-hex-key
```

Or for development only:
```rust
let config = SessionConfig {
    allow_insecure_key: true,  // WARNING: Never use in production!
    ..Default::default()
};
```

#### Rate Limiting Behind a Proxy

If your application is behind nginx, AWS ALB, or Cloudflare:

```rust
let rate_limit = RateLimitConfig::builder()
    .enabled(true)
    .per_ip()
    .trust_proxy(true)  // Enable this if behind a trusted proxy
    .build();
```

Or via environment:
```bash
export RATE_LIMIT_TRUST_PROXY=true
```

## [0.4.0] - 2025-12-11

### Added
- Comprehensive test coverage for core modules

### Changed
- **BREAKING**: `SeaOrmPool::as_ref()` renamed to `SeaOrmPool::inner()` to avoid confusion with `std::convert::AsRef` trait
- **BREAKING**: `DatabaseConnection::as_ref()` renamed to `DatabaseConnection::inner()`
- **BREAKING**: `TestUser::default()` renamed to `TestUser::generate()` to avoid confusion with `std::default::Default` trait

### Fixed
- Fixed deprecated `TimeoutLayer::new` usage (now uses `with_status_code`)
- Fixed all clippy warnings across the codebase
- Improved code quality with idiomatic Rust patterns

### Migration Guide

#### Database Connection Changes

If you were using `as_ref()` to get the inner SeaORM connection:

```rust
// Before (0.3.x)
let conn = sea_orm_pool.as_ref();

// After (0.4.0)
let conn = sea_orm_pool.inner();
```

#### TestUser Changes

If you were using `TestUser::default()` in tests:

```rust
// Before (0.3.x)
let user = TestUser::default();

// After (0.4.0)
let user = TestUser::generate();
```

The rename to `generate()` better reflects that this creates a new user with randomly generated fake data, not a "default" user with empty/zero values.

## [0.3.0] - 2025-12-11

### Added
- **Email support** with `Mailer` trait for sending transactional emails
- `ConsoleMailer` for development (prints emails to stdout)
- `SmtpMailer` using lettre for production SMTP
- `SmtpConfig` with builder pattern and `from_env()` for configuration
- `AppContext::with_mailer()` builder method for dependency injection
- Documentation for third-party email services (Resend, SendGrid, Postmark, AWS SES)
- Email example and comprehensive test suite

## [0.2.1] - 2025-12-11

### Fixed
- Various bug fixes and improvements

## [0.2.0] - 2025-12-11

### Added
- Background jobs system with `JobQueue` trait
- WebSocket support with connection management
- In-memory and Redis-backed job queues

## [0.1.0] - Initial Release

### Added
- Core framework with Axum integration
- Route modules and modular architecture
- Database support with SeaORM
- Cache and session traits
- Request validation
- Health checks
- Prometheus metrics
- Compression and security middleware
- Alba-style testing utilities
