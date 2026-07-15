# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release owners: copy a short DX gate summary into the release notes and use `docs/dx_metrics_snapshot.md` as the source of record for DX reporting.

## [Unreleased]

## [tideway-cli 0.1.42] - 2026-07-15

### Fixed

- Generated SaaS auth tests are compiled and run, use the current auth API, and exercise
  registration and login against the generated migrations on SQLite.
- Billing plan JSON is emitted as typed JSON values and generated migration crates enable
  SeaORM's JSON support, so PostgreSQL accepts the seeded `jsonb` columns.
- Organization admin columns are added and removed in separate statements for SQLite
  compatibility.
- Fresh SaaS projects use a syntactically valid local-only Stripe test key, while generated
  applications reject that placeholder outside development and test environments.
- `tideway doctor` recognizes direct `Migrator::up` calls instead of reporting that generated
  migrations are not run automatically.
- Database-backed projects are Cargo workspaces, so the application and migration crate share one
  root lockfile.
- Generated Compose files no longer use the obsolete top-level `version` field.

### DX Gate

- The complete CLI suite passes, including a warning-free generated SaaS application compiled and
  tested across all targets against Tideway 0.7.26.
- The generated SaaS auth lifecycle runs every migration on SQLite and verifies registration and
  login, preventing orphaned or stale scaffold tests from passing silently.
- Strict workspace formatting, Clippy, and repository guardrails pass.

### Migration Notes

- Install with `cargo install tideway-cli --version 0.1.42`; newly generated projects continue to
  use Tideway 0.7.26.
- Existing applications are not rewritten. They may adopt the workspace, migration dependency,
  SQLite migration, and local Stripe placeholder changes selectively where relevant.

## [tideway-cli 0.1.41] - 2026-07-15

### Added

- Fresh API and SaaS scaffolds include provider-neutral transactional email delivery with console,
  SMTP, and Resend configuration. Generated verification, password-reset, and invitation flows send
  working application-owned email templates.
- Greenfield SaaS and B2B scaffolds include application-owned organization invitation routes,
  persistence, migrations, email delivery, and an authenticated Vue acceptance flow. Invitations
  remain optional through `--without-invitations`.
- Organization administrators can resend a pending invitation through an organization-scoped,
  rate-limited endpoint that rotates the bearer token and refreshes its expiry.

### Security

- Generated invitations store token digests, verify the accepting account's email, enforce
  organization-scoped administration, reject owner-role grants, claim tokens atomically, and clean
  up failed email delivery safely.
- Invitation issuance and acceptance serialize organization membership changes and enforce billing
  seat availability, including concurrent requests for the final seat.

### Fixed

- Generated B2C checkout sessions use the authenticated database user's ID and email instead of an
  empty Stripe customer email placeholder.

### DX Gate

- The complete CLI suite passes, including warning-free generated minimal, API, auth/MFA, and SaaS
  applications compiled and tested against Tideway 0.7.26.
- Strict workspace Clippy, formatting, generated-app behavioral tests, and repository guardrails
  pass.

### Migration Notes

- Install with `cargo install tideway-cli --version 0.1.41`; newly generated projects use Tideway
  0.7.26.
- Existing generated applications remain application-owned and are not modified by upgrade checks.
  Adopt the invitation security checklist in `docs/organizations.md` with schema-compatible edits.
- Existing email templates and delivery wiring remain application-owned; use `docs/email.md` to opt
  into Resend or the provider-neutral generated configuration without overwriting custom designs.

## [0.7.26] - 2026-07-15

### Added

- `ResendMailer` and `ResendConfig` provide a first-party HTTPS adapter with bounded request
  timeouts, redacted configuration output, and provider-neutral `Mailer` integration.
- `InvitationRateLimitProvider` lets applications replace the zero-configuration, process-local
  invitation limiter with an application-owned shared provider before deploying multiple replicas.

### Fixed

- Invitation quotas replenish the configured allowance evenly across the window instead of
  replenishing only one permit per complete window after the initial burst.

### DX Gate

- Auth, billing, SeaORM billing, email, and invitation rate-limit feature tests pass alongside the
  default framework suite.
- Strict workspace Clippy, formatting, documentation drift, filesystem-write, and public-API
  guardrails pass.

### Migration Notes

- This is an additive framework update with no required database migration. Existing `Mailer`
  implementations and `SmtpMailer` integrations remain compatible.
- The in-memory limiter remains the default and requires no Redis configuration. Applications using
  multiple API replicas should provide a shared `InvitationRateLimitProvider`.

## [tideway-cli 0.1.40] - 2026-07-14

### Fixed

- Fresh SaaS applications now compile their shared modules once through the generated library crate, eliminating warning noise without suppressing useful compiler diagnostics.
- `tideway resource` adds modules to `lib.rs` for library-based SaaS applications and registers the resource through the application crate, preserving auth visibility and warning-free compilation.
- The generated SaaS compile regression now treats warnings as errors.

### DX Gate

- The complete CLI suite passes, including warning-free SaaS generation and the `new SaaS` → `resource` → compile workflow.
- Strict CLI Clippy, formatting, and repository guardrails pass.

### Migration Notes

- Install with `cargo install tideway-cli --version 0.1.40`; generated projects continue to use Tideway 0.7.25.
- Existing applications do not require changes; this release affects newly generated files and future resource wiring.

## [tideway-cli 0.1.39] - 2026-07-14

### Added

- New SaaS backends include an application-owned `BillingEventSink` for provisioning, email, analytics, dunning, and durable job dispatch without changing Tideway's core billing state machine.
- `tideway doctor --upgrade` warns when a custom production billing store relies on the non-atomic compatibility implementation of `compare_and_save_subscription`.

### DX Gate

- The complete CLI suite passes, including clean generated minimal, API, auth/MFA, and SaaS projects compiled against Tideway 0.7.25.
- CLI packaging and repository documentation, filesystem-write, and public-API guardrails pass.

### Migration Notes

- Install with `cargo install tideway-cli --version 0.1.39`; generated projects use Tideway 0.7.25.
- Existing generated applications remain application-owned and are not overwritten. They may opt into lifecycle hooks with `WebhookHandler::with_event_sink`.

## [0.7.25] - 2026-07-14

### Added

- `BillingEventSink` provides typed, application-owned hooks after checkout, subscription, and invoice webhook processing, with a backward-compatible no-op default.

### Fixed

- Subscription compare-and-save operations now advance their optimistic-lock version, and the built-in SeaORM store performs subscription updates atomically so concurrent seat changes cannot silently overwrite each other.
- Billing lifecycle sink failures release the webhook claim for provider retry while retaining Tideway's successfully synchronized core subscription state.

### DX Gate

- The 641-test auth and billing feature suite, full workspace suite, formatting, and Cargo packaging verification pass.

### Migration Notes

- Custom production billing stores that support seat changes must implement atomic `compare_and_save_subscription` and advance the stored version after every successful write.
- Lifecycle event sinks must make side effects idempotent using the Stripe event ID and should enqueue slow work rather than performing it in the webhook request.

## [tideway-cli 0.1.38] - 2026-07-14

### Added

- `tideway doctor --upgrade` warns when a downstream custom `BillingStore` is missing the atomic `claim_event` or retry-safe `release_event_claim` override.
- The upgrade guide documents the required built-in SeaORM migration and the claim lifecycle contract for custom stores.
- Upgrade JSON now includes stable finding codes, affected paths, and documentation links; `--deny-warnings` provides a strict CI and agent exit status without modifying files.
- New backend scaffolds include an additive `billing_processed_events` migration with a primary-key event ID, and upgrade checks detect missing or incomplete versions of that migration.

### Migration Notes

- Install with `cargo install tideway-cli --version 0.1.38`; its upgrade checks target Tideway 0.7.24.

## [0.7.24] - 2026-07-14

### Fixed

- `SeaOrmBillingStore` now distinguishes inserted webhook claims from conflict results, preventing concurrent duplicate deliveries from both running handler side effects.
- Empty claim inserts fail closed, and a database-backed concurrency regression test verifies that exactly one caller wins.

### Migration Notes

- Built-in `SeaOrmBillingStore` users must add the `billing_processed_events` migration unless their application already has that table with `event_id` as its primary key.
- Custom `BillingStore` implementations must provide atomic `claim_event` and retry-safe `release_event_claim` implementations.

## [tideway-cli 0.1.37] - 2026-07-13

### Added

- `tideway dev` now watches Rust sources, migrations, Cargo manifests, and `.env`, then rebuilds and restarts the application after successful changes.
- Compile failures keep the last working server available, while superseded builds are cancelled and rapid editor saves are coalesced.
- `--no-watch` preserves the one-shot `cargo run` workflow, and a second `--` separates application arguments from Cargo arguments.

### Fixed

- Watch mode validates the configured host and port before compiling, with actionable guidance when the port is unavailable.
- `.env` changes are reloaded on restart, shell values retain precedence, and Ctrl-C or termination signals clean up child process trees.

### DX Gate

- A generated API was dogfooded through successful edits, compile failure and recovery, `.env` reload, save bursts, argument forwarding, health checks, and process cleanup.
- The CLI golden-path suite and repository DX guardrails pass without manually triggering hosted workflows.

### Migration Notes

- `tideway dev` now watches by default; use `tideway dev --no-watch` for the previous one-shot behaviour.
- Install with `cargo install tideway-cli --version 0.1.37`; generated projects use Tideway 0.7.23.

## [0.7.23] - 2026-07-13

### Fixed

- Graceful shutdown now hands control to Axum immediately instead of delaying connection draining by a fixed five seconds, substantially reducing development restart latency.
- The locked dependency graph uses the non-yanked `spin` 0.9.9 patch release.

### DX Gate

- The framework library suite, shutdown regression, generated-app health tests, and downstream smoke-project tests pass.
- Real-project incremental builds complete in roughly one second, with restart occurring immediately after graceful shutdown begins.

### Migration Notes

- No public APIs or generated source paths changed.
- Upgrade to `tideway = "0.7.23"`; applications receive the corrected shutdown behaviour without code changes.

## [tideway-cli 0.1.36] - 2026-07-13

### Fixed

- `tideway new --features mfa` now normalizes to the supported `auth-mfa` feature and generates the complete MFA entity, migration, route, and test scaffold.
- Unknown feature names fail before any files are written, with the supported feature list and a nearby suggestion when available.
- Existing shell environment variables now take precedence over `.env` for dev preflight, displayed URLs, and the Cargo child process.
- `tideway dev --no-migrate` explicitly sets `DATABASE_AUTO_MIGRATE=false` for the run, even when the shell or `.env` enables it.

### DX Gate

- Full CLI and workspace tests, strict all-feature Clippy, formatting, and all repository DX guardrails pass.
- A published-framework clean-room app booted on a shell-provided port that differed from `.env`, reported the effective URLs, honored `--no-migrate`, and returned a healthy response.

### Migration Notes

- No generated source paths or public framework APIs changed.
- Install with `cargo install tideway-cli --version 0.1.36`; generated projects continue to use Tideway 0.7.22.

## [0.7.22] - 2026-07-13

### Security

- Trusted-proxy resolution now accepts forwarded client IPs only from explicitly configured proxy networks and safely handles malformed or untrusted forwarding chains.
- Generated database-backed auth includes production-shaped registration, login, refresh rotation, logout, email verification, password reset, and access-token purpose checks.
- Generated MFA setup encrypts TOTP secrets at rest, hashes single-use backup codes, prevents secret disclosure through logs or caches, and verifies the complete enrollment and recovery lifecycle.
- Generated API onboarding uses secure environment defaults and makes authentication boundaries explicit in the starter routes and OpenAPI output.

### Fixed

- Fresh database-backed projects now include a runnable migration binary and automatically run migrations during local development when `DATABASE_AUTO_MIGRATE=true`.
- `tideway migrate` reuses the application target directory by default, avoiding a redundant migration build while preserving an explicitly configured `CARGO_TARGET_DIR`.
- Generated repository/service resources and auth extension hooks compile cleanly under strict Clippy without broad warning suppression.

### Changed

- `tideway-cli` 0.1.35 scaffolds Tideway 0.7.22.
- Database-enabled presets now generate a consistent entities and migration structure, including worker presets.
- The documented API workflow consistently follows `new` -> `dev --fix-env` -> `resource` -> `migrate`.

### DX Gate

- Quickstart parity, documentation drift, scaffold idempotency, golden-path integration, CLI filesystem policy, and public API checks pass.
- Fresh generated API projects compile, test, pass strict Clippy, start with an initialized database, and expose working health, resource, auth, OpenAPI, and Swagger routes.

### Migration Notes

- No public API removals or intentional breaking changes are included.
- Upgrade the framework to `tideway = "0.7.22"` and install `tideway-cli` 0.1.35 for newly generated projects.
- Existing generated applications are not rewritten automatically; adopt the new migration runner and hardened auth scaffolding deliberately when upgrading.
- Applications behind reverse proxies should configure trusted proxy networks explicitly before relying on forwarded client IP headers.

## [0.7.21] - 2026-07-11

### Security

- Access-token verification now rejects refresh tokens and enforces issuer/audience checks in generated auth paths.
- HS256 issuer and verifier setup now provides checked constructors that reject short and known-placeholder secrets; unchecked constructors are deprecated.
- Credentialed CORS configurations now reject wildcard origins and headers.
- Request logging redacts sensitive headers, query parameters, and structured body fields, and bounds body preview work.
- Generated billing webhooks claim events atomically before side effects and release retryable claims safely.
- Organization invitations are claimed atomically and cannot be consumed more than once.

### Fixed

- Per-IP rate limiting no longer trusts forwarded headers by default and uses a shared fallback bucket when client IP data is unavailable.
- In-memory job dequeue/retry coordination and WebSocket broadcasts avoid lock contention and stale membership cleanup races.
- Generated billing redirects are validated and billing route access boundaries are explicit.
- CLI dependency editing returns actionable errors for malformed `Cargo.toml` tables and feature arrays instead of panicking.

### Added

- Hot-path Criterion benchmarks and a manual-only end-to-end HTTP/WebSocket load-test workflow with artifact upload.
- Dependency auditing, formatting, all-feature Clippy, and MSRV checks in CI.
- Immutable SHA pinning and least-privilege permissions for GitHub Actions workflows.

### Changed

- Minimum supported Rust version is now 1.88 so the dependency graph includes the security-fixed `time` release.
- `tideway-cli` 0.1.34 scaffolds Tideway 0.7.21 with safer auth and billing defaults.

### Performance

- Reduced allocation and lock hold time in request logging, rate limiting, jobs, and WebSocket hot paths.
- Added reproducible microbenchmarks and integration load-test baselines for future regression tracking.

### DX Gate

- Quickstart parity, documentation drift, scaffold idempotency, golden-path integration, CLI filesystem policy, and public API checks pass.
- Generated API and SaaS presets compile and test against the workspace source.

### Migration Notes

- Install Rust 1.88 or newer before upgrading.
- Replace `JwtIssuerConfig::with_secret` with `with_secure_secret` and `JwtVerifier::from_secret` with `from_secret_checked`.
- Credentialed CORS must list explicit origins and headers rather than using `*`.
- No public API removals are included; deprecated JWT constructors remain available for compatibility.

## [0.7.19] - 2026-05-04

### Changed

- README and getting-started quickstarts now use `tideway dev --fix-env`, matching the enforced onboarding guardrails.
- Docs taxonomy checks now match the current Vue-focused advanced CLI helper wording.
- `tideway-cli` now scaffolds Tideway `0.7.19`.

### Notes

- This release includes `tideway-cli` `0.1.31`.
- No semver-breaking public API changes were introduced.

## [0.7.18] - 2026-04-27

### Added

- API-first scaffold refinements, including a seeded todo resource following the entity -> repository -> service path.
- Agent- and CI-friendly plan output plumbing across mutating CLI commands.
- SaaS resource generation improvements for auth-scoped resources, ownership checks, audit hooks, and service-owned validation.
- Testcontainers-backed Postgres helper support behind `test-containers`.

### Changed

- `tideway-cli` now scaffolds Tideway `0.7.18`.
- CLI onboarding now promotes the tested API path first, with advanced frontend/backend presets one step deeper.
- Dev-mode diagnostics, request dumping, doctor findings, and generated service errors are more explicit.

### Notes

- This release includes `tideway-cli` `0.1.30`.

## [0.7.17] - 2026-03-17

### Added

- `App::into_make_service_with_connect_info()` to mirror `serve()` when manually calling `axum::serve`.

### Changed

- Request logging body previews are now disabled by default (`body_preview_size = 0`).
- Manual-serve docs now use the same `ConnectInfo<SocketAddr>` path as `serve()` for per-IP middleware parity.

### Fixed

- Cookie session stores now reject expired sessions on load and set cookie `Max-Age` from the actual session expiry.
- Auth extractors now reuse cached users without redundant `validate_user()` calls.
- Testing body assertions preserve response status and headers for subsequent assertions.
- In-memory job workers now use queue wakeups instead of polling idle loops.
- `tideway doctor` now accepts valid `sqlite:...` URLs generated by Tideway itself.
- `tideway dev` no longer treats `dev-dependencies` and `build-dependencies` as runtime database requirements.
- `tideway setup` now exits non-zero on real setup failures and safely updates Vite alias config.

### Notes

- No semver-breaking public API changes were introduced in this batch. This should ship as a patch release.
- Two rollout-sensitive behavior changes are worth calling out in release notes:
  - `tideway setup` now returns a non-zero exit code when frontend setup fails instead of reporting success.
  - Request logging no longer captures body previews by default; set `body_preview_size` explicitly if you relied on that output.

## [0.7.9] - 2026-01-26

### Added

- `ensure!` guard macro for concise precondition checks.
- `module!` macro for route groups plus OpenAPI module helpers.
- Alba-style testing helpers (`TestApp`, JSON helpers, `post_json`, status/header assertions).
- Auth extractor caching for users and claims (`ClaimsRef`) to avoid duplicate verification.
- Expanded docs and README examples for auth extractors, testing helpers, OpenAPI modules, and CLI flags.

## [0.7.8] - 2026-01-23

### Changed

- Metrics and request logging now prefer route templates when available, reducing label cardinality.
- Request logging skips formatting work when the configured log level is disabled.
- Feature matrix added to README; install snippet updated.
- Added optional `feature-gate-warnings` and `feature-gate-errors` for clearer feature diagnostics.
- Added tests covering MatchedPath metrics and logging guard behavior.

## [0.7.7] - 2026-01-23

### Changed

- Seat add-ons via Checkout are now rejected; use `SeatManager::add_seats` (proration-safe).
- `create_seat_checkout_session` is deprecated in favor of `SeatManager::add_seats`.

## [0.7.6] - 2026-01-23

### Security

- Password reset and email verification tokens now use OS CSPRNG for generation.
- MFA tokens are hashed before storage and consumption in the login flow.
- Trusted-device verification now rejects missing fingerprints when fingerprint validation is enabled.

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
