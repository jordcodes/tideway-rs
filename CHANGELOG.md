# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2025-12-11

### Added
- Nothing new in this release

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
