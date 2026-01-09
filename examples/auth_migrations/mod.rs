//! Example SeaORM migrations for tideway-auth.
//!
//! Copy these migrations to your project's migration folder and adapt as needed.
//!
//! # Tables
//!
//! - `users` - User accounts with password hashes
//! - `refresh_token_families` - Token rotation tracking
//! - `user_mfa` - TOTP secrets and backup codes
//! - `verification_tokens` - Email verification and password reset tokens
//!
//! # Usage
//!
//! 1. Copy the migration files to your `migration/src/` folder
//! 2. Add them to your `Migrator` in `migration/src/lib.rs`
//! 3. Run migrations with `sea-orm-cli migrate up`

pub mod m001_create_users;
pub mod m002_create_refresh_tokens;
pub mod m003_create_mfa;
pub mod m004_create_verification_tokens;

pub use m001_create_users::Migration as M001CreateUsers;
pub use m002_create_refresh_tokens::Migration as M002CreateRefreshTokens;
pub use m003_create_mfa::Migration as M003CreateMfa;
pub use m004_create_verification_tokens::Migration as M004CreateVerificationTokens;
