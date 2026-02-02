//! Authentication module.
//!
//! Provides JWT verification, token issuance, password hashing, MFA support,
//! and complete authentication flows.
//!
//! # Features
//!
//! - `auth` - Enables password hashing with Argon2
//! - `auth-mfa` - Enables TOTP and backup code support
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::auth::{
//!     JwtIssuer, JwtIssuerConfig, TokenSubject,
//!     PasswordHasher, PasswordPolicy,
//!     LoginFlow, LoginFlowConfig,
//! };
//!
//! // Hash a password
//! let hasher = PasswordHasher::default();
//! let hash = hasher.hash("my-password")?;
//!
//! // Issue tokens
//! let issuer = JwtIssuer::new(JwtIssuerConfig::with_secret("secret", "my-app"))?;
//! let tokens = issuer.issue(TokenSubject::new("user-123"), false)?;
//! ```

// Existing modules
pub mod extractors;
pub mod jwt;
pub mod middleware;
pub mod provider;
pub mod token;

// New auth modules
#[cfg(feature = "auth-breach")]
pub mod breach;
pub mod deletion;
#[cfg(feature = "auth")]
pub mod flows;
pub mod impersonation;
pub mod jwt_issuer;
pub mod lockout;
#[cfg(feature = "auth-mfa")]
pub mod mfa;
pub mod password;
pub mod refresh;
pub mod sessions;
pub mod storage;
pub mod trusted_device;

// Existing re-exports
pub use extractors::{AdminUser, AuthUser, Claims, ClaimsRef, OptionalAuth, RequireAdmin};
pub use jwt::{JwkSet, JwtVerifier};
pub use middleware::RequireAuth;
pub use provider::AuthProvider;
pub use token::TokenExtractor;

// JWT issuer re-exports
pub use jwt_issuer::{
    AccessTokenClaims, JwtIssuer, JwtIssuerConfig, RefreshTokenClaims, StandardClaims, TokenPair,
    TokenSubject, TokenType,
};

// Password re-exports
pub use password::{PasswordConfig, PasswordError, PasswordHasher, PasswordPolicy};

// Refresh token re-exports
pub use refresh::{TokenRefreshFlow, UserLoader};

// Storage trait re-exports
pub use storage::{RefreshTokenStore, UserStore};

// Flow re-exports (when auth feature enabled)
#[cfg(feature = "auth")]
pub use flows::{
    EmailVerificationFlow, EmailVerifyRequest, LoginFlow, LoginFlowConfig, LoginRateLimitConfig,
    LoginRateLimiter, LoginRequest, LoginResponse, LogoutRequest, MfaType, MfaVerifyRequest,
    PasswordChangeConfig, PasswordChangeFlow, PasswordChangeRequest, PasswordChangeStore,
    PasswordResetComplete, PasswordResetFlow, PasswordResetRequest, RefreshRequest,
    RegisterRequest, RegistrationFlow, ResendVerificationRequest, TokenIssuance, TokenIssuer,
    WithRateLimiter, WithRefreshStore,
};

// MFA re-exports (when auth-mfa feature enabled)
#[cfg(feature = "auth-mfa")]
pub use mfa::{BackupCodeGenerator, BackupCodes, MfaStore, TotpConfig, TotpManager, TotpSetup};

// Breach checking re-exports (when auth-breach feature enabled)
#[cfg(feature = "auth-breach")]
pub use breach::{BreachCheckConfig, BreachChecker};

// Additional storage trait re-exports
pub use storage::token::MfaTokenStore;
pub use storage::user::{PasswordResetStore, UserCreator, VerificationStore};

// Session re-exports
#[cfg(any(test, feature = "test-auth-bypass"))]
pub use sessions::test::InMemorySessionStore;
pub use sessions::{
    SessionCreateResult, SessionInfo, SessionLimitConfig, SessionManager, SessionMetadata,
    SessionOverflowBehavior, SessionStore,
};

// Trusted device re-exports
#[cfg(any(test, feature = "test-auth-bypass"))]
pub use trusted_device::test::InMemoryTrustedDeviceStore;
pub use trusted_device::{
    DeviceFingerprint, TrustedDevice, TrustedDeviceConfig, TrustedDeviceManager, TrustedDeviceStore,
};

// Lockout re-exports
#[cfg(any(test, feature = "test-auth-bypass"))]
pub use lockout::test::InMemoryLockoutStore;
pub use lockout::{
    FailedAttemptResult, LockoutManager, LockoutPolicy, LockoutStatus, LockoutStore,
};

// Deletion re-exports
#[cfg(any(test, feature = "test-auth-bypass"))]
pub use deletion::test::InMemoryDeletionStore;
pub use deletion::{
    AccountDeletionFlow, AccountDeletionStore, CleanupStats, DeletionConfig, DeletionRequest,
    DeletionResult, PendingDeletion,
};

// Impersonation re-exports
#[cfg(any(test, feature = "test-auth-bypass"))]
pub use impersonation::test::InMemoryImpersonationStore;
pub use impersonation::{
    BlockedAction, ImpersonationAuditEntry, ImpersonationClaims, ImpersonationConfig,
    ImpersonationEvent, ImpersonationManager, ImpersonationRequest, ImpersonationSession,
    ImpersonationStore,
};
