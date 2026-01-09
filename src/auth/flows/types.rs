//! Request and response types for authentication flows.

use serde::{Deserialize, Serialize};

/// Login request from client.
#[derive(Debug, Clone, Deserialize)]
pub struct LoginRequest {
    /// User's email address.
    pub email: String,
    /// User's password.
    pub password: String,
    /// Optional MFA code (TOTP or backup code).
    pub mfa_code: Option<String>,
    /// Remember this device (extends session).
    #[serde(default)]
    pub remember_me: bool,
}

/// MFA verification request (second step of login).
#[derive(Debug, Clone, Deserialize)]
pub struct MfaVerifyRequest {
    /// The MFA token received from the initial login attempt.
    pub mfa_token: String,
    /// The MFA code (TOTP or backup code).
    pub code: String,
}

/// Response to a login attempt.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status")]
pub enum LoginResponse {
    /// Login successful, here's your tokens.
    #[serde(rename = "success")]
    Success {
        /// Access token for API requests.
        access_token: String,
        /// Refresh token for obtaining new access tokens.
        refresh_token: String,
        /// Access token expiry in seconds.
        expires_in: u64,
        /// Token type (always "Bearer").
        token_type: &'static str,
    },
    /// MFA required, use this token to complete verification.
    #[serde(rename = "mfa_required")]
    MfaRequired {
        /// Temporary token to complete MFA verification.
        mfa_token: String,
        /// Type of MFA expected.
        mfa_type: MfaType,
        /// How many backup codes remain (warn user if low).
        #[serde(skip_serializing_if = "Option::is_none")]
        backup_codes_remaining: Option<usize>,
    },
    /// Login failed.
    #[serde(rename = "error")]
    Error {
        /// Error message.
        message: String,
    },
}

impl LoginResponse {
    /// Create a successful login response.
    pub fn success(
        access_token: String,
        refresh_token: String,
        expires_in: u64,
    ) -> Self {
        Self::Success {
            access_token,
            refresh_token,
            expires_in,
            token_type: "Bearer",
        }
    }

    /// Create an MFA required response.
    pub fn mfa_required(mfa_token: String, backup_codes_remaining: Option<usize>) -> Self {
        Self::MfaRequired {
            mfa_token,
            mfa_type: MfaType::Totp,
            backup_codes_remaining,
        }
    }

    /// Create an error response.
    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            message: message.into(),
        }
    }
}

/// Type of MFA being used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MfaType {
    /// Time-based one-time password.
    Totp,
    /// Backup recovery code.
    BackupCode,
}

/// Registration request.
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterRequest {
    /// User's email address.
    pub email: String,
    /// User's password.
    pub password: String,
    /// User's name (optional).
    pub name: Option<String>,
}

/// Password reset request.
#[derive(Debug, Clone, Deserialize)]
pub struct PasswordResetRequest {
    /// User's email address.
    pub email: String,
}

/// Password reset completion request.
#[derive(Debug, Clone, Deserialize)]
pub struct PasswordResetComplete {
    /// The reset token from the email.
    pub token: String,
    /// The new password.
    pub new_password: String,
}

/// Email verification request.
#[derive(Debug, Clone, Deserialize)]
pub struct EmailVerifyRequest {
    /// The verification token from the email.
    pub token: String,
}

/// Request to resend verification email.
#[derive(Debug, Clone, Deserialize)]
pub struct ResendVerificationRequest {
    /// User's email address.
    pub email: String,
}

/// Token refresh request.
#[derive(Debug, Clone, Deserialize)]
pub struct RefreshRequest {
    /// The refresh token.
    pub refresh_token: String,
}

/// Logout request.
#[derive(Debug, Clone, Deserialize)]
pub struct LogoutRequest {
    /// The refresh token to revoke.
    pub refresh_token: String,
}
