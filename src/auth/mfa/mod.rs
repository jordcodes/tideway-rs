//! Multi-factor authentication.
//!
//! Provides TOTP (Time-based One-Time Password) and backup code support.
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::auth::mfa::{TotpManager, TotpConfig, BackupCodeGenerator};
//!
//! // Setup TOTP
//! let totp = TotpManager::new(TotpConfig::new("MyApp"));
//! let setup = totp.generate_setup("user@example.com")?;
//!
//! // Show QR code to user
//! println!("Scan this QR code: {}", setup.qr_code_base64);
//!
//! // Generate backup codes
//! let backup = BackupCodeGenerator::new().generate();
//! println!("Save these codes: {:?}", backup.display_codes());
//! ```

mod backup;
mod storage;
mod totp;

pub use backup::{BackupCodeGenerator, BackupCodes};
pub use storage::MfaStore;
pub use totp::{TotpConfig, TotpManager, TotpSetup};
