use serde::Deserialize;
use tideway::auth::{JwtIssuerConfig, JwtVerifier};
use tideway::{AppContext, Result};
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct UpgradeRequest {
    #[validate(length(min = 1))]
    pub name: String,
}

pub fn database_is_configured(context: &AppContext) -> bool {
    context.database_opt().is_some()
}

pub fn build_jwt_surfaces(
    secret: &str,
) -> Result<(JwtIssuerConfig, JwtVerifier<serde_json::Value>)> {
    let issuer = JwtIssuerConfig::with_secure_secret(secret, "upgrade-contract")?;
    let verifier = JwtVerifier::from_secret_checked(secret.as_bytes())?;
    Ok((issuer, verifier))
}

pub fn stripe_client_type_is_available() -> usize {
    std::mem::size_of::<stripe::Client>()
}
