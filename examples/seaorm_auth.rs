//! Complete SeaORM authentication example.
//!
//! This example demonstrates how to implement all the tideway-auth storage traits
//! using SeaORM for a real database-backed authentication system.
//!
//! Features demonstrated:
//! - User registration with password hashing
//! - Login with JWT token issuance
//! - MFA with TOTP and backup codes
//! - Token refresh with rotation
//! - Password reset flow
//! - Email verification flow
//!
//! Run with: cargo run --example seaorm_auth --features "database,auth,auth-mfa"
//!
//! Prerequisites:
//! - Set DATABASE_URL environment variable
//! - Run migrations from examples/auth_migrations/

use async_trait::async_trait;
use axum::{
    routing::post,
    Extension, Json, Router,
};
use sea_orm::{
    entity::prelude::*, ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait,
    QueryFilter, Set,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tideway::{App, AppContext, RouteModule, TidewayError};

// Use tideway's Result for our handlers, but std::result::Result for SeaORM
type AppResult<T> = tideway::Result<T>;

// =============================================================================
// SeaORM Entities
// =============================================================================

mod entity {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    // -------------------------------------------------------------------------
    // User Entity
    // -------------------------------------------------------------------------
    pub mod user {
        use super::*;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
        #[sea_orm(table_name = "users")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub id: Uuid,
            #[sea_orm(unique)]
            pub email: String,
            pub password_hash: String,
            pub name: Option<String>,
            pub email_verified_at: Option<DateTimeWithTimeZone>,
            pub locked_until: Option<DateTimeWithTimeZone>,
            pub failed_attempts: i32,
            pub created_at: DateTimeWithTimeZone,
            pub updated_at: DateTimeWithTimeZone,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {
            #[sea_orm(has_one = "super::user_mfa::Entity")]
            UserMfa,
            #[sea_orm(has_many = "super::refresh_token_family::Entity")]
            RefreshTokenFamilies,
        }

        impl Related<super::user_mfa::Entity> for Entity {
            fn to() -> RelationDef {
                Relation::UserMfa.def()
            }
        }

        impl Related<super::refresh_token_family::Entity> for Entity {
            fn to() -> RelationDef {
                Relation::RefreshTokenFamilies.def()
            }
        }

        impl ActiveModelBehavior for ActiveModel {}
    }

    // -------------------------------------------------------------------------
    // User MFA Entity
    // -------------------------------------------------------------------------
    pub mod user_mfa {
        use super::*;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
        #[sea_orm(table_name = "user_mfa")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub user_id: Uuid,
            pub totp_secret: Option<String>,
            pub totp_enabled: bool,
            pub backup_codes: Option<serde_json::Value>,
            pub enabled_at: Option<DateTimeWithTimeZone>,
            pub created_at: DateTimeWithTimeZone,
            pub updated_at: DateTimeWithTimeZone,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {
            #[sea_orm(
                belongs_to = "super::user::Entity",
                from = "Column::UserId",
                to = "super::user::Column::Id"
            )]
            User,
        }

        impl Related<super::user::Entity> for Entity {
            fn to() -> RelationDef {
                Relation::User.def()
            }
        }

        impl ActiveModelBehavior for ActiveModel {}
    }

    // -------------------------------------------------------------------------
    // Refresh Token Family Entity
    // -------------------------------------------------------------------------
    pub mod refresh_token_family {
        use super::*;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
        #[sea_orm(table_name = "refresh_token_families")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub family: String,
            pub user_id: Uuid,
            pub generation: i32,
            pub revoked: bool,
            pub created_at: DateTimeWithTimeZone,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {
            #[sea_orm(
                belongs_to = "super::user::Entity",
                from = "Column::UserId",
                to = "super::user::Column::Id"
            )]
            User,
        }

        impl Related<super::user::Entity> for Entity {
            fn to() -> RelationDef {
                Relation::User.def()
            }
        }

        impl ActiveModelBehavior for ActiveModel {}
    }

    // -------------------------------------------------------------------------
    // Verification Token Entity
    // -------------------------------------------------------------------------
    pub mod verification_token {
        use super::*;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
        #[sea_orm(table_name = "verification_tokens")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub id: Uuid,
            pub user_id: Uuid,
            pub token_hash: String,
            pub token_type: String, // "email_verification" or "password_reset"
            pub expires_at: DateTimeWithTimeZone,
            pub used_at: Option<DateTimeWithTimeZone>,
            pub created_at: DateTimeWithTimeZone,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {
            #[sea_orm(
                belongs_to = "super::user::Entity",
                from = "Column::UserId",
                to = "super::user::Column::Id"
            )]
            User,
        }

        impl Related<super::user::Entity> for Entity {
            fn to() -> RelationDef {
                Relation::User.def()
            }
        }

        impl ActiveModelBehavior for ActiveModel {}
    }
}

use entity::{refresh_token_family, user, user_mfa, verification_token};

// =============================================================================
// Helper Functions
// =============================================================================

fn system_time_to_chrono(st: SystemTime) -> chrono::DateTime<chrono::FixedOffset> {
    let duration = st.duration_since(UNIX_EPOCH).unwrap();
    chrono::DateTime::from_timestamp(duration.as_secs() as i64, duration.subsec_nanos())
        .unwrap()
        .with_timezone(&chrono::Utc)
        .fixed_offset()
}

fn chrono_to_system_time(dt: chrono::DateTime<chrono::FixedOffset>) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(dt.timestamp() as u64)
}

// =============================================================================
// Store Implementations
// =============================================================================

/// SeaORM-backed user store implementing UserStore and UserCreator traits.
#[derive(Clone)]
pub struct SeaOrmUserStore {
    db: DatabaseConnection,
}

impl SeaOrmUserStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl tideway::auth::storage::UserStore for SeaOrmUserStore {
    type User = user::Model;

    async fn find_by_email(&self, email: &str) -> AppResult<Option<Self::User>> {
        user::Entity::find()
            .filter(user::Column::Email.eq(email))
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))
    }

    async fn find_by_id(&self, id: &str) -> AppResult<Option<Self::User>> {
        let uuid = Uuid::parse_str(id).map_err(|e| TidewayError::BadRequest(e.to_string()))?;
        user::Entity::find_by_id(uuid)
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))
    }

    fn user_id(&self, user: &Self::User) -> String {
        user.id.to_string()
    }

    fn user_email(&self, user: &Self::User) -> String {
        user.email.clone()
    }

    fn user_name(&self, user: &Self::User) -> Option<String> {
        user.name.clone()
    }

    async fn get_password_hash(&self, user: &Self::User) -> AppResult<String> {
        Ok(user.password_hash.clone())
    }

    async fn update_password_hash(&self, user: &Self::User, hash: &str) -> AppResult<()> {
        let mut active: user::ActiveModel = user.clone().into();
        active.password_hash = Set(hash.to_string());
        active.updated_at = Set(chrono::Utc::now().fixed_offset());
        active
            .update(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;
        Ok(())
    }

    async fn is_verified(&self, user: &Self::User) -> AppResult<bool> {
        Ok(user.email_verified_at.is_some())
    }

    async fn mark_verified(&self, user: &Self::User) -> AppResult<()> {
        let mut active: user::ActiveModel = user.clone().into();
        active.email_verified_at = Set(Some(chrono::Utc::now().fixed_offset()));
        active.updated_at = Set(chrono::Utc::now().fixed_offset());
        active
            .update(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;
        Ok(())
    }

    async fn is_locked(&self, user: &Self::User) -> AppResult<Option<SystemTime>> {
        Ok(user.locked_until.map(chrono_to_system_time))
    }

    async fn record_failed_attempt(&self, user: &Self::User) -> AppResult<()> {
        let new_attempts = user.failed_attempts + 1;
        let mut active: user::ActiveModel = user.clone().into();
        active.failed_attempts = Set(new_attempts);

        // Lock after 5 failed attempts for 15 minutes
        if new_attempts >= 5 {
            let lock_until = chrono::Utc::now() + chrono::Duration::minutes(15);
            active.locked_until = Set(Some(lock_until.fixed_offset()));
        }

        active.updated_at = Set(chrono::Utc::now().fixed_offset());
        active
            .update(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;
        Ok(())
    }

    async fn clear_failed_attempts(&self, user: &Self::User) -> AppResult<()> {
        let mut active: user::ActiveModel = user.clone().into();
        active.failed_attempts = Set(0);
        active.locked_until = Set(None);
        active.updated_at = Set(chrono::Utc::now().fixed_offset());
        active
            .update(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;
        Ok(())
    }

    async fn has_mfa_enabled(&self, user: &Self::User) -> AppResult<bool> {
        let mfa = user_mfa::Entity::find_by_id(user.id)
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;
        Ok(mfa.map(|m| m.totp_enabled).unwrap_or(false))
    }

    #[cfg(feature = "auth-mfa")]
    async fn get_totp_secret(&self, user: &Self::User) -> AppResult<Option<String>> {
        let mfa = user_mfa::Entity::find_by_id(user.id)
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;
        Ok(mfa.and_then(|m| m.totp_secret))
    }

    #[cfg(feature = "auth-mfa")]
    async fn get_backup_codes(&self, user: &Self::User) -> AppResult<Vec<String>> {
        let mfa = user_mfa::Entity::find_by_id(user.id)
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        let codes = mfa
            .and_then(|m| m.backup_codes)
            .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok())
            .unwrap_or_default();

        Ok(codes)
    }

    #[cfg(feature = "auth-mfa")]
    async fn remove_backup_code(&self, user: &Self::User, index: usize) -> AppResult<()> {
        let mfa = user_mfa::Entity::find_by_id(user.id)
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        if let Some(mfa) = mfa {
            let mut codes: Vec<String> = mfa
                .backup_codes
                .clone()
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default();

            if index < codes.len() {
                codes.remove(index);
                let mut active: user_mfa::ActiveModel = mfa.into();
                active.backup_codes = Set(Some(serde_json::to_value(&codes).unwrap()));
                active.updated_at = Set(chrono::Utc::now().fixed_offset());
                active
                    .update(&self.db)
                    .await
                    .map_err(|e| TidewayError::Database(e.to_string()))?;
            }
        }

        Ok(())
    }
}

#[async_trait]
impl tideway::auth::storage::UserCreator for SeaOrmUserStore {
    type User = user::Model;

    fn user_id(&self, user: &Self::User) -> String {
        user.id.to_string()
    }

    async fn email_exists(&self, email: &str) -> AppResult<bool> {
        let count = user::Entity::find()
            .filter(user::Column::Email.eq(email))
            .count(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;
        Ok(count > 0)
    }

    async fn create_user(
        &self,
        email: &str,
        password_hash: &str,
        name: Option<&str>,
    ) -> AppResult<Self::User> {
        let now = chrono::Utc::now().fixed_offset();
        let user = user::ActiveModel {
            id: Set(Uuid::new_v4()),
            email: Set(email.to_string()),
            password_hash: Set(password_hash.to_string()),
            name: Set(name.map(String::from)),
            email_verified_at: Set(None),
            locked_until: Set(None),
            failed_attempts: Set(0),
            created_at: Set(now),
            updated_at: Set(now),
        };

        user.insert(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))
    }

    async fn send_verification_email(&self, user: &Self::User) -> AppResult<()> {
        // In production, integrate with your email service
        tracing::info!(
            user_id = %user.id,
            email = %user.email,
            "Would send verification email (not implemented in example)"
        );
        Ok(())
    }
}

/// SeaORM-backed refresh token store.
#[derive(Clone)]
pub struct SeaOrmRefreshTokenStore {
    db: DatabaseConnection,
}

impl SeaOrmRefreshTokenStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl tideway::auth::storage::RefreshTokenStore for SeaOrmRefreshTokenStore {
    async fn is_family_revoked(&self, family: &str) -> AppResult<bool> {
        let record = refresh_token_family::Entity::find_by_id(family)
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;
        Ok(record.map(|r| r.revoked).unwrap_or(false))
    }

    async fn get_family_generation(&self, family: &str) -> AppResult<Option<u32>> {
        let record = refresh_token_family::Entity::find_by_id(family)
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;
        Ok(record.map(|r| r.generation as u32))
    }

    async fn set_family_generation(&self, family: &str, generation: u32) -> AppResult<()> {
        let record = refresh_token_family::Entity::find_by_id(family)
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        if let Some(record) = record {
            let mut active: refresh_token_family::ActiveModel = record.into();
            active.generation = Set(generation as i32);
            active
                .update(&self.db)
                .await
                .map_err(|e| TidewayError::Database(e.to_string()))?;
        }
        Ok(())
    }

    async fn revoke_family(&self, family: &str) -> AppResult<()> {
        let record = refresh_token_family::Entity::find_by_id(family)
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        if let Some(record) = record {
            let mut active: refresh_token_family::ActiveModel = record.into();
            active.revoked = Set(true);
            active
                .update(&self.db)
                .await
                .map_err(|e| TidewayError::Database(e.to_string()))?;
        }
        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: &str) -> AppResult<()> {
        let uuid =
            Uuid::parse_str(user_id).map_err(|e| TidewayError::BadRequest(e.to_string()))?;

        refresh_token_family::Entity::update_many()
            .filter(refresh_token_family::Column::UserId.eq(uuid))
            .col_expr(refresh_token_family::Column::Revoked, Expr::value(true))
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    async fn associate_family_with_user(&self, family: &str, user_id: &str) -> AppResult<()> {
        let uuid =
            Uuid::parse_str(user_id).map_err(|e| TidewayError::BadRequest(e.to_string()))?;

        // Check if family already exists
        let existing = refresh_token_family::Entity::find_by_id(family)
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        if existing.is_none() {
            let record = refresh_token_family::ActiveModel {
                family: Set(family.to_string()),
                user_id: Set(uuid),
                generation: Set(0),
                revoked: Set(false),
                created_at: Set(chrono::Utc::now().fixed_offset()),
            };

            record
                .insert(&self.db)
                .await
                .map_err(|e| TidewayError::Database(e.to_string()))?;
        }

        Ok(())
    }
}

/// SeaORM-backed password reset store.
#[derive(Clone)]
pub struct SeaOrmPasswordResetStore {
    db: DatabaseConnection,
}

impl SeaOrmPasswordResetStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl tideway::auth::storage::PasswordResetStore for SeaOrmPasswordResetStore {
    type User = user::Model;

    async fn find_by_email(&self, email: &str) -> AppResult<Option<Self::User>> {
        user::Entity::find()
            .filter(user::Column::Email.eq(email))
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))
    }

    fn user_id(&self, user: &Self::User) -> String {
        user.id.to_string()
    }

    async fn store_reset_token(
        &self,
        user_id: &str,
        token_hash: &str,
        expires: SystemTime,
    ) -> AppResult<()> {
        let uuid =
            Uuid::parse_str(user_id).map_err(|e| TidewayError::BadRequest(e.to_string()))?;

        let token = verification_token::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(uuid),
            token_hash: Set(token_hash.to_string()),
            token_type: Set("password_reset".to_string()),
            expires_at: Set(system_time_to_chrono(expires)),
            used_at: Set(None),
            created_at: Set(chrono::Utc::now().fixed_offset()),
        };

        token
            .insert(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    async fn consume_reset_token(&self, token_hash: &str) -> AppResult<Option<String>> {
        let token = verification_token::Entity::find()
            .filter(verification_token::Column::TokenHash.eq(token_hash))
            .filter(verification_token::Column::TokenType.eq("password_reset"))
            .filter(verification_token::Column::UsedAt.is_null())
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        if let Some(token) = token {
            // Check expiration
            let expires = chrono_to_system_time(token.expires_at);
            if SystemTime::now() > expires {
                return Ok(None);
            }

            // Mark as used
            let mut active: verification_token::ActiveModel = token.clone().into();
            active.used_at = Set(Some(chrono::Utc::now().fixed_offset()));
            active
                .update(&self.db)
                .await
                .map_err(|e| TidewayError::Database(e.to_string()))?;

            return Ok(Some(token.user_id.to_string()));
        }

        Ok(None)
    }

    async fn update_password(&self, user_id: &str, hash: &str) -> AppResult<()> {
        let uuid =
            Uuid::parse_str(user_id).map_err(|e| TidewayError::BadRequest(e.to_string()))?;

        user::Entity::update_many()
            .filter(user::Column::Id.eq(uuid))
            .col_expr(user::Column::PasswordHash, Expr::value(hash))
            .col_expr(
                user::Column::UpdatedAt,
                Expr::value(chrono::Utc::now().fixed_offset()),
            )
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    async fn invalidate_sessions(&self, user_id: &str) -> AppResult<()> {
        // Revoke all refresh tokens for this user
        let uuid =
            Uuid::parse_str(user_id).map_err(|e| TidewayError::BadRequest(e.to_string()))?;

        refresh_token_family::Entity::update_many()
            .filter(refresh_token_family::Column::UserId.eq(uuid))
            .col_expr(refresh_token_family::Column::Revoked, Expr::value(true))
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    async fn send_reset_email(
        &self,
        user: &Self::User,
        token: &str,
        expires_in: Duration,
    ) -> AppResult<()> {
        // In production, integrate with your email service
        tracing::info!(
            user_id = %user.id,
            email = %user.email,
            token = %token,
            expires_in_secs = expires_in.as_secs(),
            "Would send password reset email (not implemented in example)"
        );
        Ok(())
    }
}

/// SeaORM-backed email verification store.
#[derive(Clone)]
pub struct SeaOrmVerificationStore {
    db: DatabaseConnection,
}

impl SeaOrmVerificationStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl tideway::auth::storage::VerificationStore for SeaOrmVerificationStore {
    async fn store_verification_token(
        &self,
        user_id: &str,
        token_hash: &str,
        expires: SystemTime,
    ) -> AppResult<()> {
        let uuid =
            Uuid::parse_str(user_id).map_err(|e| TidewayError::BadRequest(e.to_string()))?;

        let token = verification_token::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(uuid),
            token_hash: Set(token_hash.to_string()),
            token_type: Set("email_verification".to_string()),
            expires_at: Set(system_time_to_chrono(expires)),
            used_at: Set(None),
            created_at: Set(chrono::Utc::now().fixed_offset()),
        };

        token
            .insert(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    async fn consume_verification_token(&self, token_hash: &str) -> AppResult<Option<String>> {
        let token = verification_token::Entity::find()
            .filter(verification_token::Column::TokenHash.eq(token_hash))
            .filter(verification_token::Column::TokenType.eq("email_verification"))
            .filter(verification_token::Column::UsedAt.is_null())
            .one(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        if let Some(token) = token {
            // Check expiration
            let expires = chrono_to_system_time(token.expires_at);
            if SystemTime::now() > expires {
                return Ok(None);
            }

            // Mark as used
            let mut active: verification_token::ActiveModel = token.clone().into();
            active.used_at = Set(Some(chrono::Utc::now().fixed_offset()));
            active
                .update(&self.db)
                .await
                .map_err(|e| TidewayError::Database(e.to_string()))?;

            return Ok(Some(token.user_id.to_string()));
        }

        Ok(None)
    }

    async fn mark_user_verified(&self, user_id: &str) -> AppResult<()> {
        let uuid =
            Uuid::parse_str(user_id).map_err(|e| TidewayError::BadRequest(e.to_string()))?;

        user::Entity::update_many()
            .filter(user::Column::Id.eq(uuid))
            .col_expr(
                user::Column::EmailVerifiedAt,
                Expr::value(chrono::Utc::now().fixed_offset()),
            )
            .col_expr(
                user::Column::UpdatedAt,
                Expr::value(chrono::Utc::now().fixed_offset()),
            )
            .exec(&self.db)
            .await
            .map_err(|e| TidewayError::Database(e.to_string()))?;

        Ok(())
    }

    async fn send_verification_email(
        &self,
        user_id: &str,
        email: &str,
        token: &str,
        expires_in: Duration,
    ) -> AppResult<()> {
        // In production, integrate with your email service
        tracing::info!(
            user_id = %user_id,
            email = %email,
            token = %token,
            expires_in_secs = expires_in.as_secs(),
            "Would send verification email (not implemented in example)"
        );
        Ok(())
    }
}

/// In-memory MFA token store (use Redis in production).
#[derive(Clone, Default)]
pub struct InMemoryMfaTokenStore {
    tokens: Arc<std::sync::RwLock<std::collections::HashMap<String, (String, SystemTime)>>>,
}

impl InMemoryMfaTokenStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl tideway::auth::storage::MfaTokenStore for InMemoryMfaTokenStore {
    async fn store(&self, token: &str, user_id: &str, ttl: Duration) -> AppResult<()> {
        let expires = SystemTime::now() + ttl;
        let mut tokens = self.tokens.write().unwrap();
        tokens.insert(token.to_string(), (user_id.to_string(), expires));
        Ok(())
    }

    async fn consume(&self, token: &str) -> AppResult<Option<String>> {
        let mut tokens = self.tokens.write().unwrap();
        if let Some((user_id, expires)) = tokens.remove(token) {
            if SystemTime::now() < expires {
                return Ok(Some(user_id));
            }
        }
        Ok(None)
    }
}

// =============================================================================
// Application State
// =============================================================================

/// Application state containing all auth components.
#[derive(Clone)]
pub struct AuthState {
    pub user_store: SeaOrmUserStore,
    pub refresh_store: SeaOrmRefreshTokenStore,
    pub mfa_store: InMemoryMfaTokenStore,
    pub jwt_issuer: tideway::auth::JwtIssuer,
    pub jwt_secret: Vec<u8>,
}

// =============================================================================
// HTTP Handlers
// =============================================================================

#[derive(Deserialize)]
struct RegisterRequest {
    email: String,
    password: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
    remember_me: Option<bool>,
    mfa_code: Option<String>,
}

#[derive(Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

#[derive(Serialize)]
struct AuthResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
    token_type: String,
}

#[derive(Serialize)]
struct MfaRequiredResponse {
    mfa_required: bool,
    mfa_token: String,
    backup_codes_remaining: Option<usize>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum LoginResponseBody {
    Success(AuthResponse),
    MfaRequired(MfaRequiredResponse),
    Error { error: String },
}

async fn register(
    Extension(auth_state): Extension<Arc<AuthState>>,
    Json(req): Json<RegisterRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let flow = tideway::auth::flows::RegistrationFlow::new(auth_state.user_store.clone());

    let user = flow
        .register(tideway::auth::flows::RegisterRequest {
            email: req.email,
            password: req.password,
            name: req.name,
        })
        .await?;

    Ok(Json(serde_json::json!({
        "id": user.id.to_string(),
        "email": user.email,
        "message": "Registration successful. Please verify your email."
    })))
}

async fn login(
    Extension(auth_state): Extension<Arc<AuthState>>,
    Json(req): Json<LoginRequest>,
) -> AppResult<Json<LoginResponseBody>> {
    // Create token issuer adapter
    let token_issuer = JwtTokenIssuer {
        issuer: auth_state.jwt_issuer.clone(),
    };

    let config = tideway::auth::flows::LoginFlowConfig::new("MyApp")
        .require_verification(false); // Set to true in production

    let flow = tideway::auth::flows::LoginFlow::new(
        auth_state.user_store.clone(),
        auth_state.mfa_store.clone(),
        token_issuer,
        config,
    )
    .with_refresh_store(auth_state.refresh_store.clone());

    let response = flow
        .login(tideway::auth::flows::LoginRequest {
            email: req.email,
            password: req.password,
            remember_me: req.remember_me.unwrap_or(false),
            mfa_code: req.mfa_code,
        })
        .await?;

    // Convert LoginResponse to our API response
    match response {
        tideway::auth::flows::LoginResponse::Success {
            access_token,
            refresh_token,
            expires_in,
            ..
        } => Ok(Json(LoginResponseBody::Success(AuthResponse {
            access_token,
            refresh_token,
            expires_in,
            token_type: "Bearer".to_string(),
        }))),
        tideway::auth::flows::LoginResponse::MfaRequired {
            mfa_token,
            backup_codes_remaining,
            ..
        } => Ok(Json(LoginResponseBody::MfaRequired(MfaRequiredResponse {
            mfa_required: true,
            mfa_token,
            backup_codes_remaining,
        }))),
        tideway::auth::flows::LoginResponse::Error { message } => {
            Ok(Json(LoginResponseBody::Error { error: message }))
        }
    }
}

async fn refresh_token(
    Extension(auth_state): Extension<Arc<AuthState>>,
    Json(req): Json<RefreshRequest>,
) -> AppResult<Json<AuthResponse>> {
    let user_loader = SeaOrmUserLoader {
        store: auth_state.user_store.clone(),
    };

    let flow = tideway::auth::TokenRefreshFlow::new(
        auth_state.jwt_issuer.clone(),
        auth_state.refresh_store.clone(),
        user_loader,
        &auth_state.jwt_secret,
    );

    let tokens = flow.refresh(&req.refresh_token).await?;

    Ok(Json(AuthResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
        token_type: "Bearer".to_string(),
    }))
}

// =============================================================================
// Helper Adapters
// =============================================================================

/// Adapter to implement TokenIssuer for JwtIssuer.
#[derive(Clone)]
struct JwtTokenIssuer {
    issuer: tideway::auth::JwtIssuer,
}

impl tideway::auth::flows::TokenIssuer for JwtTokenIssuer {
    type User = user::Model;

    fn issue(
        &self,
        user: &Self::User,
        remember_me: bool,
    ) -> AppResult<tideway::auth::flows::TokenIssuance> {
        let user_id = user.id.to_string();
        let mut subject = tideway::auth::TokenSubject::new(&user_id)
            .with_email(&user.email);

        if let Some(ref name) = user.name {
            subject = subject.with_name(name);
        }

        let tokens = self.issuer.issue(subject, remember_me)?;

        Ok(tideway::auth::flows::TokenIssuance {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_in: tokens.expires_in,
            family: tokens.family,
        })
    }
}

/// Adapter to implement UserLoader for SeaOrmUserStore.
#[derive(Clone)]
struct SeaOrmUserLoader {
    store: SeaOrmUserStore,
}

#[async_trait]
impl tideway::auth::refresh::UserLoader for SeaOrmUserLoader {
    type User = user::Model;

    async fn load_user(&self, user_id: &str) -> AppResult<Option<Self::User>> {
        use tideway::auth::storage::UserStore;
        self.store.find_by_id(user_id).await
    }

    fn user_email(&self, user: &Self::User) -> Option<String> {
        Some(user.email.clone())
    }

    fn user_name(&self, user: &Self::User) -> Option<String> {
        user.name.clone()
    }
}

// =============================================================================
// Route Module
// =============================================================================

struct AuthModule {
    auth_state: Arc<AuthState>,
}

impl RouteModule for AuthModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new()
            .route("/register", post(register))
            .route("/login", post(login))
            .route("/refresh", post(refresh_token))
            .layer(Extension(self.auth_state.clone()))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api/auth")
    }
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    tideway::init_tracing();

    // Get database URL from environment
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:./auth_example.db?mode=rwc".to_string());

    tracing::info!("Connecting to database: {}", database_url);

    // Connect to database
    let db = sea_orm::Database::connect(&database_url).await?;

    // JWT configuration
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "your-super-secret-jwt-key-change-in-production".to_string());

    let jwt_config = tideway::auth::JwtIssuerConfig::with_secret(&jwt_secret, "my-app");
    let jwt_issuer = tideway::auth::JwtIssuer::new(jwt_config)?;

    // Create auth state
    let auth_state = Arc::new(AuthState {
        user_store: SeaOrmUserStore::new(db.clone()),
        refresh_store: SeaOrmRefreshTokenStore::new(db.clone()),
        mfa_store: InMemoryMfaTokenStore::new(),
        jwt_issuer,
        jwt_secret: jwt_secret.into_bytes(),
    });

    // Build app
    let app = App::new()
        .register_module(AuthModule { auth_state });

    tracing::info!("SeaORM Auth example starting on http://0.0.0.0:8000");
    tracing::info!("Endpoints:");
    tracing::info!("  POST /api/auth/register - Register a new user");
    tracing::info!("  POST /api/auth/login    - Login and get tokens");
    tracing::info!("  POST /api/auth/refresh  - Refresh access token");
    tracing::info!("");
    tracing::info!("Make sure to run migrations first!");
    tracing::info!("See examples/auth_migrations/ for migration files");

    app.serve().await?;

    Ok(())
}
