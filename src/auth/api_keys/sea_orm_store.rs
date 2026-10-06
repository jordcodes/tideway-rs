//! SeaORM-backed API key storage.
//!
//! Expects the `api_keys` table created by the `create_api_keys` migration
//! that `tideway add api-keys` generates. Timestamps are Unix seconds and
//! scopes are a JSON array stored as text.

use async_trait::async_trait;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{ApiKey, ApiKeyStore};
use crate::{Result, TidewayError};

mod entity {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "api_keys")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub organization_id: String,
        pub name: String,
        pub key_hash: String,
        #[sea_orm(column_type = "Text")]
        pub scopes: String,
        pub created_by: Option<String>,
        pub created_at: i64,
        pub expires_at: Option<i64>,
        pub last_used_at: Option<i64>,
        pub revoked_at: Option<i64>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

use entity::{ActiveModel, Column, Entity, Model};

/// Production API key store backed by SeaORM.
#[derive(Clone, Debug)]
pub struct SeaOrmApiKeyStore {
    db: DatabaseConnection,
}

impl SeaOrmApiKeyStore {
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    #[must_use]
    pub fn connection(&self) -> &DatabaseConnection {
        &self.db
    }
}

fn db_error(error: sea_orm::DbErr) -> TidewayError {
    TidewayError::Database(error.to_string())
}

fn to_timestamp(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn from_timestamp(seconds: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(u64::try_from(seconds).unwrap_or(0))
}

fn from_model(model: Model) -> Result<ApiKey> {
    let scopes = serde_json::from_str(&model.scopes).map_err(|error| {
        TidewayError::internal(format!("Invalid scopes for API key {}: {error}", model.id))
    })?;
    Ok(ApiKey {
        id: model.id,
        organization_id: model.organization_id,
        name: model.name,
        key_hash: model.key_hash,
        scopes,
        created_by: model.created_by,
        created_at: from_timestamp(model.created_at),
        expires_at: model.expires_at.map(from_timestamp),
        last_used_at: model.last_used_at.map(from_timestamp),
        revoked_at: model.revoked_at.map(from_timestamp),
    })
}

#[async_trait]
impl ApiKeyStore for SeaOrmApiKeyStore {
    async fn create_api_key(&self, key: &ApiKey) -> Result<()> {
        let scopes = serde_json::to_string(&key.scopes)
            .map_err(|error| TidewayError::internal(error.to_string()))?;
        Entity::insert(ActiveModel {
            id: Set(key.id.clone()),
            organization_id: Set(key.organization_id.clone()),
            name: Set(key.name.clone()),
            key_hash: Set(key.key_hash.clone()),
            scopes: Set(scopes),
            created_by: Set(key.created_by.clone()),
            created_at: Set(to_timestamp(key.created_at)),
            expires_at: Set(key.expires_at.map(to_timestamp)),
            last_used_at: Set(key.last_used_at.map(to_timestamp)),
            revoked_at: Set(key.revoked_at.map(to_timestamp)),
        })
        .exec(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn find_api_key(&self, id: &str) -> Result<Option<ApiKey>> {
        Entity::find_by_id(id.to_string())
            .one(&self.db)
            .await
            .map_err(db_error)?
            .map(from_model)
            .transpose()
    }

    async fn list_api_keys(&self, organization_id: &str) -> Result<Vec<ApiKey>> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .order_by_desc(Column::CreatedAt)
            .order_by_desc(Column::Id)
            .all(&self.db)
            .await
            .map_err(db_error)?
            .into_iter()
            .map(from_model)
            .collect()
    }

    async fn touch_api_key(&self, id: &str, used_at: SystemTime) -> Result<()> {
        Entity::update_many()
            .col_expr(Column::LastUsedAt, Expr::value(to_timestamp(used_at)))
            .filter(Column::Id.eq(id))
            .exec(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn revoke_api_key(&self, id: &str, revoked_at: SystemTime) -> Result<bool> {
        let result = Entity::update_many()
            .col_expr(Column::RevokedAt, Expr::value(to_timestamp(revoked_at)))
            .filter(Column::Id.eq(id))
            .filter(Column::RevokedAt.is_null())
            .exec(&self.db)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected > 0)
    }

    async fn revoke_all_api_keys(
        &self,
        organization_id: &str,
        revoked_at: SystemTime,
    ) -> Result<usize> {
        let result = Entity::update_many()
            .col_expr(Column::RevokedAt, Expr::value(to_timestamp(revoked_at)))
            .filter(Column::OrganizationId.eq(organization_id))
            .filter(Column::RevokedAt.is_null())
            .exec(&self.db)
            .await
            .map_err(db_error)?;
        Ok(usize::try_from(result.rows_affected).unwrap_or(usize::MAX))
    }
}
