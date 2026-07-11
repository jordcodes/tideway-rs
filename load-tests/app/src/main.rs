use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use sea_orm::entity::prelude::*;
use sea_orm::{
    Database, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tideway::auth::{AccessTokenClaims, JwtIssuer, JwtIssuerConfig, JwtVerifier, TokenSubject};
use tideway::ratelimit::{RateLimitConfig, build_rate_limit_layer};
use tideway::{App, ConfigBuilder, TidewayError};
use tokio::sync::broadcast;

const DEFAULT_SECRET: &str = "0123456789abcdef0123456789abcdef";

mod item {
    use sea_orm::entity::prelude::*;
    use serde::Serialize;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize)]
    #[sea_orm(table_name = "load_items")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub name: String,
        pub category: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(Clone)]
struct LoadState {
    db: DatabaseConnection,
    issuer: Arc<JwtIssuer>,
    verifier: Arc<JwtVerifier<AccessTokenClaims>>,
    websocket_tx: broadcast::Sender<String>,
}

#[derive(Deserialize)]
struct ListQuery {
    #[serde(default = "default_limit")]
    limit: u64,
    #[serde(default)]
    offset: u64,
    q: Option<String>,
}

fn default_limit() -> u64 {
    20
}

#[derive(Serialize)]
struct ListResponse {
    items: Vec<item::Model>,
    total: u64,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
}

async fn token(State(state): State<Arc<LoadState>>) -> Result<Json<TokenResponse>, TidewayError> {
    let pair = state.issuer.issue(TokenSubject::new("load-user"), false)?;
    Ok(Json(TokenResponse {
        access_token: pair.access_token,
    }))
}

async fn authenticated(
    State(state): State<Arc<LoadState>>,
    headers: HeaderMap,
) -> Result<StatusCode, TidewayError> {
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| TidewayError::unauthorized("Missing bearer token"))?;
    state.verifier.verify_access_token(token).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_items(
    State(state): State<Arc<LoadState>>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ListResponse>, TidewayError> {
    let mut select = item::Entity::find();
    if let Some(q) = query.q.as_deref().filter(|value| !value.is_empty()) {
        select = select.filter(item::Column::Name.contains(q));
    }
    let total = select
        .clone()
        .count(&state.db)
        .await
        .map_err(|error| TidewayError::Database(error.to_string()))?;
    let items = select
        .order_by_asc(item::Column::Id)
        .offset(query.offset)
        .limit(query.limit.clamp(1, 100))
        .all(&state.db)
        .await
        .map_err(|error| TidewayError::Database(error.to_string()))?;
    Ok(Json(ListResponse { items, total }))
}

async fn websocket(ws: WebSocketUpgrade, State(state): State<Arc<LoadState>>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| websocket_connection(socket, state.websocket_tx.subscribe()))
}

async fn websocket_connection(socket: WebSocket, mut receiver: broadcast::Receiver<String>) {
    let (mut sender, mut incoming) = socket.split();
    loop {
        tokio::select! {
            message = receiver.recv() => {
                let Ok(message) = message else { break; };
                if sender.send(Message::Text(message.into())).await.is_err() { break; }
            }
            message = incoming.next() => {
                if !matches!(message, Some(Ok(_))) { break; }
            }
        }
    }
}

async fn broadcast(State(state): State<Arc<LoadState>>) -> StatusCode {
    let _ = state.websocket_tx.send("load-test-broadcast".to_string());
    StatusCode::ACCEPTED
}

async fn prepare_database(db: &DatabaseConnection) -> anyhow::Result<()> {
    use sea_orm::{ConnectionTrait, Statement};
    db.execute(Statement::from_string(
        db.get_database_backend(),
        "CREATE TABLE IF NOT EXISTS load_items (id SERIAL PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL)".to_string(),
    ))
    .await?;
    db.execute(Statement::from_string(
        db.get_database_backend(),
        "INSERT INTO load_items (name, category) SELECT 'item-' || value, 'category-' || (value % 20) FROM generate_series(1, 10000) value WHERE NOT EXISTS (SELECT 1 FROM load_items LIMIT 1)".to_string(),
    ))
    .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://tideway:tideway@127.0.0.1:55432/tideway_load".to_string());
    let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| DEFAULT_SECRET.to_string());
    let db = Database::connect(database_url).await?;
    prepare_database(&db).await?;

    let issuer_config =
        JwtIssuerConfig::with_secure_secret(&secret, "tideway-load")?.audience("tideway-load");
    let issuer = Arc::new(JwtIssuer::new(issuer_config)?);
    let verifier = Arc::new(
        JwtVerifier::<AccessTokenClaims>::from_secret_checked(secret.as_bytes())?
            .with_issuer("tideway-load")
            .with_audience("tideway-load"),
    );
    let (websocket_tx, _) = broadcast::channel(16_384);
    let state = Arc::new(LoadState {
        db,
        issuer,
        verifier,
        websocket_tx,
    });

    let rate_limit = RateLimitConfig::builder()
        .enabled(true)
        .max_requests(1_000_000)
        .window_seconds(1)
        .per_ip()
        .build();
    let rate_routes = Router::new()
        .route(
            "/load/rate-limited",
            get(|| async { StatusCode::NO_CONTENT }),
        )
        .layer(build_rate_limit_layer(&rate_limit).expect("enabled rate limit"));

    let routes = Router::new()
        .route("/load/token", get(token))
        .route("/load/authenticated", get(authenticated))
        .route("/api/items", get(list_items))
        .route("/load/ws", get(websocket))
        .route("/load/broadcast", post(broadcast))
        .with_state(state)
        .merge(rate_routes);
    let config = ConfigBuilder::new()
        .with_host("0.0.0.0")
        .with_port(18080)
        .build()?;
    App::with_config(config)
        .merge_router(routes)
        .serve()
        .await?;
    Ok(())
}
