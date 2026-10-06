use crate::error::{Result, TidewayError};
use redis::aio::ConnectionManager;
use std::sync::Arc;
use tokio::sync::OnceCell;

/// Lazily connect so the public constructors stay synchronous. Clones share both
/// initialization and the manager's multiplexed connection/reconnection state.
#[derive(Clone)]
pub(crate) struct SharedRedisConnection {
    client: redis::Client,
    manager: Arc<OnceCell<ConnectionManager>>,
}

impl SharedRedisConnection {
    pub(crate) fn new(url: &str) -> Result<Self> {
        let client = redis::Client::open(url)
            .map_err(|e| TidewayError::internal(format!("Failed to create Redis client: {}", e)))?;
        Ok(Self {
            client,
            manager: Arc::new(OnceCell::new()),
        })
    }

    pub(crate) async fn get(&self) -> Result<ConnectionManager> {
        self.manager
            .get_or_try_init(|| ConnectionManager::new(self.client.clone()))
            .await
            .cloned()
            .map_err(|e| TidewayError::internal(format!("Failed to get Redis connection: {}", e)))
    }
}
