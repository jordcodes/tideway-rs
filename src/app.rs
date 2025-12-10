use std::sync::Arc;

#[cfg(feature = "database")]
use crate::traits::database::DatabasePool;
#[cfg(feature = "cache")]
use crate::traits::cache::Cache;
#[cfg(feature = "sessions")]
use crate::traits::session::SessionStore;
#[cfg(feature = "jobs")]
use crate::traits::job::JobQueue;
#[cfg(feature = "websocket")]
use crate::websocket::ConnectionManager;

/// Application context for dependency injection and shared state
///
/// This struct holds references to application-wide dependencies like
/// database connections, cache, and session stores. All dependencies
/// are optional and can be accessed via trait objects.
#[derive(Clone)]
pub struct AppContext {
    #[cfg(feature = "database")]
    pub database: Option<Arc<dyn DatabasePool>>,

    #[cfg(feature = "cache")]
    pub cache: Option<Arc<dyn Cache>>,

    #[cfg(feature = "sessions")]
    pub sessions: Option<Arc<dyn SessionStore>>,

    #[cfg(feature = "jobs")]
    pub jobs: Option<Arc<dyn JobQueue>>,

    #[cfg(feature = "websocket")]
    pub websocket_manager: Option<Arc<ConnectionManager>>,

    /// Authentication provider (application-specific)
    ///
    /// Note: Stored as `Arc<dyn Any>` due to AuthProvider's associated types.
    /// Applications should downcast to their concrete auth provider type when needed.
    pub auth_provider: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

impl AppContext {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "database")]
            database: None,
            #[cfg(feature = "cache")]
            cache: None,
            #[cfg(feature = "sessions")]
            sessions: None,
            #[cfg(feature = "jobs")]
            jobs: None,
            #[cfg(feature = "websocket")]
            websocket_manager: None,
            auth_provider: None,
        }
    }

    /// Builder pattern for constructing AppContext
    pub fn builder() -> AppContextBuilder {
        AppContextBuilder::new()
    }

    /// Get the database pool, returning an error if not configured
    #[cfg(feature = "database")]
    pub fn database(&self) -> crate::error::Result<&Arc<dyn DatabasePool>> {
        self.database.as_ref().ok_or_else(|| {
            crate::error::TidewayError::internal("Database pool not configured")
        })
    }

    /// Get the database pool as an Option
    #[cfg(feature = "database")]
    pub fn database_opt(&self) -> Option<&Arc<dyn DatabasePool>> {
        self.database.as_ref()
    }

    /// Get the cache, returning an error if not configured
    #[cfg(feature = "cache")]
    pub fn cache(&self) -> crate::error::Result<&Arc<dyn Cache>> {
        self.cache.as_ref().ok_or_else(|| {
            crate::error::TidewayError::internal("Cache not configured")
        })
    }

    /// Get the cache as an Option
    #[cfg(feature = "cache")]
    pub fn cache_opt(&self) -> Option<&Arc<dyn Cache>> {
        self.cache.as_ref()
    }

    /// Get the session store, returning an error if not configured
    #[cfg(feature = "sessions")]
    pub fn sessions(&self) -> crate::error::Result<&Arc<dyn SessionStore>> {
        self.sessions.as_ref().ok_or_else(|| {
            crate::error::TidewayError::internal("Session store not configured")
        })
    }

    /// Get the session store as an Option
    #[cfg(feature = "sessions")]
    pub fn sessions_opt(&self) -> Option<&Arc<dyn SessionStore>> {
        self.sessions.as_ref()
    }

    /// Get the job queue, returning an error if not configured
    #[cfg(feature = "jobs")]
    pub fn jobs(&self) -> crate::error::Result<&Arc<dyn JobQueue>> {
        self.jobs.as_ref().ok_or_else(|| {
            crate::error::TidewayError::internal("Job queue not configured")
        })
    }

    /// Get the job queue as an Option
    #[cfg(feature = "jobs")]
    pub fn jobs_opt(&self) -> Option<&Arc<dyn JobQueue>> {
        self.jobs.as_ref()
    }

    /// Get the WebSocket manager, returning an error if not configured
    #[cfg(feature = "websocket")]
    pub fn websocket_manager(&self) -> crate::error::Result<Arc<ConnectionManager>> {
        self.websocket_manager.clone().ok_or_else(|| {
            crate::error::TidewayError::internal("WebSocket manager not configured")
        })
    }

    /// Get the WebSocket manager as an Option
    #[cfg(feature = "websocket")]
    pub fn websocket_manager_opt(&self) -> Option<Arc<ConnectionManager>> {
        self.websocket_manager.clone()
    }

    /// Get the auth provider, downcast to the concrete type
    ///
    /// # Example
    /// ```ignore
    /// if let Some(provider) = ctx.auth_provider_opt::<OutsetaAuthProvider>() {
    ///     // Use provider
    /// }
    /// ```
    pub fn auth_provider_opt<T: 'static>(&self) -> Option<&T> {
        self.auth_provider
            .as_ref()
            .and_then(|p| p.downcast_ref::<T>())
    }

    /// Get the auth provider, returning an error if not configured or wrong type
    pub fn auth_provider<T: 'static>(&self) -> crate::error::Result<&T> {
        self.auth_provider_opt::<T>().ok_or_else(|| {
            crate::error::TidewayError::internal("Auth provider not configured or wrong type")
        })
    }

    /// Get SeaORM connection from the database pool
    ///
    /// This is a convenience method for applications using SeaORM.
    /// Returns an error if the database pool is not SeaOrmPool.
    #[cfg(feature = "database")]
    pub fn sea_orm_connection(&self) -> crate::error::Result<sea_orm::DatabaseConnection> {
        use crate::database::SeaOrmPool;
        let pool = self.database()?;
        // Downcast to SeaOrmPool
        let sea_orm_pool = pool
            .as_any()
            .downcast_ref::<SeaOrmPool>()
            .ok_or_else(|| crate::error::TidewayError::internal("Database pool is not SeaOrmPool"))?;
        Ok(sea_orm_pool.as_ref().clone())
    }
}

impl Default for AppContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for AppContext with fluent API
#[must_use = "builder does nothing until you call build()"]
pub struct AppContextBuilder {
    #[cfg(feature = "database")]
    database: Option<Arc<dyn DatabasePool>>,
    #[cfg(feature = "cache")]
    cache: Option<Arc<dyn Cache>>,
    #[cfg(feature = "sessions")]
    sessions: Option<Arc<dyn SessionStore>>,

    #[cfg(feature = "jobs")]
    jobs: Option<Arc<dyn JobQueue>>,

    #[cfg(feature = "websocket")]
    websocket_manager: Option<Arc<ConnectionManager>>,

    auth_provider: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

impl AppContextBuilder {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "database")]
            database: None,
            #[cfg(feature = "cache")]
            cache: None,
            #[cfg(feature = "sessions")]
            sessions: None,
            #[cfg(feature = "jobs")]
            jobs: None,
            #[cfg(feature = "websocket")]
            websocket_manager: None,
            auth_provider: None,
        }
    }

    /// Set the database pool
    #[cfg(feature = "database")]
    pub fn with_database(mut self, pool: Arc<dyn DatabasePool>) -> Self {
        self.database = Some(pool);
        self
    }

    /// Set the cache
    #[cfg(feature = "cache")]
    pub fn with_cache(mut self, cache: Arc<dyn Cache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Set the session store
    #[cfg(feature = "sessions")]
    pub fn with_sessions(mut self, sessions: Arc<dyn SessionStore>) -> Self {
        self.sessions = Some(sessions);
        self
    }

    /// Set the job queue
    #[cfg(feature = "jobs")]
    pub fn with_job_queue(mut self, queue: Arc<dyn JobQueue>) -> Self {
        self.jobs = Some(queue);
        self
    }

    /// Set the WebSocket manager
    #[cfg(feature = "websocket")]
    pub fn with_websocket_manager(mut self, manager: Arc<ConnectionManager>) -> Self {
        self.websocket_manager = Some(manager);
        self
    }

    /// Set the auth provider
    ///
    /// # Example
    /// ```ignore
    /// let auth_provider = Arc::new(OutsetaAuthProvider::new(config).await?);
    /// let context = AppContext::builder()
    ///     .with_auth_provider(auth_provider)
    ///     .build();
    /// ```
    pub fn with_auth_provider<T: Send + Sync + 'static>(mut self, provider: Arc<T>) -> Self {
        self.auth_provider = Some(provider as Arc<dyn std::any::Any + Send + Sync>);
        self
    }

    pub fn build(self) -> AppContext {
        AppContext {
            #[cfg(feature = "database")]
            database: self.database,
            #[cfg(feature = "cache")]
            cache: self.cache,
            #[cfg(feature = "sessions")]
            sessions: self.sessions,

            #[cfg(feature = "jobs")]
            jobs: self.jobs,
            #[cfg(feature = "websocket")]
            websocket_manager: self.websocket_manager,
            auth_provider: self.auth_provider,
        }
    }
}

impl Default for AppContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}
