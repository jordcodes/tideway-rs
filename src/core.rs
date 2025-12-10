use crate::{
    app::AppContext,
    config::Config,
    compression::build_compression_layer,
    cors::build_cors_layer,
    http::RouteModule,
    middleware::MakeRequestUuid,
    ratelimit::build_rate_limit_layer,
    request_logging::build_request_logging_layer,
    security::build_security_headers_layer,
    timeout::build_timeout_layer,
};
use axum::{extract::DefaultBodyLimit, Router};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tower_http::request_id::{PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;

#[cfg(feature = "metrics")]
use crate::metrics::{build_metrics_layer, metrics_handler, MetricsCollector};

#[cfg(feature = "jobs")]
use crate::jobs::{JobRegistry, WorkerPool};

/// Main application structure for Tideway
pub struct App {
    router: Router<AppContext>,
    config: Config,
    context: AppContext,
    /// Routers without state that will be merged after with_state is called
    extra_routers: Vec<Router>,
    #[cfg(feature = "metrics")]
    metrics_collector: Option<Arc<MetricsCollector>>,
    #[cfg(feature = "jobs")]
    worker_pool: Option<WorkerPool>,
}

impl App {
    /// Creates a new App with default configuration
    pub fn new() -> Self {
        Self::with_config(Config::default())
    }

    /// Creates a new App with the provided configuration
    pub fn with_config(config: Config) -> Self {
        let context = AppContext::new();
        let router = Self::build_router(&config);

        #[cfg(feature = "metrics")]
        let metrics_collector = if config.metrics.enabled {
            Some(Arc::new(
                MetricsCollector::new().expect("Failed to create metrics collector"),
            ))
        } else {
            None
        };

        Self {
            router,
            config,
            context,
            extra_routers: Vec::new(),
            #[cfg(feature = "metrics")]
            metrics_collector,
            #[cfg(feature = "jobs")]
            worker_pool: None,
        }
    }

    /// Builder pattern for constructing an App
    pub fn builder() -> AppBuilder {
        AppBuilder::new()
    }

    fn build_router(_config: &Config) -> Router<AppContext> {
        Router::<AppContext>::new()
    }

    /// Register a route module with the application
    ///
    /// Note: The module's router will inherit the AppContext state from the parent router.
    /// Handlers should use `State<AppContext>` to access the application context.
    pub fn register_module<M: RouteModule>(mut self, module: M) -> Self {
        let module_router = module.routes();
        if let Some(prefix) = module.prefix() {
            self.router = self.router.nest(prefix, module_router);
        } else {
            self.router = self.router.merge(module_router);
        }
        self
    }

    /// Merge a router without state into the application
    ///
    /// Note: This accepts `Router<()>` - routers that have already had their state provided.
    /// These routers will be merged after `with_state` is called in `serve()`.
    /// For routers that need `AppContext`, use `register_module` instead.
    pub fn merge_router(mut self, router: Router) -> Self {
        self.extra_routers.push(router);
        self
    }

    /// Set the application context
    pub fn with_context(mut self, context: AppContext) -> Self {
        self.context = context;
        // Add health routes to the existing router
        use axum::routing::get;
        use crate::health;
        let health_routes = Router::<AppContext>::new()
            .route("/health", get(health::health_handler));
        self.router = self.router.merge(health_routes);
        self
    }

    /// Apply a layer to the main application router
    ///
    /// Use this to apply middleware/layers to all routes registered via `register_module`.
    /// Example: `app.layer(axum::Extension(auth_provider))`
    pub fn layer<L>(mut self, layer: L) -> Self
    where
        L: tower::Layer<axum::routing::Route> + Clone + Send + Sync + 'static,
        L::Service: tower::Service<axum::http::Request<axum::body::Body>, Error = std::convert::Infallible> + Clone + Send + Sync + 'static,
        <L::Service as tower::Service<axum::http::Request<axum::body::Body>>>::Response: axum::response::IntoResponse + 'static,
        <L::Service as tower::Service<axum::http::Request<axum::body::Body>>>::Future: Send + 'static,
    {
        self.router = self.router.layer(layer);
        self
    }

    /// Get the router for testing purposes
    ///
    /// This method allows tests to extract the router with AppContext state applied.
    /// The returned router can be used with tideway::testing helpers.
    pub fn into_test_router(self) -> Router {
        self.router.with_state(self.context)
    }

    /// Apply middleware stack and prepare for serving
    fn with_middleware(mut self) -> Self {
        let mut router = self.router;

        // Middleware order (from outer to inner):
        // 1. Metrics (if enabled) - needs to be outermost to track all requests
        #[cfg(feature = "metrics")]
        {
            if let Some(ref collector) = self.metrics_collector {
                // Metrics handler uses State<Arc<MetricsCollector>>, not AppContext
                // We need to handle this separately - nest it so it can have its own state
                // But nested routers inherit parent state, so we need a different approach
                // For now, create metrics router with MetricsCollector state and nest it
                let _metrics_router: Router = Router::new()
                    .route(
                        self.config.metrics.path.as_str(),
                        axum::routing::get(metrics_handler),
                    )
                    .with_state(collector.clone());

                // Nest metrics router - it will inherit AppContext but handler expects MetricsCollector
                // This won't work - we need to handle metrics differently
                // TODO: Fix metrics to work with AppContext or handle separately
                // router = router.nest("/", _metrics_router);

                // Then add metrics middleware layer (outermost)
                router = router.layer(build_metrics_layer(collector.clone()));
            }
        }

        // 2. Body size limit - reject large bodies early to prevent DoS attacks
        router = router.layer(DefaultBodyLimit::max(self.config.server.max_body_size));

        // 3. Timeout - early in stack to catch slow requests
        if let Some(timeout_layer) = build_timeout_layer(&self.config.timeout) {
            router = router.layer(timeout_layer);
        }

        // 4. Security headers - early to secure all responses
        if let Some(security_layer) = build_security_headers_layer(&self.config.security) {
            router = router.layer(security_layer);
        }

        // 5. Compression - compress responses before sending
        if let Some(compression_layer) = build_compression_layer(&self.config.compression) {
            router = router.layer(compression_layer);
        }

        // 6. Rate limiting - after compression/security but before request processing
        if let Some(rate_limit_layer) = build_rate_limit_layer(&self.config.rate_limit) {
            router = router.layer(rate_limit_layer);
        }

        // 7. CORS - handle cross-origin requests
        if let Some(cors_layer) = build_cors_layer(&self.config.cors) {
            router = router.layer(cors_layer);
        }

        // 8. Request ID - add request IDs for tracing
        router = router
            .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
            .layer(PropagateRequestIdLayer::x_request_id());

        // 9. Trace layer - HTTP tracing
        router = router.layer(TraceLayer::new_for_http());

        // 10. Request logging - log requests/responses (innermost of logging layers)
        if let Some(logging_layer) = build_request_logging_layer(&self.config.request_logging) {
            router = router.layer(logging_layer);
        }

        self.router = router;
        self
    }

    /// Start background job workers if jobs are enabled
    #[cfg(feature = "jobs")]
    pub fn start_workers(mut self, registry: Arc<JobRegistry>) -> Self {
        if let Some(ref queue) = self.context.jobs {
            if self.config.jobs.enabled {
                let pool = WorkerPool::new(
                    queue.clone(),
                    registry,
                    Arc::new(self.context.clone()),
                    self.config.jobs.worker_count,
                );
                self.worker_pool = Some(pool);
                tracing::info!(
                    worker_count = self.config.jobs.worker_count,
                    "Background job workers started"
                );
            }
        }
        self
    }

    /// Start the application server
    pub async fn serve(self) -> Result<(), std::io::Error> {
        let addr = self
            .config
            .server
            .addr()
            .expect("Invalid server address in config");

        #[allow(unused_mut)] // Needed for worker_pool.take() when jobs feature is enabled
        let mut app = self.with_middleware();

        let listener = tokio::net::TcpListener::bind(addr).await?;

        tracing::info!("Server starting on http://{}", addr);
        tracing::info!("Health check available at http://{}/health", addr);

        // Create shutdown future that also shuts down workers
        #[cfg(feature = "jobs")]
        let worker_pool = app.worker_pool.take();

        let shutdown = async move {
            shutdown_signal().await;
            #[cfg(feature = "jobs")]
            {
                if let Some(pool) = worker_pool {
                    pool.shutdown().await;
                }
            }
        };

        // Router<AppContext> means "a router missing AppContext state"
        // Call with_state to transition Router<AppContext> -> Router<()>
        // Only Router<()> (a router not missing any state) can be served
        let mut final_router = app.router.with_state(app.context);

        // Merge any extra routers (Router<()>) that were added via merge_router
        for extra in app.extra_routers {
            final_router = final_router.merge(extra);
        }

        // Apply CORS to the final merged router (to cover extra_routers that missed middleware)
        if let Some(cors_layer) = crate::cors::build_cors_layer(&app.config.cors) {
            final_router = final_router.layer(cors_layer);
        }

        axum::serve(listener, final_router)
            .with_graceful_shutdown(shutdown)
            .await
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for App with fluent API
#[must_use = "builder does nothing until you call build()"]
pub struct AppBuilder {
    config: Config,
    context: AppContext,
    modules: Vec<Router<AppContext>>,
    #[cfg(feature = "metrics")]
    metrics_collector: Option<Arc<MetricsCollector>>,
}

impl AppBuilder {
    pub fn new() -> Self {
        Self {
            config: Config::default(),
            context: AppContext::new(),
            modules: Vec::new(),
            #[cfg(feature = "metrics")]
            metrics_collector: None,
        }
    }

    pub fn with_config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    pub fn with_context(mut self, context: AppContext) -> Self {
        self.context = context;
        self
    }

    pub fn with_cors(mut self, cors: crate::cors::CorsConfig) -> Self {
        self.config.cors = cors;
        self
    }

    pub fn register_module<M: RouteModule>(mut self, module: M) -> Self {
        self.modules.push(module.routes());
        self
    }

    pub fn build(self) -> App {
        let mut app = App::with_config(self.config);
        app.context = self.context;

        #[cfg(feature = "metrics")]
        {
            app.metrics_collector = self.metrics_collector;
        }

        for module_router in self.modules {
            app.router = app.router.merge(module_router);
        }

        app
    }
}

impl Default for AppBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Graceful shutdown signal handler
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C signal, starting graceful shutdown");
        },
        _ = terminate => {
            tracing::info!("Received terminate signal, starting graceful shutdown");
        },
    }

    // Give connections a grace period to close
    tokio::time::sleep(Duration::from_secs(1)).await;
    tracing::info!("Shutdown complete");
}
