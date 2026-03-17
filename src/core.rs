use crate::{
    app::AppContext,
    compression::build_compression_layer,
    config::Config,
    dev::{build_dev_error_layer, build_request_dumper_layer},
    http::RouteModule,
    middleware::MakeRequestUuid,
    ratelimit::build_rate_limit_layer,
    request_logging::build_request_logging_layer,
    security::build_security_headers_layer,
    timeout::build_timeout_layer,
};

#[cfg(feature = "database")]
use crate::error::TidewayError;
use axum::{
    Router,
    extract::{DefaultBodyLimit, connect_info::IntoMakeServiceWithConnectInfo},
};
#[cfg(feature = "database")]
use sea_orm_migration::MigratorTrait;
use std::time::Duration;
use tokio::signal;
use tower_http::request_id::{PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;

use std::sync::Arc;

#[cfg(feature = "metrics")]
use crate::metrics::{MetricsCollector, build_metrics_layer, metrics_handler};

#[cfg(feature = "jobs")]
use crate::jobs::{JobRegistry, WorkerPool};

/// Main application structure for Tideway
pub struct App {
    router: Router<AppContext>,
    config: Config,
    context: AppContext,
    /// Routers without state that will be merged after with_state is called
    extra_routers: Vec<Router>,
    /// Layers to apply after all modules and extra routers are registered
    global_layers: Vec<GlobalLayer>,
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
        #[allow(unused_mut)]
        let mut context = AppContext::new();
        #[allow(unused_mut)]
        let mut router = Self::build_router(&config);

        #[cfg(feature = "metrics")]
        let metrics_collector = if config.metrics.enabled {
            match MetricsCollector::new() {
                Ok(collector) => Some(Arc::new(collector)),
                Err(e) => {
                    tracing::error!(
                        "Failed to create metrics collector: {}. Metrics disabled.",
                        e
                    );
                    None
                }
            }
        } else {
            None
        };

        // Store metrics collector in context so handler can access it
        #[cfg(feature = "metrics")]
        {
            context.metrics = metrics_collector.clone();
        }

        // Add metrics endpoint route (needs to be here so into_test_router() includes it)
        #[cfg(feature = "metrics")]
        {
            if metrics_collector.is_some() {
                router = router.route(
                    config.metrics.path.as_str(),
                    axum::routing::get(metrics_handler),
                );
            }
        }

        Self {
            router,
            config,
            context,
            extra_routers: Vec::new(),
            global_layers: Vec::new(),
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
        use crate::health;
        use axum::routing::get;

        Router::<AppContext>::new().route("/health", get(health::health_handler))
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

    /// Register a list of modules with the application.
    ///
    /// Note: This is useful for homogeneous module lists. Use the macro
    /// `register_modules!` for mixed module types.
    pub fn register_modules<I, M>(self, modules: I) -> Self
    where
        I: IntoIterator<Item = M>,
        M: RouteModule,
    {
        let mut app = self;
        for module in modules {
            app = app.register_module(module);
        }
        app
    }

    /// Register an optional module, skipping when None.
    pub fn register_optional_module<M: RouteModule>(self, module: Option<M>) -> Self {
        if let Some(module) = module {
            self.register_module(module)
        } else {
            self
        }
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
        self
    }

    /// Transform the application context while preserving existing dependencies.
    ///
    /// This is especially useful in tests when you want to override one dependency
    /// without rebuilding the full `AppContext` from scratch.
    pub fn map_context<F>(mut self, configure: F) -> Self
    where
        F: FnOnce(crate::app::AppContextBuilder) -> crate::app::AppContextBuilder,
    {
        self.context = configure(self.context.to_builder()).build();
        self
    }

    /// Run database migrations if DATABASE_AUTO_MIGRATE=true
    ///
    /// This method checks the `DATABASE_AUTO_MIGRATE` environment variable and runs
    /// pending migrations if set to "true". Call this before `serve()`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use my_app::migration::Migrator;
    ///
    /// App::with_config(config)
    ///     .with_context(context)
    ///     .run_migrations::<Migrator>().await?
    ///     .serve().await?;
    /// ```
    #[cfg(feature = "database")]
    pub async fn run_migrations<M: MigratorTrait>(self) -> Result<Self, TidewayError> {
        if should_auto_migrate() {
            if self.context.database_opt().is_some() {
                run_migrations_with_context::<M>(&self.context).await?;
            } else {
                tracing::warn!("DATABASE_AUTO_MIGRATE is enabled but no database is configured");
            }
        }
        Ok(self)
    }

    /// Always run database migrations
    ///
    /// Unlike `run_migrations`, this always runs migrations regardless of
    /// the DATABASE_AUTO_MIGRATE environment variable.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use my_app::migration::Migrator;
    ///
    /// App::with_config(config)
    ///     .with_context(context)
    ///     .run_migrations_now::<Migrator>().await?
    ///     .serve().await?;
    /// ```
    #[cfg(feature = "database")]
    pub async fn run_migrations_now<M: MigratorTrait>(self) -> Result<Self, TidewayError> {
        if self.context.database_opt().is_none() {
            return Err(TidewayError::internal(
                "Cannot run migrations: no database configured",
            ));
        }

        run_migrations_with_context::<M>(&self.context).await?;
        Ok(self)
    }

    /// Apply a layer to the main application router
    ///
    /// Use this to apply middleware/layers to all routes registered via `register_module`.
    /// Example: `app.layer(axum::Extension(auth_provider))`
    pub fn layer<L>(mut self, layer: L) -> Self
    where
        L: tower::Layer<axum::routing::Route> + Clone + Send + Sync + 'static,
        L::Service: tower::Service<axum::http::Request<axum::body::Body>, Error = std::convert::Infallible>
            + Clone
            + Send
            + Sync
            + 'static,
        <L::Service as tower::Service<axum::http::Request<axum::body::Body>>>::Response:
            axum::response::IntoResponse + 'static,
        <L::Service as tower::Service<axum::http::Request<axum::body::Body>>>::Future:
            Send + 'static,
    {
        self.router = self.router.layer(layer);
        self
    }

    /// Apply a layer after all modules and extra routers are registered.
    ///
    /// Note: This is applied in `serve()` and `into_router_with_middleware()`.
    /// It is not applied in `into_router()`.
    pub fn with_global_layer<L>(mut self, layer: L) -> Self
    where
        L: tower::Layer<axum::routing::Route> + Clone + Send + Sync + 'static,
        L::Service: tower::Service<axum::http::Request<axum::body::Body>, Error = std::convert::Infallible>
            + Clone
            + Send
            + Sync
            + 'static,
        <L::Service as tower::Service<axum::http::Request<axum::body::Body>>>::Response:
            axum::response::IntoResponse + 'static,
        <L::Service as tower::Service<axum::http::Request<axum::body::Body>>>::Future:
            Send + 'static,
    {
        self.global_layers
            .push(Box::new(move |router: Router| router.layer(layer.clone())));
        self
    }

    /// Convert the App into an axum Router without applying middleware.
    ///
    /// This applies the AppContext state to the router, making it ready to serve.
    /// Use this when you want to manually serve the router with `axum::serve`
    /// and you plan to add your own middleware stack. If you want Tideway's
    /// default middleware, use `into_router_with_middleware()`.
    ///
    /// # Example
    /// ```ignore
    /// let app = App::new()
    ///     .register_module(auth_module)
    ///     .register_module(admin_module);
    ///
    /// let router = app.into_router();
    /// let listener = TcpListener::bind("0.0.0.0:3000").await?;
    /// axum::serve(listener, router).await?;
    /// ```
    pub fn into_router(self) -> Router {
        build_stateful_router(self.router, self.context, self.extra_routers)
    }

    /// Convert the App into an axum Router with Tideway's middleware stack applied.
    ///
    /// This preserves Tideway's middleware stack when you want to serve manually.
    /// If your middleware or handlers rely on `ConnectInfo<SocketAddr>` (for
    /// example per-IP rate limiting), pair the returned router with
    /// `Router::into_make_service_with_connect_info`, or use
    /// `App::into_make_service_with_connect_info()` for the exact `serve()` path.
    pub fn into_router_with_middleware(self) -> Router {
        let app = self.with_middleware();
        apply_global_layers_with_config(
            build_stateful_router(app.router, app.context, app.extra_routers),
            &app.global_layers,
            &app.config.cors,
        )
    }

    /// Convert the App into an axum make-service with Tideway's middleware stack
    /// and `ConnectInfo<SocketAddr>` wiring applied.
    ///
    /// This matches the service path used by `serve()` and is the safest option
    /// when you want to call `axum::serve` manually without losing client address
    /// information for per-IP middleware or extractors.
    pub fn into_make_service_with_connect_info(
        self,
    ) -> IntoMakeServiceWithConnectInfo<Router, std::net::SocketAddr> {
        self.into_router_with_middleware()
            .into_make_service_with_connect_info::<std::net::SocketAddr>()
    }

    /// Get the router for testing purposes
    ///
    /// This method allows tests to extract the router with AppContext state applied.
    /// The returned router can be used with tideway::testing helpers.
    #[deprecated(since = "0.7.4", note = "Use `into_router()` instead")]
    pub fn into_test_router(self) -> Router {
        self.into_router()
    }

    /// Apply middleware stack and prepare for serving
    fn with_middleware(mut self) -> Self {
        let mut router = self.router;

        // Middleware order (from outer to inner):
        // 1. Metrics (if enabled) - needs to be outermost to track all requests
        #[cfg(feature = "metrics")]
        {
            if let Some(ref collector) = self.metrics_collector {
                // Add metrics middleware layer (outermost)
                // Note: metrics route is added in with_config() so it's available in tests
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

        // 7. Request ID - add request IDs for tracing
        router = router
            .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
            .layer(PropagateRequestIdLayer::x_request_id());

        // 8. Trace layer - HTTP tracing
        router = router.layer(TraceLayer::new_for_http());

        // 9. Dev middleware - request dumper and error logging
        if self.config.dev.enabled {
            let dev_config = Arc::new(self.config.dev.clone());
            if dev_config.enable_request_dumper {
                router = router.layer(build_request_dumper_layer(dev_config.clone()));
            }
            router = router.layer(build_dev_error_layer(dev_config));
        }

        // 10. Request logging - log requests/responses (innermost of logging layers)
        if let Some(logging_layer) = build_request_logging_layer(&self.config.request_logging) {
            router = router.layer(logging_layer);
        }

        #[cfg(feature = "auth")]
        {
            // 11. Auth provider bridge - make AppContext auth provider available to extractors.
            if let Some(auth_provider) = self.context.auth_provider_extension() {
                router = router.layer(axum::middleware::from_fn({
                    move |mut request: axum::extract::Request, next: axum::middleware::Next| {
                        let auth_provider = auth_provider.clone();
                        async move {
                            request.extensions_mut().insert(auth_provider);
                            next.run(request).await
                        }
                    }
                }));
            }
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
        let addr = self.config.server.addr().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid server address in config: {}", e),
            )
        })?;

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

        let final_router = apply_global_layers_with_config(
            build_stateful_router(app.router, app.context, app.extra_routers),
            &app.global_layers,
            &app.config.cors,
        );

        axum::serve(
            listener,
            final_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
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
    /// Modules stored as (router, optional_prefix)
    modules: Vec<(Router<AppContext>, Option<String>)>,
    global_layers: Vec<GlobalLayer>,
}

impl AppBuilder {
    pub fn new() -> Self {
        Self {
            config: Config::default(),
            context: AppContext::new(),
            modules: Vec::new(),
            global_layers: Vec::new(),
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
        let prefix = module.prefix().map(|s| s.to_owned());
        self.modules.push((module.routes(), prefix));
        self
    }

    /// Register a list of modules with the application builder.
    ///
    /// Note: This is useful for homogeneous module lists. Use the macro
    /// `register_modules!` for mixed module types.
    pub fn register_modules<I, M>(self, modules: I) -> Self
    where
        I: IntoIterator<Item = M>,
        M: RouteModule,
    {
        let mut builder = self;
        for module in modules {
            builder = builder.register_module(module);
        }
        builder
    }

    /// Register an optional module, skipping when None.
    pub fn register_optional_module<M: RouteModule>(self, module: Option<M>) -> Self {
        if let Some(module) = module {
            self.register_module(module)
        } else {
            self
        }
    }

    /// Apply a layer after all modules and extra routers are registered.
    pub fn with_global_layer<L>(mut self, layer: L) -> Self
    where
        L: tower::Layer<axum::routing::Route> + Clone + Send + Sync + 'static,
        L::Service: tower::Service<axum::http::Request<axum::body::Body>, Error = std::convert::Infallible>
            + Clone
            + Send
            + Sync
            + 'static,
        <L::Service as tower::Service<axum::http::Request<axum::body::Body>>>::Response:
            axum::response::IntoResponse + 'static,
        <L::Service as tower::Service<axum::http::Request<axum::body::Body>>>::Future:
            Send + 'static,
    {
        self.global_layers
            .push(Box::new(move |router: Router| router.layer(layer.clone())));
        self
    }

    pub fn build(self) -> App {
        let mut app = App::with_config(self.config);
        app.context = self.context;
        app.global_layers = self.global_layers;

        #[cfg(feature = "metrics")]
        {
            if let Some(ref collector) = app.metrics_collector {
                app.context.metrics = Some(collector.clone());
            }
        }

        for (module_router, prefix) in self.modules {
            if let Some(prefix) = prefix {
                app.router = app.router.nest(&prefix, module_router);
            } else {
                app.router = app.router.merge(module_router);
            }
        }

        app
    }
}

type GlobalLayer = Box<dyn Fn(Router) -> Router + Send + Sync>;

fn apply_global_layers(mut router: Router, layers: &[GlobalLayer]) -> Router {
    for layer in layers {
        router = layer(router);
    }
    router
}

#[cfg(feature = "database")]
fn should_auto_migrate() -> bool {
    std::env::var("DATABASE_AUTO_MIGRATE")
        .map(|v| v.parse::<bool>().unwrap_or(false))
        .unwrap_or(false)
}

#[cfg(feature = "database")]
async fn run_migrations_with_context<M: MigratorTrait>(
    context: &AppContext,
) -> Result<(), TidewayError> {
    let conn = context.sea_orm_connection()?;
    crate::database::migration::run_migrations::<M>(&conn).await?;
    Ok(())
}

fn build_stateful_router(
    router: Router<AppContext>,
    context: AppContext,
    extra_routers: Vec<Router>,
) -> Router {
    let mut router = router.with_state(context);
    for extra in extra_routers {
        router = router.merge(extra);
    }
    router
}

fn apply_global_layers_with_config(
    router: Router,
    global_layers: &[GlobalLayer],
    cors_config: &crate::cors::CorsConfig,
) -> Router {
    let mut router = apply_global_layers(router, global_layers);
    if let Some(cors_layer) = crate::cors::build_cors_layer(cors_config) {
        router = router.layer(cors_layer);
    }
    router
}

impl Default for AppBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};

    struct PingModule;

    impl RouteModule for PingModule {
        fn routes(&self) -> Router<AppContext> {
            Router::new().route("/ping", get(|| async { "pong" }))
        }

        fn prefix(&self) -> Option<&str> {
            None
        }
    }

    #[tokio::test]
    async fn test_serve_applies_connect_info_for_per_ip_rate_limit() {
        let port = {
            let probe = match std::net::TcpListener::bind("127.0.0.1:0") {
                Ok(listener) => listener,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    // Some sandboxed CI/dev environments disallow opening sockets.
                    // Skip this end-to-end network test in those environments.
                    return;
                }
                Err(e) => panic!("should bind ephemeral probe port: {}", e),
            };
            let port = probe
                .local_addr()
                .expect("probe should have local addr")
                .port();
            drop(probe);
            port
        };

        let rate_limit = crate::RateLimitConfig::builder()
            .enabled(true)
            .max_requests(1)
            .window_seconds(60)
            .per_ip()
            .build();
        let config = crate::ConfigBuilder::new()
            .with_host("127.0.0.1")
            .with_port(port)
            .with_rate_limit(rate_limit)
            .build()
            .expect("config should be valid");

        let app = App::with_config(config).register_module(PingModule);

        let server = tokio::spawn(async move { app.serve().await });

        let client = reqwest::Client::new();
        let url = format!("http://127.0.0.1:{}/ping", port);

        // Wait for server startup (brief retry loop).
        let mut ready = false;
        for _ in 0..30 {
            match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                Ok(_) => {
                    ready = true;
                    break;
                }
                _ => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        }
        assert!(ready, "server did not become ready in time");

        let first = client
            .get(&url)
            .send()
            .await
            .expect("first request should be sent");
        assert_eq!(first.status(), reqwest::StatusCode::OK);

        let second = client
            .get(&url)
            .send()
            .await
            .expect("second request should be sent");
        assert_eq!(second.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);

        server.abort();
        let _ = server.await;
    }
}

/// Graceful shutdown signal handler
async fn shutdown_signal() {
    let ctrl_c = async {
        match signal::ctrl_c().await {
            Ok(()) => {}
            Err(e) => {
                tracing::error!("Failed to install Ctrl+C handler: {}. Using fallback.", e);
                // Fallback: wait forever (other signals or manual shutdown still work)
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(e) => {
                tracing::error!("Failed to install SIGTERM handler: {}. Using fallback.", e);
                std::future::pending::<()>().await;
            }
        }
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
    // TODO: Make this configurable via ServerConfig
    tokio::time::sleep(Duration::from_secs(5)).await;
    tracing::info!("Shutdown complete");
}
