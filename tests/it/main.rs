//! Tideway's integration tests, compiled as a single test binary.
//!
//! Each file in this directory is a module rather than its own `tests/*.rs` target, so the
//! crate and its dependencies are linked once per feature set instead of once per file. Add new
//! integration tests as a module here; gate feature-specific files with `#[cfg(feature = ...)]`
//! (or a `#![cfg(...)]` at the top of the file).
//!
//! Every test shares one process. Tests that change process-global state (environment
//! variables, the global tracing subscriber, the Sentry main hub) must run in a child process
//! via [`support::isolated`].

mod support;

mod api_key_auth_test;
mod api_key_seaorm_test;
mod app_builder_test;
mod app_context_builder_test;
mod auth_extractor_cache_test;
mod auth_integration_test;
mod auth_provider_bridge_test;
mod compression_test;
mod config_from_env_test;
mod cors_tests;
mod credit_migration_test;
mod dev_mode_production_guard_test;
mod dev_mode_test;
mod docs_version_pins_test;
mod email_test;
mod ensure_macro_test;
mod error_reporting_test;
mod failure_scenarios_test;
mod jobs_integration_test;
mod macro_docs_test;
mod merge_router_middleware_test;
mod metrics_integration_test;
mod middleware_stack_test;
#[cfg(feature = "auth-oauth")]
mod oauth_test;
mod organization_transfer_seaorm_test;
#[cfg(feature = "otel")]
mod otel_export_test;
mod prelude_smoke_test;
mod redis_cache_clear_test;
mod redis_cache_test;
mod redis_connection_reuse_test;
mod request_overhead;
mod security_headers_regression;
#[cfg(feature = "sentry")]
mod sentry_reporter_test;
mod sqlx_feature_contract_test;
mod storage_test;
mod test_auth_bypass_test;
mod test_db_cleanup_test;
mod test_db_template_test;
mod test_host_bootstrap_test;
mod test_host_builder_test;
mod test_host_test;
mod testing_app_test;
