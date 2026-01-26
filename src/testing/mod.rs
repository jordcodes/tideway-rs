//! Testing utilities for Tideway applications
//!
//! This module provides comprehensive testing tools including:
//! - Alba-style HTTP endpoint testing without running a server
//! - Database testing with SQLite in-memory
//! - Fluent assertion APIs
//!
//! # Example
//!
//! ```rust,ignore
//! use axum::{Router, routing, Json};
//! use tideway::testing;
//! use serde_json::json;
//!
//! async fn hello() -> Json<serde_json::Value> {
//!     Json(json!({"message": "Hello!"}))
//! }
//!
//! #[tokio::test]
//! async fn test_hello() {
//!     let app = Router::new().route("/hello", routing::get(hello));
//!
//!     let response = testing::get(app, "/hello")
//!         .send()
//!         .await
//!         .assert_json_ok();
//!
//!     let body: serde_json::Value = response.json().await;
//!     assert_eq!(body["message"], "Hello!");
//! }
//! ```
//!
//! Using `TestApp` with a Tideway `App`:
//!
//! ```rust,ignore
//! use tideway::{App, RouteModule, AppContext};
//! use tideway::testing::TestApp;
//! use axum::{routing::get, Router};
//!
//! struct HealthModule;
//!
//! impl RouteModule for HealthModule {
//!     fn routes(&self) -> Router<AppContext> {
//!         Router::new().route("/health", get(|| async { "ok" }))
//!     }
//! }
//!
//! let app = App::new().register_module(HealthModule);
//! let test_app = TestApp::new(app);
//! test_app.get("/health").execute().await.assert_ok();
//! ```

#[cfg(feature = "database")]
mod database;
mod app;
mod scenario;
mod fixtures;

#[cfg(feature = "database")]
pub use database::TestDb;
pub use app::TestApp;
pub use scenario::{Scenario, ScenarioAssert, delete, get, patch, post, put};
pub use fixtures::{TestFactory, TestUser, fake};
