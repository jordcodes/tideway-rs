//! Testing utilities for Tideway applications
//!
//! This module provides comprehensive testing tools including:
//! - Alba-style HTTP endpoint testing without running a server
//! - Database testing with SQLite in-memory
//! - Fluent assertion APIs
//!
//! # Example
//!
//! ```rust,no_run
//! use axum::{Router, routing::get, Json};
//! use tideway::testing::{get, post, TestDb};
//! use serde_json::json;
//!
//! async fn hello() -> Json<serde_json::Value> {
//!     Json(json!({"message": "Hello!"}))
//! }
//!
//! #[tokio::test]
//! async fn test_hello() {
//!     let app = Router::new().route("/hello", get(hello));
//!
//!     let response = get(app, "/hello")
//!         .execute()
//!         .await
//!         .assert_ok()
//!         .assert_json();
//!
//!     let body: serde_json::Value = response.json().await;
//!     assert_eq!(body["message"], "Hello!");
//! }
//! ```

#[cfg(feature = "database")]
mod database;
mod scenario;
mod fixtures;

#[cfg(feature = "database")]
pub use database::TestDb;
pub use scenario::{Scenario, ScenarioAssert, delete, get, patch, post, put};
pub use fixtures::{TestFactory, TestUser, fake};
