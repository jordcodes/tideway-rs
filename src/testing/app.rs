use axum::Router;
use axum::http::Method;

use crate::App;
use crate::testing::Scenario;

/// Alba-style test harness for Tideway `App` instances.
pub struct TestApp {
    router: Router,
}

pub struct AuthTestApp {
    router: Router,
    token: String,
}

impl TestApp {
    /// Build a test app from a Tideway `App`, including middleware.
    pub fn new(app: App) -> Self {
        Self::from_router(app.into_router_with_middleware())
    }

    /// Build a test app from a Tideway `App` without middleware.
    pub fn without_middleware(app: App) -> Self {
        Self::from_router(app.into_router())
    }

    /// Build a test app from an Axum router.
    pub fn from_router(router: Router) -> Self {
        Self { router }
    }

    /// Consume the test app and return the underlying router.
    pub fn into_router(self) -> Router {
        self.router
    }

    /// Create an authenticated test app that applies a bearer token to requests.
    pub fn auth(&self, token: &str) -> AuthTestApp {
        AuthTestApp {
            router: self.router.clone(),
            token: token.to_string(),
        }
    }

    pub fn get(&self, uri: &str) -> Scenario {
        Scenario::new(self.router.clone())
            .method(Method::GET)
            .uri(uri)
    }

    pub fn post(&self, uri: &str) -> Scenario {
        Scenario::new(self.router.clone())
            .method(Method::POST)
            .uri(uri)
    }

    pub fn post_json<T: serde::Serialize>(&self, uri: &str, body: &T) -> Scenario {
        self.post(uri).json(body)
    }

    pub fn put(&self, uri: &str) -> Scenario {
        Scenario::new(self.router.clone())
            .method(Method::PUT)
            .uri(uri)
    }

    pub fn delete(&self, uri: &str) -> Scenario {
        Scenario::new(self.router.clone())
            .method(Method::DELETE)
            .uri(uri)
    }

    pub fn patch(&self, uri: &str) -> Scenario {
        Scenario::new(self.router.clone())
            .method(Method::PATCH)
            .uri(uri)
    }
}

impl AuthTestApp {
    pub fn get(&self, uri: &str) -> Scenario {
        Scenario::new(self.router.clone())
            .method(Method::GET)
            .uri(uri)
            .with_auth(&self.token)
    }

    pub fn post(&self, uri: &str) -> Scenario {
        Scenario::new(self.router.clone())
            .method(Method::POST)
            .uri(uri)
            .with_auth(&self.token)
    }

    pub fn post_json<T: serde::Serialize>(&self, uri: &str, body: &T) -> Scenario {
        self.post(uri).json(body)
    }

    pub fn put(&self, uri: &str) -> Scenario {
        Scenario::new(self.router.clone())
            .method(Method::PUT)
            .uri(uri)
            .with_auth(&self.token)
    }

    pub fn delete(&self, uri: &str) -> Scenario {
        Scenario::new(self.router.clone())
            .method(Method::DELETE)
            .uri(uri)
            .with_auth(&self.token)
    }

    pub fn patch(&self, uri: &str) -> Scenario {
        Scenario::new(self.router.clone())
            .method(Method::PATCH)
            .uri(uri)
            .with_auth(&self.token)
    }
}
