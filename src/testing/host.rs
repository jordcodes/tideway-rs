use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Method, Request, StatusCode, Uri, header},
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tower::ServiceExt;

use crate::App;
#[cfg(feature = "test-auth-bypass")]
use crate::auth::extractors::{TEST_CLAIMS_HEADER, TEST_USER_ID_HEADER, encode_test_claims_header};

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
type BeforeEachHook = Arc<dyn for<'a> Fn(&'a mut Request<Body>) -> BoxFuture<'a, ()> + Send + Sync>;
type AfterEachHook = Arc<dyn for<'a> Fn(&'a ScenarioOutcome) -> BoxFuture<'a, ()> + Send + Sync>;
type ScenarioAssertion = Box<dyn Fn(&ScenarioOutcome) -> Result<(), String> + Send + Sync>;

/// Builder for constructing a `TestHost` with test-time overrides.
///
/// This allows tests to swap dependencies or mutate the `App` before the host
/// is materialized, which is the closest Tideway analogue to Alba host setup.
pub struct TestHostBuilder {
    app: App,
    with_middleware: bool,
    before_each: Option<BeforeEachHook>,
    after_each: Option<AfterEachHook>,
}

/// Reusable Alba-style host for in-process Tideway integration tests.
///
/// Unlike the lower-level `Scenario` helper, `TestHost` reuses a single router,
/// supports before/after hooks, and applies a default `200 OK` expectation unless
/// you explicitly override it.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::testing::TestHost;
///
/// let host = TestHost::new(app).before_each(|request| {
///     request
///         .headers_mut()
///         .insert("x-trace", "spec".parse().unwrap());
/// });
///
/// let response = host
///     .scenario(|scenario| {
///         scenario.get("/health");
///         scenario.header_should_exist("x-request-id");
///     })
///     .await;
///
/// assert_eq!(response.status(), axum::http::StatusCode::OK);
/// ```
pub struct TestHost {
    router: Router,
    before_each: Option<BeforeEachHook>,
    after_each: Option<AfterEachHook>,
}

impl TestHost {
    /// Create a builder from an application for test-time overrides.
    pub fn builder(app: App) -> TestHostBuilder {
        TestHostBuilder::new(app)
    }

    /// Build a test host from a Tideway `App`, including middleware.
    pub fn new(app: App) -> Self {
        Self::from_router(app.into_router_with_middleware())
    }

    /// Build a test host from a Tideway `App` without middleware.
    pub fn without_middleware(app: App) -> Self {
        Self::from_router(app.into_router())
    }

    /// Build a test host from an Axum router.
    pub fn from_router(router: Router) -> Self {
        Self {
            router,
            before_each: None,
            after_each: None,
        }
    }

    /// Register a synchronous action that runs before every scenario.
    ///
    /// Like Alba, hooks are not additive: the last registered hook wins.
    pub fn before_each<F>(mut self, hook: F) -> Self
    where
        F: Fn(&mut Request<Body>) + Send + Sync + 'static,
    {
        self.before_each = Some(Arc::new(move |request| {
            hook(request);
            Box::pin(async {})
        }));
        self
    }

    /// Register an asynchronous action that runs before every scenario.
    ///
    /// Like Alba, hooks are not additive: the last registered hook wins.
    pub fn before_each_async<F>(mut self, hook: F) -> Self
    where
        F: for<'a> Fn(&'a mut Request<Body>) -> BoxFuture<'a, ()> + Send + Sync + 'static,
    {
        self.before_each = Some(Arc::new(hook));
        self
    }

    /// Register a synchronous action that runs after every scenario request completes.
    ///
    /// Like Alba, hooks are not additive: the last registered hook wins.
    pub fn after_each<F>(mut self, hook: F) -> Self
    where
        F: Fn(&ScenarioOutcome) + Send + Sync + 'static,
    {
        self.after_each = Some(Arc::new(move |outcome| {
            hook(outcome);
            Box::pin(async {})
        }));
        self
    }

    /// Register an asynchronous action that runs after every scenario request completes.
    ///
    /// Like Alba, hooks are not additive: the last registered hook wins.
    pub fn after_each_async<F>(mut self, hook: F) -> Self
    where
        F: for<'a> Fn(&'a ScenarioOutcome) -> BoxFuture<'a, ()> + Send + Sync + 'static,
    {
        self.after_each = Some(Arc::new(hook));
        self
    }

    /// Execute a scenario and panic if any declarative assertion fails.
    pub async fn scenario<F>(&self, configure: F) -> ScenarioOutcome
    where
        F: FnOnce(&mut HostScenario),
    {
        self.try_scenario(configure)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
    }

    /// Execute a scenario and return a structured failure instead of panicking.
    pub async fn try_scenario<F>(&self, configure: F) -> Result<ScenarioOutcome, ScenarioFailure>
    where
        F: FnOnce(&mut HostScenario),
    {
        let mut scenario = HostScenario::new();
        configure(&mut scenario);

        let HostScenario {
            request,
            expected_status,
            ignore_status_code,
            assertions,
        } = scenario;

        let mut request = request;
        if let Some(hook) = &self.before_each {
            hook(&mut request).await;
        }

        let request_summary = RequestSummary::from_request(&request);

        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("test host request should succeed");

        let outcome = ScenarioOutcome::from_response(request_summary.clone(), response).await;

        if let Some(hook) = &self.after_each {
            hook(&outcome).await;
        }

        let mut failures = Vec::new();
        if !ignore_status_code {
            let expected_status = expected_status.unwrap_or(StatusCode::OK);
            if outcome.status() != expected_status {
                failures.push(format!(
                    "Expected status {}, got {}",
                    expected_status,
                    outcome.status()
                ));
            }
        }

        for assertion in assertions {
            if let Err(message) = assertion(&outcome) {
                failures.push(message);
            }
        }

        if failures.is_empty() {
            Ok(outcome)
        } else {
            Err(ScenarioFailure {
                request: request_summary,
                failures,
            })
        }
    }
}

impl TestHostBuilder {
    pub fn new(app: App) -> Self {
        Self {
            app,
            with_middleware: true,
            before_each: None,
            after_each: None,
        }
    }

    /// Transform the underlying app before the host is built.
    pub fn configure_app<F>(mut self, configure: F) -> Self
    where
        F: FnOnce(App) -> App,
    {
        self.app = configure(self.app);
        self
    }

    /// Transform the app context before the host is built.
    pub fn configure_context<F>(mut self, configure: F) -> Self
    where
        F: FnOnce(crate::app::AppContextBuilder) -> crate::app::AppContextBuilder,
    {
        self.app = self.app.map_context(configure);
        self
    }

    /// Build the host without Tideway's middleware stack.
    pub fn without_middleware(mut self) -> Self {
        self.with_middleware = false;
        self
    }

    /// Build the host with Tideway's middleware stack applied.
    pub fn with_middleware(mut self) -> Self {
        self.with_middleware = true;
        self
    }

    /// Register a synchronous action that runs before every scenario.
    pub fn before_each<F>(mut self, hook: F) -> Self
    where
        F: Fn(&mut Request<Body>) + Send + Sync + 'static,
    {
        self.before_each = Some(Arc::new(move |request| {
            hook(request);
            Box::pin(async {})
        }));
        self
    }

    /// Register an asynchronous action that runs before every scenario.
    pub fn before_each_async<F>(mut self, hook: F) -> Self
    where
        F: for<'a> Fn(&'a mut Request<Body>) -> BoxFuture<'a, ()> + Send + Sync + 'static,
    {
        self.before_each = Some(Arc::new(hook));
        self
    }

    /// Register a synchronous action that runs after every scenario.
    pub fn after_each<F>(mut self, hook: F) -> Self
    where
        F: Fn(&ScenarioOutcome) + Send + Sync + 'static,
    {
        self.after_each = Some(Arc::new(move |outcome| {
            hook(outcome);
            Box::pin(async {})
        }));
        self
    }

    /// Register an asynchronous action that runs after every scenario.
    pub fn after_each_async<F>(mut self, hook: F) -> Self
    where
        F: for<'a> Fn(&'a ScenarioOutcome) -> BoxFuture<'a, ()> + Send + Sync + 'static,
    {
        self.after_each = Some(Arc::new(hook));
        self
    }

    pub fn build(self) -> TestHost {
        let mut host = if self.with_middleware {
            TestHost::new(self.app)
        } else {
            TestHost::without_middleware(self.app)
        };
        host.before_each = self.before_each;
        host.after_each = self.after_each;
        host
    }
}

/// Declarative scenario builder used by `TestHost::scenario`.
pub struct HostScenario {
    request: Request<Body>,
    expected_status: Option<StatusCode>,
    ignore_status_code: bool,
    assertions: Vec<ScenarioAssertion>,
}

impl HostScenario {
    fn new() -> Self {
        Self {
            request: Request::builder()
                .method(Method::GET)
                .uri("/")
                .body(Body::empty())
                .unwrap(),
            expected_status: None,
            ignore_status_code: false,
            assertions: Vec::new(),
        }
    }

    /// Set the HTTP method.
    pub fn method(&mut self, method: Method) -> &mut Self {
        *self.request.method_mut() = method;
        self
    }

    /// Set the request URI.
    pub fn uri(&mut self, uri: &str) -> &mut Self {
        *self.request.uri_mut() = uri.parse().unwrap();
        self
    }

    /// Configure a GET request.
    pub fn get(&mut self, uri: &str) -> &mut Self {
        self.method(Method::GET).uri(uri)
    }

    /// Configure a POST request.
    pub fn post(&mut self, uri: &str) -> &mut Self {
        self.method(Method::POST).uri(uri)
    }

    /// Configure a PUT request.
    pub fn put(&mut self, uri: &str) -> &mut Self {
        self.method(Method::PUT).uri(uri)
    }

    /// Configure a DELETE request.
    pub fn delete(&mut self, uri: &str) -> &mut Self {
        self.method(Method::DELETE).uri(uri)
    }

    /// Configure a PATCH request.
    pub fn patch(&mut self, uri: &str) -> &mut Self {
        self.method(Method::PATCH).uri(uri)
    }

    /// Add a request header.
    pub fn header(&mut self, key: &str, value: &str) -> &mut Self {
        use axum::http::HeaderName;

        self.request.headers_mut().insert(
            HeaderName::from_bytes(key.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        self
    }

    /// Alba-style alias for `header`.
    pub fn with_request_header(&mut self, key: &str, value: &str) -> &mut Self {
        self.header(key, value)
    }

    /// Convenience alias for `header`.
    pub fn with_header(&mut self, key: &str, value: &str) -> &mut Self {
        self.header(key, value)
    }

    /// Set the Authorization header with a Bearer token.
    pub fn bearer_token(&mut self, token: &str) -> &mut Self {
        self.header("Authorization", &format!("Bearer {}", token))
    }

    /// Convenience alias for `bearer_token`.
    pub fn with_auth(&mut self, token: &str) -> &mut Self {
        self.bearer_token(token)
    }

    /// Set the test bypass user identity when the `test-auth-bypass` feature is enabled.
    #[cfg(feature = "test-auth-bypass")]
    pub fn with_test_user(&mut self, user_id: &str) -> &mut Self {
        self.header(TEST_USER_ID_HEADER, user_id)
    }

    /// Set synthetic claims for test bypass when the `test-auth-bypass` feature is enabled.
    #[cfg(feature = "test-auth-bypass")]
    pub fn with_test_claims<T: Serialize>(&mut self, claims: &T) -> &mut Self {
        let encoded = encode_test_claims_header(claims);
        self.header(TEST_CLAIMS_HEADER, &encoded)
    }

    /// Add query parameters to the request URI.
    pub fn with_query(&mut self, params: &[(&str, &str)]) -> &mut Self {
        let uri = self.request.uri().clone();
        let mut query_parts = vec![];

        if let Some(query) = uri.query() {
            query_parts.push(query.to_string());
        }

        for (key, value) in params {
            query_parts.push(format!(
                "{}={}",
                urlencoding::encode(key),
                urlencoding::encode(value)
            ));
        }

        let path = uri.path();
        let new_uri = if query_parts.is_empty() {
            path.to_string()
        } else {
            format!("{}?{}", path, query_parts.join("&"))
        };

        *self.request.uri_mut() = new_uri.parse().unwrap();
        self
    }

    /// Set a JSON request body.
    pub fn json<T: Serialize>(&mut self, body: &T) -> &mut Self {
        let json = serde_json::to_string(body).unwrap();
        *self.request.body_mut() = Body::from(json);
        self.request
            .headers_mut()
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        self.request
            .headers_mut()
            .insert(header::ACCEPT, "application/json".parse().unwrap());
        self
    }

    /// Convenience alias for `json`.
    pub fn with_json<T: Serialize>(&mut self, body: &T) -> &mut Self {
        self.json(body)
    }

    /// Set URL-encoded form data from a serializable type.
    pub fn form<T: Serialize>(&mut self, body: &T) -> &mut Self {
        let encoded = serde_urlencoded::to_string(body).unwrap();
        *self.request.body_mut() = Body::from(encoded);
        self.request.headers_mut().insert(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        self
    }

    /// Convenience alias for `form`.
    pub fn with_form<T: Serialize>(&mut self, body: &T) -> &mut Self {
        self.form(body)
    }

    /// Set a plain-text request body.
    pub fn text_body(&mut self, body: impl Into<String>) -> &mut Self {
        *self.request.body_mut() = Body::from(body.into());
        self
    }

    /// Expect a specific status code.
    pub fn status_code_should_be(&mut self, status: u16) -> &mut Self {
        self.expected_status = Some(
            StatusCode::from_u16(status)
                .unwrap_or_else(|_| panic!("Invalid HTTP status code: {status}")),
        );
        self.ignore_status_code = false;
        self
    }

    /// Expect `200 OK`.
    pub fn status_code_should_be_ok(&mut self) -> &mut Self {
        self.status_code_should_be(StatusCode::OK.as_u16())
    }

    /// Disable the default status code expectation.
    pub fn ignore_status_code(&mut self) -> &mut Self {
        self.ignore_status_code = true;
        self
    }

    /// Assert that the response contains a header with the expected value.
    pub fn header_should_be(&mut self, key: &str, expected: &str) -> &mut Self {
        let key = key.to_string();
        let expected = expected.to_string();
        self.assert_with(move |outcome| {
            let Some(actual) = outcome.header(&key) else {
                return Err(format!("Expected header '{key}' to exist"));
            };

            if actual == expected {
                Ok(())
            } else {
                Err(format!(
                    "Expected header '{key}' to be '{expected}', got '{actual}'"
                ))
            }
        })
    }

    /// Assert that the response contains a header.
    pub fn header_should_exist(&mut self, key: &str) -> &mut Self {
        let key = key.to_string();
        self.assert_with(move |outcome| {
            if outcome.header(&key).is_some() {
                Ok(())
            } else {
                Err(format!("Expected header '{key}' to exist"))
            }
        })
    }

    /// Assert that the response is a redirect and has a matching `Location` header.
    pub fn redirect_to_should_be(&mut self, expected: &str) -> &mut Self {
        let expected = expected.to_string();
        self.assert_with(move |outcome| {
            if !outcome.status().is_redirection() {
                return Err(format!(
                    "Expected redirect status, got {}",
                    outcome.status()
                ));
            }

            let Some(location) = outcome.header(header::LOCATION.as_str()) else {
                return Err("Expected Location header to exist".to_string());
            };

            if location == expected {
                Ok(())
            } else {
                Err(format!(
                    "Expected redirect location '{expected}', got '{location}'"
                ))
            }
        })
    }

    /// Assert that the response body contains the given text.
    pub fn content_should_contain(&mut self, text: &str) -> &mut Self {
        let text = text.to_string();
        self.assert_with(move |outcome| {
            let body = outcome.body_string();
            if body.contains(&text) {
                Ok(())
            } else {
                Err(format!("Expected body to contain '{text}', got '{body}'"))
            }
        })
    }

    /// Assert that a JSON path matches the expected value.
    pub fn json_path_should_be(&mut self, path: &str, expected: serde_json::Value) -> &mut Self {
        let path = path.to_string();
        self.assert_with(move |outcome| {
            let json = parse_json_body(outcome)?;
            let Some(actual) = json_path_get(&json, &path) else {
                return Err(format!("Path '{path}' not found in JSON response"));
            };

            if actual == &expected {
                Ok(())
            } else {
                Err(format!(
                    "Expected JSON path '{path}' to equal {expected}, got {actual}"
                ))
            }
        })
    }

    /// Assert that the JSON response contains the expected subset.
    pub fn json_should_contain(&mut self, expected: serde_json::Value) -> &mut Self {
        self.assert_with(move |outcome| {
            let json = parse_json_body(outcome)?;
            if json_contains(&json, &expected) {
                Ok(())
            } else {
                Err(format!("Expected JSON to contain {expected}, got {json}"))
            }
        })
    }

    /// Add a custom assertion over the fully materialized response.
    pub fn assert_with<F>(&mut self, assertion: F) -> &mut Self
    where
        F: Fn(&ScenarioOutcome) -> Result<(), String> + Send + Sync + 'static,
    {
        self.assertions.push(Box::new(assertion));
        self
    }
}

/// Summary of the executed request for hooks and diagnostics.
#[derive(Clone, Debug)]
pub struct RequestSummary {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
}

impl RequestSummary {
    fn from_request(request: &Request<Body>) -> Self {
        Self {
            method: request.method().clone(),
            uri: request.uri().clone(),
            headers: request.headers().clone(),
        }
    }

    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn header(&self, key: &str) -> Option<&str> {
        self.headers.get(key).and_then(|value| value.to_str().ok())
    }
}

/// Materialized response snapshot returned by `TestHost`.
#[derive(Clone, Debug)]
pub struct ScenarioOutcome {
    request: RequestSummary,
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl ScenarioOutcome {
    async fn from_response(request: RequestSummary, response: axum::response::Response) -> Self {
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("test host response body should be readable")
            .to_vec();

        Self {
            request,
            status,
            headers,
            body,
        }
    }

    pub fn request(&self) -> &RequestSummary {
        &self.request
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn header(&self, key: &str) -> Option<&str> {
        self.headers.get(key).and_then(|value| value.to_str().ok())
    }

    pub fn body_bytes(&self) -> &[u8] {
        &self.body
    }

    pub fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json<T: DeserializeOwned>(&self) -> T {
        serde_json::from_slice(&self.body).expect("failed to parse JSON response")
    }

    pub fn json_value(&self) -> serde_json::Value {
        self.json()
    }
}

/// Structured failure returned by `TestHost::try_scenario`.
#[derive(Clone, Debug)]
pub struct ScenarioFailure {
    request: RequestSummary,
    failures: Vec<String>,
}

impl ScenarioFailure {
    pub fn request(&self) -> &RequestSummary {
        &self.request
    }

    pub fn failures(&self) -> &[String] {
        &self.failures
    }
}

impl fmt::Display for ScenarioFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Scenario failed for {} {}:",
            self.request.method(),
            self.request.uri()
        )?;

        for failure in &self.failures {
            writeln!(f, "- {failure}")?;
        }

        Ok(())
    }
}

impl std::error::Error for ScenarioFailure {}

fn parse_json_body(outcome: &ScenarioOutcome) -> Result<serde_json::Value, String> {
    serde_json::from_slice(outcome.body_bytes())
        .map_err(|error| format!("Expected JSON response body, got parse error: {error}"))
}

fn json_path_get<'a>(json: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = json;

    for part in parts {
        if let Ok(index) = part.parse::<usize>() {
            current = current.get(index)?;
        } else {
            current = current.get(part)?;
        }
    }

    Some(current)
}

fn json_contains(actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
    match (actual, expected) {
        (serde_json::Value::Object(actual_map), serde_json::Value::Object(expected_map)) => {
            expected_map.iter().all(|(key, expected_value)| {
                actual_map
                    .get(key)
                    .map(|actual_value| json_contains(actual_value, expected_value))
                    .unwrap_or(false)
            })
        }
        (serde_json::Value::Array(actual_array), serde_json::Value::Array(expected_array)) => {
            expected_array.iter().all(|expected_value| {
                actual_array
                    .iter()
                    .any(|actual_value| json_contains(actual_value, expected_value))
            })
        }
        _ => actual == expected,
    }
}
