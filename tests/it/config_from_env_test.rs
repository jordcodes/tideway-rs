use tideway::{
    ConfigBuilder, CorsConfig, DevConfig, RateLimitConfig, RequestLoggingConfig, SecurityConfig,
    TimeoutConfig,
};

/// Re-runs `test` in a child process with the given environment so env var
/// changes cannot race with other tests. Returns `true` in the parent.
fn isolated(test: &str, overrides: &[(&str, &str)]) -> bool {
    crate::support::isolated(module_path!(), test, |command| {
        // Drop any inherited Tideway configuration so the child sees only `overrides`.
        for (key, _) in std::env::vars() {
            if key.starts_with("TIDEWAY_")
                || [
                    "CORS_",
                    "RATE_LIMIT_",
                    "SECURITY_",
                    "TIMEOUT_",
                    "REQUEST_LOGGING_",
                    "DEV_",
                ]
                .iter()
                .any(|prefix| key.starts_with(prefix))
            {
                command.env_remove(key);
            }
        }
        command.envs(overrides.iter().copied());
    })
}

fn builder() -> ConfigBuilder {
    ConfigBuilder::new()
        .with_cors(
            CorsConfig::builder()
                .enabled(true)
                .allow_origin("https://app.example.com")
                .max_age(42)
                .build(),
        )
        .with_rate_limit(RateLimitConfig {
            enabled: true,
            max_requests: 7,
            window_seconds: 11,
            ..Default::default()
        })
        .with_security(SecurityConfig::builder().hsts_max_age(86400).build())
        .with_timeout(TimeoutConfig {
            enabled: true,
            timeout_seconds: 99,
        })
        .with_request_logging(RequestLoggingConfig {
            include_headers: true,
            ..Default::default()
        })
        .with_dev_config(DevConfig {
            enabled: true,
            include_stack_traces: true,
            ..Default::default()
        })
}

#[test]
fn builder_settings_survive_from_env() {
    if isolated(
        "builder_settings_survive_from_env",
        &[("TIDEWAY_ENV", "development")],
    ) {
        return;
    }
    let config = builder().from_env().build().unwrap();

    assert!(config.cors.enabled);
    assert_eq!(config.cors.allowed_origins, ["https://app.example.com"]);
    assert_eq!(config.cors.max_age_seconds, 42);
    assert!(config.rate_limit.enabled);
    assert_eq!(config.rate_limit.max_requests, 7);
    assert_eq!(config.rate_limit.window_seconds, 11);
    assert_eq!(config.security.hsts_max_age, 86400);
    assert!(config.timeout.enabled);
    assert_eq!(config.timeout.timeout_seconds, 99);
    assert!(config.request_logging.include_headers);
    assert!(config.dev.enabled);
    assert!(config.dev.include_stack_traces);
}

#[test]
fn present_env_vars_override_builder_settings() {
    if isolated(
        "present_env_vars_override_builder_settings",
        &[
            ("TIDEWAY_RATE_LIMIT_MAX_REQUESTS", "3"),
            ("TIDEWAY_TIMEOUT_SECONDS", "5"),
            ("TIDEWAY_DEV_STACK_TRACES", "false"),
        ],
    ) {
        return;
    }
    let config = builder().from_env().build().unwrap();

    assert_eq!(config.rate_limit.max_requests, 3);
    assert_eq!(config.rate_limit.window_seconds, 11);
    assert_eq!(config.timeout.timeout_seconds, 5);
    assert!(config.timeout.enabled);
    assert!(!config.dev.include_stack_traces);
    assert!(config.dev.enabled);
}
