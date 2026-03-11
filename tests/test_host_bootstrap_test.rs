use axum::{Router, routing::post};
use tideway::testing::TestHost;
use tideway::{AppContext, ConfigBuilder, Result, RouteModule};

async fn accept_body(_body: String) -> &'static str {
    "ok"
}

struct EchoModule;

impl RouteModule for EchoModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/echo", post(accept_body))
    }
}

#[tokio::test]
async fn test_host_bootstrap_applies_config_overrides_before_app_build() {
    let host = TestHost::bootstrap()
        .configure_config(|mut config| {
            config.server.max_body_size = 4;
            config
        })
        .configure_app(|app| app.register_module(EchoModule))
        .build();

    host.scenario(|scenario| {
        scenario.post("/echo");
        scenario.text_body("12345");
        scenario.status_code_should_be(axum::http::StatusCode::PAYLOAD_TOO_LARGE.as_u16());
    })
    .await;
}

#[tokio::test]
async fn test_host_bootstrap_supports_config_builder_before_app_build() -> Result<()> {
    let host = TestHost::from_config_builder(ConfigBuilder::new().with_max_body_size(4))
        .configure_app(|app| app.register_module(EchoModule))
        .try_build()?;

    host.scenario(|scenario| {
        scenario.post("/echo");
        scenario.text_body("12345");
        scenario.status_code_should_be(axum::http::StatusCode::PAYLOAD_TOO_LARGE.as_u16());
    })
    .await;

    Ok(())
}

#[tokio::test]
async fn test_host_bootstrap_supports_env_backed_config_without_leaking_env() -> Result<()> {
    unsafe {
        std::env::set_var("TIDEWAY_MAX_BODY_SIZE", "128");
    }

    let host = TestHost::bootstrap()
        .from_env()
        .with_env_var("TIDEWAY_MAX_BODY_SIZE", "4")
        .configure_app(|app| app.register_module(EchoModule))
        .try_build()?;

    host.scenario(|scenario| {
        scenario.post("/echo");
        scenario.text_body("12345");
        scenario.status_code_should_be(axum::http::StatusCode::PAYLOAD_TOO_LARGE.as_u16());
    })
    .await;

    assert_eq!(std::env::var("TIDEWAY_MAX_BODY_SIZE").as_deref(), Ok("128"));

    unsafe {
        std::env::remove_var("TIDEWAY_MAX_BODY_SIZE");
    }

    Ok(())
}
