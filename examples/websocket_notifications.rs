//! WebSocket Notifications Example
//!
//! This example demonstrates real-time notifications using WebSockets with:
//! - User-specific channels
//! - Integration with background jobs
//! - Server-to-client push notifications

#[cfg(feature = "websocket")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use tideway::{
        App, AppContext, ConfigBuilder, Result,
        websocket::{ws, ConnectionManager, WebSocketHandler, Connection, Message},
    };
    use axum::Router;
    use async_trait::async_trait;
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::sleep;

    // Initialize logging
    tideway::init_tracing();

    // Create WebSocket manager
    let manager = Arc::new(ConnectionManager::new());

    // Define notification handler
    struct NotificationHandler;

    #[derive(Serialize, Deserialize)]
    struct Notification {
        id: String,
        user_id: String,
        title: String,
        message: String,
        timestamp: u64,
    }

    #[async_trait]
    impl WebSocketHandler for NotificationHandler {
        async fn on_connect(&self, conn: &mut Connection, ctx: &tideway::AppContext) -> Result<()> {
            tracing::info!(conn_id = %conn.id(), "Client connected");

            // In a real app, you'd extract user_id from JWT token
            // For this example, we'll use a query parameter or set it manually
            // For demo purposes, we'll use the connection ID as user_id
            let user_id = conn.id().to_string();
            conn.set_user_id(user_id.clone());

            // The connection is already registered by the extractor
            // We just need to update the user mapping if needed

            // Send welcome notification
            conn.send_json(&Notification {
                id: uuid::Uuid::new_v4().to_string(),
                user_id: user_id.clone(),
                title: "Connected".to_string(),
                message: "You are now connected to the notification service".to_string(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            }).await?;

            Ok(())
        }

        async fn on_message(&self, conn: &mut Connection, msg: Message, _ctx: &tideway::AppContext) -> Result<()> {
            match msg {
                Message::Text(text) => {
                    // Handle ping/pong for keepalive
                    if text == "ping" {
                        conn.send_text("pong").await?;
                    }
                }
                Message::Ping(data) => {
                    conn.send(Message::Pong(data)).await?;
                }
                _ => {}
            }
            Ok(())
        }

        async fn on_disconnect(&self, conn: &mut Connection, _ctx: &tideway::AppContext) {
            tracing::info!(conn_id = %conn.id(), user_id = ?conn.user_id(), "Client disconnected");
        }
    }

    // Create app context with WebSocket manager
    let ctx = AppContext::builder()
        .with_websocket_manager(manager.clone())
        .build();

    // Create config
    let config = ConfigBuilder::new()
        .with_log_level("info")
        .build()?;

    // Create WebSocket router (returns Router<AppContext>)
    let ws_router = ws("/notifications", NotificationHandler, manager.clone());

    // Create app with WebSocket route
    let app = App::with_config(config)
        .with_context(ctx.clone())
        .register_module(WsModule(ws_router));

    // Helper module to wrap WebSocket router
    struct WsModule(Router<tideway::AppContext>);
    impl tideway::RouteModule for WsModule {
        fn routes(&self) -> Router<tideway::AppContext> { self.0.clone() }
        fn prefix(&self) -> Option<&str> { None }
    }

    // Spawn background task to send periodic notifications
    let manager_clone = manager.clone();
    tokio::spawn(async move {
        let mut counter = 0;
        loop {
            sleep(Duration::from_secs(5)).await;
            counter += 1;

            // Send notification to all connected users
            // In a real app, you'd query the database for pending notifications
            // and send them to specific users
            let notification = Notification {
                id: uuid::Uuid::new_v4().to_string(),
                user_id: "all".to_string(),
                title: "System Update".to_string(),
                message: format!("This is notification #{}", counter),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };

            // Broadcast to all connections
            if let Err(e) = manager_clone.broadcast_json(&notification).await {
                tracing::error!(error = %e, "Failed to broadcast notification");
            } else {
                tracing::info!(notification_id = %notification.id, "Sent notification to all users");
            }
        }
    });

    println!("WebSocket notifications example started!");
    println!("Connect to ws://localhost:8000/notifications to receive notifications");
    println!("Notifications will be sent every 5 seconds");

    // Start server
    app.serve().await?;

    Ok(())
}

#[cfg(not(feature = "websocket"))]
fn main() {
    println!("This example requires the 'websocket' feature to be enabled.");
    println!("Run with: cargo run --example websocket_notifications --features websocket");
}
