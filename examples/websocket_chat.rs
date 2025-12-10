//! WebSocket Chat Example
//!
//! This example demonstrates a simple chat room using WebSockets with:
//! - Room management
//! - Broadcasting messages
//! - User join/leave notifications

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

    // Initialize logging
    tideway::init_tracing();

    // Create WebSocket manager
    let manager = Arc::new(ConnectionManager::new());

    // Define chat handler
    struct ChatHandler;

    #[async_trait]
    impl WebSocketHandler for ChatHandler {
        async fn on_connect(&self, conn: &mut Connection, ctx: &tideway::AppContext) -> Result<()> {
            tracing::info!(conn_id = %conn.id(), "Client connected");

            // Send welcome message
            conn.send_text("Welcome to the chat room! Type /join <room> to join a room, or just start chatting.").await?;

            // Join default room
            conn.join_room("general");
            let manager = ctx.websocket_manager()?;
            manager.add_to_room(conn.id(), "general");

            // Notify others in the room
            manager.broadcast_text_to_room(
                "general",
                format!("User {} joined the room", conn.id())
            ).await?;

            Ok(())
        }

        async fn on_message(&self, conn: &mut Connection, msg: Message, ctx: &tideway::AppContext) -> Result<()> {
            match msg {
                Message::Text(text) => {
                    let manager = ctx.websocket_manager()?;

                    // Handle commands
                    if text.starts_with("/join ") {
                        let room_name = text.strip_prefix("/join ").unwrap().trim();
                        if !room_name.is_empty() {
                            // Leave current rooms
                            let rooms_to_leave: Vec<String> = conn.rooms().iter().cloned().collect();
                            for room in &rooms_to_leave {
                                manager.remove_from_room(conn.id(), room);
                                conn.leave_room(room);
                            }

                            // Join new room
                            conn.join_room(room_name);
                            manager.add_to_room(conn.id(), room_name);
                            conn.send_text(format!("Joined room: {}", room_name)).await?;

                            // Notify room
                            manager.broadcast_text_to_room(
                                room_name,
                                format!("User {} joined the room", conn.id())
                            ).await?;
                        }
                    } else if text.starts_with("/rooms") {
                        // List rooms
                        let rooms: Vec<String> = conn.rooms().iter().cloned().collect();
                        conn.send_json(&serde_json::json!({
                            "type": "rooms",
                            "rooms": rooms
                        })).await?;
                    } else {
                        // Broadcast message to all rooms this connection is in
                        let message = format!("{}: {}", conn.id(), text);
                        for room in conn.rooms().iter() {
                            manager.broadcast_text_to_room(room, &message).await?;
                        }

                        // If not in any room, send to general
                        if conn.rooms().is_empty() {
                            conn.join_room("general");
                            manager.add_to_room(conn.id(), "general");
                            manager.broadcast_text_to_room("general", &message).await?;
                        }
                    }
                }
                Message::Ping(data) => {
                    // Respond to ping with pong
                    conn.send(Message::Pong(data)).await?;
                }
                _ => {}
            }
            Ok(())
        }

        async fn on_disconnect(&self, conn: &mut Connection, ctx: &tideway::AppContext) {
            tracing::info!(conn_id = %conn.id(), "Client disconnected");

            // Notify rooms
            if let Ok(manager) = ctx.websocket_manager() {
                for room in conn.rooms().iter() {
                    let _ = manager.broadcast_text_to_room(
                        room,
                        format!("User {} left the room", conn.id())
                    ).await;
                }
            }
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
    let ws_router = ws("/ws", ChatHandler, manager);

    // Helper module to wrap WebSocket router
    struct WsModule(Router<tideway::AppContext>);
    impl tideway::RouteModule for WsModule {
        fn routes(&self) -> Router<tideway::AppContext> { self.0.clone() }
        fn prefix(&self) -> Option<&str> { None }
    }

    // Create app with WebSocket route
    let app = App::with_config(config)
        .with_context(ctx)
        .register_module(WsModule(ws_router));

    println!("WebSocket chat example started!");
    println!("Connect to ws://localhost:8000/ws to join the chat");
    println!("Commands:");
    println!("  /join <room> - Join a room");
    println!("  /rooms - List your rooms");
    println!("  <message> - Send a message to your current rooms");

    // Start server
    app.serve().await?;

    Ok(())
}

#[cfg(not(feature = "websocket"))]
fn main() {
    println!("This example requires the 'websocket' feature to be enabled.");
    println!("Run with: cargo run --example websocket_chat --features websocket");
}
