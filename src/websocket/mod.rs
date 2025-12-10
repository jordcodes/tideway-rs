//! WebSocket support for Tideway
//!
//! This module provides WebSocket functionality for real-time communication
//! in Tideway applications. It includes connection management, room/channel
//! support, and broadcasting capabilities.
//!
//! # Example
//!
//! ```rust,no_run
//! use tideway::websocket::{ws, ConnectionManager, WebSocketHandler, Connection, Message};
//! use tideway::{App, AppContext, Result};
//! use async_trait::async_trait;
//! use std::sync::Arc;
//!
//! struct ChatHandler;
//!
//! #[async_trait]
//! impl WebSocketHandler for ChatHandler {
//!     async fn on_connect(&self, conn: &mut Connection, _ctx: &AppContext) -> Result<()> {
//!         conn.send_text("Welcome!").await?;
//!         Ok(())
//!     }
//!
//!     async fn on_message(&self, conn: &mut Connection, msg: Message, ctx: &AppContext) -> Result<()> {
//!         if let Message::Text(text) = msg {
//!             let manager = ctx.websocket_manager()?;
//!             manager.broadcast_text(format!("{}: {}", conn.id(), text)).await?;
//!         }
//!         Ok(())
//!     }
//!
//!     async fn on_disconnect(&self, _conn: &mut Connection, _ctx: &AppContext) {
//!         // Cleanup
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     let manager = Arc::new(ConnectionManager::new());
//!     let ctx = AppContext::builder()
//!         .with_websocket_manager(manager.clone())
//!         .build();
//!
//!     let app = App::new()
//!         .with_context(ctx)
//!         .merge_router(ws("/ws", ChatHandler, manager));
//!
//!     app.serve().await.unwrap();
//! }
//! ```

mod connection;
mod extractor;
mod manager;
mod message;
mod room;
mod traits;

#[cfg(test)]
mod tests;

pub use connection::Connection;
pub use extractor::ws;
pub use manager::{ConnectionManager, ConnectionHandle, ConnectionMetrics};
pub use message::{CloseFrame, Message};
pub use room::Room;
pub use traits::WebSocketHandler;
