//! WebSocket handler trait
//!
//! This module defines the trait that users implement to handle WebSocket connections.

use crate::app::AppContext;
use crate::error::Result;
use async_trait::async_trait;
use super::connection::Connection;
use super::message::Message;

/// Trait for handling WebSocket connections
///
/// Implement this trait to define how your application handles WebSocket connections.
/// The handler is called at various points in the connection lifecycle.
///
/// # Example
///
/// ```rust,no_run
/// use tideway::websocket::{WebSocketHandler, Connection, Message};
/// use tideway::{AppContext, Result};
/// use async_trait::async_trait;
///
/// struct ChatHandler;
///
/// #[async_trait]
/// impl WebSocketHandler for ChatHandler {
///     async fn on_connect(&self, conn: &mut Connection, ctx: &AppContext) -> Result<()> {
///         conn.send_text("Welcome!").await?;
///         Ok(())
///     }
///
///     async fn on_message(&self, conn: &mut Connection, msg: Message, ctx: &AppContext) -> Result<()> {
///         if let Message::Text(text) = msg {
///             // Handle message
///         }
///         Ok(())
///     }
///
///     async fn on_disconnect(&self, conn: &mut Connection, _ctx: &AppContext) {
///         // Cleanup
///     }
/// }
/// ```
#[async_trait]
pub trait WebSocketHandler: Send + Sync + 'static {
    /// Called when a new connection is established
    ///
    /// This is called after the WebSocket upgrade is complete and the connection
    /// is ready to send/receive messages. Use this to send welcome messages,
    /// initialize connection state, or authenticate the user.
    async fn on_connect(&self, conn: &mut Connection, ctx: &AppContext) -> Result<()>;

    /// Called when a message is received from the client
    ///
    /// This is called for every message received from the client. Handle the
    /// message type appropriately (Text, Binary, Ping, etc.).
    async fn on_message(&self, conn: &mut Connection, msg: Message, ctx: &AppContext) -> Result<()>;

    /// Called when the connection is closed
    ///
    /// This is called when the WebSocket connection is closed, either by the client
    /// or server. Use this for cleanup, logging, or notifying other connections.
    ///
    /// Note: This method cannot return an error - it's called during cleanup.
    async fn on_disconnect(&self, conn: &mut Connection, ctx: &AppContext);

    /// Optional: Validate connection before accepting
    ///
    /// This is called during the WebSocket upgrade, before `on_connect`.
    /// Return an error to reject the connection (e.g., authentication failure).
    /// By default, all connections are accepted.
    async fn on_upgrade(&self, _ctx: &AppContext) -> Result<()> {
        Ok(())
    }
}

