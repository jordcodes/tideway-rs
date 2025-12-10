//! Room/channel abstraction for WebSocket connections
//!
//! This module provides a high-level Room abstraction for grouping connections
//! and broadcasting messages to specific channels.

use crate::error::Result;
use super::manager::ConnectionManager;
use super::message::Message;
use serde::Serialize;
use std::sync::Arc;

/// A room/channel for grouping WebSocket connections
///
/// Rooms allow you to organize connections into logical groups and broadcast
/// messages to all connections in a room.
///
/// # Example
///
/// ```rust,no_run
/// use tideway::websocket::{Room, ConnectionManager};
/// use std::sync::Arc;
///
/// let manager = Arc::new(ConnectionManager::new());
/// let room = Room::new("chat", manager.clone());
/// room.broadcast_text("Hello room!").await?;
/// ```
pub struct Room {
    /// Room name
    name: String,
    /// Connection manager
    manager: Arc<ConnectionManager>,
}

impl Room {
    /// Create a new room
    pub fn new(name: impl Into<String>, manager: Arc<ConnectionManager>) -> Self {
        Self {
            name: name.into(),
            manager,
        }
    }

    /// Get the room name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Broadcast a message to all connections in this room
    pub async fn broadcast(&self, msg: Message) -> Result<()> {
        self.manager.broadcast_to_room(&self.name, msg).await
    }

    /// Broadcast a text message to all connections in this room
    pub async fn broadcast_text(&self, text: impl Into<String>) -> Result<()> {
        self.manager.broadcast_text_to_room(&self.name, text).await
    }

    /// Broadcast a JSON message to all connections in this room
    pub async fn broadcast_json<T: Serialize>(&self, data: &T) -> Result<()> {
        self.manager.broadcast_json_to_room(&self.name, data).await
    }

    /// Get all connection IDs in this room
    pub fn members(&self) -> Vec<String> {
        self.manager.room_members(&self.name)
    }

    /// Get the number of connections in this room
    pub fn member_count(&self) -> usize {
        self.members().len()
    }
}

