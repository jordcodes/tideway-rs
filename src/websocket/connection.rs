//! WebSocket connection wrapper
//!
//! This module provides a Connection struct that wraps the WebSocket connection
//! with additional state, metadata, and room tracking.

use crate::error::{Result, TidewayError};
use super::message::Message;
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc;
use serde::Serialize;

/// WebSocket connection wrapper with state and metadata
///
/// This struct provides a high-level interface for managing WebSocket connections,
/// including sending messages, tracking rooms, and storing metadata.
pub struct Connection {
    /// Unique connection identifier
    id: String,
    /// Optional user identifier (from authentication)
    user_id: Option<String>,
    /// Custom connection metadata
    metadata: HashMap<String, String>,
    /// Rooms this connection is in
    rooms: HashSet<String>,
    /// Channel sender for sending messages to the WebSocket
    sender: mpsc::Sender<Message>,
}

impl Connection {
    /// Create a new connection
    pub(crate) fn new(id: String, sender: mpsc::Sender<Message>) -> Self {
        Self {
            id,
            user_id: None,
            metadata: HashMap::new(),
            rooms: HashSet::new(),
            sender,
        }
    }

    /// Get the connection ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the user ID if set
    pub fn user_id(&self) -> Option<&str> {
        self.user_id.as_deref()
    }

    /// Set the user ID for this connection
    pub fn set_user_id(&mut self, user_id: String) {
        self.user_id = Some(user_id);
    }

    /// Get connection metadata
    pub fn metadata(&self) -> &HashMap<String, String> {
        &self.metadata
    }

    /// Set a metadata value
    pub fn set_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    /// Get the rooms this connection is in
    pub fn rooms(&self) -> &HashSet<String> {
        &self.rooms
    }

    /// Send a message to this connection
    ///
    /// Returns an error if the channel is full (backpressure) or the connection is closed.
    pub async fn send(&self, msg: Message) -> Result<()> {
        self.sender.send(msg).await.map_err(|_| {
            TidewayError::internal("Failed to send message: channel full or connection closed")
        })
    }

    /// Send a text message
    pub async fn send_text(&self, text: impl Into<String>) -> Result<()> {
        self.send(Message::Text(text.into())).await
    }

    /// Send a JSON message
    pub async fn send_json<T: Serialize>(&self, data: &T) -> Result<()> {
        let json = serde_json::to_string(data)
            .map_err(|e| TidewayError::internal(format!("Failed to serialize JSON: {}", e)))?;
        self.send_text(json).await
    }

    /// Send a binary message
    pub async fn send_binary(&self, data: Vec<u8>) -> Result<()> {
        self.send(Message::Binary(data)).await
    }

    /// Close the connection
    pub async fn close(&self) -> Result<()> {
        self.send(Message::Close(None)).await
    }

    /// Join a room/channel
    ///
    /// Note: This only updates the local connection state. The ConnectionManager
    /// must also be updated to enable room-based broadcasting.
    pub fn join_room(&mut self, room: impl Into<String>) {
        self.rooms.insert(room.into());
    }

    /// Leave a room/channel
    ///
    /// Note: This only updates the local connection state. The ConnectionManager
    /// must also be updated.
    pub fn leave_room(&mut self, room: &str) {
        self.rooms.remove(room);
    }

    /// Check if connection is in a room
    pub fn is_in_room(&self, room: &str) -> bool {
        self.rooms.contains(room)
    }
}
