//! WebSocket connection wrapper
//!
//! This module provides a Connection struct that wraps the WebSocket connection
//! with additional state, metadata, and room tracking.

use super::message::Message;
use super::upgrade::{UpgradeRequest, cookie_from_headers};
use crate::error::{Result, TidewayError};
use axum::http::{HeaderMap, Uri};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc;

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
    /// Headers from the upgrade request
    headers: HeaderMap,
    /// URI from the upgrade request
    uri: Uri,
}

impl Connection {
    /// Create a connection backed by a bounded outbound message channel.
    ///
    /// This is useful for custom WebSocket transports, integration tests, and
    /// performance harnesses that need to consume outbound messages directly.
    pub fn channel(id: impl Into<String>, capacity: usize) -> (Self, mpsc::Receiver<Message>) {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        (Self::new(id.into(), sender), receiver)
    }

    /// Create a new connection
    pub(crate) fn new(id: String, sender: mpsc::Sender<Message>) -> Self {
        Self {
            id,
            user_id: None,
            metadata: HashMap::new(),
            rooms: HashSet::new(),
            sender,
            headers: HeaderMap::new(),
            uri: Uri::default(),
        }
    }

    /// Create a connection from an accepted upgrade request, keeping its
    /// headers, URI, and any user ID or metadata set by `on_upgrade`.
    pub(crate) fn from_upgrade(
        id: String,
        sender: mpsc::Sender<Message>,
        request: UpgradeRequest,
    ) -> Self {
        let (headers, uri, user_id, metadata) = request.into_parts();
        Self {
            user_id,
            metadata,
            headers,
            uri,
            ..Self::new(id, sender)
        }
    }

    /// Get the connection ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the headers from the upgrade request
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Get a header from the upgrade request, if present and valid UTF-8
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    /// Get a cookie value from the upgrade request
    pub fn cookie(&self, name: &str) -> Option<&str> {
        cookie_from_headers(&self.headers, name)
    }

    /// Get the URI of the upgrade request
    pub fn uri(&self) -> &Uri {
        &self.uri
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

    /// Clone the outbound channel sender.
    ///
    /// This allows callers to send without holding a connection lock across await points.
    pub(crate) fn sender_clone(&self) -> mpsc::Sender<Message> {
        self.sender.clone()
    }

    /// Send a message to this connection
    ///
    /// Waits for bounded channel capacity and returns an error if the connection is closed.
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
