//! Connection manager for WebSocket connections
//!
//! This module provides a global connection manager that tracks all active
//! WebSocket connections and enables broadcasting to all connections or specific rooms.

use crate::error::{Result, TidewayError};
use super::connection::Connection;
use super::message::Message;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use dashmap::DashMap;

/// Handle to a connection for the manager
///
/// This wraps the connection with Arc for sharing across threads.
pub type ConnectionHandle = Arc<tokio::sync::RwLock<Connection>>;

/// Global connection manager for WebSocket connections
///
/// This manager tracks all active connections and provides methods for
/// broadcasting messages to all connections or specific rooms/users.
///
/// # Example
///
/// ```rust,no_run
/// use tideway::websocket::ConnectionManager;
/// use std::sync::Arc;
///
/// let manager = Arc::new(ConnectionManager::new());
/// manager.register(connection_handle).await;
/// manager.broadcast_text("Hello all!").await?;
/// ```
#[derive(Clone)]
pub struct ConnectionManager {
    /// Map of connection ID to connection handle
    connections: Arc<DashMap<String, ConnectionHandle>>,
    /// Map of room name to set of connection IDs
    rooms: Arc<DashMap<String, HashSet<String>>>,
    /// Map of user ID to set of connection IDs (for user-specific broadcasting)
    users: Arc<DashMap<String, HashSet<String>>>,
    /// Maximum number of connections allowed (0 = unlimited)
    max_connections: usize,
    /// Total connections ever created (for metrics)
    total_connections: Arc<AtomicU64>,
    /// Total messages broadcast (for metrics)
    total_broadcasts: Arc<AtomicU64>,
}

impl ConnectionManager {
    /// Create a new connection manager with unlimited connections
    pub fn new() -> Self {
        Self::with_max_connections(0)
    }

    /// Create a new connection manager with a maximum connection limit
    ///
    /// # Arguments
    /// * `max_connections` - Maximum number of concurrent connections (0 = unlimited)
    pub fn with_max_connections(max_connections: usize) -> Self {
        Self {
            connections: Arc::new(DashMap::new()),
            rooms: Arc::new(DashMap::new()),
            users: Arc::new(DashMap::new()),
            max_connections,
            total_connections: Arc::new(AtomicU64::new(0)),
            total_broadcasts: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Register a new connection
    ///
    /// # Returns
    /// * `Ok(())` - Connection registered successfully
    /// * `Err(TidewayError)` - Connection limit reached or other error
    pub async fn register(&self, conn: ConnectionHandle) -> Result<()> {
        // Check connection limit
        if self.max_connections > 0 && self.connections.len() >= self.max_connections {
            return Err(TidewayError::service_unavailable(format!(
                "Maximum connection limit ({}) reached",
                self.max_connections
            )));
        }
        let conn_id = {
            let conn_guard = conn.read().await;
            let id = conn_guard.id().to_string();
            if let Some(user_id) = conn_guard.user_id() {
                self.users
                    .entry(user_id.to_string())
                    .or_insert_with(HashSet::new)
                    .insert(id.clone());
            }
            id
        };

        self.connections.insert(conn_id.clone(), conn);
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Unregister a connection
    pub async fn unregister(&self, conn_id: &str) {
        // Remove from connections
        if let Some((_, conn)) = self.connections.remove(conn_id) {
            let conn_guard = conn.read().await;

            // Remove from user mapping
            if let Some(user_id) = conn_guard.user_id() {
                if let Some(mut user_conns) = self.users.get_mut(user_id) {
                    user_conns.remove(conn_id);
                    if user_conns.is_empty() {
                        drop(user_conns);
                        self.users.remove(user_id);
                    }
                }
            }

            // Remove from all rooms
            for room_name in conn_guard.rooms() {
                if let Some(mut room_conns) = self.rooms.get_mut(room_name) {
                    room_conns.remove(conn_id);
                    if room_conns.is_empty() {
                        drop(room_conns);
                        self.rooms.remove(room_name);
                    }
                }
            }
        }
    }

    /// Get a connection by ID
    pub fn get(&self, conn_id: &str) -> Option<ConnectionHandle> {
        self.connections.get(conn_id).map(|entry| entry.clone())
    }

    /// Broadcast a message to all connections
    ///
    /// This method clones the message for each connection. For large messages,
    /// consider using `broadcast_with` to avoid cloning.
    pub async fn broadcast(&self, msg: Message) -> Result<()> {
        self.total_broadcasts.fetch_add(1, Ordering::Relaxed);
        let mut errors = Vec::new();
        let mut failed_conns = Vec::new();

        // Collect connection handles first to minimize lock time
        let conns: Vec<(String, ConnectionHandle)> = self.connections
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();

        // Send to each connection
        for (conn_id, conn) in conns {
            if let Ok(conn_guard) = conn.try_read() {
                if let Err(e) = conn_guard.send(msg.clone()).await {
                    errors.push(e);
                    failed_conns.push(conn_id);
                }
            } else {
                // Connection is locked, skip for now (will be cleaned up later)
                failed_conns.push(conn_id);
            }
        }

        // Clean up failed connections
        for conn_id in failed_conns {
            let _ = self.unregister(&conn_id).await;
        }

        if !errors.is_empty() {
            Err(TidewayError::internal(format!(
                "Failed to send to {} connections",
                errors.len()
            )))
        } else {
            Ok(())
        }
    }

    /// Broadcast a text message to all connections
    pub async fn broadcast_text(&self, text: impl Into<String>) -> Result<()> {
        self.broadcast(Message::Text(text.into())).await
    }

    /// Broadcast a JSON message to all connections
    pub async fn broadcast_json<T: Serialize>(&self, data: &T) -> Result<()> {
        let json = serde_json::to_string(data)
            .map_err(|e| TidewayError::internal(format!("Failed to serialize JSON: {}", e)))?;
        self.broadcast_text(json).await
    }

    /// Broadcast a message to all connections in a room
    pub async fn broadcast_to_room(&self, room: &str, msg: Message) -> Result<()> {
        // Clone connection IDs first to minimize lock time
        let conn_ids: Vec<String> = self
            .rooms
            .get(room)
            .map(|entry| entry.value().iter().cloned().collect())
            .unwrap_or_default();

        if conn_ids.is_empty() {
            return Ok(());
        }

        let mut errors = Vec::new();
        let mut failed_conns = Vec::new();

        for conn_id in conn_ids {
            if let Some(conn) = self.connections.get(&conn_id) {
                if let Ok(conn_guard) = conn.try_read() {
                    if let Err(e) = conn_guard.send(msg.clone()).await {
                        errors.push(e);
                        failed_conns.push(conn_id);
                    }
                } else {
                    // Connection locked, skip
                    failed_conns.push(conn_id);
                }
            }
        }

        // Clean up failed connections
        for conn_id in failed_conns {
            let _ = self.unregister(&conn_id).await;
        }

        if !errors.is_empty() {
            Err(TidewayError::internal(format!(
                "Failed to send to {} connections in room {}",
                errors.len(),
                room
            )))
        } else {
            Ok(())
        }
    }

    /// Broadcast a text message to all connections in a room
    pub async fn broadcast_text_to_room(&self, room: &str, text: impl Into<String>) -> Result<()> {
        self.broadcast_to_room(room, Message::Text(text.into())).await
    }

    /// Broadcast a JSON message to all connections in a room
    pub async fn broadcast_json_to_room<T: Serialize>(&self, room: &str, data: &T) -> Result<()> {
        let json = serde_json::to_string(data)
            .map_err(|e| TidewayError::internal(format!("Failed to serialize JSON: {}", e)))?;
        self.broadcast_text_to_room(room, json).await
    }

    /// Broadcast a message to all connections for a specific user
    pub async fn broadcast_to_user(&self, user_id: &str, msg: Message) -> Result<()> {
        // Clone connection IDs first to minimize lock time
        let conn_ids: Vec<String> = self
            .users
            .get(user_id)
            .map(|entry| entry.value().iter().cloned().collect())
            .unwrap_or_default();

        if conn_ids.is_empty() {
            return Ok(());
        }

        let mut errors = Vec::new();
        let mut failed_conns = Vec::new();

        for conn_id in conn_ids {
            if let Some(conn) = self.connections.get(&conn_id) {
                if let Ok(conn_guard) = conn.try_read() {
                    if let Err(e) = conn_guard.send(msg.clone()).await {
                        errors.push(e);
                        failed_conns.push(conn_id);
                    }
                } else {
                    // Connection locked, skip
                    failed_conns.push(conn_id);
                }
            }
        }

        // Clean up failed connections
        for conn_id in failed_conns {
            let _ = self.unregister(&conn_id).await;
        }

        if !errors.is_empty() {
            Err(TidewayError::internal(format!(
                "Failed to send to {} connections for user {}",
                errors.len(),
                user_id
            )))
        } else {
            Ok(())
        }
    }

    /// Broadcast a text message to all connections for a specific user
    pub async fn broadcast_text_to_user(&self, user_id: &str, text: impl Into<String>) -> Result<()> {
        self.broadcast_to_user(user_id, Message::Text(text.into())).await
    }

    /// Broadcast a JSON message to all connections for a specific user
    pub async fn broadcast_json_to_user<T: Serialize>(&self, user_id: &str, data: &T) -> Result<()> {
        let json = serde_json::to_string(data)
            .map_err(|e| TidewayError::internal(format!("Failed to serialize JSON: {}", e)))?;
        self.broadcast_text_to_user(user_id, json).await
    }

    /// Add a connection to a room
    pub fn add_to_room(&self, conn_id: &str, room: &str) {
        self.rooms
            .entry(room.to_string())
            .or_insert_with(HashSet::new)
            .insert(conn_id.to_string());

        // Also update the connection's local state
        if let Some(conn) = self.connections.get(conn_id) {
            if let Ok(mut conn_guard) = conn.try_write() {
                conn_guard.join_room(room);
            }
        }
    }

    /// Remove a connection from a room
    pub fn remove_from_room(&self, conn_id: &str, room: &str) {
        if let Some(mut room_conns) = self.rooms.get_mut(room) {
            room_conns.remove(conn_id);
            if room_conns.is_empty() {
                drop(room_conns);
                self.rooms.remove(room);
            }
        }

        // Also update the connection's local state
        if let Some(conn) = self.connections.get(conn_id) {
            if let Ok(mut conn_guard) = conn.try_write() {
                conn_guard.leave_room(room);
            }
        }
    }

    /// Get all connection IDs in a room
    pub fn room_members(&self, room: &str) -> Vec<String> {
        self.rooms
            .get(room)
            .map(|entry| entry.value().iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get the number of rooms
    pub fn room_count(&self) -> usize {
        self.rooms.len()
    }

    /// Get the number of active connections
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Get the maximum number of connections allowed (0 = unlimited)
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Get the total number of connections ever created
    pub fn total_connections(&self) -> u64 {
        self.total_connections.load(Ordering::Relaxed)
    }

    /// Get the total number of broadcasts sent
    pub fn total_broadcasts(&self) -> u64 {
        self.total_broadcasts.load(Ordering::Relaxed)
    }

    /// Get connection metrics
    pub fn metrics(&self) -> ConnectionMetrics {
        ConnectionMetrics {
            active_connections: self.connection_count(),
            max_connections: self.max_connections,
            total_connections: self.total_connections(),
            total_broadcasts: self.total_broadcasts(),
            room_count: self.room_count(),
        }
    }

    /// Update user ID mapping for an existing connection
    ///
    /// Call this after setting user_id on a connection to update the manager's
    /// user-to-connections mapping.
    pub fn update_user_mapping(&self, conn_id: &str) {
        if let Some(conn) = self.connections.get(conn_id) {
            // Try to read without blocking
            if let Ok(conn_guard) = conn.try_read() {
                if let Some(user_id) = conn_guard.user_id() {
                    self.users
                        .entry(user_id.to_string())
                        .or_insert_with(HashSet::new)
                        .insert(conn_id.to_string());
                }
            }
        }
    }
}

/// Connection metrics for monitoring
#[derive(Debug, Clone)]
pub struct ConnectionMetrics {
    /// Current number of active connections
    pub active_connections: usize,
    /// Maximum connections allowed (0 = unlimited)
    pub max_connections: usize,
    /// Total connections ever created
    pub total_connections: u64,
    /// Total broadcasts sent
    pub total_broadcasts: u64,
    /// Number of active rooms
    pub room_count: usize,
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}
