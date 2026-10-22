//! Connection manager for WebSocket connections
//!
//! This module provides a global connection manager that tracks all active
//! WebSocket connections and enables broadcasting to all connections or specific rooms.

use super::connection::Connection;
use super::message::Message;
use crate::error::{Result, TidewayError};
use dashmap::DashMap;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Notify, mpsc};

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
///
/// let manager = ConnectionManager::new();
/// // Connection handles are created internally by the websocket handler.
/// // manager.register(connection_handle).await?;
/// // manager.broadcast_text("Hello all!").await?;
/// ```
#[derive(Clone)]
pub struct ConnectionManager {
    /// Map of connection ID to connection handle
    connections: Arc<DashMap<String, ConnectionHandle>>,
    /// Outbound senders by connection ID, so broadcasts never need a connection lock.
    /// Handlers run while holding the connection's write lock and may broadcast to
    /// rooms or users that include their own connection.
    senders: Arc<DashMap<String, mpsc::Sender<Message>>>,
    /// Map of room name to set of connection IDs
    rooms: Arc<DashMap<String, HashSet<String>>>,
    /// Authoritative reverse room index, independent of connection-lock contention.
    connection_rooms: Arc<DashMap<String, HashSet<String>>>,
    /// Map of user ID to set of connection IDs (for user-specific broadcasting)
    users: Arc<DashMap<String, HashSet<String>>>,
    /// Reverse user index, so cleanup does not need the connection lock.
    connection_users: Arc<DashMap<String, String>>,
    /// Close signals by connection ID. Unregistering a connection (including evicting one whose
    /// outbound channel is full) fires its signal so the socket is torn down, not just uncounted.
    closers: Arc<DashMap<String, Arc<Notify>>>,
    /// Maximum number of connections allowed (0 = unlimited)
    max_connections: usize,
    /// Current active connection count (atomic for race-free limit checking)
    active_count: Arc<AtomicU64>,
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
            senders: Arc::new(DashMap::new()),
            rooms: Arc::new(DashMap::new()),
            connection_rooms: Arc::new(DashMap::new()),
            users: Arc::new(DashMap::new()),
            connection_users: Arc::new(DashMap::new()),
            closers: Arc::new(DashMap::new()),
            max_connections,
            active_count: Arc::new(AtomicU64::new(0)),
            total_connections: Arc::new(AtomicU64::new(0)),
            total_broadcasts: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Register a new connection
    ///
    /// # Returns
    /// * `Ok(())` - Connection registered successfully
    /// * `Err(TidewayError)` - Connection limit reached or other error
    ///
    /// # Thread Safety
    ///
    /// This method uses a compare-and-swap loop on an atomic counter to prevent
    /// race conditions when enforcing the connection limit. Multiple concurrent
    /// registration attempts are handled safely without exceeding the limit.
    pub async fn register(&self, conn: ConnectionHandle) -> Result<()> {
        self.register_with_close(conn, Arc::new(Notify::new()))
            .await
    }

    /// Register a connection with the signal that closes it when it is unregistered.
    pub(crate) async fn register_with_close(
        &self,
        conn: ConnectionHandle,
        close: Arc<Notify>,
    ) -> Result<()> {
        // Get connection info first (before checking limit)
        let (conn_id, user_id, sender) = {
            let conn_guard = conn.read().await;
            (
                conn_guard.id().to_string(),
                conn_guard.user_id().map(String::from),
                conn_guard.sender_clone(),
            )
        };

        // Use atomic compare-and-swap to safely reserve a slot
        // This prevents TOCTOU race conditions where multiple threads could
        // exceed the connection limit.
        if self.max_connections > 0 {
            let max = self.max_connections as u64;
            loop {
                let current = self.active_count.load(Ordering::Acquire);
                if current >= max {
                    return Err(TidewayError::service_unavailable(format!(
                        "Maximum connection limit ({}) reached",
                        self.max_connections
                    )));
                }

                // Try to atomically increment the counter
                // If another thread changed it, retry
                match self.active_count.compare_exchange_weak(
                    current,
                    current + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,     // Successfully reserved a slot
                    Err(_) => continue, // Another thread modified it, retry
                }
            }
        } else {
            // No limit, just increment
            self.active_count.fetch_add(1, Ordering::Relaxed);
        }

        // Now insert the connection (we've already reserved the slot)
        self.closers.insert(conn_id.clone(), close);
        self.senders.insert(conn_id.clone(), sender);
        self.connections.insert(conn_id.clone(), conn);

        // Update user mapping if user is authenticated
        self.sync_user(&conn_id, user_id.as_deref());

        self.total_connections.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Unregister a connection
    ///
    /// Safely removes a connection, decrements the active connection count, and signals the
    /// connection's socket to close, so a removed connection no longer holds an open socket.
    pub async fn unregister(&self, conn_id: &str) {
        // Remove from connections
        if let Some((_, conn)) = self.connections.remove(conn_id) {
            // Decrement active count (matches the increment in register)
            self.active_count.fetch_sub(1, Ordering::Relaxed);
            self.senders.remove(conn_id);
            if let Some((_, close)) = self.closers.remove(conn_id) {
                // notify_one stores a permit, so the socket closes even if it is not waiting yet.
                close.notify_one();
            }
            drop(conn);

            // Removing the connection above excludes concurrent user updates, and
            // the reverse index avoids waiting on a lock a handler may hold.
            if let Some((_, user_id)) = self.connection_users.remove(conn_id) {
                self.remove_user_member(conn_id, &user_id);
            }

            // Removing the connection above excludes concurrent room updates. Only
            // visit its indexed rooms, even when connection-local updates were skipped.
            if let Some((_, rooms)) = self.connection_rooms.remove(conn_id) {
                for room in rooms {
                    self.remove_room_member(conn_id, &room);
                }
            }
        }
    }

    fn remove_room_member(&self, conn_id: &str, room: &str) {
        // Remove empty rooms atomically with membership changes so a concurrent
        // join cannot be lost between checking emptiness and removing the room.
        self.rooms.remove_if_mut(room, |_, members| {
            members.remove(conn_id);
            members.is_empty()
        });
    }

    fn remove_user_member(&self, conn_id: &str, user_id: &str) {
        self.users.remove_if_mut(user_id, |_, conns| {
            conns.remove(conn_id);
            conns.is_empty()
        });
    }

    /// Point a registered connection's user mapping at `user_id`. Unknown
    /// connection IDs are ignored.
    pub(crate) fn sync_user(&self, conn_id: &str, user_id: Option<&str>) {
        // Hold the connection entry so unregister cannot interleave; lock order
        // matches add_to_room: connections -> connection_users -> users.
        let Some(_conn) = self.connections.get(conn_id) else {
            return;
        };
        match user_id {
            Some(user_id) => {
                let previous = self
                    .connection_users
                    .insert(conn_id.to_string(), user_id.to_string());
                if previous.as_deref() == Some(user_id) {
                    return;
                }
                if let Some(previous) = previous {
                    self.remove_user_member(conn_id, &previous);
                }
                self.users
                    .entry(user_id.to_string())
                    .or_default()
                    .insert(conn_id.to_string());
            }
            None => {
                if let Some((_, previous)) = self.connection_users.remove(conn_id) {
                    self.remove_user_member(conn_id, &previous);
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
    /// This method clones the message once for each connection. Conversion to
    /// the outbound WebSocket frame consumes that clone without copying its payload.
    pub async fn broadcast(&self, msg: Message) -> Result<()> {
        self.total_broadcasts.fetch_add(1, Ordering::Relaxed);
        let mut errors = Vec::new();
        let mut failed_conns = Vec::new();

        // Collect senders first so no map guard is held while sending
        let senders: Vec<(String, mpsc::Sender<Message>)> = self
            .senders
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();

        // Send to each connection
        for (conn_id, sender) in senders {
            if sender.try_send(msg.clone()).is_err() {
                errors.push(TidewayError::internal(
                    "Failed to send message: channel full or connection closed",
                ));
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
            // Never lock the connection here: the sender may be broadcasting from
            // inside its own handler, which holds that connection's write lock.
            let Some(sender) = self
                .senders
                .get(&conn_id)
                .map(|entry| entry.value().clone())
            else {
                continue;
            };

            if sender.try_send(msg.clone()).is_err() {
                errors.push(TidewayError::internal(
                    "Failed to send message: channel full or connection closed",
                ));
                failed_conns.push(conn_id);
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
        self.broadcast_to_room(room, Message::Text(text.into()))
            .await
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
            // Never lock the connection here: the sender may be broadcasting from
            // inside its own handler, which holds that connection's write lock.
            let Some(sender) = self
                .senders
                .get(&conn_id)
                .map(|entry| entry.value().clone())
            else {
                continue;
            };

            if sender.try_send(msg.clone()).is_err() {
                errors.push(TidewayError::internal(
                    "Failed to send message: channel full or connection closed",
                ));
                failed_conns.push(conn_id);
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
    pub async fn broadcast_text_to_user(
        &self,
        user_id: &str,
        text: impl Into<String>,
    ) -> Result<()> {
        self.broadcast_to_user(user_id, Message::Text(text.into()))
            .await
    }

    /// Broadcast a JSON message to all connections for a specific user
    pub async fn broadcast_json_to_user<T: Serialize>(
        &self,
        user_id: &str,
        data: &T,
    ) -> Result<()> {
        let json = serde_json::to_string(data)
            .map_err(|e| TidewayError::internal(format!("Failed to serialize JSON: {}", e)))?;
        self.broadcast_text_to_user(user_id, json).await
    }

    /// Add a registered connection to a room. Unknown connection IDs are ignored.
    pub fn add_to_room(&self, conn_id: &str, room: &str) {
        // Keep the map guard until both indexes are updated: unregister must
        // remove this entry before cleaning memberships. Lock order is always
        // connections -> connection_rooms -> rooms; no guards cross an await.
        let Some(conn) = self.connections.get(conn_id) else {
            return;
        };
        let mut memberships = self
            .connection_rooms
            .entry(conn_id.to_string())
            .or_default();
        memberships.insert(room.to_string());
        self.rooms
            .entry(room.to_string())
            .or_default()
            .insert(conn_id.to_string());

        // Local state is best effort; cleanup relies on the reverse index.
        if let Ok(mut conn_guard) = conn.try_write() {
            conn_guard.join_room(room);
        }
    }

    /// Remove a connection from a room
    pub fn remove_from_room(&self, conn_id: &str, room: &str) {
        let Some(conn) = self.connections.get(conn_id) else {
            return;
        };
        if let Some(mut memberships) = self.connection_rooms.get_mut(conn_id) {
            memberships.remove(room);
            self.remove_room_member(conn_id, room);
        }

        if let Ok(mut conn_guard) = conn.try_write() {
            conn_guard.leave_room(room);
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
    ///
    /// Uses the atomic counter for accurate counting that matches
    /// the limit enforcement.
    pub fn connection_count(&self) -> usize {
        self.active_count.load(Ordering::Relaxed) as usize
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
    /// Connections served by [`ws`](super::ws) are synced automatically after
    /// `on_connect` and `on_message`, so handlers only need `conn.set_user_id`.
    /// Call this for connections managed outside that route after changing their
    /// user ID. It is a no-op while another task holds the connection lock.
    pub fn update_user_mapping(&self, conn_id: &str) {
        let Some(conn) = self.get(conn_id) else {
            return;
        };
        // Try to read without blocking
        if let Ok(conn_guard) = conn.try_read() {
            self.sync_user(conn_id, conn_guard.user_id());
        }
    }

    /// Reconcile the atomic connection counter with the actual map size
    ///
    /// In rare cases (panics during cleanup, abnormal termination), the atomic
    /// counter may drift from the actual number of connections. Call this method
    /// periodically (e.g., every 5 minutes) to detect and correct drift.
    ///
    /// # Returns
    ///
    /// Returns `Some((atomic_count, actual_count))` if drift was detected and corrected,
    /// or `None` if no drift was found.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Run reconciliation periodically
    /// tokio::spawn(async move {
    ///     let mut interval = tokio::time::interval(Duration::from_secs(300));
    ///     loop {
    ///         interval.tick().await;
    ///         if let Some((old, new)) = manager.reconcile_counter() {
    ///             tracing::warn!(old, new, "Connection counter drift corrected");
    ///         }
    ///     }
    /// });
    /// ```
    pub fn reconcile_counter(&self) -> Option<(u64, u64)> {
        let actual_count = self.connections.len() as u64;
        let atomic_count = self.active_count.load(Ordering::Acquire);

        if actual_count != atomic_count {
            tracing::warn!(
                actual = actual_count,
                atomic = atomic_count,
                drift = (atomic_count as i64 - actual_count as i64),
                "Connection counter drift detected, correcting"
            );
            self.active_count.store(actual_count, Ordering::Release);
            Some((atomic_count, actual_count))
        } else {
            None
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unregister_does_not_lock_unrelated_rooms() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let manager = ConnectionManager::new();
        let (conn, _rx) = Connection::channel("departing", 1);
        runtime
            .block_on(manager.register(Arc::new(tokio::sync::RwLock::new(conn))))
            .unwrap();
        manager
            .rooms
            .insert("unrelated".into(), HashSet::from(["other".into()]));
        let room_guard = manager.rooms.get_mut("unrelated").unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker_manager = manager.clone();
        let worker = std::thread::spawn(move || {
            runtime.block_on(worker_manager.unregister("departing"));
            done_tx.send(()).unwrap();
        });
        let result = done_rx.recv_timeout(std::time::Duration::from_secs(2));
        // Release the lock before joining so a regression fails instead of hanging.
        drop(room_guard);
        worker.join().unwrap();
        result.expect("disconnect must not access unrelated rooms");
    }
}
