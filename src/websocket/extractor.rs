//! WebSocket extractor and route helpers
//!
//! This module provides Axum integration for WebSocket connections, including
//! the upgrade handler and route creation helpers.

use crate::app::AppContext;
use super::connection::Connection;
use super::manager::{ConnectionManager, ConnectionHandle};
use super::message::Message;
use super::traits::WebSocketHandler;
use axum::{
    extract::{ws::WebSocketUpgrade, State},
    routing::get,
    Router,
};
use futures::StreamExt;
use futures::SinkExt;
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;

/// Create a WebSocket route
///
/// This helper function creates an Axum route that handles WebSocket upgrades
/// and manages the connection lifecycle.
///
/// # Example
///
/// ```rust,no_run
/// use tideway::websocket::{ws, ConnectionManager, WebSocketHandler};
/// use tideway::{App, AppContext};
/// use std::sync::Arc;
///
/// struct MyHandler;
/// impl WebSocketHandler for MyHandler { /* ... */ }
///
/// let manager = Arc::new(ConnectionManager::new());
/// let router = ws("/ws", MyHandler, manager);
/// ```
pub fn ws<H>(
    path: &str,
    handler: H,
    manager: Arc<ConnectionManager>,
) -> Router<AppContext>
where
    H: WebSocketHandler,
{
    let handler = Arc::new(handler);
    Router::new().route(
        path,
        get(move |upgrade: WebSocketUpgrade, State(ctx): State<AppContext>| {
            let handler = handler.clone();
            let manager = manager.clone();
            let ctx = Arc::new(ctx);

            async move {
                upgrade.on_upgrade(move |socket| {
                    handle_socket(socket, handler, manager, ctx)
                })
            }
        }),
    )
}

/// Handle a WebSocket connection lifecycle
async fn handle_socket<H: WebSocketHandler>(
    socket: axum::extract::ws::WebSocket,
    handler: Arc<H>,
    manager: Arc<ConnectionManager>,
    ctx: Arc<AppContext>,
) {
    // Generate unique connection ID
    let conn_id = Uuid::new_v4().to_string();

    // Create bounded channels for sending/receiving messages
    // Default to 1000 messages buffer - prevents unbounded memory growth
    let channel_capacity = 1000;
    let (tx, mut rx) = mpsc::channel::<Message>(channel_capacity);
    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Create connection wrapper
    let conn_handle: ConnectionHandle = Arc::new(tokio::sync::RwLock::new(
        Connection::new(conn_id.clone(), tx.clone()),
    ));

    // Register connection with manager (check connection limit)
    if let Err(e) = manager.register(conn_handle.clone()).await {
        tracing::warn!(conn_id = %conn_id, error = %e, "Failed to register connection");
        // Send error response and close
        let _ = ws_sender.close().await;
        return;
    }

    // Call on_connect handler
    {
        let mut conn = conn_handle.write().await;
        if let Err(e) = handler.on_connect(&mut conn, &ctx).await {
            tracing::error!(conn_id = %conn_id, error = %e, "Error in on_connect");
            let _ = manager.unregister(&conn_id).await;
            return;
        }
    }

    // Use a oneshot channel to coordinate cleanup
    let (cleanup_tx, mut cleanup_rx) = tokio::sync::oneshot::channel::<()>();
    let cleanup_tx = Arc::new(tokio::sync::Mutex::new(Some(cleanup_tx)));

    // Heartbeat configuration
    let heartbeat_interval = tokio::time::Duration::from_secs(30);
    let heartbeat_timeout = tokio::time::Duration::from_secs(60);
    let last_pong = Arc::new(tokio::sync::RwLock::new(std::time::Instant::now()));

    // Spawn heartbeat task to detect dead connections
    let heartbeat_task = {
        let conn_handle = conn_handle.clone();
        let manager = manager.clone();
        let conn_id = conn_id.clone();
        let last_pong = last_pong.clone();
        let cleanup_tx = cleanup_tx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(heartbeat_interval);
            loop {
                interval.tick().await;

                // Check if we've received a pong recently
                let last_pong_time = *last_pong.read().await;
                if last_pong_time.elapsed() > heartbeat_timeout {
                    tracing::warn!(conn_id = %conn_id, "Connection heartbeat timeout");
                    // Signal cleanup
                    if let Some(tx) = cleanup_tx.lock().await.take() {
                        let _ = tx.send(());
                        let _ = manager.unregister(&conn_id).await;
                    }
                    break;
                }

                // Send ping
                if let Ok(conn_guard) = conn_handle.try_read() {
                    let _ = conn_guard.send(Message::Ping(vec![])).await;
                }
            }
        })
    };

    // Spawn task to send messages from channel to WebSocket
    let send_task = tokio::spawn({
        let conn_id = conn_id.clone();
        let manager = manager.clone();
        let cleanup_tx = cleanup_tx.clone();
        async move {
            while let Some(msg) = rx.recv().await {
                let axum_msg = msg.into_axum();
                if ws_sender.send(axum_msg).await.is_err() {
                    // WebSocket closed
                    break;
                }
            }

            // Signal cleanup and unregister
            if let Some(tx) = cleanup_tx.lock().await.take() {
                let _ = tx.send(());
                let _ = manager.unregister(&conn_id).await;
            }
        }
    });

    // Spawn task to receive messages from WebSocket
    let recv_task = tokio::spawn({
        let handler = handler.clone();
        let conn_handle = conn_handle.clone();
        let ctx = ctx.clone();
        let manager = manager.clone();
        let conn_id = conn_id.clone();
        let cleanup_tx = cleanup_tx.clone();

        async move {
            while let Some(result) = ws_receiver.next().await {
                match result {
                    Ok(axum_msg) => {
                        let msg = Message::from_axum(axum_msg);

                        // Handle ping frames automatically
                        if let Message::Ping(data) = msg {
                            // Auto-respond to ping with pong
                            {
                                let conn = conn_handle.read().await;
                                let _ = conn.send(Message::Pong(data)).await;
                            }
                            continue;
                        }

                        // Handle pong frames (update heartbeat)
                        if matches!(msg, Message::Pong(_)) {
                            *last_pong.write().await = std::time::Instant::now();
                            continue;
                        }

                        // Handle close messages
                        if matches!(msg, Message::Close(_)) {
                            break;
                        }

                        // Call on_message handler
                        {
                            let mut conn = conn_handle.write().await;
                            if let Err(e) = handler.on_message(&mut conn, msg, &ctx).await {
                                tracing::error!(conn_id = %conn_id, error = %e, "Error in on_message");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(conn_id = %conn_id, error = %e, "WebSocket receive error");
                        break;
                    }
                }
            }

            // Call on_disconnect handler
            {
                let mut conn = conn_handle.write().await;
                handler.on_disconnect(&mut conn, &ctx).await;
            }

            // Signal cleanup and unregister (only if not already done)
            if let Some(tx) = cleanup_tx.lock().await.take() {
                let _ = tx.send(());
                let _ = manager.unregister(&conn_id).await;
            }
        }
    });

    // Wait for any task to complete, then ensure cleanup happens
    // Use tokio::select! with pinned futures
    tokio::pin!(send_task);
    tokio::pin!(recv_task);
    tokio::pin!(heartbeat_task);

    tokio::select! {
        _ = send_task.as_mut() => {
            recv_task.abort();
            heartbeat_task.abort();
            // Wait a bit for recv_task to finish cleanup if it's running
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
        _ = recv_task.as_mut() => {
            send_task.abort();
            heartbeat_task.abort();
        }
        _ = heartbeat_task.as_mut() => {
            // Heartbeat timeout - connection is dead
            send_task.abort();
            recv_task.abort();
        }
    }

    // Final cleanup check - ensure unregister happens even if both tasks abort
    if cleanup_rx.try_recv().is_err() {
        // Cleanup hasn't happened yet, do it now
        let _ = manager.unregister(&conn_id).await;
    }
}
