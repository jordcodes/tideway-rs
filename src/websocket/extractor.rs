//! WebSocket extractor and route helpers
//!
//! This module provides Axum integration for WebSocket connections, including
//! the upgrade handler and route creation helpers.

use super::connection::Connection;
use super::manager::{ConnectionHandle, ConnectionManager};
use super::message::Message;
use super::traits::WebSocketHandler;
use super::upgrade::UpgradeRequest;
use crate::app::AppContext;
use crate::error::Result;
use axum::{
    Router,
    extract::{State, ws::WebSocketUpgrade},
    http::{HeaderMap, Uri},
    response::IntoResponse,
    routing::get,
};
use futures::SinkExt;
use futures::StreamExt;
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
/// use async_trait::async_trait;
/// use std::sync::Arc;
/// use tideway::websocket::{ws, ConnectionManager, Connection, Message, WebSocketHandler};
/// use tideway::{AppContext, Result};
///
/// struct MyHandler;
///
/// #[async_trait]
/// impl WebSocketHandler for MyHandler {
///     async fn on_connect(&self, _conn: &mut Connection, _ctx: &AppContext) -> Result<()> {
///         Ok(())
///     }
///
///     async fn on_message(&self, _conn: &mut Connection, _msg: Message, _ctx: &AppContext) -> Result<()> {
///         Ok(())
///     }
///
///     async fn on_disconnect(&self, _conn: &mut Connection, _ctx: &AppContext) {}
/// }
///
/// let manager = Arc::new(ConnectionManager::new());
/// let _router = ws("/ws", MyHandler, manager);
/// ```
pub fn ws<H>(path: &str, handler: H, manager: Arc<ConnectionManager>) -> Router<AppContext>
where
    H: WebSocketHandler,
{
    let handler = Arc::new(handler);
    Router::new().route(
        path,
        get(
            move |upgrade: WebSocketUpgrade,
                  State(ctx): State<AppContext>,
                  headers: HeaderMap,
                  uri: Uri| {
                let handler = handler.clone();
                let manager = manager.clone();
                let ctx = Arc::new(ctx);

                async move {
                    let mut request = UpgradeRequest::new(headers, uri);
                    // Reject before switching protocols so the client gets a normal HTTP error.
                    if let Err(e) = handler.on_upgrade(&mut request, &ctx).await {
                        return e.into_response();
                    }
                    upgrade.on_upgrade(move |socket| {
                        handle_socket(socket, request, handler, manager, ctx)
                    })
                }
            },
        ),
    )
}

/// Heartbeat timing for a WebSocket connection
#[derive(Debug, Clone, Copy)]
pub(crate) struct Heartbeat {
    pub(crate) interval: tokio::time::Duration,
    pub(crate) timeout: tokio::time::Duration,
}

impl Default for Heartbeat {
    fn default() -> Self {
        Self {
            interval: tokio::time::Duration::from_secs(30),
            timeout: tokio::time::Duration::from_secs(60),
        }
    }
}

/// Handle a WebSocket connection lifecycle
async fn handle_socket<H: WebSocketHandler>(
    socket: axum::extract::ws::WebSocket,
    request: UpgradeRequest,
    handler: Arc<H>,
    manager: Arc<ConnectionManager>,
    ctx: Arc<AppContext>,
) {
    let (ws_sender, ws_receiver) = socket.split();
    run_connection(
        ws_sender,
        ws_receiver,
        request,
        handler,
        manager,
        ctx,
        Heartbeat::default(),
    )
    .await;
}

/// Drive a connection until the peer disconnects, the socket fails, or the
/// heartbeat times out. `on_disconnect` runs exactly once on every exit path
/// after `on_connect` succeeded.
pub(crate) async fn run_connection<H, Si, St>(
    mut ws_sender: Si,
    mut ws_receiver: St,
    request: UpgradeRequest,
    handler: Arc<H>,
    manager: Arc<ConnectionManager>,
    ctx: Arc<AppContext>,
    heartbeat: Heartbeat,
) where
    H: WebSocketHandler,
    Si: futures::Sink<axum::extract::ws::Message> + Unpin + Send + 'static,
    St: futures::Stream<Item = std::result::Result<axum::extract::ws::Message, axum::Error>>
        + Unpin
        + Send
        + 'static,
{
    // Generate unique connection ID
    let conn_id = Uuid::new_v4().to_string();

    // Create bounded channels for sending/receiving messages
    // Default to 1000 messages buffer - prevents unbounded memory growth
    let channel_capacity = 1000;
    let (tx, mut rx) = mpsc::channel::<Message>(channel_capacity);

    // Create connection wrapper
    let conn_handle: ConnectionHandle = Arc::new(tokio::sync::RwLock::new(
        Connection::from_upgrade(conn_id.clone(), tx.clone(), request),
    ));

    // Register connection with manager (check connection limit)
    if let Err(e) = manager.register(conn_handle.clone()).await {
        tracing::warn!(conn_id = %conn_id, error = %e, "Failed to register connection");
        // Send error response and close
        let _ = ws_sender.close().await;
        return;
    }

    // Call on_connect handler
    if let Err(e) = run_on_connect(&*handler, &conn_handle, &manager, &ctx).await {
        tracing::error!(conn_id = %conn_id, error = %e, "Error in on_connect");
        let _ = manager.unregister(&conn_id).await;
        return;
    }

    let last_pong = Arc::new(tokio::sync::RwLock::new(std::time::Instant::now()));

    // Spawn heartbeat task to detect dead connections
    let mut heartbeat_task = {
        let tx = tx.clone();
        let conn_id = conn_id.clone();
        let last_pong = last_pong.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(heartbeat.interval);
            loop {
                interval.tick().await;

                // Check if we've received a pong recently
                let last_pong_time = *last_pong.read().await;
                if last_pong_time.elapsed() > heartbeat.timeout {
                    tracing::warn!(conn_id = %conn_id, "Connection heartbeat timeout");
                    break;
                }

                // Send ping without the connection lock, which handlers may hold
                let _ = tx.try_send(Message::Ping(vec![]));
            }
        })
    };

    // Spawn task to send messages from channel to WebSocket
    let mut send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_sender.send(msg.into_axum()).await.is_err() {
                // WebSocket closed
                break;
            }
        }
    });

    // Spawn task to receive messages from WebSocket
    let mut recv_task = tokio::spawn({
        let handler = handler.clone();
        let conn_handle = conn_handle.clone();
        let ctx = ctx.clone();
        let manager = manager.clone();
        let conn_id = conn_id.clone();

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
                        if let Err(e) =
                            run_on_message(&*handler, &conn_handle, msg, &manager, &ctx).await
                        {
                            tracing::error!(conn_id = %conn_id, error = %e, "Error in on_message");
                        }
                    }
                    Err(e) => {
                        tracing::error!(conn_id = %conn_id, error = %e, "WebSocket receive error");
                        break;
                    }
                }
            }
        }
    });

    // Whichever task ends first ends the connection; stop the others.
    let remaining = tokio::select! {
        _ = &mut send_task => [recv_task, heartbeat_task],
        _ = &mut recv_task => [send_task, heartbeat_task],
        _ = &mut heartbeat_task => [send_task, recv_task],
    };
    // Wait for aborted tasks to drop, releasing any connection lock an
    // in-flight on_message held, before running on_disconnect.
    for task in remaining {
        task.abort();
        let _ = task.await;
    }

    {
        let mut conn = conn_handle.write().await;
        handler.on_disconnect(&mut conn, &ctx).await;
    }
    let _ = manager.unregister(&conn_id).await;
}

// Handlers run under the connection's write lock to get `&mut Connection`, so the
// manager must not lock connections while broadcasting. User IDs set by a handler
// are synced here, after it returns, because the manager cannot read them sooner.
pub(crate) async fn run_on_connect<H: WebSocketHandler>(
    handler: &H,
    conn_handle: &ConnectionHandle,
    manager: &ConnectionManager,
    ctx: &AppContext,
) -> Result<()> {
    let mut conn = conn_handle.write().await;
    let result = handler.on_connect(&mut conn, ctx).await;
    manager.sync_user(conn.id(), conn.user_id());
    result
}

pub(crate) async fn run_on_message<H: WebSocketHandler>(
    handler: &H,
    conn_handle: &ConnectionHandle,
    msg: Message,
    manager: &ConnectionManager,
    ctx: &AppContext,
) -> Result<()> {
    let mut conn = conn_handle.write().await;
    let result = handler.on_message(&mut conn, msg, ctx).await;
    manager.sync_user(conn.id(), conn.user_id());
    result
}
