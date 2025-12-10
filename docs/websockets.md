# WebSockets

Tideway provides comprehensive WebSocket support for real-time communication in your applications. This includes connection management, room/channel support, and broadcasting capabilities.

## Overview

The WebSocket system consists of:

- **WebSocketHandler**: Trait you implement to handle connections
- **Connection**: Wrapper around WebSocket with state and metadata
- **ConnectionManager**: Global manager for tracking and broadcasting
- **Room**: High-level abstraction for grouping connections
- **Message**: WebSocket message types (Text, Binary, Ping, Pong, Close)

## Quick Start

### Basic Example

```rust
use tideway::websocket::{ws, ConnectionManager, WebSocketHandler, Connection, Message};
use tideway::{App, AppContext, Result};
use async_trait::async_trait;
use std::sync::Arc;

struct MyHandler;

#[async_trait]
impl WebSocketHandler for MyHandler {
    async fn on_connect(&self, conn: &mut Connection, _ctx: &AppContext) -> Result<()> {
        conn.send_text("Welcome!").await?;
        Ok(())
    }

    async fn on_message(&self, conn: &mut Connection, msg: Message, ctx: &AppContext) -> Result<()> {
        if let Message::Text(text) = msg {
            let manager = ctx.websocket_manager()?;
            manager.broadcast_text(format!("{}: {}", conn.id(), text)).await?;
        }
        Ok(())
    }

    async fn on_disconnect(&self, _conn: &mut Connection, _ctx: &AppContext) {
        // Cleanup
    }
}

#[tokio::main]
async fn main() {
    let manager = Arc::new(ConnectionManager::new());
    let ctx = AppContext::builder()
        .with_websocket_manager(manager.clone())
        .build();

    let app = App::new()
        .with_context(ctx)
        .merge_router(ws("/ws", MyHandler, manager));

    app.serve().await.unwrap();
}
```

## Enabling WebSockets

Add the `websocket` feature to your `Cargo.toml`:

```toml
[dependencies]
tideway = { path = "../tideway", features = ["websocket"] }
```

## Connection Lifecycle

### 1. Connection Established

When a client connects, the following happens:

1. WebSocket upgrade is accepted
2. Connection is created with a unique ID
3. Connection is registered with the `ConnectionManager`
4. `on_connect` handler is called
5. Send/receive tasks are spawned

### 2. Message Handling

When a message is received:

1. Message is converted from Axum format to Tideway `Message`
2. `on_message` handler is called with the connection and message
3. Handler can send responses or broadcast to other connections

### 3. Connection Closed

When a connection closes:

1. Send/receive tasks complete
2. `on_disconnect` handler is called
3. Connection is unregistered from the manager
4. Connection is removed from all rooms

## Sending Messages

### To a Single Connection

```rust
async fn on_message(&self, conn: &mut Connection, msg: Message, _ctx: &AppContext) -> Result<()> {
    // Send text
    conn.send_text("Hello!").await?;

    // Send JSON
    conn.send_json(&serde_json::json!({
        "type": "message",
        "data": "Hello!"
    })).await?;

    // Send binary
    conn.send_binary(vec![1, 2, 3]).await?;

    // Close connection
    conn.close().await?;

    Ok(())
}
```

### Broadcasting to All Connections

```rust
let manager = ctx.websocket_manager()?;

// Broadcast text
manager.broadcast_text("Hello everyone!").await?;

// Broadcast JSON
manager.broadcast_json(&serde_json::json!({
    "type": "announcement",
    "message": "Server maintenance in 5 minutes"
})).await?;
```

## Rooms and Channels

Rooms allow you to group connections and broadcast to specific groups.

### Joining and Leaving Rooms

```rust
async fn on_message(&self, conn: &mut Connection, msg: Message, ctx: &AppContext) -> Result<()> {
    if let Message::Text(text) = msg {
        if text.starts_with("/join ") {
            let room_name = text.strip_prefix("/join ").unwrap();

            // Join room
            conn.join_room(room_name);
            let manager = ctx.websocket_manager()?;
            manager.add_to_room(conn.id(), room_name);

            conn.send_text(format!("Joined room: {}", room_name)).await?;
        } else if text.starts_with("/leave ") {
            let room_name = text.strip_prefix("/leave ").unwrap();

            // Leave room
            conn.leave_room(room_name);
            let manager = ctx.websocket_manager()?;
            manager.remove_from_room(conn.id(), room_name);

            conn.send_text(format!("Left room: {}", room_name)).await?;
        }
    }
    Ok(())
}
```

### Broadcasting to a Room

```rust
let manager = ctx.websocket_manager()?;

// Broadcast to a specific room
manager.broadcast_text_to_room("chat", "Hello chat room!").await?;

// Or use the Room abstraction
use tideway::websocket::Room;
let room = Room::new("chat", manager.clone());
room.broadcast_text("Hello!").await?;
```

## User-Specific Broadcasting

If you set a `user_id` on connections, you can broadcast to all connections for a specific user:

```rust
async fn on_connect(&self, conn: &mut Connection, _ctx: &AppContext) -> Result<()> {
    // Extract user_id from JWT or session
    let user_id = extract_user_id_from_request();
    conn.set_user_id(user_id);
    Ok(())
}

// Later, broadcast to a specific user
let manager = ctx.websocket_manager()?;
manager.broadcast_text_to_user("user-123", "You have a new message!").await?;
```

## Examples

See the following examples for complete implementations:

- [`websocket_chat.rs`](../examples/websocket_chat.rs) - Chat room with rooms and broadcasting
- [`websocket_notifications.rs`](../examples/websocket_notifications.rs) - Real-time notifications

