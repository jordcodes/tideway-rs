#[cfg(feature = "websocket")]
#[cfg(test)]
mod websocket_tests {
    use crate::error::TidewayError;
    use crate::websocket::{Connection, ConnectionManager, Message};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    #[test]
    fn test_outbound_conversion_reuses_payload_allocation() {
        use crate::websocket::CloseFrame;

        let text = "broadcast payload".repeat(128);
        let ptr = text.as_ptr();
        let axum::extract::ws::Message::Text(converted) = Message::Text(text).into_axum() else {
            panic!("expected text");
        };
        assert_eq!(converted.as_str().as_ptr(), ptr);

        let reason = String::from("connection closed");
        let ptr = reason.as_ptr();
        let axum::extract::ws::Message::Close(Some(converted)) =
            Message::Close(Some(CloseFrame { code: 1000, reason })).into_axum()
        else {
            panic!("expected close frame");
        };
        assert_eq!(converted.reason.as_str().as_ptr(), ptr);
    }

    #[tokio::test]
    async fn test_room_membership_lifecycle_with_contended_local_state() {
        let manager = ConnectionManager::new();
        let (conn, _rx) = Connection::channel("departing", 16);
        let conn = Arc::new(tokio::sync::RwLock::new(conn));
        manager.register(conn.clone()).await.unwrap();
        let (other, _other_rx) = Connection::channel("remaining", 16);
        manager
            .register(Arc::new(tokio::sync::RwLock::new(other)))
            .await
            .unwrap();
        manager.add_to_room("remaining", "shared");
        manager.add_to_room("remaining", "unrelated");

        let guard = conn.write().await;
        manager.add_to_room("departing", "shared");
        manager.add_to_room("departing", "private");
        manager.add_to_room("departing", "left");
        manager.remove_from_room("departing", "left");
        assert!(manager.room_members("left").is_empty());
        drop(guard);

        manager.unregister("departing").await;
        // Late joins must not recreate memberships after disconnect.
        manager.add_to_room("departing", "late");
        manager.add_to_room("unknown", "unknown");
        assert_eq!(manager.room_count(), 2);
        assert_eq!(manager.room_members("shared"), vec!["remaining"]);
        assert_eq!(manager.room_members("unrelated"), vec!["remaining"]);
        manager.unregister("remaining").await;
        assert_eq!(manager.room_count(), 0);
    }

    #[tokio::test]
    async fn test_connection_manager_register_unregister() {
        let manager = ConnectionManager::new();

        // Create a mock connection (using bounded channel as expected by Connection)
        let (tx, _rx) = mpsc::channel::<Message>(16);
        let conn = Arc::new(tokio::sync::RwLock::new(Connection::new(
            "test-conn-1".to_string(),
            tx,
        )));

        // Register
        assert!(manager.register(conn.clone()).await.is_ok());
        assert_eq!(manager.connection_count(), 1);

        // Unregister
        manager.unregister("test-conn-1").await;
        assert_eq!(manager.connection_count(), 0);
    }

    #[tokio::test]
    async fn test_room_operations() {
        let manager = Arc::new(ConnectionManager::new());

        // Create connections (using bounded channel as expected by Connection)
        let (tx1, _rx1) = mpsc::channel::<Message>(16);
        let conn1 = Arc::new(tokio::sync::RwLock::new(Connection::new(
            "conn-1".to_string(),
            tx1,
        )));

        let (tx2, _rx2) = mpsc::channel::<Message>(16);
        let conn2 = Arc::new(tokio::sync::RwLock::new(Connection::new(
            "conn-2".to_string(),
            tx2,
        )));

        // Register connections
        assert!(manager.register(conn1.clone()).await.is_ok());
        assert!(manager.register(conn2.clone()).await.is_ok());

        // Add to room
        manager.add_to_room("conn-1", "room-1");
        manager.add_to_room("conn-2", "room-1");

        // Check room members
        let members = manager.room_members("room-1");
        assert_eq!(members.len(), 2);
        assert!(members.contains(&"conn-1".to_string()));
        assert!(members.contains(&"conn-2".to_string()));

        // Remove from room
        manager.remove_from_room("conn-1", "room-1");
        let members = manager.room_members("room-1");
        assert_eq!(members.len(), 1);
        assert_eq!(members[0], "conn-2");
    }

    #[tokio::test]
    async fn test_broadcast_to_room() {
        let manager = Arc::new(ConnectionManager::new());

        // Create connections with receivers (using bounded channel as expected by Connection)
        let (tx1, mut rx1) = mpsc::channel::<Message>(16);
        let conn1 = Arc::new(tokio::sync::RwLock::new(Connection::new(
            "conn-1".to_string(),
            tx1,
        )));

        let (tx2, mut rx2) = mpsc::channel::<Message>(16);
        let conn2 = Arc::new(tokio::sync::RwLock::new(Connection::new(
            "conn-2".to_string(),
            tx2,
        )));

        // Register and add to room
        assert!(manager.register(conn1.clone()).await.is_ok());
        assert!(manager.register(conn2.clone()).await.is_ok());
        manager.add_to_room("conn-1", "room-1");
        manager.add_to_room("conn-2", "room-1");

        // Broadcast to room
        manager
            .broadcast_text_to_room("room-1", "Hello room!")
            .await
            .unwrap();

        // Check messages received
        let msg1 = rx1.recv().await.unwrap();
        let msg2 = rx2.recv().await.unwrap();

        assert!(matches!(msg1, Message::Text(ref t) if t == "Hello room!"));
        assert!(matches!(msg2, Message::Text(ref t) if t == "Hello room!"));
    }

    #[tokio::test]
    async fn test_broadcast_does_not_unregister_on_lock_contention() {
        use tokio::time::{Duration, timeout};

        let manager = Arc::new(ConnectionManager::new());

        let (tx, mut rx) = mpsc::channel::<Message>(16);
        let conn = Arc::new(tokio::sync::RwLock::new(Connection::new(
            "conn-1".to_string(),
            tx,
        )));

        assert!(manager.register(conn.clone()).await.is_ok());
        assert_eq!(manager.connection_count(), 1);

        let (lock_acquired_tx, lock_acquired_rx) = tokio::sync::oneshot::channel();
        let conn_for_lock = conn.clone();
        let hold_lock = tokio::spawn(async move {
            let _guard = conn_for_lock.write().await;
            let _ = lock_acquired_tx.send(());
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        // Ensure the write lock is held before broadcasting.
        let _ = lock_acquired_rx.await;

        // Broadcast should wait for lock contention, not treat it as a dead connection.
        assert!(manager.broadcast_text("hello").await.is_ok());
        hold_lock.await.unwrap();

        let received = timeout(Duration::from_millis(250), rx.recv())
            .await
            .expect("message should be delivered")
            .expect("channel should still be open");
        assert!(matches!(received, Message::Text(ref t) if t == "hello"));
        assert_eq!(manager.connection_count(), 1);
    }

    #[tokio::test]
    async fn test_broadcast_does_not_block_on_full_connection_channel() {
        use tokio::time::{Duration, timeout};

        let manager = Arc::new(ConnectionManager::new());
        let (slow_tx, _slow_rx) = mpsc::channel::<Message>(1);
        slow_tx
            .send(Message::Text("already full".into()))
            .await
            .unwrap();
        let slow = Arc::new(tokio::sync::RwLock::new(Connection::new(
            "slow".to_string(),
            slow_tx,
        )));
        let (fast_tx, mut fast_rx) = mpsc::channel::<Message>(1);
        let fast = Arc::new(tokio::sync::RwLock::new(Connection::new(
            "fast".to_string(),
            fast_tx,
        )));
        manager.register(slow).await.unwrap();
        manager.register(fast).await.unwrap();

        let result = timeout(Duration::from_millis(100), manager.broadcast_text("hello"))
            .await
            .expect("broadcast must not wait for slow consumers");
        assert!(result.is_err());
        assert!(matches!(fast_rx.recv().await, Some(Message::Text(text)) if text == "hello"));
        assert!(manager.get("slow").is_none());
    }

    #[tokio::test]
    async fn test_unregister_cleans_stale_room_membership_after_lock_contention() {
        let manager = Arc::new(ConnectionManager::new());

        let (tx, _rx) = mpsc::channel::<Message>(16);
        let conn = Arc::new(tokio::sync::RwLock::new(Connection::new(
            "conn-1".to_string(),
            tx,
        )));

        assert!(manager.register(conn.clone()).await.is_ok());

        // Hold a write lock so add_to_room can't update connection-local room state.
        let conn_write_guard = conn.write().await;
        manager.add_to_room("conn-1", "room-1");
        drop(conn_write_guard);

        // Manager room index contains the member even though local state missed the update.
        assert_eq!(manager.room_members("room-1").len(), 1);

        manager.unregister("conn-1").await;

        // Unregister should fully clean stale room membership.
        assert!(manager.room_members("room-1").is_empty());
        assert_eq!(manager.room_count(), 0);
    }

    #[tokio::test]
    async fn test_connection_limit_enforced() {
        // Create manager with limit of 2 connections
        let manager = ConnectionManager::with_max_connections(2);

        // Create 3 connections
        let (tx1, _rx1) = mpsc::channel::<Message>(16);
        let conn1 = Arc::new(tokio::sync::RwLock::new(Connection::new(
            "conn-1".to_string(),
            tx1,
        )));

        let (tx2, _rx2) = mpsc::channel::<Message>(16);
        let conn2 = Arc::new(tokio::sync::RwLock::new(Connection::new(
            "conn-2".to_string(),
            tx2,
        )));

        let (tx3, _rx3) = mpsc::channel::<Message>(16);
        let conn3 = Arc::new(tokio::sync::RwLock::new(Connection::new(
            "conn-3".to_string(),
            tx3,
        )));

        // First two should succeed
        assert!(manager.register(conn1).await.is_ok());
        assert!(manager.register(conn2).await.is_ok());
        assert_eq!(manager.connection_count(), 2);

        // Third should be rejected
        let result = manager.register(conn3).await;
        assert!(result.is_err());
        assert_eq!(manager.connection_count(), 2);

        // Error should be service unavailable
        if let Err(TidewayError::ServiceUnavailable(msg)) = result {
            assert!(msg.contains("connection limit"));
        } else {
            panic!("Expected ServiceUnavailable error");
        }
    }

    #[tokio::test]
    async fn test_connection_limit_after_unregister() {
        // Create manager with limit of 1 connection
        let manager = ConnectionManager::with_max_connections(1);

        let (tx1, _rx1) = mpsc::channel::<Message>(16);
        let conn1 = Arc::new(tokio::sync::RwLock::new(Connection::new(
            "conn-1".to_string(),
            tx1,
        )));

        let (tx2, _rx2) = mpsc::channel::<Message>(16);
        let conn2 = Arc::new(tokio::sync::RwLock::new(Connection::new(
            "conn-2".to_string(),
            tx2,
        )));

        // First should succeed
        assert!(manager.register(conn1).await.is_ok());
        assert_eq!(manager.connection_count(), 1);

        // Second should fail (at limit)
        assert!(manager.register(conn2.clone()).await.is_err());

        // Unregister first connection
        manager.unregister("conn-1").await;
        assert_eq!(manager.connection_count(), 0);

        // Now second should succeed
        assert!(manager.register(conn2).await.is_ok());
        assert_eq!(manager.connection_count(), 1);
    }

    #[tokio::test]
    async fn test_concurrent_registration_respects_limit() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Test that concurrent registrations don't exceed the limit
        // This tests the CAS-based atomic registration
        let manager = Arc::new(ConnectionManager::with_max_connections(5));
        let success_count = Arc::new(AtomicUsize::new(0));
        let failure_count = Arc::new(AtomicUsize::new(0));

        let mut handles = vec![];

        // Spawn 20 concurrent tasks trying to register
        for i in 0..20 {
            let manager = manager.clone();
            let success_count = success_count.clone();
            let failure_count = failure_count.clone();

            handles.push(tokio::spawn(async move {
                let (tx, _rx) = mpsc::channel::<Message>(16);
                let conn = Arc::new(tokio::sync::RwLock::new(Connection::new(
                    format!("conn-{}", i),
                    tx,
                )));

                match manager.register(conn).await {
                    Ok(_) => {
                        success_count.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        failure_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }

        // Verify: exactly 5 succeeded (the limit)
        let successes = success_count.load(Ordering::Relaxed);
        let failures = failure_count.load(Ordering::Relaxed);

        assert_eq!(successes, 5, "Exactly 5 connections should have succeeded");
        assert_eq!(failures, 15, "15 connections should have been rejected");
        assert_eq!(
            manager.connection_count(),
            5,
            "Connection count should be exactly 5"
        );
    }

    struct ChatLikeHandler;

    #[async_trait::async_trait]
    impl crate::websocket::WebSocketHandler for ChatLikeHandler {
        async fn on_connect(
            &self,
            conn: &mut Connection,
            ctx: &crate::AppContext,
        ) -> crate::Result<()> {
            conn.set_user_id("user-1".to_string());
            conn.join_room("general");
            let manager = ctx.websocket_manager()?;
            manager.add_to_room(conn.id(), "general");
            manager
                .broadcast_text_to_room("general", format!("{} joined", conn.id()))
                .await
        }

        async fn on_message(
            &self,
            conn: &mut Connection,
            msg: Message,
            ctx: &crate::AppContext,
        ) -> crate::Result<()> {
            let Message::Text(text) = msg else {
                return Ok(());
            };
            let manager = ctx.websocket_manager()?;
            for room in conn.rooms().iter() {
                manager.broadcast_text_to_room(room, &text).await?;
            }
            manager
                .broadcast_text_to_user("user-1", format!("dm: {text}"))
                .await
        }

        async fn on_disconnect(&self, _conn: &mut Connection, _ctx: &crate::AppContext) {}
    }

    #[tokio::test]
    async fn test_handlers_can_broadcast_to_own_room_and_user() {
        use crate::websocket::extractor::{run_on_connect, run_on_message};
        use tokio::time::{Duration, timeout};

        let manager = Arc::new(ConnectionManager::new());
        let ctx = crate::AppContext::builder()
            .with_websocket_manager(manager.clone())
            .build();
        let (conn, mut rx) = Connection::channel("conn-1", 16);
        let conn = Arc::new(tokio::sync::RwLock::new(conn));
        manager.register(conn.clone()).await.unwrap();

        timeout(
            Duration::from_secs(2),
            run_on_connect(&ChatLikeHandler, &conn, &manager, &ctx),
        )
        .await
        .expect("on_connect must not deadlock broadcasting to its own room")
        .unwrap();
        assert!(matches!(rx.recv().await, Some(Message::Text(t)) if t == "conn-1 joined"));

        timeout(
            Duration::from_secs(2),
            run_on_message(
                &ChatLikeHandler,
                &conn,
                Message::Text("hi".into()),
                &manager,
                &ctx,
            ),
        )
        .await
        .expect("on_message must not deadlock broadcasting to its own room")
        .unwrap();
        assert!(matches!(rx.recv().await, Some(Message::Text(t)) if t == "hi"));
        assert!(matches!(rx.recv().await, Some(Message::Text(t)) if t == "dm: hi"));

        manager.unregister("conn-1").await;
        manager
            .broadcast_text_to_user("user-1", "gone")
            .await
            .unwrap();
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_user_mapping_follows_connection_user_id() {
        let manager = ConnectionManager::new();
        let (mut conn, mut rx) = Connection::channel("conn-1", 16);
        conn.set_user_id("alice".into());
        let conn = Arc::new(tokio::sync::RwLock::new(conn));
        manager.register(conn.clone()).await.unwrap();

        conn.write().await.set_user_id("bob".into());
        manager.update_user_mapping("conn-1");
        manager
            .broadcast_text_to_user("alice", "stale")
            .await
            .unwrap();
        manager
            .broadcast_text_to_user("bob", "fresh")
            .await
            .unwrap();
        assert!(matches!(rx.recv().await, Some(Message::Text(t)) if t == "fresh"));
        assert!(rx.try_recv().is_err());

        // Unregister must not wait on a lock a handler might hold.
        let _guard = conn.write().await;
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            manager.unregister("conn-1"),
        )
        .await
        .expect("unregister must not need the connection lock");
        manager.broadcast_text_to_user("bob", "gone").await.unwrap();
        assert!(rx.try_recv().is_err());
    }

    struct CookieAuthHandler;

    #[async_trait::async_trait]
    impl crate::websocket::WebSocketHandler for CookieAuthHandler {
        async fn on_upgrade(
            &self,
            req: &mut crate::websocket::UpgradeRequest,
            _ctx: &crate::AppContext,
        ) -> crate::Result<()> {
            if req.cookie("session") != Some("good") {
                return Err(TidewayError::unauthorized("invalid session"));
            }
            let user = req.header("x-user").unwrap_or("anonymous").to_string();
            req.set_user_id(user);
            Ok(())
        }

        async fn on_connect(
            &self,
            conn: &mut Connection,
            _ctx: &crate::AppContext,
        ) -> crate::Result<()> {
            let greeting = format!(
                "{}|{}|{}",
                conn.user_id().unwrap_or_default(),
                conn.cookie("theme").unwrap_or_default(),
                conn.uri().query().unwrap_or_default(),
            );
            conn.send_text(greeting).await
        }

        async fn on_message(
            &self,
            _conn: &mut Connection,
            _msg: Message,
            _ctx: &crate::AppContext,
        ) -> crate::Result<()> {
            Ok(())
        }

        async fn on_disconnect(&self, _conn: &mut Connection, _ctx: &crate::AppContext) {}
    }

    async fn ws_handshake(
        addr: std::net::SocketAddr,
        extra_headers: &str,
    ) -> (String, tokio::net::TcpStream) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = format!(
            "GET /ws?room=lobby HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n{extra_headers}\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
        (String::from_utf8(head).unwrap(), stream)
    }

    #[tokio::test]
    async fn test_on_upgrade_authenticates_from_request_metadata() {
        use tokio::io::AsyncReadExt;

        let manager = Arc::new(ConnectionManager::new());
        let ctx = crate::AppContext::builder()
            .with_websocket_manager(manager.clone())
            .build();
        let app = crate::websocket::ws("/ws", CookieAuthHandler, manager.clone()).with_state(ctx);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        // Missing or wrong session cookie: rejected with an HTTP error, no upgrade.
        let (head, _) = ws_handshake(addr, "").await;
        assert!(head.starts_with("HTTP/1.1 401"), "{head}");
        let (head, _) = ws_handshake(addr, "Cookie: session=bad\r\n").await;
        assert!(head.starts_with("HTTP/1.1 401"), "{head}");
        assert_eq!(manager.connection_count(), 0);

        // Valid cookie: accepted, and on_connect sees the identity and request metadata.
        let (head, mut stream) = ws_handshake(
            addr,
            "Cookie: theme=dark; session=good\r\nX-User: alice\r\n",
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");

        let mut frame_head = [0u8; 2];
        stream.read_exact(&mut frame_head).await.unwrap();
        assert_eq!(frame_head[0], 0x81, "expected a final text frame");
        let mut payload = vec![0u8; (frame_head[1] & 0x7f) as usize];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(String::from_utf8(payload).unwrap(), "alice|dark|room=lobby");
        assert_eq!(manager.connection_count(), 1);
    }

    #[derive(Default)]
    struct DisconnectCounter(std::sync::atomic::AtomicUsize);

    #[async_trait::async_trait]
    impl crate::websocket::WebSocketHandler for DisconnectCounter {
        async fn on_connect(
            &self,
            _conn: &mut Connection,
            _ctx: &crate::AppContext,
        ) -> crate::Result<()> {
            Ok(())
        }

        async fn on_message(
            &self,
            _conn: &mut Connection,
            _msg: Message,
            _ctx: &crate::AppContext,
        ) -> crate::Result<()> {
            Ok(())
        }

        async fn on_disconnect(&self, _conn: &mut Connection, _ctx: &crate::AppContext) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    type ClientInbound = futures::channel::mpsc::UnboundedReceiver<axum::extract::ws::Message>;
    type ClientOutbound = futures::channel::mpsc::UnboundedSender<
        std::result::Result<axum::extract::ws::Message, axum::Error>,
    >;

    /// Run a connection over in-memory channels with a fast heartbeat.
    fn spawn_test_connection(
        handler: Arc<DisconnectCounter>,
        manager: Arc<ConnectionManager>,
    ) -> (tokio::task::JoinHandle<()>, ClientInbound, ClientOutbound) {
        use crate::websocket::extractor::{Heartbeat, run_connection};
        use futures::SinkExt;

        let (server_tx, client_rx) = futures::channel::mpsc::unbounded();
        let (client_tx, server_rx) = futures::channel::mpsc::unbounded();
        let ctx = Arc::new(
            crate::AppContext::builder()
                .with_websocket_manager(manager.clone())
                .build(),
        );
        let request = crate::websocket::UpgradeRequest::new(
            axum::http::HeaderMap::new(),
            "/ws".parse().unwrap(),
        );
        let heartbeat = Heartbeat {
            interval: std::time::Duration::from_millis(10),
            timeout: std::time::Duration::from_millis(50),
        };
        let task = tokio::spawn(run_connection(
            server_tx.sink_map_err(|_| ()),
            server_rx,
            request,
            handler,
            manager,
            ctx,
            heartbeat,
        ));
        (task, client_rx, client_tx)
    }

    #[tokio::test]
    async fn test_evicted_slow_reader_is_closed_not_just_uncounted() {
        use crate::websocket::extractor::{Heartbeat, run_connection};
        use futures::SinkExt;
        use std::sync::atomic::Ordering;

        let manager = Arc::new(ConnectionManager::with_max_connections(1));
        let handler = Arc::new(DisconnectCounter::default());
        // A client that never reads: the server's sink blocks once this zero-capacity channel
        // holds one frame, so the connection's outbound buffer fills up.
        let (server_tx, _client_rx) = futures::channel::mpsc::channel(0);
        let (mut client_tx, server_rx) =
            futures::channel::mpsc::unbounded::<std::result::Result<_, axum::Error>>();
        let ctx = Arc::new(
            crate::AppContext::builder()
                .with_websocket_manager(manager.clone())
                .build(),
        );
        let task = tokio::spawn(run_connection(
            server_tx.sink_map_err(|_| ()),
            server_rx,
            crate::websocket::UpgradeRequest::new(
                axum::http::HeaderMap::new(),
                "/ws".parse().unwrap(),
            ),
            handler.clone(),
            manager.clone(),
            ctx,
            Heartbeat {
                interval: std::time::Duration::from_millis(10),
                timeout: std::time::Duration::from_millis(100),
            },
        ));
        // Unsolicited pongs keep the heartbeat satisfied.
        let keepalive = tokio::spawn(async move {
            loop {
                if client_tx
                    .send(Ok(axum::extract::ws::Message::Pong(Vec::new().into())))
                    .await
                    .is_err()
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        });

        while manager.connection_count() == 0 {
            tokio::task::yield_now().await;
        }
        // Fill the outbound buffer until the broadcast evicts the connection.
        for _ in 0..1100 {
            let _ = manager.broadcast_text("tick").await;
        }
        assert_eq!(manager.connection_count(), 0);

        // The evicted socket must actually close and run on_disconnect.
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("an evicted connection must be torn down")
            .unwrap();
        assert_eq!(handler.0.load(Ordering::SeqCst), 1);
        keepalive.abort();
    }

    #[tokio::test]
    async fn test_on_disconnect_runs_on_heartbeat_timeout() {
        use std::sync::atomic::Ordering;

        let manager = Arc::new(ConnectionManager::new());
        let handler = Arc::new(DisconnectCounter::default());
        // Keep both client ends open and never pong, so only the heartbeat can end it.
        let (task, _client_rx, _client_tx) =
            spawn_test_connection(handler.clone(), manager.clone());

        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("heartbeat timeout must end the connection")
            .unwrap();
        assert_eq!(handler.0.load(Ordering::SeqCst), 1);
        assert_eq!(manager.connection_count(), 0);
    }

    #[tokio::test]
    async fn test_on_disconnect_runs_when_send_fails() {
        use std::sync::atomic::Ordering;

        let manager = Arc::new(ConnectionManager::new());
        let handler = Arc::new(DisconnectCounter::default());
        // Dropping the client's inbound side makes the first ping send fail.
        let (task, client_rx, _client_tx) = spawn_test_connection(handler.clone(), manager.clone());
        drop(client_rx);

        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("send failure must end the connection")
            .unwrap();
        assert_eq!(handler.0.load(Ordering::SeqCst), 1);
        assert_eq!(manager.connection_count(), 0);
    }

    #[tokio::test]
    async fn test_on_disconnect_runs_once_on_client_close() {
        use std::sync::atomic::Ordering;

        let manager = Arc::new(ConnectionManager::new());
        let handler = Arc::new(DisconnectCounter::default());
        let (task, _client_rx, client_tx) = spawn_test_connection(handler.clone(), manager.clone());
        drop(client_tx);

        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("client close must end the connection")
            .unwrap();
        assert_eq!(handler.0.load(Ordering::SeqCst), 1);
        assert_eq!(manager.connection_count(), 0);
    }
}
