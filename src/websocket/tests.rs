#[cfg(feature = "websocket")]
#[cfg(test)]
mod tests {
    use crate::websocket::{ConnectionManager, Message, Connection};
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use crate::error::TidewayError;

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
        manager.register(conn.clone()).await;
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
        manager.register(conn1.clone()).await;
        manager.register(conn2.clone()).await;

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
        manager.register(conn1.clone()).await;
        manager.register(conn2.clone()).await;
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
        assert_eq!(manager.connection_count(), 5, "Connection count should be exactly 5");
    }
}
