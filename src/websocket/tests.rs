#[cfg(feature = "websocket")]
#[cfg(test)]
mod tests {
    use crate::websocket::{ConnectionManager, Message, Connection};
    use std::sync::Arc;
    use tokio::sync::mpsc;

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
}
