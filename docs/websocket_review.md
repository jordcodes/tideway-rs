# WebSocket Implementation Review

## Critical Bugs Fixed ✅

### 1. Double Unregister Race Condition
**Issue**: Both `send_task` and `recv_task` called `unregister()`, causing race conditions and potential panics.

**Fix**: Added oneshot channel coordination so only one task performs cleanup. Both tasks signal via the channel, and cleanup happens exactly once.

### 2. Close Frame Code Loss
**Issue**: Close frames always used `NormalClosure` instead of preserving the actual close code.

**Fix**: Added mapping for common WebSocket close codes (1000-1011) to preserve the original code.

### 3. Missing Ping/Pong Handling
**Issue**: Ping frames weren't automatically responded to, which can cause connection timeouts.

**Fix**: Added automatic ping/pong handling in the receive loop.

## Performance Optimizations ✅

### 1. Reduced Lock Contention
**Issue**: Broadcasting held locks while iterating, blocking other operations.

**Fix**: Collect connection handles first, then release locks before sending. This minimizes lock time and improves concurrency.

### 2. Failed Connection Cleanup
**Issue**: Failed connections weren't automatically removed, causing memory leaks.

**Fix**: Automatically unregister connections that fail to send, preventing accumulation of dead connections.

### 3. Early Returns for Empty Sets
**Issue**: Broadcasting to empty rooms/users still did work.

**Fix**: Added early returns when room/user sets are empty.

## Remaining Performance Concerns ⚠️

### 1. Unbounded Channel Memory Growth
**Current**: Uses `mpsc::unbounded_channel` which can grow indefinitely if WebSocket writes are slow.

**Impact**: Under high load with slow clients, memory can grow unbounded, leading to OOM.

**Recommendation**:
- Add configurable bounded channel with backpressure
- Or add message dropping when channel is full
- Monitor channel size and log warnings

**Example Fix**:
```rust
// In extractor.rs, make channel bounded
let (tx, mut rx) = mpsc::channel::<Message>(1000); // Bounded to 1000 messages

// In Connection::send(), handle backpressure
pub async fn send(&self, msg: Message) -> Result<()> {
    self.sender.send(msg).await.map_err(|_| {
        TidewayError::internal("Failed to send message: channel full or connection closed")
    })
}
```

### 2. Message Cloning in Broadcasts
**Current**: Every broadcast clones the message for each connection.

**Impact**: For large messages (e.g., 1MB JSON) broadcast to 10K connections = 10GB memory allocation.

**Recommendation**:
- Use `Arc<Message>` for large broadcasts
- Or serialize once and clone bytes instead of full Message struct
- Add `broadcast_arc()` method for large messages

**Example Fix**:
```rust
pub async fn broadcast_arc(&self, msg: Arc<Message>) -> Result<()> {
    // Clone Arc instead of Message
    for conn in connections {
        conn.send_arc(msg.clone()).await?; // Clone Arc, not Message
    }
}
```

### 3. No Connection Limits
**Current**: No maximum connection limit.

**Impact**: Memory can grow unbounded with many connections.

**Recommendation**:
- Add `max_connections` config option
- Reject new connections when limit reached
- Return 503 Service Unavailable

### 4. Lock Contention on Connection Reads
**Current**: Every `send()` requires a read lock on `RwLock<Connection>`.

**Impact**: With many concurrent sends, lock contention becomes a bottleneck.

**Recommendation**:
- Consider using `Arc<Mutex<>>` instead of `RwLock` (writes are rare)
- Or move sender channel out of Connection struct
- Use lock-free data structures where possible

### 5. Room Cleanup Race Condition
**Current**: When unregistering, we iterate over `conn_guard.rooms()` while holding a read lock, then release and modify rooms map.

**Impact**: Connection could be added to a room between reading rooms and removing from manager.

**Fix Applied**: The current implementation is safe because:
- We read rooms list while holding lock
- We clone the list before releasing lock
- Then we remove from manager's room map

However, there's still a window where connection could be added to a new room after we've read the list but before we've removed it from all rooms.

**Better Fix**:
```rust
// In unregister, use a two-phase approach:
// 1. Mark connection as disconnecting
// 2. Remove from all rooms atomically
```

### 6. User ID Update After Registration
**Current**: If `set_user_id()` is called after registration, manager's user mapping isn't updated.

**Fix Applied**: Added `update_user_mapping()` method. Users should call this after setting user_id.

**Better Fix**: Could automatically update on `set_user_id()`, but requires passing manager reference to Connection, which breaks encapsulation.

## Scalability Limitations

### Single-Server Only
**Current**: ConnectionManager is in-memory and doesn't work across multiple servers.

**Impact**: Can't scale horizontally - each server has its own connection pool.

**Future Enhancement**: Redis pub/sub backend for multi-server deployments.

### No Message Ordering Guarantees
**Current**: Messages sent to same connection aren't guaranteed to arrive in order.

**Impact**: For applications requiring strict ordering, this could be an issue.

**Note**: This is actually fine for most use cases - WebSocket protocol itself doesn't guarantee ordering across frames.

## Recommendations for Production

1. **Add Connection Limits**: Prevent unbounded memory growth
2. **Add Bounded Channels**: Prevent message queue buildup
3. **Add Metrics**: Track connection count, message queue sizes, broadcast latencies
4. **Add Health Checks**: Monitor WebSocket subsystem health
5. **Add Rate Limiting**: Per-connection message rate limits
6. **Consider Redis Backend**: For multi-server deployments

## Testing Recommendations

1. **Load Testing**: Test with 10K+ concurrent connections
2. **Slow Client Testing**: Test with clients that read slowly
3. **Rapid Connect/Disconnect**: Test connection churn
4. **Large Message Broadcasting**: Test with 1MB+ messages
5. **Concurrent Broadcasts**: Test multiple simultaneous broadcasts
