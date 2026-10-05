#![cfg(any(feature = "cache-redis", feature = "jobs-redis"))]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

// A small RESP server counts accepted sockets without requiring an external Redis.
// It returns empty collections for reads and successful replies for writes.
struct TestRedis {
    url: String,
    connections: Arc<AtomicUsize>,
    scripts: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl TestRedis {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("redis://{}/", listener.local_addr().unwrap());
        let connections = Arc::new(AtomicUsize::new(0));
        let scripts = Arc::new(AtomicUsize::new(0));
        let accepted = connections.clone();
        let script_count = scripts.clone();
        let task = tokio::spawn(async move {
            let mut clients = tokio::task::JoinSet::new();
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                accepted.fetch_add(1, Ordering::SeqCst);
                let scripts = script_count.clone();
                clients.spawn(async move {
                    let mut socket = BufReader::new(socket);
                    loop {
                        let mut line = String::new();
                        if socket.read_line(&mut line).await.unwrap() == 0 {
                            break;
                        }
                        let count: usize = line.trim().strip_prefix('*').unwrap().parse().unwrap();
                        let mut args = Vec::new();
                        for _ in 0..count {
                            line.clear();
                            socket.read_line(&mut line).await.unwrap();
                            let len: usize =
                                line.trim().strip_prefix('$').unwrap().parse().unwrap();
                            let mut arg = vec![0; len + 2];
                            socket.read_exact(&mut arg).await.unwrap();
                            arg.truncate(len);
                            args.push(arg);
                        }
                        let reply = match args[0].as_slice() {
                            b"PING" => "+PONG\r\n",
                            b"GET" | b"RPOPLPUSH" => "$-1\r\n",
                            b"BRPOPLPUSH" => {
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                "$-1\r\n"
                            }
                            b"LRANGE" => "*0\r\n",
                            b"EVALSHA" => {
                                scripts.fetch_add(1, Ordering::SeqCst);
                                ":0\r\n"
                            }
                            b"LPUSH" | b"ZADD" | b"SADD" | b"DEL" => ":1\r\n",
                            b"CLIENT" | b"SETEX" | b"PSETEX" => "+OK\r\n",
                            b"SCAN" => "*2\r\n$1\r\n0\r\n*0\r\n",
                            command => panic!("unexpected command: {:?}", command),
                        };
                        if socket.get_mut().write_all(reply.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        Self {
            url,
            connections,
            scripts,
            task,
        }
    }
}
impl Drop for TestRedis {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(feature = "cache-redis")]
#[tokio::test]
async fn cache_operations_and_clones_reuse_one_connection() {
    use tideway::{cache::RedisCache, traits::cache::Cache};
    let server = TestRedis::start().await;
    let cache = RedisCache::new(&server.url, Duration::from_secs(60)).unwrap();
    let clone = cache.clone();
    let (a, b) = tokio::join!(cache.ping(), clone.ping());
    assert!(a && b);
    cache.set_bytes("key", vec![1], None).await.unwrap();
    assert_eq!(clone.get_bytes("key").await.unwrap(), None);
    cache.delete("key").await.unwrap();
    clone.clear().await.unwrap();
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "jobs-redis")]
#[tokio::test]
async fn job_operations_clones_and_scheduler_reuse_one_connection() {
    use tideway::{jobs::RedisJobQueue, traits::job::JobQueue};
    #[derive(Debug)]
    struct TestJob;
    #[async_trait::async_trait]
    impl tideway::traits::job::Job for TestJob {
        fn job_type(&self) -> &str {
            "test"
        }
        fn serialize(&self) -> tideway::Result<serde_json::Value> {
            Ok(serde_json::json!({}))
        }
        async fn execute(&self, _: &tideway::AppContext) -> tideway::Result<()> {
            Ok(())
        }
    }
    let server = TestRedis::start().await;
    let queue = RedisJobQueue::new(&server.url, None, 3, 5).unwrap();
    let clone = queue.clone();
    let (a, b) = tokio::join!(queue.ping(), clone.ping());
    assert!(a && b);
    queue.complete("missing").await.unwrap();
    clone.fail("missing", "error".into()).await.unwrap();
    queue.retry("missing").await.unwrap();
    queue.enqueue(&TestJob).await.unwrap();
    clone.schedule(&TestJob, chrono::Utc::now()).await.unwrap();
    let reader = clone.clone();
    let dequeue = tokio::spawn(async move { reader.dequeue().await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;
    tokio::time::timeout(Duration::from_secs(1), queue.enqueue(&TestJob))
        .await
        .unwrap()
        .unwrap();
    // Allow at least two scheduler ticks to exercise its connection reuse too.
    tokio::time::timeout(Duration::from_secs(4), async {
        while server.scripts.load(Ordering::SeqCst) < 4 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(6), dequeue)
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
    queue.shutdown().await;
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
}
