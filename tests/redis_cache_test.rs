#![cfg(feature = "cache-redis")]

use std::sync::{Arc, Mutex};
use std::time::Duration;
use tideway::{cache::RedisCache, traits::cache::Cache};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

// A small RESP server that records every command it receives. `SCAN` returns two pages
// of keys so `clear()` has to follow the cursor.
struct RecordingRedis {
    url: String,
    commands: Arc<Mutex<Vec<Vec<String>>>>,
    task: tokio::task::JoinHandle<()>,
}

impl RecordingRedis {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("redis://{}/", listener.local_addr().unwrap());
        let commands = Arc::new(Mutex::new(Vec::new()));
        let recorded = commands.clone();
        let task = tokio::spawn(async move {
            let mut clients = tokio::task::JoinSet::new();
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let recorded = recorded.clone();
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
                            args.push(String::from_utf8_lossy(&arg).into_owned());
                        }
                        let reply = match args[0].as_str() {
                            "PING" => "+PONG\r\n",
                            "GET" => "$-1\r\n",
                            "DEL" => ":1\r\n",
                            "CLIENT" | "PSETEX" => "+OK\r\n",
                            "SCAN" if args[1] == "0" => {
                                "*2\r\n$1\r\n7\r\n*2\r\n$7\r\ncache:a\r\n$7\r\ncache:b\r\n"
                            }
                            "SCAN" => "*2\r\n$1\r\n0\r\n*1\r\n$7\r\ncache:c\r\n",
                            command => panic!("unexpected command: {command}"),
                        };
                        if args[0] != "CLIENT" {
                            recorded.lock().unwrap().push(args);
                        }
                        if socket.get_mut().write_all(reply.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        Self {
            url,
            commands,
            task,
        }
    }

    fn take_commands(&self) -> Vec<Vec<String>> {
        std::mem::take(&mut *self.commands.lock().unwrap())
    }
}

impl Drop for RecordingRedis {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn command(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| arg.to_string()).collect()
}

#[tokio::test]
async fn keys_are_namespaced_under_default_prefix() {
    let server = RecordingRedis::start().await;
    let cache = RedisCache::new(&server.url, Duration::from_secs(60)).unwrap();

    cache.get_bytes("user:1").await.unwrap();
    cache
        .set_bytes("user:1", b"v".to_vec(), None)
        .await
        .unwrap();
    cache.delete("user:1").await.unwrap();

    assert_eq!(
        server.take_commands(),
        vec![
            command(&["GET", "cache:user:1"]),
            command(&["PSETEX", "cache:user:1", "60000", "v"]),
            command(&["DEL", "cache:user:1"]),
        ]
    );
}

#[tokio::test]
async fn sub_second_ttl_is_sent_in_milliseconds() {
    let server = RecordingRedis::start().await;
    let cache = RedisCache::new(&server.url, Duration::from_secs(60)).unwrap();

    cache
        .set_bytes("k", b"v".to_vec(), Some(Duration::from_millis(250)))
        .await
        .unwrap();
    cache
        .set_bytes("k", b"v".to_vec(), Some(Duration::ZERO))
        .await
        .unwrap();

    assert_eq!(
        server.take_commands(),
        vec![
            command(&["PSETEX", "cache:k", "250", "v"]),
            command(&["PSETEX", "cache:k", "1", "v"]),
        ]
    );
}

#[tokio::test]
async fn clear_deletes_only_prefixed_keys_without_flushing_database() {
    let server = RecordingRedis::start().await;
    let cache = RedisCache::new(&server.url, Duration::from_secs(60)).unwrap();

    cache.clear().await.unwrap();

    assert_eq!(
        server.take_commands(),
        vec![
            command(&["SCAN", "0", "MATCH", "cache:*", "COUNT", "500"]),
            command(&["DEL", "cache:a", "cache:b"]),
            command(&["SCAN", "7", "MATCH", "cache:*", "COUNT", "500"]),
            command(&["DEL", "cache:c"]),
        ]
    );
}

#[tokio::test]
async fn custom_prefix_is_used_for_keys_and_escaped_for_clear() {
    let server = RecordingRedis::start().await;
    let cache = RedisCache::new(&server.url, Duration::from_secs(60))
        .unwrap()
        .with_prefix("app[1]:");

    cache.delete("k").await.unwrap();
    // The fake server ignores the pattern, so only the SCAN arguments matter here.
    cache.clear().await.unwrap();

    let commands = server.take_commands();
    assert_eq!(commands[0], command(&["DEL", "app[1]:k"]));
    assert_eq!(
        commands[1],
        command(&["SCAN", "0", "MATCH", r"app\[1\]:*", "COUNT", "500"])
    );
}
