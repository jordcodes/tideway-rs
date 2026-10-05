#![cfg(feature = "cache-redis")]

//! `RedisCache::clear()` must only remove cache entries, never other data (such as the
//! `jobs:*` keys used by `RedisJobQueue`) stored in the same Redis database.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tideway::{cache::RedisCache, traits::cache::Cache};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

type Store = Arc<Mutex<State>>;

#[derive(Default)]
struct State {
    keys: BTreeMap<Vec<u8>, Vec<Vec<u8>>>,
    /// `SCAN` cursor `n` resumes at the key `cursors[n - 1]` (inclusive). Cursors point at keys
    /// rather than positions so deleting keys between calls never skips any, as Redis guarantees.
    cursors: Vec<Vec<u8>>,
}

// A small in-process RESP server that keeps real key state, so tests can observe which keys a
// command removes without requiring an external Redis. Strings are stored as a one-element value;
// lists, sets and sorted sets as their members.
struct TestRedis {
    url: String,
    store: Store,
    task: tokio::task::JoinHandle<()>,
}

impl TestRedis {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("redis://{}/", listener.local_addr().unwrap());
        let store: Store = Arc::default();
        let shared = store.clone();
        let task = tokio::spawn(async move {
            let mut clients = tokio::task::JoinSet::new();
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let store = shared.clone();
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
                        let reply = handle(&store, &args);
                        if socket.get_mut().write_all(&reply).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        Self { url, store, task }
    }

    fn insert(&self, key: &str, values: &[&str]) {
        self.store.lock().unwrap().keys.insert(
            key.as_bytes().to_vec(),
            values.iter().map(|v| v.as_bytes().to_vec()).collect(),
        );
    }

    fn keys(&self) -> Vec<String> {
        self.store
            .lock()
            .unwrap()
            .keys
            .keys()
            .map(|key| String::from_utf8(key.clone()).unwrap())
            .collect()
    }
}

impl Drop for TestRedis {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn bulk(value: &[u8]) -> Vec<u8> {
    let mut reply = format!("${}\r\n", value.len()).into_bytes();
    reply.extend_from_slice(value);
    reply.extend_from_slice(b"\r\n");
    reply
}

fn array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut reply = format!("*{}\r\n", items.len()).into_bytes();
    for item in items {
        reply.extend(bulk(item));
    }
    reply
}

/// Redis glob matching for the subset used by `SCAN MATCH`: `*`, `?` and `\` escapes.
fn glob_match(pattern: &[u8], key: &[u8]) -> bool {
    match pattern.split_first() {
        None => key.is_empty(),
        Some((b'*', rest)) => (0..=key.len()).any(|i| glob_match(rest, &key[i..])),
        Some((b'?', rest)) => !key.is_empty() && glob_match(rest, &key[1..]),
        Some((b'\\', rest)) if !rest.is_empty() => {
            key.first() == Some(&rest[0]) && glob_match(&rest[1..], &key[1..])
        }
        Some((byte, rest)) => key.first() == Some(byte) && glob_match(rest, &key[1..]),
    }
}

fn handle(store: &Store, args: &[Vec<u8>]) -> Vec<u8> {
    let mut state = store.lock().unwrap();
    let State {
        keys: store,
        cursors,
    } = &mut *state;
    let int = |n: usize| format!(":{n}\r\n").into_bytes();
    match args[0].to_ascii_uppercase().as_slice() {
        b"PING" => b"+PONG\r\n".to_vec(),
        b"CLIENT" => b"+OK\r\n".to_vec(),
        b"GET" => match store.get(&args[1]) {
            Some(value) => bulk(&value[0]),
            None => b"$-1\r\n".to_vec(),
        },
        b"SET" => {
            store.insert(args[1].clone(), vec![args[2].clone()]);
            b"+OK\r\n".to_vec()
        }
        b"SETEX" => {
            store.insert(args[1].clone(), vec![args[3].clone()]);
            b"+OK\r\n".to_vec()
        }
        b"DEL" => int(args[1..]
            .iter()
            .filter(|key| store.remove(*key).is_some())
            .count()),
        b"FLUSHDB" => {
            store.clear();
            b"+OK\r\n".to_vec()
        }
        b"LPUSH" => {
            let list = store.entry(args[1].clone()).or_default();
            for value in &args[2..] {
                list.insert(0, value.clone());
            }
            int(list.len())
        }
        b"SADD" => {
            let set = store.entry(args[1].clone()).or_default();
            if !set.contains(&args[2]) {
                set.push(args[2].clone());
            }
            int(1)
        }
        b"ZADD" => {
            store
                .entry(args[1].clone())
                .or_default()
                .push(args[3].clone());
            int(1)
        }
        b"RPOPLPUSH" => {
            let Some(value) = store.get_mut(&args[1]).and_then(Vec::pop) else {
                return b"$-1\r\n".to_vec();
            };
            store.retain(|_, values| !values.is_empty());
            store
                .entry(args[2].clone())
                .or_default()
                .insert(0, value.clone());
            bulk(&value)
        }
        b"EVALSHA" => int(0),
        b"SCAN" => {
            let cursor: usize = std::str::from_utf8(&args[1]).unwrap().parse().unwrap();
            let mut pattern = b"*".to_vec();
            let mut count = 10;
            for option in args[2..].chunks(2) {
                match option[0].to_ascii_uppercase().as_slice() {
                    b"MATCH" => pattern = option[1].clone(),
                    b"COUNT" => count = std::str::from_utf8(&option[1]).unwrap().parse().unwrap(),
                    other => panic!("unexpected SCAN option: {:?}", other),
                }
            }
            let start = match cursor {
                0 => Vec::new(),
                n => cursors[n - 1].clone(),
            };
            let mut page = store.range(start..).map(|(key, _)| key.clone());
            let visited: Vec<_> = page.by_ref().take(count).collect();
            let next = match page.next() {
                Some(key) => {
                    cursors.push(key);
                    cursors.len()
                }
                None => 0,
            };
            let matched: Vec<_> = visited
                .into_iter()
                .filter(|key| glob_match(&pattern, key))
                .collect();
            let mut reply = b"*2\r\n".to_vec();
            reply.extend(bulk(next.to_string().as_bytes()));
            reply.extend(array(&matched));
            reply
        }
        command => panic!("unexpected command: {:?}", String::from_utf8_lossy(command)),
    }
}

#[tokio::test]
async fn clear_removes_cache_entries_but_keeps_jobs_in_shared_database() {
    let server = TestRedis::start().await;
    server.insert("jobs:pending", &[r#"{"id":"1"}"#]);
    server.insert("jobs:scheduled", &[r#"{"id":"2"}"#]);
    server.insert("jobs:processing:worker-1", &[r#"{"id":"3"}"#]);
    server.insert("jobs:failed", &[r#"{"id":"4"}"#]);
    server.insert("session:abc", &["other app data"]);

    let cache = RedisCache::new(&server.url, Duration::from_secs(60)).unwrap();
    // Enough entries that clearing has to follow the SCAN cursor across several pages.
    for i in 0..1200 {
        cache
            .set_bytes(&format!("user:{i}"), vec![1], None)
            .await
            .unwrap();
    }
    assert_eq!(cache.get_bytes("user:7").await.unwrap(), Some(vec![1]));

    cache.clear().await.unwrap();

    for i in [0, 7, 599, 1199] {
        assert_eq!(cache.get_bytes(&format!("user:{i}")).await.unwrap(), None);
    }
    assert_eq!(
        server.keys(),
        [
            "jobs:failed",
            "jobs:pending",
            "jobs:processing:worker-1",
            "jobs:scheduled",
            "session:abc",
        ]
    );
}

#[tokio::test]
async fn clear_does_not_treat_glob_characters_in_prefix_as_wildcards() {
    let server = TestRedis::start().await;
    let cache = RedisCache::new(&server.url, Duration::from_secs(60))
        .unwrap()
        .with_prefix("app*:");
    cache.set_bytes("key", vec![1], None).await.unwrap();
    server.insert("application:key", &["unrelated"]);

    cache.clear().await.unwrap();

    assert_eq!(cache.get_bytes("key").await.unwrap(), None);
    assert_eq!(server.keys(), ["application:key"]);
}

#[tokio::test]
async fn caches_with_different_prefixes_are_independent() {
    let server = TestRedis::start().await;
    let users = RedisCache::new(&server.url, Duration::from_secs(60))
        .unwrap()
        .with_prefix("users:");
    let pages = RedisCache::new(&server.url, Duration::from_secs(60))
        .unwrap()
        .with_prefix("pages:");
    users.set_bytes("1", vec![1], None).await.unwrap();
    pages.set_bytes("1", vec![2], None).await.unwrap();

    users.clear().await.unwrap();

    assert_eq!(users.get_bytes("1").await.unwrap(), None);
    assert_eq!(pages.get_bytes("1").await.unwrap(), Some(vec![2]));
}

#[cfg(feature = "jobs-redis")]
#[tokio::test]
async fn enqueued_and_scheduled_jobs_survive_cache_clear() {
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
    let queue = RedisJobQueue::new(&server.url, Some("worker-1".into()), 3, 5).unwrap();
    let cache = RedisCache::new(&server.url, Duration::from_secs(60)).unwrap();
    let job_id = queue.enqueue(&TestJob).await.unwrap();
    queue
        .schedule(&TestJob, chrono::Utc::now() + chrono::Duration::hours(1))
        .await
        .unwrap();
    cache.set_bytes("key", vec![1], None).await.unwrap();

    cache.clear().await.unwrap();

    assert_eq!(cache.get_bytes("key").await.unwrap(), None);
    assert!(server.keys().contains(&"jobs:scheduled".to_string()));
    let job = queue
        .dequeue()
        .await
        .unwrap()
        .expect("pending job was lost");
    assert_eq!(job.job_id, job_id);
    queue.shutdown().await;
}
