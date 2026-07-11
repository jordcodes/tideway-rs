use futures_util::StreamExt;
use serde::Serialize;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tokio_tungstenite::connect_async;

#[derive(Serialize)]
struct ResultSummary {
    clients: usize,
    connected_ms: u128,
    broadcast_delivery_ms: u128,
    received: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let clients = std::env::args()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000);
    let ws_url =
        std::env::var("WS_URL").unwrap_or_else(|_| "ws://127.0.0.1:18080/load/ws".to_string());
    let http_url = std::env::var("HTTP_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18080/load/broadcast".to_string());

    let connect_started = Instant::now();
    let mut sockets = Vec::with_capacity(clients);
    for _ in 0..clients {
        let (socket, _) = connect_async(&ws_url).await?;
        sockets.push(socket);
    }
    let connected_ms = connect_started.elapsed().as_millis();

    let broadcast_started = Instant::now();
    reqwest::Client::new()
        .post(http_url)
        .send()
        .await?
        .error_for_status()?;

    let mut received = 0;
    for socket in &mut sockets {
        if timeout(Duration::from_secs(10), socket.next())
            .await?
            .transpose()?
            .is_some()
        {
            received += 1;
        }
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&ResultSummary {
            clients,
            connected_ms,
            broadcast_delivery_ms: broadcast_started.elapsed().as_millis(),
            received,
        })?
    );
    if received != clients {
        anyhow::bail!("only {received}/{clients} clients received the broadcast");
    }
    Ok(())
}
