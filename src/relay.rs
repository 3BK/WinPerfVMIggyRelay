use crate::guards::PipeGuard;
use crate::audit::AuditGuard;
use crate::config::RelayConfig;
use std::sync::Arc; // Fixes E0425 [cite: 22]
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::windows::named_pipe::ServerOptions;

// Iggy 0.10 Path Updates (Fixes E0432, E0433) [cite: 1, 2, 4]
use iggy::client::Client; 
use iggy::messages::send_messages::{Message, Partitioning, SendMessages};
use iggy::identifier::Identifier;

use rand::Rng;
use winlog::Level;

pub async fn run_ingestion(pipe_path: String, s_id: u32, t_id: u32, client: impl Client, audit: Arc<AuditGuard>) {
    let mut server = ServerOptions::new().first_pipe_instance(true).create(&pipe_path).unwrap();
    let stream = Identifier::numeric(s_id).unwrap();
    let topic = Identifier::numeric(t_id).unwrap();

    loop {
        if server.connect().await.is_ok() {
            let _g = PipeGuard(&mut server);
            let mut buf = vec![0; 65536];
            while let Ok(n) = _g.0.read(&mut buf).await {
                if n == 0 { break; }
                let msg = Message::from_str(&String::from_utf8_lossy(&buf[..n])).unwrap();
                let _ = client.send_messages(&mut SendMessages {
                    stream_id: stream.clone(),
                    topic_id: topic.clone(),
                    partitioning: Partitioning::default(),
                    messages: vec![msg],
                }).await;
            }
        }
    }
}

pub async fn run_egress(url: String, http: reqwest::Client, cfg: RelayConfig, audit: Arc<AuditGuard>) {
    let mut backoff = cfg.base_backoff_ms;
    let mut rng = rand::rng(); // Rand 0.10 syntax (Fixes E0425) [cite: 27, 28]

    loop {
        match http.post(&url).body("data").send().await {
            Ok(r) if r.status().is_success() => {
                backoff = cfg.base_backoff_ms;
                tokio::time::sleep(Duration::from_millis(100)).await;
            },
            _ => {
                use rand::Rng;
                let sleep = backoff + rng.random_range(0..cfg.max_jitter_ms);
                // Fixes E0603: Use log::Level [cite: 36]
                audit.log(log::Level::Warn, 500, &format!("Backoff: {}ms", sleep));
                tokio::time::sleep(Duration::from_millis(sleep)).await;
                backoff = std::cmp::min(backoff * 2, cfg.max_backoff_ms);
            }
        }
    }
}
