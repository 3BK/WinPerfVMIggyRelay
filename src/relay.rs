use crate::guards::PipeGuard;
use crate::audit::AuditGuard;
use iggy::client::MessageClient;
use iggy::messages::send_messages::{Message as IggyMsg, SendMessages};
use iggy::identifier::Identifier;
use rand::Rng;
use winlog::Level;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::windows::named_pipe::ServerOptions;

pub async fn run_ingestion(pipe_path: String, s_id: u32, t_id: u32, mut iggy: impl MessageClient, audit: Arc<AuditGuard>) {
    let mut server = ServerOptions::new().first_pipe_instance(true).create(&pipe_path).unwrap();
    let stream = Identifier::numeric(s_id).unwrap();
    let topic = Identifier::numeric(t_id).unwrap();

    audit.log(Level::Info, 1001, "Named Pipe Ingestion Started.");

    loop {
        if server.connect().await.is_ok() {
            let _guard = PipeGuard(&mut server);
            audit.log(Level::Info, 1002, "VictoriaMetrics agent connected.");
            
            let mut buf = vec![0; 32768];
            while let Ok(n) = _guard.0.read(&mut buf).await {
                if n == 0 { break; }
                let msg = IggyMsg::from_str(&String::from_utf8_lossy(&buf[..n])).unwrap();
                let _ = iggy.send_messages(&mut SendMessages {
                    stream_id: stream.clone(), topic_id: topic.clone(),
                    partitioning: iggy::messages::send_messages::Partitioning::partition_id(1),
                    messages: vec![msg],
                }).await;
            }
            audit.log(Level::Info, 1003, "VictoriaMetrics agent disconnected.");
        }
    }
}

pub async fn run_egress(url: String, http: reqwest::Client, cfg: crate::config::RelayConfig, audit: Arc<AuditGuard>) {
    let mut backoff = cfg.base_backoff_ms;

    loop {
        // Logic to poll from Iggy here...
        let payload = "audit_heartbeat 1";

        match http.post(&url).body(payload).send().await {
            Ok(resp) if resp.status().is_success() => {
                backoff = cfg.base_backoff_ms;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            _ => {
                let jitter = rand::thread_rng().gen_range(0..cfg.max_jitter_ms);
                let sleep = backoff + jitter;
                
                audit.log(Level::Warning, 2001, &format!("Egress failed. Backoff: {}ms", sleep));
                tokio::time::sleep(Duration::from_millis(sleep)).await;
                backoff = std::cmp::min(backoff * 2, cfg.max_backoff_ms);
            }
        }
    }
}
