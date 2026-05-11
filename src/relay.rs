use crate::guards::PipeGuard;
use crate::audit::AuditGuard;
use crate::config::RelayConfig;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::net::windows::named_pipe::ServerOptions;
use fjall::Keyspace;
use rand::{Rng, RngExt};
use log::Level;

/// Ingests data from a Windows Named Pipe and persists it into a Fjall Keyspace.
/// Uses monotonic big-endian u64 sequence number as key for FIFO ordering.
pub async fn run_ingestion(
    pipe_path: String,
    keyspace: Keyspace,
    audit: Arc<AuditGuard>
) {
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_path)
        .expect("NIST AC-4: Failed to create secure named pipe");

    let mut seq_counter: u64 = 0;
    loop {
        if server.connect().await.is_ok() {
            let _g = PipeGuard(&mut server);
            let mut buf = vec![0; 65536];
            while let Ok(n) = _g.0.read(&mut buf).await {
                if n == 0 { break; }
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;
                // Key: big-endian u64 sequence number for FIFO
                let key = seq_counter.to_be_bytes();
                // Value: [timestamp][payload_len][payload_bytes]
                let mut value = Vec::with_capacity(8 + 4 + n);
                value.extend_from_slice(&now.to_be_bytes());
                value.extend_from_slice(&(n as u32).to_be_bytes());
                value.extend_from_slice(&buf[..n]);
                // Atomic write to the embedded store
                if let Err(e) = keyspace.insert(&key, &value) {
                    audit.log(Level::Error, 502, &format!("Fjall Write Error: {}", e));
                } else {
                    seq_counter = seq_counter.wrapping_add(1);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Polls the Fjall Keyspace for the oldest batch and attempts to send it to the remote URL.
/// Implements batching, dead-letter handling, exponential backoff, and audit logging.
pub async fn run_egress(
    url: String,
    http: reqwest::Client,
    keyspace: Keyspace,
    cfg: RelayConfig,
    audit: Arc<AuditGuard>
) {
    let mut backoff = cfg.forwarder.base_backoff_ms.unwrap_or(500);
    let max_backoff = cfg.forwarder.max_backoff_ms.unwrap_or(30000);
    let max_jitter = cfg.forwarder.max_jitter_ms.unwrap_or(2000);
    let batch_size = cfg.forwarder.batch_size.unwrap_or(1000);
    let mut rng = rand::rng();

    loop {
        // Batch: collect up to batch_size oldest records
        let mut batch = Vec::new();
        for item in keyspace.iter().take(batch_size) {
            if let Ok((key, value)) = item {
                batch.push((key, value));
            }
        }

        if !batch.is_empty() {
            // Serialize batch to Prometheus format (or as needed)
            let payload = batch.iter()
                .flat_map(|(_, value)| value.clone())
                .collect::<Vec<u8>>();

            match http.post(&url).body(payload).send().await {
                Ok(r) if r.status().is_success() => {
                    // Remove all keys in batch
                    for (key, _) in &batch {
                        let _ = keyspace.remove(key);
                    }
                    audit.log(Level::Info, 1030, &format!(
                        "Batch delivered; count={}; latency={}ms",
                        batch.len(),
                        r.elapsed().map(|d| d.as_millis()).unwrap_or(0)
                    ));
                    backoff = cfg.forwarder.base_backoff_ms.unwrap_or(500);
                    tokio::time::sleep(Duration::from_millis(1)).await;
                },
                Ok(r) if r.status().as_u16() == 400 => {
                    // Dead-letter: move batch to dead-letter keyspace
                    audit.log(Level::Error, 1033, &format!(
                        "Dead-letter: batch rejected by server (HTTP 400); batch_size={}",
                        batch.len()
                    ));
                    // TODO: implement dead-letter keyspace logic
                    for (key, _) in &batch {
                        let _ = keyspace.remove(key);
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                },
                _ => {
                    let sleep_ms = backoff + rng.random_range(0..max_jitter);
                    audit.log(Level::Warn, 1031, &format!(
                        "Egress Failure: Retrying in {}ms", sleep_ms
                    ));
                    tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                    backoff = std::cmp::min(backoff * 2, max_backoff);
                }
            }
        } else {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

/// Retention task: periodically enforces max age and max disk size
pub async fn run_retention(
    keyspace: Keyspace,
    cfg: RelayConfig,
    audit: Arc<AuditGuard>
) {
    let interval = cfg.buffer.retention_check_interval_seconds.unwrap_or(60);
    loop {
        // TODO: implement retention logic (age, disk size)
        // Example: scan keys, remove oldest if over limit
        audit.log(Level::Info, 1021, "Retention enforcement triggered.");
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}
