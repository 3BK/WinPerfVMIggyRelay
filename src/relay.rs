use crate::guards::PipeGuard;
use crate::audit::AuditGuard;
use crate::config::RelayConfig;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::net::windows::named_pipe::ServerOptions;

// Embedded Storage - Fjall 2.x
use fjall::PartitionHandle;

// Randomness & Logging
use rand::Rng;
use rand::RngExt;
use log::Level;

/// Ingests data from a Windows Named Pipe and persists it into a Fjall LSM-tree partition.
/// Uses a monotonic key composed of a timestamp and a counter to ensure chronological ordering.
pub async fn run_ingestion(
    pipe_path: String, 
    db_partition: PartitionHandle, 
    audit: Arc<AuditGuard>
) {
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_path)
        .expect("NIST AC-4: Failed to create secure named pipe");

    // Counter provides uniqueness if multiple messages arrive within the same millisecond
    let mut counter: u64 = 0;

    loop {
        if server.connect().await.is_ok() {
            let _g = PipeGuard(&mut server);
            let mut buf = vec![0; 65536];

            while let Ok(n) = _g.0.read(&mut buf).await {
                if n == 0 { break; }

                // Generate a monotonic key: [timestamp_ms (8 bytes)][counter (8 bytes)]
                // Big-Endian (to_be_bytes) is critical for lexicographical sorting in the LSM-tree
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                
                let mut key = [0u8; 16];
                key[..8].copy_from_slice(&now.to_be_bytes());
                key[8..].copy_from_slice(&counter.to_be_bytes());

                // Atomic write to the embedded store
                if let Err(e) = db_partition.insert(key, &buf[..n]) {
                    audit.log(Level::Error, 502, &format!("Fjall Write Error: {}", e));
                } else {
                    counter = counter.wrapping_add(1);
                }
            }
        }
        // Yield briefly if the connection fails to prevent tight-looping
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Polls the Fjall partition for the oldest message and attempts to send it to the remote URL.
/// Implements at-least-once delivery: data is only deleted after a successful HTTP 200 response.
pub async fn run_egress(
    url: String, 
    http: reqwest::Client, 
    db_partition: PartitionHandle, 
    cfg: RelayConfig, 
    audit: Arc<AuditGuard>
) {
    let mut backoff = cfg.base_backoff_ms;
    let mut rng = rand::rng(); 

    loop {
        // Retrieve the oldest item (first available key in the sorted LSM tree)
        // Fjall iterators are efficient and respect the sorted order of keys
        let first_item = db_partition.iter().next();

        if let Some(Ok((key, value))) = first_item {
            match http.post(&url).body(value.to_vec()).send().await {
                Ok(r) if r.status().is_success() => {
                    // SUCCESS: Remove from persistent store now that it's successfully egressed
                    let _ = db_partition.remove(key);
                    
                    // Reset backoff on success
                    backoff = cfg.base_backoff_ms;
                    
                    // Tiny yield to prevent CPU pinning during high-volume bursts
                    tokio::time::sleep(Duration::from_millis(1)).await;
                },
                _ => {
                    // FAILURE: Apply Exponential Backoff with Jitter (NIST/PCI compliance)
                    let sleep_ms = backoff + rng.random_range(0..cfg.max_jitter_ms);
                    
                    audit.log(Level::Warn, 501, &format!("Egress Failure: Retrying in {}ms", sleep_ms));
                    
                    tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                    
                    // Double backoff for next attempt, capped at max_backoff_ms
                    backoff = std::cmp::min(backoff * 2, cfg.max_backoff_ms);
                }
            }
        } else {
            // Queue is empty: Wait for new data to arrive via ingestion
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}
