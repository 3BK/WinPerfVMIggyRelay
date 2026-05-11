use crate::audit::AuditGuard;
use crate::config::RelayConfig;
use crate::guards::PipeGuard;

use fjall::Keyspace;
use log::Level;
use rand::RngExt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::net::windows::named_pipe::ServerOptions;

/// Stored value encoding (unchanged):
/// [0..8)   = ingest_ts_ns (u64 BE)
/// [8..12)  = payload_len (u32 BE)
/// [12..]   = payload bytes
const HEADER_LEN: usize = 8 + 4;

/// Fjall key encoding (new):
/// [0..8)   = timestamp_ns (u64 BE)
/// [8..16)  = counter (u64 BE)
const KEY_LEN: usize = 16;

/// Build a lexicographically sortable key: (timestamp_ns_be, counter_be)
fn make_key(ts_ns: u64, ctr: u64) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    key[..8].copy_from_slice(&ts_ns.to_be_bytes());
    key[8..].copy_from_slice(&ctr.to_be_bytes());
    key
}

/// Extract timestamp_ns from a (timestamp_ns, counter) key.
fn key_timestamp_ns(key: &[u8]) -> Option<u64> {
    if key.len() < 8 {
        return None;
    }
    Some(u64::from_be_bytes([
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
    ]))
}

/// Ingests data from a Windows Named Pipe and persists it into a Fjall Keyspace.
/// Uses (timestamp_ns, counter) as the key for restart-safe FIFO ordering.
///
/// Important:
/// - Fjall stores keys in lexicographic order; big-endian integer keys preserve numeric ordering,
///   which gives predictable ordering for FIFO scans. 【1-575fa8】【2-fae269】
/// - If the wall clock moves backwards (NTP step), we clamp timestamps to keep ordering monotonic.
pub async fn run_ingestion(pipe_path: String, keyspace: Keyspace, audit: Arc<AuditGuard>) {
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_path)
        .expect("NIST AC-4: Failed to create secure named pipe");

    // Used to keep keys monotonic even if SystemTime steps backward.
    let mut last_ts_ns: u64 = 0;

    // Counter used to break ties within the same timestamp_ns.
    let mut counter: u64 = 0;

    loop {
        if server.connect().await.is_ok() {
            let _g = PipeGuard(&mut server);

            // Consider making this configurable.
            let mut buf = vec![0u8; 65_536];

            while let Ok(n) = _g.0.read(&mut buf).await {
                if n == 0 {
                    break;
                }

                // Wall-clock timestamp; may step backward due to NTP.
                let mut now_ns = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;

                // Clamp to monotonic time to preserve FIFO ordering.
                if now_ns < last_ts_ns {
                    now_ns = last_ts_ns;
                }

                // Reset counter on timestamp change, otherwise increment.
                if now_ns != last_ts_ns {
                    counter = 0;
                    last_ts_ns = now_ns;
                } else {
                    counter = counter.wrapping_add(1);
                }

                // Key: (timestamp_ns_be, counter_be)
                let key = make_key(now_ns, counter);

                // Value (unchanged): [timestamp_ns][payload_len][payload]
                let mut value = Vec::with_capacity(HEADER_LEN + n);
                value.extend_from_slice(&now_ns.to_be_bytes());
                value.extend_from_slice(&(n as u32).to_be_bytes());
                value.extend_from_slice(&buf[..n]);

                if let Err(e) = keyspace.insert(&key, &value) {
                    audit.log(Level::Error, 1022, &format!("Fjall insert failed: {e}"));
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Polls the Fjall Keyspace for the oldest batch and attempts to send it to the remote URL.
/// Implements batching, exponential backoff, and audit logging.
///
/// Notes:
/// - Fjall iter yields a Guard; we must extract key/value from it via Guard::into_inner(). 【3-c1b7cb】
/// - HTTP 400 is treated as non-retriable (dead-letter TODO).
/// - Sends only the payload bytes (skipping the envelope header).
pub async fn run_egress(
    url: String,
    http: reqwest::Client,
    keyspace: Keyspace,
    cfg: RelayConfig,
    audit: Arc<AuditGuard>,
) {
    let base_backoff = cfg.forwarder.base_backoff_ms.unwrap_or(500);
    let max_backoff = cfg.forwarder.max_backoff_ms.unwrap_or(30_000);
    let max_jitter = cfg.forwarder.max_jitter_ms.unwrap_or(2_000);
    let batch_size = cfg.forwarder.batch_size.unwrap_or(1_000);

    let mut backoff = base_backoff;
    let mut rng = rand::rng();

    loop {
        // Collect up to batch_size oldest records (FIFO by key ordering).
        let mut batch: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(batch_size);

        for guard in keyspace.iter().take(batch_size) {
            match guard.into_inner() {
                Ok((k, v_opt)) => {
                    if let Some(v) = v_opt {
                        batch.push((k.to_vec(), v.to_vec()));
                    }
                }
                Err(e) => {
                    audit.log(Level::Warn, 1031, &format!("Fjall iter read error: {e}"));
                }
            }
        }

        if batch.is_empty() {
            tokio::time::sleep(Duration::from_millis(500)).await;
            continue;
        }

        // Build payload by concatenating payload bytes from each record (skip envelope).
        let mut payload: Vec<u8> = Vec::new();

        for (_k, v) in &batch {
            if v.len() < HEADER_LEN {
                audit.log(Level::Warn, 1031, "Stored record too small to contain header; skipping.");
                continue;
            }

            let declared_len = u32::from_be_bytes([v[8], v[9], v[10], v[11]]) as usize;
            let available = v.len().saturating_sub(HEADER_LEN);
            let take_len = declared_len.min(available);

            payload.extend_from_slice(&v[HEADER_LEN..HEADER_LEN + take_len]);
        }

        if payload.is_empty() {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }

        let started = Instant::now();
        match http.post(&url).body(payload).send().await {
            Ok(resp) if resp.status().is_success() => {
                for (k, _v) in &batch {
                    let _ = keyspace.remove(k);
                }

                let latency_ms = started.elapsed().as_millis();
                audit.log(
                    Level::Info,
                    1030,
                    &format!("Batch delivered; count={}; latency={}ms", batch.len(), latency_ms),
                );

                backoff = base_backoff;
                tokio::time::sleep(Duration::from_millis(1)).await;
            }

            Ok(resp) if resp.status().as_u16() == 400 => {
                // Non-retriable payload. Spec says: move to dead-letter keyspace.
                // TODO: implement dead-letter keyspace and write records there before removal.
                audit.log(
                    Level::Error,
                    1033,
                    &format!(
                        "Dead-letter (not retried): HTTP 400; dropping batch_size={}",
                        batch.len()
                    ),
                );

                // Drop records to prevent infinite retry loop.
                for (k, _v) in &batch {
                    let _ = keyspace.remove(k);
                }

                backoff = base_backoff;
                tokio::time::sleep(Duration::from_millis(250)).await;
            }

            Ok(resp) => {
                let status = resp.status().as_u16();
                let sleep_ms = backoff + rng.random_range(0..max_jitter);

                audit.log(
                    Level::Warn,
                    1031,
                    &format!("Egress failure HTTP {}; retrying in {}ms", status, sleep_ms),
                );

                tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                backoff = std::cmp::min(backoff.saturating_mul(2), max_backoff);
            }

            Err(e) => {
                let sleep_ms = backoff + rng.random_range(0..max_jitter);

                audit.log(
                    Level::Warn,
                    1031,
                    &format!("Egress failure (transport): {e}; retrying in {}ms", sleep_ms),
                );

                tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                backoff = std::cmp::min(backoff.saturating_mul(2), max_backoff);
            }
        }
    }
}

/// Retention task: periodically enforces max age and max disk size.
///
/// Optimization:
/// - Since timestamp_ns is in the key, age checks can parse the key rather than reading the value.
/// - Deletes are capped per pass to avoid IO starvation.
///
/// Fjall stores keys in lexicographic order, so scanning from the start evicts oldest first,
/// which aligns with FIFO eviction. 【1-575fa8】【2-fae269】
pub async fn run_retention(keyspace: Keyspace, cfg: RelayConfig, audit: Arc<AuditGuard>) {
    let interval = cfg.buffer.retention_check_interval_seconds.unwrap_or(60);
    let max_age_seconds = cfg.buffer.max_age_seconds.unwrap_or(259_200); // 72h default
    let max_disk_bytes = cfg.buffer.max_disk_bytes.unwrap_or(4_294_967_296); // 4GiB default

    let max_deletes_per_pass: usize = 10_000;

    loop {
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let cutoff_ns = now_ns.saturating_sub(max_age_seconds.saturating_mul(1_000_000_000));

        // 1) Age-based eviction (bounded)
        let mut deleted_age = 0usize;

        for guard in keyspace.iter().take(max_deletes_per_pass) {
            let (k, _v_opt) = match guard.into_inner() {
                Ok(pair) => pair,
                Err(_) => continue,
            };

            let k_bytes = k.as_ref();
            let Some(ts_ns) = key_timestamp_ns(k_bytes) else {
                // Bad key; remove.
                let _ = keyspace.remove(k_bytes);
                deleted_age += 1;
                if deleted_age >= max_deletes_per_pass {
                    break;
                }
                continue;
            };

            if ts_ns < cutoff_ns {
                let _ = keyspace.remove(k_bytes);
                deleted_age += 1;
                if deleted_age >= max_deletes_per_pass {
                    break;
                }
            } else {
                // Since keys are ordered oldest->newest, we can stop once not-expired.
                break;
            }
        }

        if deleted_age > 0 {
            audit.log(
                Level::Warn,
                1021,
                &format!("Retention (age): evicted_records={}", deleted_age),
            );
        }

        // 2) Disk-based eviction (bounded)
        let mut deleted_disk = 0usize;
        let mut disk = keyspace.disk_space();

        if disk > max_disk_bytes {
            for guard in keyspace.iter().take(max_deletes_per_pass) {
                let (k, _v_opt) = match guard.into_inner() {
                    Ok(pair) => pair,
                    Err(_) => continue,
                };

                let k_bytes = k.as_ref();
                let _ = keyspace.remove(k_bytes);
                deleted_disk += 1;

                disk = keyspace.disk_space();
                if disk <= max_disk_bytes || deleted_disk >= max_deletes_per_pass {
                    break;
                }
            }

            audit.log(
                Level::Warn,
                1021,
                &format!(
                    "Retention (disk): disk_bytes={} max_disk_bytes={} evicted_records={}",
                    disk, max_disk_bytes, deleted_disk
                ),
            );
        }

        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}
