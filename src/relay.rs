use crate::audit::AuditGuard;
use crate::config::RelayConfig;
use crate::guards::PipeGuard;

use fjall::Keyspace;
use log::Level;
use rand::RngExt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::net::windows::named_pipe::ServerOptions;

/// Stored value encoding:
/// [0..8)   = ingest_ts_ns (u64 BE)
/// [8..12)  = payload_len (u32 BE)
/// [12..]   = payload bytes
const HEADER_LEN: usize = 8 + 4;

/// Fjall key encoding:
/// [0..8)   = timestamp_ns (u64 BE)
/// [8..16)  = counter (u64 BE)
const KEY_LEN: usize = 16;

/// Shared gate used to pause ingestion when disk high-water mark is hit.
/// This enforces backpressure without dropping unsent data.
#[derive(Debug)]
pub struct IngestGate {
    paused: AtomicBool,
}

impl IngestGate {
    pub fn new() -> Self {
        Self { paused: AtomicBool::new(false) }
    }

    pub fn set_paused(&self, v: bool) {
        self.paused.store(v, Ordering::Relaxed);
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }
}

/// Build a lexicographically sortable key: (timestamp_ns_be, counter_be).
/// Big-endian integer keys preserve numeric ordering under lexicographic comparison.
fn make_key(ts_ns: u64, ctr: u64) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    key[..8].copy_from_slice(&ts_ns.to_be_bytes());
    key[8..].copy_from_slice(&ctr.to_be_bytes());
    key
}

/// Ingests data from a Windows Named Pipe and persists it into a single Fjall Keyspace.
///
/// Guarantees:
/// - FIFO ordering by key (timestamp_ns, counter) big-endian.
/// - No record is deleted here.
/// - Backpressure: if gate is paused, ingestion stops reading the pipe (producer/pipe buffers apply backpressure).
pub async fn run_ingestion(
    pipe_path: String,
    keyspace: Keyspace,
    audit: Arc<AuditGuard>,
    gate: Arc<IngestGate>,
) {
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_path)
        .expect("NIST AC-4: Failed to create secure named pipe");

    // Keep timestamps monotonic to avoid key reordering if the system clock jumps backward.
    let mut last_ts_ns: u64 = 0;
    let mut counter: u64 = 0;

    loop {
        if server.connect().await.is_ok() {
            let _g = PipeGuard(&mut server);

            // Consider making this configurable (cfg.ingest.pipe_buffer_size).
            let mut buf = vec![0u8; 65_536];

            loop {
                // Backpressure: stop consuming input while disk is above the watermark.
                if gate.is_paused() {
                    audit.log(Level::Warn, 1023, "Ingest paused due to disk high-water mark.");
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                }

                let n = match _g.0.read(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        audit.log(Level::Warn, 1012, &format!("Named pipe read error: {e}"));
                        break;
                    }
                };

                if n == 0 {
                    break;
                }

                let mut now_ns = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;

                // Clamp backward time jumps to preserve monotonic ordering.
                if now_ns < last_ts_ns {
                    now_ns = last_ts_ns;
                }

                // Reset counter on timestamp change; else increment tie-breaker.
                if now_ns != last_ts_ns {
                    counter = 0;
                    last_ts_ns = now_ns;
                } else {
                    counter = counter.wrapping_add(1);
                }

                let key = make_key(now_ns, counter);

                // Value: [timestamp_ns][payload_len][payload]
                let mut value = Vec::with_capacity(HEADER_LEN + n);
                value.extend_from_slice(&now_ns.to_be_bytes());
                value.extend_from_slice(&(n as u32).to_be_bytes());
                value.extend_from_slice(&buf[..n]);

                if let Err(e) = keyspace.insert(&key, &value) {
                    audit.log(Level::Error, 1022, &format!("Fjall insert failed: {e}"));
                    // Avoid a tight loop in case of persistent disk/IO errors
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Disk guard task:
/// - Uses keyspace.disk_space() to monitor local buffer usage.
/// - Pauses ingestion when disk usage exceeds max_disk_bytes.
/// - Resumes ingestion once disk drops below a hysteresis threshold.
///
/// This provides "don't run out of disk" without deleting unsent data.
pub async fn run_disk_guard(
    keyspace: Keyspace,
    cfg: RelayConfig,
    audit: Arc<AuditGuard>,
    gate: Arc<IngestGate>,
) {
    // Reuse your existing interval knob; default to frequent checks because this is a safety mechanism.
    let interval_secs = cfg.buffer.retention_check_interval_seconds.unwrap_or(5).max(1);
    let max_disk_bytes = cfg.buffer.max_disk_bytes.unwrap_or(4_294_967_296);

    // Resume hysteresis at 95% of max to prevent rapid toggling.
    let resume_bytes = (max_disk_bytes as f64 * 0.95) as u64;

    loop {
        let disk = keyspace.disk_space();

        if disk >= max_disk_bytes {
            if !gate.is_paused() {
                gate.set_paused(true);
                audit.log(
                    Level::Error,
                    1023,
                    &format!(
                        "Disk high-water exceeded: disk_bytes={disk} max_disk_bytes={max_disk_bytes}. Pausing ingest."
                    ),
                );
            }
        } else if disk <= resume_bytes {
            if gate.is_paused() {
                gate.set_paused(false);
                audit.log(
                    Level::Info,
                    1034,
                    &format!(
                        "Disk back under threshold: disk_bytes={disk} resume_bytes={resume_bytes}. Resuming ingest."
                    ),
                );
            }
        }

        tokio::time::sleep(Duration::from_secs(interval_secs)).await;
    }
}

/// Egress loop:
/// - Strict FIFO: reads oldest records first from the single keyspace.
/// - Deletes records ONLY AFTER successful HTTP 2xx.
/// - Any non-success (including HTTP 400) keeps records and retries.
/// - This ensures all records are eventually sent when VictoriaMetrics becomes available.
///
/// Fjall iter yields Guard; extract with into_inner().
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
        // Collect up to batch_size oldest records (FIFO by key order).
        let mut batch: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(batch_size);

        for guard in keyspace.iter().take(batch_size) {
            match guard.into_inner() {
                // FIX: in Fjall 3.1, into_inner() yields (key, value) and value is not Option<T>. 【2-c5c646】【1-89c95c】
                Ok((k, v)) => {
                    batch.push((k.to_vec(), v.to_vec()));
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

        // Build payload: concatenate payload bytes from each record (skip envelope).
        // If a record is malformed, FIFO cannot safely skip it without breaking "all records".
        let mut payload: Vec<u8> = Vec::new();
        let mut malformed = 0usize;

        for (_k, v) in &batch {
            if v.len() < HEADER_LEN {
                malformed += 1;
                continue;
            }

            let declared_len = u32::from_be_bytes([v[8], v[9], v[10], v[11]]) as usize;
            let available = v.len().saturating_sub(HEADER_LEN);
            let take_len = declared_len.min(available);

            payload.extend_from_slice(&v[HEADER_LEN..HEADER_LEN + take_len]);
        }

        if malformed > 0 {
            audit.log(
                Level::Error,
                1033,
                &format!(
                    "Malformed records encountered in FIFO head; count={malformed}. \
                     Records retained (no DLQ, no skip). Fix producer/encoding to proceed."
                ),
            );
        }

        if payload.is_empty() {
            // FIFO head is malformed; we cannot progress without violating requirements.
            let sleep_ms = backoff + rng.random_range(0..max_jitter);
            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
            backoff = std::cmp::min(backoff.saturating_mul(2), max_backoff);
            continue;
        }

        let started = Instant::now();
        match http.post(&url).body(payload).send().await {
            Ok(resp) if resp.status().is_success() => {
                // Success: remove all keys in this batch.
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

            Ok(resp) => {
                // Any non-success: keep records, retry with backoff (strict FIFO).
                let status = resp.status().as_u16();
                let sleep_ms = backoff + rng.random_range(0..max_jitter);

                audit.log(
                    Level::Warn,
                    1031,
                    &format!("Egress failure HTTP {status}; FIFO retained; retrying in {sleep_ms}ms"),
                );

                tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                backoff = std::cmp::min(backoff.saturating_mul(2), max_backoff);
            }

            Err(e) => {
                let sleep_ms = backoff + rng.random_range(0..max_jitter);

                audit.log(
                    Level::Warn,
                    1031,
                    &format!("Egress transport failure: {e}; FIFO retained; retrying in {sleep_ms}ms"),
                );

                tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                backoff = std::cmp::min(backoff.saturating_mul(2), max_backoff);
            }
        }
    }
}
