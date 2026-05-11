# WinPerfVMFjallRelay — System Specification Narrative

---

## 1  Purpose and Scope

### 1.1  Purpose

This document defines the system specification for **WinPerfVMFjallRelay** (hereafter "the Relay"), a Rust-based Windows service and console application that receives Windows Performance Data Helper (PDH) telemetry from a local collector agent via a named pipe, durably buffers that telemetry in an embedded Fjall LSM-tree key-value store, and forwards it over mTLS to a VictoriaMetrics time-series database through a Pingora reverse-proxy sidecar.

The Relay exists to solve a single, critical operational problem:

> **Enable the PDH collector agent to ride through network outages, maintenance windows, and downstream failures without data loss.**

### 1.2  Scope

This specification covers:

- Functional requirements (ingest, buffer, forward, audit)
- Non-functional requirements (durability, security, performance, observability)
- Component architecture and data flow
- Configuration model
- Failure modes and recovery behaviour
- Security controls and compliance alignment
- Operational model (console and Windows service modes)
- Interface contracts (named pipe, Fjall, HTTP/mTLS, Windows Event Log)

This specification does **not** cover:

- The PDH collector agent itself (treated as an external producer)
- The Pingora sidecar configuration (treated as an external TLS termination point)
- The VictoriaMetrics server configuration (treated as an external sink)
- Network infrastructure (firewalls, load balancers, DNS)

### 1.3  Definitions and Abbreviations

| Term | Definition |
|---|---|
| PDH | Performance Data Helper — Windows API for collecting performance counters |
| Fjall | Embedded Rust LSM-tree key-value storage engine |
| LSM-tree | Log-Structured Merge-tree — write-optimized storage structure |
| WAL | Write-Ahead Log — sequential durability journal |
| mTLS | Mutual Transport Layer Security — bidirectional certificate authentication |
| Pingora | Cloudflare Pingora — Rust-based reverse proxy used as an mTLS sidecar |
| VictoriaMetrics | Open-source time-series database (VictoriaMetrics OSS) |
| Named Pipe | Windows IPC mechanism (kernel-mode, byte-stream or message-mode) |
| RAII | Resource Acquisition Is Initialization — deterministic cleanup pattern |
| SecureGuard | RAII wrapper that zeroizes or releases sensitive handles on drop |
| PFS | Perfect Forward Secrecy |
| TDS | Tabular Data Stream (not used directly; referenced for context) |

---

## 2  System Context

### 2.1  Context Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                        Windows Host                              │
│                                                                  │
│  ┌─────────────┐    Named Pipe     ┌──────────────────────────┐ │
│  │ PDH         │ ═══════════════>  │ WinPerfVMFjallRelay      │ │
│  │ Collector   │  \\.\pipe\pdh     │                          │ │
│  │ Agent       │  _metrics         │  ┌────────────────────┐  │ │
│  └─────────────┘                   │  │ Ingest Thread      │  │ │
│                                    │  └────────┬───────────┘  │ │
│                                    │           │              │ │
│                                    │           ▼              │ │
│                                    │  ┌────────────────────┐  │ │
│                                    │  │ Fjall LSM-tree     │  │ │
│                                    │  │ (Durable Buffer)   │  │ │
│                                    │  └────────┬───────────┘  │ │
│                                    │           │              │ │
│                                    │           ▼              │ │
│                                    │  ┌────────────────────┐  │ │
│                                    │  │ Forwarder Thread   │  │ │
│                                    │  └────────┬───────────┘  │ │
│                                    │           │              │ │
│  ┌─────────────┐                   │           │              │ │
│  │ Windows     │ <── audit logs ── │           │              │ │
│  │ Event Log   │                   └───────────┼──────────────┘ │
│                                                │                │
└────────────────────────────────────────────────┼────────────────┘
                                                 │ mTLS (TLS 1.2+)
                                                 │ HTTP/1.1
                                                 ▼
                                    ┌────────────────────────┐
                                    │ Pingora mTLS Sidecar   │
                                    │ (TLS termination /     │
                                    │  certificate pinning)  │
                                    └────────────┬───────────┘
                                                 │ plaintext or
                                                 │ backend TLS
                                                 ▼
                                    ┌────────────────────────┐
                                    │ VictoriaMetrics OSS    │
                                    │ (Time-Series Database) │
                                    └────────────────────────┘
```

### 2.2  Actors and External Systems

| Actor / System | Role | Interface |
|---|---|---|
| PDH Collector Agent | Produces serialized metric batches | Named pipe (producer) |
| Fjall LSM-tree Store | Provides durable, ordered, local buffering | Embedded library (in-process) |
| Pingora Sidecar | Terminates mTLS; forwards to VictoriaMetrics | HTTPS endpoint (mTLS) |
| VictoriaMetrics OSS | Stores time-series telemetry | HTTP import API (behind Pingora) |
| Windows Event Log | Receives structured audit log entries | Windows API (ReportEvent / ETW) |
| Windows SCM | Manages service lifecycle | Windows Service Control Manager |
| Operator / Administrator | Configures, deploys, monitors | TOML config file; Event Viewer; console |

---

## 3  Functional Requirements

### 3.1  FR-01 — Named Pipe Ingest

| Attribute | Specification |
|---|---|
| **Pipe Name** | Configurable; default `\\.\pipe\pdh_metrics` |
| **Pipe Mode** | Message mode (discrete metric batches) |
| **Pipe Direction** | Inbound (read-only from Relay perspective) |
| **Access Control** | Pipe DACL restricts access to the PDH agent service account and LOCAL SYSTEM / SERVICE |
| **Serialization** | Line-delimited Prometheus exposition format (UTF-8) or length-prefixed binary (configurable) |
| **Backpressure** | If the Relay cannot consume fast enough, the pipe buffer (kernel) provides natural backpressure to the producer |
| **Reconnection** | The Relay re-creates the pipe listener if the client disconnects; supports unlimited reconnections |

**Behaviour:**

1. The Relay creates a named pipe server instance on startup.
2. The Relay waits for the PDH collector agent to connect.
3. On connection, the Relay reads complete messages (metric batches).
4. Each message is assigned:
   - A monotonically increasing sequence number (`u64`)
   - An ingest timestamp (UTC, nanosecond precision)
5. The message (with metadata envelope) is written to Fjall.
6. The Relay acknowledges consumption by reading the next message.
7. On client disconnect, the Relay returns to listening state.

### 3.2  FR-02 — Fjall Durable Buffer

| Attribute | Specification |
|---|---|
| **Storage Engine** | Fjall (Rust, embedded, LSM-tree) |
| **Data Directory** | Configurable; default `%ProgramData%\WinPerfVMFjallRelay\fjall_data` |
| **Keyspace** | Single keyspace: `metrics` |
| **Key Format** | `{sequence_number:u64}` — big-endian encoded for lexicographic ordering |
| **Value Format** | Envelope: `{ingest_ts_ns:u64}{payload_len:u32}{payload_bytes}` |
| **Durability** | WAL enabled; fsync on every batch (configurable: per-message or per-batch) |
| **Retention** | Configurable maximum age (default: 72 hours) and maximum disk size (default: 4 GiB) |
| **Compaction** | Background compaction managed by Fjall runtime |
| **Encryption at Rest** | Deferred to OS-level (BitLocker / NTFS EFS); Fjall stores plaintext |

**Behaviour:**

1. Every metric batch received from the named pipe is written to Fjall **before** any forwarding attempt.
2. The write is considered committed only after Fjall WAL persistence completes.
3. The forwarder reads from Fjall in sequence-number order (FIFO).
4. A record is deleted from Fjall **only after** confirmed successful delivery to VictoriaMetrics (acknowledged by HTTP 2xx from Pingora).
5. On startup, the Relay scans Fjall for any un-forwarded records (incomplete deliveries from prior run) and resumes forwarding from the lowest unacknowledged sequence number.
6. A background maintenance task enforces retention policy:
   - Deletes records older than the configured maximum age.
   - If disk usage exceeds the configured maximum, deletes oldest records first (LRU eviction).
   - Retention enforcement runs on a configurable interval (default: 60 seconds).
7. Fjall compaction runs in background threads managed by the Fjall runtime; the Relay does not interfere with compaction scheduling.

**Design Rationale:**

The Fjall buffer is the **core resilience mechanism**. It decouples ingest from forwarding. The PDH agent can write at full speed regardless of downstream availability. The Relay can absorb:

- Network outages (minutes to days, bounded by retention)
- VictoriaMetrics maintenance windows
- Pingora restarts
- TLS certificate rotation events
- Transient DNS or routing failures

### 3.3  FR-03 — mTLS Forwarding to VictoriaMetrics

| Attribute | Specification |
|---|---|
| **Protocol** | HTTP/1.1 over TLS 1.2 or TLS 1.3 |
| **TLS Library** | rustls (statically linked; no OpenSSL dependency) |
| **Client Certificate** | Loaded from Windows Certificate Store (CurrentMachine\My) by thumbprint or subject |
| **Server Certificate Pinning** | SHA-256 pin of expected Pingora server certificate (configurable) |
| **Client Certificate Pinning** | SHA-256 pin of client certificate (configurable; validated at startup) |
| **Cipher Suites** | TLS 1.2: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384; TLS 1.3: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 |
| **Curves** | P-384 (secp384r1) preferred; P-256 (secp256r1) acceptable |
| **Endpoint** | Configurable; e.g., `https://pingora-sidecar.domain.local:8443/api/v1/import/prometheus` |
| **Connection Pooling** | Enabled; persistent HTTP/1.1 connection reused across requests (Connection: keep-alive) |
| **Batch Size** | Configurable number of Fjall records per HTTP request (default: 1000) |
| **Request Timeout** | Configurable (default: 30 seconds) |
| **Retry Policy** | Exponential backoff with jitter; configurable base (default: 1s), max (default: 300s), and max attempts (default: unlimited / until retention expiry) |

**Behaviour:**

1. The forwarder thread runs continuously, polling Fjall for un-forwarded records.
2. It reads up to `batch_size` records in sequence order.
3. It serializes the batch into Prometheus exposition format (line-delimited).
4. It sends the batch via HTTP POST to the configured VictoriaMetrics import endpoint through the Pingora sidecar.
5. On HTTP 2xx response:
   - The forwarded records are deleted from Fjall.
   - The high-water-mark sequence number is updated.
   - An audit event is logged (batch delivered; count; latency).
6. On HTTP 4xx response (client error):
   - The batch is logged as rejected.
   - An audit event is logged at Warning level.
   - If `400 Bad Request`, the batch is moved to a dead-letter keyspace in Fjall (not retried).
   - Other 4xx errors are retried with backoff.
7. On HTTP 5xx response or connection failure:
   - The batch remains in Fjall (not deleted).
   - Retry with exponential backoff and jitter.
   - An audit event is logged at Warning level on first failure; Error level after configurable threshold (default: 10 consecutive failures).
8. On TLS handshake failure:
   - An audit event is logged at Error level (includes failure reason).
   - Retry with backoff.
   - If server certificate does not match the configured pin, the connection is refused and an audit event is logged at Critical level.

**Certificate Handling (RAII / SecureGuard):**

- The client certificate private key is accessed from the Windows Certificate Store via the CryptoAPI / CNG interface.
- A `SecureGuard` RAII wrapper holds the certificate context handle.
- On drop, the `SecureGuard`:
  - Releases the certificate context (`CertFreeCertificateContext`)
  - Zeroizes any in-memory key material copies
  - Logs handle release to trace-level diagnostics
- The `SecureGuard` is non-cloneable and non-copyable (`!Clone`, `!Copy`).
- If the `SecureGuard` is dropped due to panic unwinding, the destructor still executes (guaranteed cleanup).

### 3.4  FR-04 — Windows Event Log Audit

| Attribute | Specification |
|---|---|
| **Event Source** | `WinPerfVMFjallRelay` |
| **Event Log** | `Application` (or dedicated custom log if registered) |
| **Event ID Range** | 1000–1999 (application-defined) |

**Event Catalogue:**

| Event ID | Level | Category | Description |
|---|---|---|---|
| 1000 | Information | Lifecycle | Service started successfully |
| 1001 | Information | Lifecycle | Service stopped gracefully |
| 1002 | Warning | Lifecycle | Service stop requested; draining Fjall buffer |
| 1003 | Error | Lifecycle | Service terminated unexpectedly (panic / crash) |
| 1010 | Information | Ingest | Named pipe client connected |
| 1011 | Information | Ingest | Named pipe client disconnected |
| 1012 | Warning | Ingest | Named pipe read error (details in message) |
| 1013 | Error | Ingest | Named pipe creation failed (details in message) |
| 1020 | Information | Buffer | Fjall store opened successfully; N records pending |
| 1021 | Warning | Buffer | Fjall retention enforcement triggered; N records evicted |
| 1022 | Error | Buffer | Fjall write failure (details in message) |
| 1023 | Warning | Buffer | Fjall disk usage exceeds threshold (N% of maximum) |
| 1030 | Information | Forward | Batch delivered; count=N; latency=Xms |
| 1031 | Warning | Forward | Batch delivery failed; attempt=N; reason=X |
| 1032 | Error | Forward | Consecutive delivery failures exceed threshold; count=N |
| 1033 | Error | Forward | Dead-letter: batch rejected by server (HTTP 400); seq_start=X; seq_end=Y |
| 1034 | Information | Forward | Network connectivity restored; forwarding resumed |
| 1040 | Error | Security | TLS handshake failed; reason=X |
| 1041 | Critical | Security | Server certificate pin mismatch; expected=X; received=Y |
| 1042 | Critical | Security | Client certificate not found in store; thumbprint=X |
| 1043 | Warning | Security | Client certificate expiry approaching; days_remaining=N |
| 1050 | Information | Config | Configuration loaded; version=X |
| 1051 | Warning | Config | Configuration validation warning; detail=X |

### 3.5  FR-05 — Dual Execution Mode (Console / Windows Service)

| Mode | Trigger | Behaviour |
|---|---|---|
| **Console** | Launched from command prompt or with `--console` flag | Runs in foreground; logs to stdout and Windows Event Log; responds to Ctrl+C for graceful shutdown |
| **Windows Service** | Started by Windows Service Control Manager (SCM) | Runs as background service; logs to Windows Event Log only; responds to SCM stop/shutdown signals |

**Service Registration:**

| Attribute | Value |
|---|---|
| Service Name | `WinPerfVMFjallRelay` |
| Display Name | `Windows Performance VM Fjall Relay` |
| Description | Durable telemetry relay: PDH metrics → Fjall buffer → VictoriaMetrics (mTLS) |
| Startup Type | Automatic (Delayed Start) |
| Service Account | Configurable; recommended: Group Managed Service Account (gMSA) or dedicated domain service account |
| Recovery | First failure: Restart service (60s delay); Second failure: Restart service (120s delay); Subsequent: Restart service (300s delay) |
| Dependencies | None (named pipe is created by the Relay; Fjall is embedded) |

**Lifecycle:**

1. **Startup:** Load configuration → validate → open Fjall → register event source → create named pipe → start forwarder → report `SERVICE_RUNNING` (or print banner in console mode).
2. **Running:** Ingest loop + forwarder loop + retention maintenance loop execute concurrently.
3. **Shutdown (graceful):**
   - Stop accepting new pipe connections.
   - Drain in-flight pipe reads (complete current message).
   - Flush Fjall WAL.
   - Attempt final forwarding batch (bounded by configurable drain timeout, default: 30 seconds).
   - Close Fjall store cleanly.
   - Log shutdown event.
   - Report `SERVICE_STOPPED`.
4. **Shutdown (forced):** If drain timeout expires, log warning and exit. Fjall WAL ensures no committed data is lost; un-forwarded records will be retried on next startup.

---

## 4  Non-Functional Requirements

### 4.1  NFR-01 — Durability

| Requirement | Specification |
|---|---|
| No data loss during network outage | Guaranteed by Fjall WAL; metrics are persisted before forwarding is attempted |
| No data loss during service restart | Fjall store survives process restart; un-forwarded records are replayed |
| No data loss during host reboot | Fjall WAL with fsync; data survives unclean shutdown |
| Bounded data loss during disk failure | Out of scope; mitigated by OS-level RAID / storage redundancy |

### 4.2  NFR-02 — Performance

| Metric | Target |
|---|---|
| Ingest throughput (named pipe → Fjall) | ≥ 50,000 metric lines/second sustained |
| Forwarding throughput (Fjall → VictoriaMetrics) | ≥ 30,000 metric lines/second sustained (network permitting) |
| Ingest latency (pipe read → Fjall commit) | < 5 ms p99 |
| Forwarding latency (Fjall read → HTTP response) | < 500 ms p99 (network dependent) |
| Memory footprint (steady state) | < 128 MiB RSS |
| CPU utilization (steady state, no backlog) | < 5% of single core |
| CPU utilization (backlog drain) | < 25% of single core |

### 4.3  NFR-03 — Security

| Control | Implementation |
|---|---|
| Transport encryption | TLS 1.2+ (rustls, statically linked) with PFS cipher suites only |
| Mutual authentication | Client certificate from Windows Certificate Store; server certificate pinned by SHA-256 |
| Certificate handling | RAII SecureGuard; zeroization on drop; no key material written to disk outside Windows cert store |
| Named pipe access control | Explicit DACL; denies access to all except authorized service accounts |
| Configuration file protection | NTFS ACL restricts read to service account and Administrators; file contains no secrets (thumbprints only, not keys) |
| Audit trail | All security-relevant events written to Windows Event Log with structured event IDs |
| Static binary | No dynamic linking to OpenSSL or other TLS libraries; reduces supply chain attack surface |
| Privilege minimization | Service runs as gMSA or least-privilege domain account; no LocalSystem |

### 4.4  NFR-04 — Observability

| Signal | Mechanism |
|---|---|
| Audit events | Windows Event Log (structured, event ID catalogue) |
| Operational metrics (self-telemetry) | Exposed as local performance counters or written to a secondary Fjall keyspace for self-reporting |
| Fjall buffer depth | Queryable via operational metric: `relay_fjall_pending_records` |
| Forwarding lag | Queryable via operational metric: `relay_forwarding_lag_seconds` |
| Last successful forward | Queryable via operational metric: `relay_last_forward_success_epoch` |
| Dead-letter count | Queryable via operational metric: `relay_deadletter_count` |
| Console diagnostics | In console mode: structured log lines to stdout (JSON or human-readable, configurable) |

### 4.5  NFR-05 — Resilience and Failure Tolerance

| Failure Scenario | Relay Behaviour | Data Impact |
|---|---|---|
| Network outage (minutes) | Fjall buffers; forwarder retries with backoff | No data loss |
| Network outage (hours) | Fjall buffers; retention policy bounds growth | No data loss within retention window |
| Network outage (days) | Fjall buffers up to retention limit; oldest records evicted | Bounded data loss (oldest records only) |
| VictoriaMetrics down | Same as network outage | No data loss within retention window |
| Pingora sidecar restart | Connection pool detects; reconnects on next attempt | No data loss; transient forwarding delay |
| Fjall disk full | Retention enforcement accelerates; oldest records evicted; ingest continues | Bounded data loss (oldest records only) |
| Fjall corruption | Fjall WAL recovery on startup; if unrecoverable, log Critical event and recreate store | Potential data loss for corrupted segments |
| PDH agent crash | Relay returns to pipe listening state; no impact on buffered data | No data loss |
| Relay service crash | SCM restarts service; Fjall WAL recovers; forwarding resumes | No data loss (WAL-committed records survive) |
| Certificate expiry | TLS handshake fails; audit event logged; forwarder retries; data buffered | No data loss; forwarding blocked until cert renewed |
| Host reboot | Service auto-starts; Fjall recovers; forwarding resumes | No data loss |

### 4.6  NFR-06 — Compliance Alignment

| Framework | Relevant Controls | How the Relay Addresses |
|---|---|---|
| ISO 27001 | A.8.24 (Cryptography), A.8.20 (Network Security) | mTLS with PFS; certificate pinning; rustls static linking |
| ISO 27001 | A.8.15 (Logging), A.8.16 (Monitoring) | Windows Event Log audit trail; structured event catalogue; self-telemetry |
| ISO 27001 | A.8.9 (Configuration Management) | TOML configuration with validation; versioned; NTFS ACL protected |
| NIST SP 800-53 | SC-8 (Transmission Confidentiality) | TLS 1.2+ with PFS cipher suites |
| NIST SP 800-53 | SC-12 (Cryptographic Key Management) | Windows Certificate Store; RAII SecureGuard; no key export |
| NIST SP 800-53 | AU-2, AU-3 (Audit Events, Content) | Event catalogue with structured IDs, levels, and categories |
| NIST SP 800-53 | CP-9 (System Backup) | Fjall WAL provides crash-consistent local recovery |
| CIS Level 1 | Service hardening | Least-privilege service account; no LocalSystem; minimal dependencies |
| PCI DSS 4.0 | 4.2.1 (Strong Cryptography in Transit) | TLS 1.2+ PFS only; no weak ciphers; certificate pinning |

---

## 5  Configuration Model

### 5.1  Configuration File

**Location:** `%ProgramData%\WinPerfVMFjallRelay\config.toml`
**Format:** TOML
**Permissions:** Read: service account, Administrators. Write: Administrators only.

### 5.2  Configuration Schema

```toml
[service]
name = "WinPerfVMFjallRelay"
display_name = "Windows Performance VM Fjall Relay"
log_level = "info"                          # trace, debug, info, warn, error

[ingest]
pipe_name = "\\\\.\\pipe\\pdh_metrics"
pipe_buffer_size = 65536                    # bytes
pipe_mode = "message"                       # "message" or "byte"

[buffer]
data_directory = "C:\\ProgramData\\WinPerfVMFjallRelay\\fjall_data"
max_disk_bytes = 4294967296                 # 4 GiB
max_age_seconds = 259200                    # 72 hours
retention_check_interval_seconds = 60
fsync_mode = "per_batch"                    # "per_message" or "per_batch"

[forwarder]
endpoint = "https://pingora-sidecar.domain.local:8443/api/v1/import/prometheus"
batch_size = 1000                           # records per HTTP POST
poll_interval_ms = 100                      # Fjall poll interval when idle
request_timeout_seconds = 30
drain_timeout_seconds = 30

[forwarder.retry]
base_delay_seconds = 1
max_delay_seconds = 300
max_consecutive_failures_before_error = 10

[forwarder.connection_pool]
enabled = true
idle_timeout_seconds = 90
max_idle_connections = 2

[tls]
min_version = "1.2"                         # "1.2" or "1.3"
cipher_suites = [
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256"
]
curves = ["P-384", "P-256"]

[tls.client_cert]
store = "LocalMachine"
store_name = "My"
thumbprint = "A1B2C3D4E5F6..."              # SHA-1 thumbprint of client certificate
pin_sha256 = "base64-encoded-sha256-of-client-public-key"

[tls.server_pin]
pin_sha256 = "base64-encoded-sha256-of-expected-server-certificate"

[audit]
event_source = "WinPerfVMFjallRelay"
event_log = "Application"
cert_expiry_warning_days = 30
```

### 5.3  Configuration Validation

On startup, the Relay validates all configuration values and:

- Logs Event 1050 (Configuration loaded) on success.
- Logs Event 1051 (Configuration validation warning) for non-fatal issues (e.g., large batch size).
- Logs Event 1003 (Unexpected termination) and exits with non-zero code if configuration is invalid (e.g., missing thumbprint, invalid path, unparseable TOML).

---

## 6  Data Flow (Detailed)

### 6.1  Normal Operation (Happy Path)

```
PDH Agent ──[metric batch]──> Named Pipe
    ──[read message]──> Ingest Thread
    ──[assign seq# + timestamp]──> Fjall Write (WAL + MemTable)
    ──[committed]──>
                        Forwarder Thread (polling Fjall)
    ──[read batch of N records]──>
    ──[serialize to Prometheus format]──>
    ──[HTTP POST over mTLS]──> Pingora Sidecar
    ──[forward]──> VictoriaMetrics
    ──[HTTP 2xx]──>
    ──[delete records from Fjall]──>
    ──[log Event 1030]──> Windows Event Log
```

### 6.2  Network Outage (Resilience Path)

```
PDH Agent ──[metric batch]──> Named Pipe
    ──[read message]──> Ingest Thread
    ──[assign seq# + timestamp]──> Fjall Write (WAL + MemTable)
    ──[committed]──>
                        Forwarder Thread (polling Fjall)
    ──[read batch of N records]──>
    ──[HTTP POST over mTLS]──> CONNECTION REFUSED / TIMEOUT
    ──[log Event 1031]──>
    ──[backoff 1s]──> retry
    ──[backoff 2s]──> retry
    ──[backoff 4s]──> retry
    ...
    ──[backoff capped at 300s]──> retry

    Meanwhile:
    PDH Agent continues writing → Fjall continues accepting
    Fjall buffer grows (bounded by retention policy)

    Network restored:
    ──[HTTP POST succeeds]──>
    ──[drain backlog at full batch rate]──>
    ──[log Event 1034]──> Windows Event Log
```

### 6.3  Service Restart (Recovery Path)

```
Service starts
    ──[load config]──> validate
    ──[open Fjall store]──> WAL recovery (if needed)
    ──[scan for lowest unacknowledged seq#]──>
    ──[log Event 1020: "Fjall opened; N records pending"]──>
    ──[create named pipe]──>
    ──[start forwarder]──> resume from last unacknowledged seq#
    ──[start ingest]──> accept new pipe connections
    ──[log Event 1000]──> Service started
```

---

## 7  Thread Model

| Thread | Role | Blocking Behaviour |
|---|---|---|
| **Main / Service** | Lifecycle management; signal handling; SCM integration | Waits on shutdown signal |
| **Ingest** | Named pipe read loop; Fjall write | Blocks on pipe read (I/O completion) |
| **Forwarder** | Fjall read; HTTP POST; retry loop | Polls Fjall; blocks on HTTP I/O with timeout |
| **Retention** | Periodic Fjall cleanup | Sleeps on interval timer; wakes to scan and evict |
| **Fjall Background** | LSM compaction; SSTable management | Managed by Fjall runtime (not application-controlled) |

**Concurrency Notes:**

- Fjall supports concurrent reads and writes from multiple threads.
- The ingest thread and forwarder thread access Fjall concurrently; Fjall's internal synchronization ensures consistency.
- No application-level locking is required between ingest and forwarder threads.
- The retention thread acquires a lightweight scan lock to avoid interfering with active forwarding.

---

## 8  Build and Deployment

### 8.1  Build Requirements

| Attribute | Value |
|---|---|
| Language | Rust (2021 edition or later) |
| Target | `x86_64-pc-windows-msvc` (AMD64, Windows Server 2022) |
| TLS | rustls (statically linked; no OpenSSL) |
| Linking | Static CRT (`target-feature=+crt-static`) |
| Binary Output | Single `.exe` (no DLL dependencies beyond Windows system DLLs) |

### 8.2  Deployment Artefacts

| Artefact | Location |
|---|---|
| `WinPerfVMFjallRelay.exe` | `C:\Program Files\WinPerfVMFjallRelay\` |
| `config.toml` | `%ProgramData%\WinPerfVMFjallRelay\` |
| Fjall data directory | `%ProgramData%\WinPerfVMFjallRelay\fjall_data\` |
| Windows Event Log source | Registered via `eventcreate` or installer |
| Service registration | `sc.exe create` or installer |

### 8.3  Service Installation (Manual)

```cmd
sc.exe create WinPerfVMFjallRelay ^
    binPath= "C:\Program Files\WinPerfVMFjallRelay\WinPerfVMFjallRelay.exe" ^
    DisplayName= "Windows Performance VM Fjall Relay" ^
    start= delayed-auto ^
    obj= "DOMAIN\gMSA-vmrelay$"

sc.exe description WinPerfVMFjallRelay ^
    "Durable telemetry relay: PDH metrics > Fjall buffer > VictoriaMetrics (mTLS)"

sc.exe failure WinPerfVMFjallRelay ^
    reset= 86400 ^
    actions= restart/60000/restart/120000/restart/300000
```

---

## 9  Acceptance Criteria

| ID | Criterion | Verification Method |
|---|---|---|
| AC-01 | PDH agent can connect to named pipe and send metric batches | Integration test; pipe client simulator |
| AC-02 | Metrics are persisted in Fjall before forwarding | Kill forwarder thread; verify Fjall contains records |
| AC-03 | Metrics are forwarded to VictoriaMetrics via mTLS through Pingora | End-to-end test; query VictoriaMetrics for ingested metrics |
| AC-04 | Network outage of 1 hour results in zero data loss | Disconnect network; reconnect after 1h; verify all metrics delivered |
| AC-05 | Service restart results in zero data loss | Stop service; start service; verify backlog is drained |
| AC-06 | Host reboot results in zero data loss | Reboot host; verify backlog is drained after restart |
| AC-07 | Retention policy evicts records older than configured maximum age | Set max age to 60s; verify old records are removed |
| AC-08 | Retention policy evicts records when disk usage exceeds maximum | Set max disk to 1 MiB; verify eviction occurs |
| AC-09 | Dead-letter records are preserved and not retried | Send malformed batch; verify 400 response moves to dead-letter keyspace |
| AC-10 | Windows Event Log contains structured audit events for all catalogued event IDs | Trigger each event scenario; verify in Event Viewer |
| AC-11 | TLS handshake fails if server certificate does not match pin | Configure wrong pin; verify connection refused and Event 1041 logged |
| AC-12 | Service runs as gMSA with no LocalSystem privileges | Install with gMSA; verify service starts and operates correctly |
| AC-13 | Console mode operates with Ctrl+C graceful shutdown | Run with `--console`; press Ctrl+C; verify drain and clean exit |
| AC-14 | Connection pooling reuses HTTP connections across batches | Monitor TCP connections; verify single persistent connection under steady load |

---

## 10  Appendix A — Sequence Number Ordering Guarantee

Fjall is an LSM-tree store with lexicographic key ordering. By encoding the sequence number as a big-endian `u64`, the Relay guarantees:

- Records are read in insertion order (FIFO).
- The forwarder always processes the oldest un-forwarded record first.
- Concurrent writes from the ingest thread do not violate ordering (monotonic counter is protected by `AtomicU64`).
- After restart, the lowest remaining key in Fjall is the resume point.

This provides **total ordering** of all metric batches, which is essential for:

- Time-series correctness in VictoriaMetrics.
- Deterministic replay after outage.
- Audit traceability (sequence gaps indicate eviction or dead-letter events).

---

## 11  Appendix B — Capacity Planning Reference

| Parameter | Value | Notes |
|---|---|---|
| Average metric batch size | ~2 KiB | Typical PDH counter set (50–100 counters) |
| Ingest rate | 1 batch/second | Configurable in PDH agent |
| Daily Fjall writes (normal) | ~86,400 records | ~168 MiB/day raw (before compaction) |
| 72-hour buffer (normal) | ~504 MiB | Well within 4 GiB default |
| Burst scenario (10x) | ~1.68 GiB for 72h | Still within default retention |
| Fjall write amplification | ~10x (typical LSM) | Compaction overhead; SSD recommended |
| Network bandwidth (forwarding) | ~16 Kbit/s sustained | Negligible; burst during backlog drain |
| Backlog drain rate | ~2 MiB/s | Limited by HTTP RTT and batch size |
| Time to drain 4 GiB backlog | ~34 minutes | At 2 MiB/s sustained |

---

**End of Document**
