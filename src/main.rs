mod config;
mod guards;
mod tls;
mod relay;
mod audit;

use std::{env, sync::Arc, path::Path};
use windows_service::{define_windows_service, service_dispatcher};
use fjall::{Config as FjallConfig, Database, Keyspace};

define_windows_service!(ffi_service_main, my_service_main);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::args().any(|x| x == "--console") {
        run_app()?;
    } else {
        // Service name should match system spec for audit traceability
        service_dispatcher::start("WinPerfVMFjallRelay", ffi_service_main)?;
    }
    Ok(())
}

fn my_service_main(_args: Vec<std::ffi::OsString>) {
    let _ = run_app();
}

#[tokio::main]
async fn run_app() -> Result<(), Box<dyn std::error::Error>> {
    // Load and validate configuration
    let cfg = config::load_config();

    // Initialize Audit Logging
    let audit = Arc::new(audit::AuditGuard::new(&cfg.audit.audit_source_name));
    audit.log(log::Level::Info, 1000, "Relay Application Initializing with Fjall v3 storage.");

    // 1. Initialize Fjall v3 Database
    let db_path = Path::new(&cfg.buffer.metrics_queue);
    let fjall_db = Database::open(FjallConfig::new(db_path))?;

    // Use "metrics" as keyspace for spec compliance
    let items: Keyspace = fjall_db.keyspace("metrics", Default::default())?;

    // 2. Setup Hardened TLS Client
    let rustls_cfg = tls::build_rustls_config(
        &cfg.tls.client_cert_sha1,
        &cfg.tls.server_sha256_pin,
        &audit,
    );

    let http_client = reqwest::Client::builder()
        .use_preconfigured_tls(rustls_cfg)
        .build()?;

    // IMPORTANT: avoid partial move of cfg by cloning pingora_url before moving cfg into run_egress
    let pingora_url = cfg.forwarder.pingora_url.clone();

    // Prepare shared handles for tasks
    let audit_ingest = Arc::clone(&audit);
    let audit_retention = Arc::clone(&audit);

    let pipe_path = cfg.ingest.named_pipe_path.clone();

    let db_ingest = items.clone();
    let db_retention = items.clone();
    let db_egress = items.clone();

    // 3. Spawn Ingestion Task
    tokio::spawn(async move {
        relay::run_ingestion(pipe_path, db_ingest, audit_ingest).await;
    });

    // 4. Spawn Retention Task (enforces max age/disk)
    let retention_cfg = cfg.clone();
    tokio::spawn(async move {
        relay::run_retention(db_retention, retention_cfg, audit_retention).await;
    });

    // 5. Run Egress Loop
    // cfg is moved here (intentionally) as the owner of forwarder parameters.
    relay::run_egress(
        pingora_url,
        http_client,
        db_egress,
        cfg,
        Arc::clone(&audit),
    )
    .await;

    audit.log(log::Level::Info, 1001, "Relay Application Shutdown Complete.");
    Ok(())
}
