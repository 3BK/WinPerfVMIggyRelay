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
        service_dispatcher::start("WinPerfVMFjallRelay", ffi_service_main)?;
    }
    Ok(())
}

fn my_service_main(_args: Vec<std::ffi::OsString>) {
    let _ = run_app();
}

#[tokio::main]
async fn run_app() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config::load_config();

    let audit = Arc::new(audit::AuditGuard::new(&cfg.audit.audit_source_name));
    audit.log(log::Level::Info, 1000, "Relay Application Initializing with Fjall v3 storage.");

    let db_path = Path::new(&cfg.buffer.metrics_queue);
    let fjall_db = Database::open(FjallConfig::new(db_path))?;

    let items: Keyspace = fjall_db.keyspace("metrics", Default::default())?;

    let rustls_cfg = tls::build_rustls_config(
        &cfg.tls.client_cert_sha1,
        &cfg.tls.server_sha256_pin,
        &audit,
    );

    audit.log(log::Level::Info, 1050, "TLS configured: CNG mTLS enabled; server pinning enabled.");

    let http_client = reqwest::Client::builder()
        .use_preconfigured_tls(rustls_cfg)
        .build()?;

    let pingora_url = cfg.forwarder.pingora_url.clone();

    let audit_ingest = Arc::clone(&audit);
    let audit_retention = Arc::clone(&audit);

    let pipe_path = cfg.ingest.named_pipe_path.clone();

    let db_ingest = items.clone();
    let db_retention = items.clone();
    let db_egress = items.clone();

    tokio::spawn(async move {
        relay::run_ingestion(pipe_path, db_ingest, audit_ingest).await;
    });

    let retention_cfg = cfg.clone();
    tokio::spawn(async move {
        relay::run_retention(db_retention, retention_cfg, audit_retention).await;
    });

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
