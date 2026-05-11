mod config; 
mod guards; 
mod tls; 
mod relay; 
mod audit;

use std::{env, sync::Arc, fs};
use windows_service::{define_windows_service, service_dispatcher};
// Use Fjall for embedded persistence
use fjall::{Config, Keyspace};

define_windows_service!(ffi_service_main, my_service_main);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::args().any(|x| x == "--console") {
        run_app()?;
    } else {
        service_dispatcher::start("VmRelay", ffi_service_main)?;
    }
    Ok(())
}

fn my_service_main(_args: Vec<std::ffi::OsString>) {
    let _ = run_app();
}

#[tokio::main]
async fn run_app() -> Result<(), Box<dyn std::error::Error>> {
    let toml_str = fs::read_to_string("config.toml")?;
    let cfg: config::RelayConfig = toml::from_str(&toml_str)?;
    
    let audit = Arc::new(audit::AuditGuard::new(&cfg.audit_source_name));
    audit.log(log::Level::Info, 1000, "Relay Application Initializing with Fjall storage.");

    // 1. Initialize Fjall Storage
    // NIST SC-28: Ensure the storage path is protected via Windows ACLs
    let keyspace = Keyspace::open_default("C:\\ProgramData\\VmRelay\\storage")?;
    let db_partition = keyspace.open_partition("metrics_queue", Config::default())?;

    // 2. Setup Hardened TLS Client
    let rustls_cfg = tls::build_rustls_config(&cfg.client_cert_sha1);
    let http_client = reqwest::Client::builder()
        .use_preconfigured_tls(rustls_cfg)
        .build()?;

    let audit_ingest = Arc::clone(&audit);
    let pipe_path = cfg.named_pipe_path.clone();
    let db_ingest = db_partition.clone();

    // 3. Spawn Ingestion Task
    tokio::spawn(async move {
        relay::run_ingestion(pipe_path, db_ingest, audit_ingest).await;
    });

    // 4. Run Egress Loop (Blocks main thread)
    relay::run_egress(cfg.pingora_url, http_client, db_partition, cfg, Arc::clone(&audit)).await;

    Ok(())
}
