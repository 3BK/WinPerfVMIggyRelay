mod config; 
mod guards; 
mod tls; 
mod relay; 
mod audit;

use std::{env, sync::Arc, fs};
use windows_service::{define_windows_service, service_dispatcher};

define_windows_service!(ffi_service_main, my_service_main);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check if running in console mode for debugging 
    if env::args().any(|x| x == "--console") {
        run_app()?;
    } else {
        // Dispatch as a Windows Service 
        service_dispatcher::start("VmIggyRelay", ffi_service_main)?;
    }
    Ok(())
}

fn my_service_main(_args: Vec<std::ffi::OsString>) {
    let _ = run_app();
}

#[tokio::main]
async fn run_app() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from TOML 
    let toml_str = fs::read_to_string("config.toml")?;
    let cfg: config::RelayConfig = toml::from_str(&toml_str)?;
    
    // Initialize Audit Logging (Windows Event Log)
    let audit = Arc::new(audit::AuditGuard::new(&cfg.audit_source_name));
    
    // Fix E0603: Use log::Level because winlog::Level is private 
    audit.log(log::Level::Info, 1000, "Relay Application Initializing.");

    // Fix E0425: Use build_rustls_config to match tls.rs 
    let rustls_cfg = tls::build_rustls_config(&cfg.client_cert_sha1);
    
    let http_client = reqwest::Client::builder()
        .use_preconfigured_tls(rustls_cfg)
        .build()?;

    // Fix E0433: Iggy 0.10 initialization uses the default Client 
    let mut iggy = iggy::client::Client::default();
    iggy.connect().await?;

    let audit_ingest = Arc::clone(&audit);
    let iggy_ingest = iggy.clone();
    let pipe_path = cfg.named_pipe_path.clone();
    let s_id = cfg.iggy_stream_id;
    let t_id = cfg.iggy_topic_id;

    // Spawn the ingestion task for the Named Pipe 
    tokio::spawn(async move {
        relay::run_ingestion(pipe_path, s_id, t_id, iggy_ingest, audit_ingest).await;
    });

    // Run the egress loop 
    relay::run_egress(cfg.pingora_url, http_client, cfg, Arc::clone(&audit)).await;

    Ok(())
}
