use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Clone, Debug)]
pub struct RelayConfig {
    pub named_pipe_path: String,
    pub metrics_queue: String,
    pub pingora_url: String,
    pub client_cert_sha1: String,
    pub server_sha256_pin: String,
    pub audit_source_name: String,
    pub base_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub max_jitter_ms: u64,
}

pub fn load_config() -> RelayConfig {
    let content = fs::read_to_string("config.toml").expect("NIST SC-28: Configuration file missing");
    toml::from_str(&content).expect("ISO 27001: Config format invalid")
}
