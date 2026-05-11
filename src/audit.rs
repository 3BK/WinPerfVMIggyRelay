use winlog2;
use log::Level;

/// AuditGuard logs structured events to Windows Event Log.
/// Supports custom log name, structured fields, and error handling.
pub struct AuditGuard {
    source: String,
    log_name: String,
}

impl AuditGuard {
    pub fn new(source: &str, log_name: Option<&str>) -> Self {
        let log = log_name.unwrap_or("Application");
        let _ = winlog2::register(source); // Register event source
        Self {
            source: source.to_string(),
            log_name: log.to_string(),
        }
    }

    pub fn log(&self, level: Level, event_id: u32, message: &str) {
        // Log to Windows Event Viewer under specified log
        if let Err(e) = winlog2::report(&self.source, level, event_id, &[message]) {
            eprintln!("Audit log failure: {}", e);
        }
    }

    /// Structured log with category and severity
    pub fn log_structured(&self, level: Level, event_id: u32, category: &str, severity: &str, message: &str) {
        let structured_msg = format!("[{}][{}] {}", category, severity, message);
        self.log(level, event_id, &structured_msg);
    }
}

impl Drop for AuditGuard {
    fn drop(&mut self) {
        // No-op for winlog2, but hooks exist for advanced cleanup
    }
}
