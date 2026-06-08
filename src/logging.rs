use chrono::Local;
use std::fs;
use std::path::PathBuf;
use tracing::{error, info};
use tracing_appender::rolling;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::{fmt, EnvFilter};

/// Initializes the global structured JSON logger for SG-X nodes.
/// Prefers `/var/log/sgx-guardian`, then `/var/lib/sgx-guardian/logs`,
/// then local `logs/`. If all file targets fail, falls back to stdout so the
/// daemon keeps running instead of panicking on startup.
///
/// Example: `/var/log/sgx-guardian/nodeA.log`
pub fn init_logger(node_id: &str) {
    let env_filter = EnvFilter::from_default_env().add_directive("info".parse().unwrap());

    if let Some(log_dir) = resolve_log_dir() {
        let file_appender = rolling::daily(&log_dir, format!("{}.log", node_id));
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        Box::leak(Box::new(guard));

        let init_result = fmt()
            .with_env_filter(env_filter.clone())
            .json()
            .with_timer(ChronoLocal::rfc_3339())
            .with_writer(non_blocking)
            .flatten_event(true)
            .with_target(false)
            .with_current_span(false)
            .with_ansi(false)
            .try_init();

        if init_result.is_ok() {
            info!(
                node = %node_id,
                time = %Local::now().to_rfc3339(),
                log_dir = %log_dir.display(),
                "Logger initialized successfully"
            );
            return;
        }
    }

    let _ = fmt()
        .with_env_filter(env_filter)
        .json()
        .with_timer(ChronoLocal::rfc_3339())
        .flatten_event(true)
        .with_target(false)
        .with_current_span(false)
        .with_ansi(false)
        .try_init();
    eprintln!(
        "warning: file logger unavailable; falling back to stdout for node {}",
        node_id
    );
    info!(
        node = %node_id,
        time = %Local::now().to_rfc3339(),
        "Logger initialized with stdout fallback"
    );
}

fn resolve_log_dir() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(override_dir) = std::env::var("SGX_LOG_DIR") {
        if !override_dir.trim().is_empty() {
            candidates.push(PathBuf::from(override_dir));
        }
    }
    candidates.push(PathBuf::from("/var/log/sgx-guardian"));
    candidates.push(PathBuf::from("/var/lib/sgx-guardian/logs"));
    candidates.push(PathBuf::from("logs"));

    for dir in candidates {
        if fs::create_dir_all(&dir).is_ok() {
            return Some(dir);
        }
    }
    None
}
/// Logs a normal information-level event for the given node,
/// automatically attaching timestamp and structured JSON fields.
pub fn log_event(node_id: &str, event: &str) {
    info!(
        node = %node_id,
        time = %Local::now().to_rfc3339(),
        event = %event
    );
}
/// Logs an error-level event for the given node, including timestamp and
/// structured JSON fields. Used for reporting failures or critical warnings.
pub fn log_error(node_id: &str, err: &str) {
    error!(
        node = %node_id,
        time = %Local::now().to_rfc3339(),
        error = %err
    );
}
