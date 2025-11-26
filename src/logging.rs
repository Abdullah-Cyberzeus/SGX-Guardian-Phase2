use chrono::Local;
use tracing::{error, info};
use tracing_appender::rolling;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::{fmt, EnvFilter};

/// Initializes the global structured JSON logger for SG-X nodes.
/// Creates a daily rotating log file under `/logs/<node>.log`, ensures
/// non-blocking async writes, and formats all events using ISO-8601 timestamps.
///
/// Example: logs/nodeA.log, logs/nodeB.log
pub fn init_logger(node_id: &str) {
    // Create a daily rotating file appender
    let file_appender = rolling::daily("logs", format!("{}.log", node_id));

    // Non-blocking writer (for async safe logging)
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // Keep guard alive so logs flush correctly at runtime exit
    Box::leak(Box::new(guard));

    // Build the tracing subscriber
    fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .json() // Output logs in JSON format
        .with_timer(ChronoLocal::rfc_3339()) // Add timestamp in ISO 8601 format
        .with_writer(non_blocking) // Write logs asynchronously
        .flatten_event(true) // Flatten structured fields into one object
        .with_target(false) // Remove Rust target module info
        .with_current_span(false) // Disable span nesting in JSON
        .with_ansi(false) // Disable color codes for log files
        .init();
    info!(node = %node_id, time = %Local::now().to_rfc3339(), "Logger initialized successfully");
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
