use chrono::Local;
use tracing::{error, info};
use tracing_appender::rolling;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::{fmt, EnvFilter};

/// Initialize global JSON logger with daily file rotation.
/// Each node writes to its own log file inside `/logs/` folder.
///
/// Example:
/// logs/nodeA.log, logs/nodeB.log, etc.
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

/// Log general information events with timestamp and node context.
pub fn log_event(node_id: &str, event: &str) {
    info!(
        node = %node_id,
        time = %Local::now().to_rfc3339(),
        event = %event
    );
}
pub fn log_error(node_id: &str, err: &str) {
    error!(
        node = %node_id,
        time = %Local::now().to_rfc3339(),
        error = %err
    );
}
