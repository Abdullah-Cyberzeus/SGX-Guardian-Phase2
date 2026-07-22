use chrono::Local;
use tracing::{error, info};
use tracing_appender::rolling;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Initializes the global structured JSON logger for SG-X nodes.
///
/// Two separate output layers:
///   - File (`logs/<node>.log`): full JSON, all crates, ISO-8601 timestamps — unchanged audit trail.
///   - Console (stdout): only our crate (`sgx_guardian_client`), no timestamps, no level prefix.
///     Clean orchestration status messages only. Library noise (hyper, axum, tonic, etc.) is silenced.
///
/// Override via RUST_LOG env var to see everything when debugging:
///   RUST_LOG=debug cargo run -- nodeA
pub fn init_logger(node_id: &str) {
    // Create a daily rotating file appender
    let file_appender = rolling::daily("logs", format!("{}.log", node_id));

    // Non-blocking writer (for async safe logging)
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // Keep guard alive so logs flush correctly at runtime exit
    Box::leak(Box::new(guard));

    // --- File layer: full structured JSON, all crates, with timestamps ---
    // Filter: info level for everything (same as before)
    let file_filter = EnvFilter::from_default_env().add_directive("info".parse().unwrap());

    let file_layer = fmt::layer()
        .json()
        .with_timer(ChronoLocal::rfc_3339())
        .with_writer(non_blocking)
        .flatten_event(true)
        .with_target(false)
        .with_current_span(false)
        .with_ansi(false)
        .with_filter(file_filter);

    // --- Console layer: our crate only, no timestamps, no level prefix ---
    // Filter: only sgx_guardian_client at info level — silences hyper/axum/tonic/tower/rustls.
    // If RUST_LOG is set it takes precedence (escape hatch for debugging).
    // Console filter: show our crate at info level, but suppress the
    // "sgx_guardian_client::audit" target which is used by log_event/log_error
    // to write structured JSON fields to the file layer only.
    let console_filter = if std::env::var("RUST_LOG").is_ok() {
        EnvFilter::from_default_env()
    } else {
        EnvFilter::new("sgx_guardian_client=info,sgx_guardian_client::audit=off")
    };

    let stdout_layer = fmt::layer()
        .without_time() // No timestamp on console
        .with_level(false) // No INFO/WARN/ERROR prefix
        .with_target(false) // No module path
        .with_ansi(true)
        .with_filter(console_filter);

    // Build and initialize the tracing subscriber registry
    tracing_subscriber::registry()
        .with(file_layer)
        .with(stdout_layer)
        .init();

    info!(node = %node_id, time = %Local::now().to_rfc3339(), "Logger initialized successfully");
}

/// Logs a normal information-level event for the given node.
/// File-only: writes full structured JSON to the audit log.
/// Important orchestration messages use direct println! in the source instead.
pub fn log_event(node_id: &str, event: &str) {
    // File-only structured record (console filter excludes the audit target)
    info!(
        target: "sgx_guardian_client::audit",
        node = %node_id,
        time = %Local::now().to_rfc3339(),
        event = %event
    );
}

/// Logs an error-level event for the given node.
/// File-only: writes full structured JSON to the audit log.
/// Important error messages use direct eprintln! in the source instead.
pub fn log_error(node_id: &str, err: &str) {
    // File-only structured record (console filter excludes the audit target)
    error!(
        target: "sgx_guardian_client::audit",
        node = %node_id,
        time = %Local::now().to_rfc3339(),
        error = %err
    );
}
