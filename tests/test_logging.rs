use sgx_guardian_client::logging::{log_error, log_event};

/// We DO NOT test init_logger() because:
/// - It sets a global logger (singleton)
/// - It cannot be initialized twice in test environment
/// - It causes panic if reinitialized
///
/// We only test log_event() and log_error(), ensuring that
/// they run safely without panicking.

#[test]
fn test_log_event_runs_without_panic() {
    // Just verify the function can be called safely.
    // This ensures tracing macros accept the arguments.
    log_event("node-test", "This is a test event");
}

#[test]
fn test_log_error_runs_without_panic() {
    log_error("node-test", "This is a test error");
}

/// Optional extra: test that log_event accepts various inputs
#[test]
fn test_log_event_multiple_inputs() {
    log_event("node1", "Event A");
    log_event("node2", "Event B");
    log_event("node3", "");
    log_event("", "Blank node");
}

/// Optional: test that log_error handles different strings
#[test]
fn test_log_error_multiple_inputs() {
    log_error("node1", "Error A");
    log_error("node2", "Error B");
    log_error("", "No node ID");
    log_error("nodeX", "");
}
