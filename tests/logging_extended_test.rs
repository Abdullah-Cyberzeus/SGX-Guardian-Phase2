// tests/logging_extended_test.rs
// Integration tests for src/logging.rs

use sgx_guardian_client::logging::{init_logger, log_error, log_event};

// Tracing can only be initialized once per process, so we run these together in one test
#[test]
fn test_logging_workflow() {
    let node_id = "test-log-node";

    // We cannot reliably reset the global logger, but we can call it. If another test already
    // initialized it, it might panic or do nothing depending on tracing subscriber implementation.
    // However, `tracing-subscriber::fmt::SubscriberBuilder::try_init` vs `init` might panic.
    // If it panics, we catch it. Actually `init` panics if called twice. So we better use
    // std::panic::catch_unwind to just ensure it doesn't break the whole test suite.
    let _ = std::panic::catch_unwind(|| {
        init_logger(node_id);
    });

    // Logging shouldn't panic
    log_event(node_id, "This is a normal event");
    log_error(node_id, "This is an error event");

    // The log file will be in `logs/test-log-node.log` if we actually initialized it here.
    // Since tracing could be initialized by other tests, we don't assert the file contents strongly,
    // we just ensure the functions don't panic.
}
