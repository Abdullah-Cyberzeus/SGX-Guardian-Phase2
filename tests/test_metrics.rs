use sgx_guardian_client::metrics::Metrics;
use std::time::Duration;

/// Mock logging module — we call these once to avoid warnings.
mod mock_logging {
    pub fn log_event(_component: &str, _msg: &str) {}
    pub fn log_error(_component: &str, _msg: &str) {}
}

// Re-export so the Metrics module uses these versions
use mock_logging::{log_error, log_event};

// Force usage to silence dead_code warnings
#[test]
fn _ensure_logging_functions_are_used() {
    log_event("test", "event log");
    log_error("test", "error log");
}

#[test]
fn test_metrics_default_values() {
    let m = Metrics::default();
    assert_eq!(m.connections_total, 0);
    assert_eq!(m.errors_total, 0);
    assert_eq!(m.enforcement_failures_total, 0);
    assert!(!m.policy_active);

    // uptime should be non-zero duration
    let u = m.uptime();
    assert!(u > Duration::from_millis(0));
}

#[test]
fn test_metrics_record_connection() {
    let mut m = Metrics::default();

    m.record_connection();
    assert_eq!(m.connections_total, 1);

    m.record_connection();
    assert_eq!(m.connections_total, 2);
}

#[test]
fn test_metrics_record_error() {
    let mut m = Metrics::default();

    m.record_error();
    assert_eq!(m.errors_total, 1);

    m.record_error();
    assert_eq!(m.errors_total, 2);
}
#[test]
fn test_metrics_policy_active_gauge() {
    let mut m = Metrics::default();

    m.set_policy_active(true);
    assert!(m.policy_active);

    m.set_policy_active(false);
    assert!(!m.policy_active);
}
#[test]
fn test_metrics_enforcement_failure_counter() {
    let mut m = Metrics::default();

    m.record_enforcement_failure();
    assert_eq!(m.enforcement_failures_total, 1);

    m.record_enforcement_failure();
    assert_eq!(m.enforcement_failures_total, 2);
}

#[test]
fn test_metrics_uptime_increases() {
    let m = Metrics::default();

    let first = m.uptime();
    std::thread::sleep(Duration::from_millis(10));
    let second = m.uptime();

    assert!(second > first, "Uptime must increase over time");
}
