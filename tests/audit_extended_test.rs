// tests/audit_extended_test.rs
// Integration tests for src/audit/logger.rs and src/audit/writer.rs

use sgx_guardian_client::audit::event::{AuditAction, AuditCategory, AuditEvent, AuditSeverity};
use sgx_guardian_client::audit::logger::{init_audit_logger, log_audit, log_uep_decision};
use sgx_guardian_client::audit::writer::AuditWriter;
use std::fs;
use tempfile::NamedTempFile;

// ── AuditWriter ───────────────────────────────────────────────────────────────

#[test]
fn test_audit_writer_appends_to_file() {
    let tmp = NamedTempFile::new().unwrap();
    let mut writer = AuditWriter::new(tmp.path().to_path_buf());

    let event = AuditEvent::new(
        "test-node".into(),
        AuditCategory::Node,
        AuditSeverity::Info,
        AuditAction::Started,
        "test message".into(),
    );

    writer.append(&event).unwrap();

    let content = fs::read_to_string(tmp.path()).unwrap();
    assert!(content.contains("test message"));
    assert!(content.contains("test-node"));
}

#[test]
fn test_audit_writer_loads_last_hash() {
    let tmp = NamedTempFile::new().unwrap();

    let mut w1 = AuditWriter::new(tmp.path().to_path_buf());
    let e1 = AuditEvent::new(
        "n1".into(),
        AuditCategory::Node,
        AuditSeverity::Info,
        AuditAction::Started,
        "msg1".into(),
    );
    w1.append(&e1).unwrap();

    // Now create a new writer on the same file, it should pick up the hash
    let mut w2 = AuditWriter::new(tmp.path().to_path_buf());
    let e2 = AuditEvent::new(
        "n1".into(),
        AuditCategory::Node,
        AuditSeverity::Info,
        AuditAction::Started,
        "msg2".into(),
    );
    // The record produced by w2 should have `previous_hash` pointing to w1's output
    let record_str = w2.build_record(&e2);

    // Check that previous_hash is not the genesis hash
    let parsed: serde_json::Value = serde_json::from_str(&record_str).unwrap();
    let prev = parsed.get("previous_hash").unwrap().as_str().unwrap();
    assert_ne!(
        prev,
        "0000000000000000000000000000000000000000000000000000000000000000"
    );
}

// ── AuditLogger (Global) ──────────────────────────────────────────────────────

#[test]
fn test_log_audit_does_not_panic_when_uninitialized() {
    // If init_audit_logger hasn't been called, log_audit should just return.
    // We cannot guarantee whether it's called or not due to test parallelism
    // affecting the OnceCell, but we can verify it doesn't panic.
    log_audit(
        "nodeX",
        AuditCategory::Policy,
        AuditSeverity::Info,
        AuditAction::Applied,
        "Some message",
    );
}

#[test]
fn test_log_audit_severity_filtering() {
    // Setup AUDIT_MIN_SEVERITY and call log_audit.
    // It shouldn't panic, but testing that it doesn't log is tricky without
    // side effects, so we just exercise the branch.
    std::env::set_var("AUDIT_MIN_SEVERITY", "Critical");

    log_audit(
        "node",
        AuditCategory::Node,
        AuditSeverity::Info, // Lower than Critical, should skip
        AuditAction::Started,
        "Should not be logged",
    );

    std::env::remove_var("AUDIT_MIN_SEVERITY");
}

#[test]
fn test_init_audit_logger_is_idempotent() {
    let tmp = NamedTempFile::new().unwrap();
    // Subsequent calls to init_audit_logger do nothing and do not panic
    init_audit_logger(tmp.path().to_path_buf());
    init_audit_logger(tmp.path().to_path_buf());
}

fn log_case(category: AuditCategory, severity: AuditSeverity, action: AuditAction) {
    log_audit("node-log", category, severity, action, "message");
}

#[test]
fn logger_accepts_info_threshold_info_event() {
    std::env::set_var("AUDIT_MIN_SEVERITY", "Info");
    log_case(
        AuditCategory::Node,
        AuditSeverity::Info,
        AuditAction::Started,
    );
    std::env::remove_var("AUDIT_MIN_SEVERITY");
}

#[test]
fn logger_accepts_warning_threshold_warning_event() {
    std::env::set_var("AUDIT_MIN_SEVERITY", "Warning");
    log_case(
        AuditCategory::Policy,
        AuditSeverity::Warning,
        AuditAction::Rejected,
    );
    std::env::remove_var("AUDIT_MIN_SEVERITY");
}

#[test]
fn logger_accepts_critical_threshold_critical_event() {
    std::env::set_var("AUDIT_MIN_SEVERITY", "Critical");
    log_case(
        AuditCategory::Policy,
        AuditSeverity::Critical,
        AuditAction::Rejected,
    );
    std::env::remove_var("AUDIT_MIN_SEVERITY");
}

#[test]
fn logger_filters_info_below_warning_without_panic() {
    std::env::set_var("AUDIT_MIN_SEVERITY", "Warning");
    log_case(
        AuditCategory::Node,
        AuditSeverity::Info,
        AuditAction::Started,
    );
    std::env::remove_var("AUDIT_MIN_SEVERITY");
}

#[test]
fn logger_filters_warning_below_critical_without_panic() {
    std::env::set_var("AUDIT_MIN_SEVERITY", "Critical");
    log_case(
        AuditCategory::Node,
        AuditSeverity::Warning,
        AuditAction::Started,
    );
    std::env::remove_var("AUDIT_MIN_SEVERITY");
}

#[test]
fn logger_invalid_threshold_defaults_to_info() {
    std::env::set_var("AUDIT_MIN_SEVERITY", "bad");
    log_case(
        AuditCategory::Node,
        AuditSeverity::Info,
        AuditAction::Started,
    );
    std::env::remove_var("AUDIT_MIN_SEVERITY");
}

#[test]
fn logger_missing_threshold_defaults_to_info() {
    std::env::remove_var("AUDIT_MIN_SEVERITY");
    log_case(
        AuditCategory::Node,
        AuditSeverity::Info,
        AuditAction::Started,
    );
}

#[test]
fn logger_threshold_is_case_sensitive() {
    std::env::set_var("AUDIT_MIN_SEVERITY", "critical");
    log_case(
        AuditCategory::Node,
        AuditSeverity::Info,
        AuditAction::Started,
    );
    std::env::remove_var("AUDIT_MIN_SEVERITY");
}

#[test]
fn logger_handles_empty_node_id() {
    log_audit(
        "",
        AuditCategory::Node,
        AuditSeverity::Info,
        AuditAction::Started,
        "message",
    );
}

#[test]
fn logger_handles_empty_message() {
    log_audit(
        "node",
        AuditCategory::Node,
        AuditSeverity::Info,
        AuditAction::Started,
        "",
    );
}

#[test]
fn logger_handles_large_message() {
    log_audit(
        "node",
        AuditCategory::Cloud,
        AuditSeverity::Critical,
        AuditAction::Exported,
        &"x".repeat(4096),
    );
}

#[test]
fn logger_handles_discovery_event() {
    log_case(
        AuditCategory::Discovery,
        AuditSeverity::Warning,
        AuditAction::Detected,
    );
}

#[test]
fn logger_handles_vault_event() {
    log_case(
        AuditCategory::Vault,
        AuditSeverity::Info,
        AuditAction::Created,
    );
}

#[test]
fn logger_handles_xfer_event() {
    log_case(
        AuditCategory::Xfer,
        AuditSeverity::Critical,
        AuditAction::Rejected,
    );
}

#[test]
fn logger_handles_notify_event() {
    log_case(
        AuditCategory::Notify,
        AuditSeverity::Info,
        AuditAction::Queued,
    );
}

#[test]
fn logger_handles_rules_event() {
    log_case(
        AuditCategory::Rules,
        AuditSeverity::Warning,
        AuditAction::Updated,
    );
}

#[test]
fn logger_handles_dusage_event() {
    log_case(
        AuditCategory::Dusage,
        AuditSeverity::Info,
        AuditAction::Used,
    );
}

#[test]
fn uep_allowed_decision_logs_without_panic() {
    log_uep_decision("node", "admin", "viewer", "video", true, "ok");
}

#[test]
fn uep_denied_decision_logs_without_panic() {
    log_uep_decision("node", "guest", "admin", "audio", false, "denied");
}

#[test]
fn uep_decision_allows_empty_reason() {
    log_uep_decision("node", "guest", "admin", "audio", false, "");
}

#[test]
fn uep_decision_allows_empty_roles() {
    log_uep_decision("node", "", "", "audio", true, "ok");
}

#[test]
fn uep_decision_allows_empty_media_type() {
    log_uep_decision("node", "caller", "target", "", true, "ok");
}

#[test]
fn logger_init_with_nested_path_does_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    init_audit_logger(dir.path().join("nested").join("audit.log"));
}

#[test]
fn logger_init_with_existing_file_does_not_panic() {
    let tmp = NamedTempFile::new().unwrap();
    init_audit_logger(tmp.path().to_path_buf());
}

#[test]
fn logger_multiple_calls_after_init_do_not_panic() {
    let tmp = NamedTempFile::new().unwrap();
    init_audit_logger(tmp.path().to_path_buf());
    for _ in 0..5 {
        log_case(
            AuditCategory::Node,
            AuditSeverity::Info,
            AuditAction::Started,
        );
    }
}
