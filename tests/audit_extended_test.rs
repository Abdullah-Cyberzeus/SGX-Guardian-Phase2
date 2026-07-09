// tests/audit_extended_test.rs
// Integration tests for src/audit/logger.rs and src/audit/writer.rs

use sgx_guardian_client::audit::event::{AuditAction, AuditCategory, AuditEvent, AuditSeverity};
use sgx_guardian_client::audit::logger::{init_audit_logger, log_audit};
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
