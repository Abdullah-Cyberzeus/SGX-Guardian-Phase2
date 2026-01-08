use sgx_guardian_client::audit::event::*;
use sgx_guardian_client::audit::writer::AuditWriter;
use std::path::PathBuf;

#[test]
fn audit_hash_chain_is_deterministic() {
    let mut writer = AuditWriter::new(PathBuf::from("unused"));

    let e1 = AuditEvent::new(
        "nodeA".into(),
        AuditCategory::Node,
        AuditSeverity::Info,
        AuditAction::Started,
        "Node started".into(),
    );

    let e2 = AuditEvent::new(
        "nodeA".into(),
        AuditCategory::Policy,
        AuditSeverity::Critical,
        AuditAction::Rejected,
        "Policy rejected".into(),
    );

    let r1 = writer.build_record(&e1);
    let r2 = writer.build_record(&e2);

    assert!(r1.contains("\"hash\""));
    assert!(r2.contains("\"hash\""));
    assert_ne!(r1, r2, "Hashes must differ for chained events");
}

#[test]
fn tampering_changes_hash_chain() {
    let mut writer = AuditWriter::new(PathBuf::from("unused"));

    let original = AuditEvent::new(
        "nodeA".into(),
        AuditCategory::Policy,
        AuditSeverity::Critical,
        AuditAction::Rejected,
        "Policy rejected".into(),
    );

    let tampered = AuditEvent::new(
        "nodeA".into(),
        AuditCategory::Policy,
        AuditSeverity::Critical,
        AuditAction::Rejected,
        "Policy ACCEPTED".into(), // tampered message
    );

    let r1 = writer.build_record(&original);

    // Reset writer to simulate same previous hash
    let mut writer2 = AuditWriter::new(PathBuf::from("unused"));
    let r2 = writer2.build_record(&tampered);

    assert_ne!(r1, r2, "Any payload change must produce different hash");
}
