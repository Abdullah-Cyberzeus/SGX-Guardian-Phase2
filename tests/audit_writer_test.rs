use sgx_guardian_client::audit::event::*;
use sgx_guardian_client::audit::verifier::AuditVerifier;
use sgx_guardian_client::audit::writer::AuditWriter;
use std::io::Write;
use std::path::PathBuf;
use tempfile::tempdir;

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

#[test]
fn verify_handles_multi_segment_log() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit-segments.log");

    {
        let mut w = AuditWriter::new(path.clone());
        let e1 = AuditEvent::new(
            "nodeA".into(),
            AuditCategory::Node,
            AuditSeverity::Info,
            AuditAction::Started,
            "seg1-line1".into(),
        );
        let e2 = AuditEvent::new(
            "nodeA".into(),
            AuditCategory::Node,
            AuditSeverity::Info,
            AuditAction::Loaded,
            "seg1-line2".into(),
        );
        w.append(&e1).unwrap();
        w.append(&e2).unwrap();
    }
    {
        use sha2::{Digest, Sha256};
        use std::fs::OpenOptions;

        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        let payload = r#"{"timestamp":999,"node_id":"nodeA","category":"Node","severity":"Info","action":"Started","message":"seg2-line1"}"#;
        let mut h = Sha256::new();
        h.update(b"GENESIS");
        h.update(payload.as_bytes());
        let hash = format!("{:x}", h.finalize());
        let line = format!(
            r#"{{"previous_hash":"GENESIS","hash":"{}","event":{}}}"#,
            hash, payload
        );
        writeln!(f, "{}", line).unwrap();
    }

    let (total, segments) =
        AuditVerifier::verify(path.to_str().unwrap()).expect("multi-segment log must verify");
    assert!(total >= 3);
    assert_eq!(
        segments, 2,
        "verifier must recognise the second segment boundary"
    );
}
