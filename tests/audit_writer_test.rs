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

fn event(message: &str) -> AuditEvent {
    AuditEvent::new(
        "nodeA".into(),
        AuditCategory::Node,
        AuditSeverity::Info,
        AuditAction::Started,
        message.into(),
    )
}

fn parse_record(record: &str) -> serde_json::Value {
    serde_json::from_str(record).unwrap()
}

#[test]
fn writer_build_record_contains_previous_hash() {
    let mut writer = AuditWriter::new(PathBuf::from("unused"));
    assert!(parse_record(&writer.build_record(&event("m")))
        .get("previous_hash")
        .is_some());
}

#[test]
fn writer_build_record_first_previous_hash_is_genesis() {
    let mut writer = AuditWriter::new(PathBuf::from("unused"));
    assert_eq!(
        parse_record(&writer.build_record(&event("m")))["previous_hash"],
        "GENESIS"
    );
}

#[test]
fn writer_build_record_hash_is_hex() {
    let mut writer = AuditWriter::new(PathBuf::from("unused"));
    let hash = parse_record(&writer.build_record(&event("m")))["hash"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn writer_build_record_embeds_event() {
    let mut writer = AuditWriter::new(PathBuf::from("unused"));
    assert_eq!(
        parse_record(&writer.build_record(&event("hello")))["event"]["message"],
        "hello"
    );
}

#[test]
fn writer_second_record_previous_hash_matches_first_hash() {
    let mut writer = AuditWriter::new(PathBuf::from("unused"));
    let first = parse_record(&writer.build_record(&event("one")));
    let second = parse_record(&writer.build_record(&event("two")));
    assert_eq!(second["previous_hash"], first["hash"]);
}

#[test]
fn writer_append_creates_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    AuditWriter::new(path.clone()).append(&event("m")).unwrap();
    assert!(path.exists());
}

#[test]
fn writer_append_adds_trailing_newline() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    AuditWriter::new(path.clone()).append(&event("m")).unwrap();
    assert!(std::fs::read_to_string(path).unwrap().ends_with('\n'));
}

#[test]
fn writer_append_two_events_writes_two_lines() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let mut writer = AuditWriter::new(path.clone());
    writer.append(&event("one")).unwrap();
    writer.append(&event("two")).unwrap();
    assert_eq!(std::fs::read_to_string(path).unwrap().lines().count(), 2);
}

#[test]
fn writer_new_uses_last_line_hash_as_anchor() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let mut writer = AuditWriter::new(path.clone());
    writer.append(&event("one")).unwrap();
    let last: serde_json::Value = serde_json::from_str(
        std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .last()
            .unwrap(),
    )
    .unwrap();
    let mut resumed = AuditWriter::new(path);
    let next = parse_record(&resumed.build_record(&event("two")));
    assert_eq!(next["previous_hash"], last["hash"]);
}

#[test]
fn writer_new_ignores_malformed_last_line() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    std::fs::write(&path, b"not-json\n").unwrap();
    let mut writer = AuditWriter::new(path);
    assert_eq!(
        parse_record(&writer.build_record(&event("m")))["previous_hash"],
        "GENESIS"
    );
}

#[test]
fn writer_new_ignores_last_line_without_hash() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    std::fs::write(&path, br#"{"event":{}}"#).unwrap();
    let mut writer = AuditWriter::new(path);
    assert_eq!(
        parse_record(&writer.build_record(&event("m")))["previous_hash"],
        "GENESIS"
    );
}

#[test]
fn writer_append_to_directory_errors() {
    let dir = tempdir().unwrap();
    assert!(AuditWriter::new(dir.path().to_path_buf())
        .append(&event("m"))
        .is_err());
}

#[test]
fn verifier_missing_file_returns_error() {
    let dir = tempdir().unwrap();
    assert!(
        AuditVerifier::verify(dir.path().join("missing.log").to_str().unwrap())
            .unwrap_err()
            .contains("Failed to open audit log")
    );
}

#[test]
fn verifier_empty_file_succeeds_with_zero_lines() {
    let file = tempfile::NamedTempFile::new().unwrap();
    assert_eq!(
        AuditVerifier::verify(file.path().to_str().unwrap()).unwrap(),
        (0, 0)
    );
}

#[test]
fn verifier_blank_lines_are_ignored() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"\n \n").unwrap();
    assert_eq!(
        AuditVerifier::verify(file.path().to_str().unwrap()).unwrap(),
        (0, 0)
    );
}

#[test]
fn verifier_valid_writer_log_succeeds() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let mut writer = AuditWriter::new(path.clone());
    writer.append(&event("one")).unwrap();
    writer.append(&event("two")).unwrap();
    assert_eq!(
        AuditVerifier::verify(path.to_str().unwrap()).unwrap(),
        (2, 1)
    );
}

#[test]
fn verifier_invalid_json_reports_line_number() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"{\n").unwrap();
    assert!(AuditVerifier::verify(file.path().to_str().unwrap())
        .unwrap_err()
        .contains("line 1"));
}

#[test]
fn verifier_missing_event_field_errors() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), br#"{"hash":"x","previous_hash":"GENESIS"}"#).unwrap();
    assert_eq!(
        AuditVerifier::verify(file.path().to_str().unwrap()).unwrap_err(),
        "Missing event field"
    );
}

#[test]
fn verifier_missing_hash_field_errors() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), br#"{"previous_hash":"GENESIS","event":{"timestamp":1,"node_id":"n","category":"Node","severity":"Info","action":"Started","message":"m"}}"#).unwrap();
    assert_eq!(
        AuditVerifier::verify(file.path().to_str().unwrap()).unwrap_err(),
        "Missing hash field"
    );
}

#[test]
fn verifier_invalid_event_errors() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        file.path(),
        br#"{"previous_hash":"GENESIS","hash":"x","event":{"timestamp":1}}"#,
    )
    .unwrap();
    assert_eq!(
        AuditVerifier::verify(file.path().to_str().unwrap()).unwrap_err(),
        "Failed to parse event"
    );
}

#[test]
fn verifier_tampered_hash_errors() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    AuditWriter::new(path.clone())
        .append(&event("one"))
        .unwrap();
    let mut value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    value["hash"] = serde_json::json!("bad");
    std::fs::write(&path, serde_json::to_string(&value).unwrap()).unwrap();
    assert!(AuditVerifier::verify(path.to_str().unwrap())
        .unwrap_err()
        .contains("TAMPER"));
}

#[test]
fn verifier_broken_chain_errors() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let mut writer = AuditWriter::new(path.clone());
    writer.append(&event("one")).unwrap();
    writer.append(&event("two")).unwrap();
    let mut lines: Vec<String> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let mut second: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
    second["previous_hash"] = serde_json::json!("broken");
    lines[1] = serde_json::to_string(&second).unwrap();
    std::fs::write(&path, lines.join("\n")).unwrap();
    assert!(AuditVerifier::verify(path.to_str().unwrap())
        .unwrap_err()
        .contains("broken chain"));
}

#[test]
fn verifier_second_genesis_starts_new_segment() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let mut writer = AuditWriter::new(path.clone());
    writer.append(&event("one")).unwrap();
    let mut segment = AuditWriter::new(PathBuf::from("unused"));
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(format!("{}\n", segment.build_record(&event("two"))).as_bytes())
        .unwrap();
    assert_eq!(
        AuditVerifier::verify(path.to_str().unwrap()).unwrap(),
        (2, 2)
    );
}

#[test]
fn verifier_first_line_custom_previous_hash_succeeds_when_hash_matches() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let event = event("seeded");
    let payload = serde_json::to_string(&event).unwrap();
    let mut chain = sgx_guardian_client::audit::hasher::AuditHashChain::new();
    chain.set_last_hash("seed".into());
    let hash = chain.next_hash(&payload);
    std::fs::write(
        file.path(),
        serde_json::json!({"previous_hash":"seed","hash":hash,"event":event}).to_string(),
    )
    .unwrap();
    assert_eq!(
        AuditVerifier::verify(file.path().to_str().unwrap()).unwrap(),
        (1, 1)
    );
}

#[test]
fn verifier_counts_nonblank_lines_only() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let mut writer = AuditWriter::new(path.clone());
    writer.append(&event("one")).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"\n\n")
        .unwrap();
    assert_eq!(
        AuditVerifier::verify(path.to_str().unwrap()).unwrap(),
        (1, 1)
    );
}

#[test]
fn writer_build_record_preserves_empty_message() {
    let mut writer = AuditWriter::new(PathBuf::from("unused"));
    assert_eq!(
        parse_record(&writer.build_record(&event("")))["event"]["message"],
        ""
    );
}

#[test]
fn writer_build_record_preserves_large_message() {
    let mut writer = AuditWriter::new(PathBuf::from("unused"));
    assert_eq!(
        parse_record(&writer.build_record(&event(&"x".repeat(2048))))["event"]["message"]
            .as_str()
            .unwrap()
            .len(),
        2048
    );
}
