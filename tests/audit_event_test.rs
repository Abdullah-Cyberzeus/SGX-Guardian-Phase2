use sgx_guardian_client::audit::event::{AuditAction, AuditCategory, AuditEvent, AuditSeverity};

#[test]
fn audit_event_can_be_created() {
    let ev = AuditEvent::new(
        "nodeA".to_string(),
        AuditCategory::Policy,
        AuditSeverity::Critical,
        AuditAction::Rejected,
        "Policy signature invalid".to_string(),
    );

    assert_eq!(ev.node_id, "nodeA");
    assert!(ev.timestamp > 0);
}

fn event(category: AuditCategory, severity: AuditSeverity, action: AuditAction) -> AuditEvent {
    AuditEvent::new(
        "node-test".into(),
        category,
        severity,
        action,
        "message-test".into(),
    )
}

#[test]
fn audit_event_preserves_message() {
    assert_eq!(
        event(
            AuditCategory::Node,
            AuditSeverity::Info,
            AuditAction::Started
        )
        .message,
        "message-test"
    );
}

#[test]
fn audit_event_timestamp_is_unix_seconds() {
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ev = event(
        AuditCategory::Node,
        AuditSeverity::Info,
        AuditAction::Started,
    );
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!((before..=after).contains(&ev.timestamp));
}

#[test]
fn audit_event_serializes_expected_fields() {
    let value = serde_json::to_value(event(
        AuditCategory::Policy,
        AuditSeverity::Critical,
        AuditAction::Rejected,
    ))
    .unwrap();
    assert_eq!(value["node_id"], "node-test");
    assert_eq!(value["category"], "Policy");
    assert_eq!(value["severity"], "Critical");
    assert_eq!(value["action"], "Rejected");
}

#[test]
fn audit_event_deserializes_from_json() {
    let parsed: AuditEvent = serde_json::from_str(
        r#"{"timestamp":1,"node_id":"n","category":"Node","severity":"Info","action":"Started","message":"m"}"#,
    )
    .unwrap();
    assert_eq!(parsed.timestamp, 1);
    assert_eq!(parsed.node_id, "n");
}

#[test]
fn audit_event_rejects_missing_timestamp() {
    assert!(serde_json::from_str::<AuditEvent>(
        r#"{"node_id":"n","category":"Node","severity":"Info","action":"Started","message":"m"}"#
    )
    .is_err());
}

#[test]
fn audit_event_rejects_unknown_category() {
    assert!(serde_json::from_str::<AuditEvent>(
        r#"{"timestamp":1,"node_id":"n","category":"Unknown","severity":"Info","action":"Started","message":"m"}"#
    )
    .is_err());
}

#[test]
fn audit_event_rejects_unknown_severity() {
    assert!(serde_json::from_str::<AuditEvent>(
        r#"{"timestamp":1,"node_id":"n","category":"Node","severity":"Debug","action":"Started","message":"m"}"#
    )
    .is_err());
}

#[test]
fn audit_event_rejects_unknown_action() {
    assert!(serde_json::from_str::<AuditEvent>(
        r#"{"timestamp":1,"node_id":"n","category":"Node","severity":"Info","action":"Unknown","message":"m"}"#
    )
    .is_err());
}

#[test]
fn audit_severity_ordering_is_expected() {
    assert!(AuditSeverity::Info < AuditSeverity::Warning);
    assert!(AuditSeverity::Warning < AuditSeverity::Critical);
}

#[test]
fn audit_severity_equality_works() {
    assert_eq!(AuditSeverity::Critical, AuditSeverity::Critical);
}

#[test]
fn audit_severity_round_trips() {
    let encoded = serde_json::to_string(&AuditSeverity::Warning).unwrap();
    assert_eq!(
        serde_json::from_str::<AuditSeverity>(&encoded).unwrap(),
        AuditSeverity::Warning
    );
}

#[test]
fn audit_category_node_serializes() {
    assert_eq!(
        serde_json::to_string(&AuditCategory::Node).unwrap(),
        "\"Node\""
    );
}

#[test]
fn audit_category_identity_serializes() {
    assert_eq!(
        serde_json::to_string(&AuditCategory::Identity).unwrap(),
        "\"Identity\""
    );
}

#[test]
fn audit_category_discovery_serializes() {
    assert_eq!(
        serde_json::to_string(&AuditCategory::Discovery).unwrap(),
        "\"Discovery\""
    );
}

#[test]
fn audit_category_vault_serializes() {
    assert_eq!(
        serde_json::to_string(&AuditCategory::Vault).unwrap(),
        "\"Vault\""
    );
}

#[test]
fn audit_category_dusage_serializes() {
    assert_eq!(
        serde_json::to_string(&AuditCategory::Dusage).unwrap(),
        "\"Dusage\""
    );
}

#[test]
fn audit_action_started_serializes() {
    assert_eq!(
        serde_json::to_string(&AuditAction::Started).unwrap(),
        "\"Started\""
    );
}

#[test]
fn audit_action_succeeded_serializes() {
    assert_eq!(
        serde_json::to_string(&AuditAction::Succeeded).unwrap(),
        "\"Succeeded\""
    );
}

#[test]
fn audit_action_failed_serializes() {
    assert_eq!(
        serde_json::to_string(&AuditAction::Failed).unwrap(),
        "\"Failed\""
    );
}

#[test]
fn audit_action_blocked_serializes() {
    assert_eq!(
        serde_json::to_string(&AuditAction::Blocked).unwrap(),
        "\"Blocked\""
    );
}

#[test]
fn audit_action_updated_serializes() {
    assert_eq!(
        serde_json::to_string(&AuditAction::Updated).unwrap(),
        "\"Updated\""
    );
}

#[test]
fn audit_event_clone_preserves_payload() {
    let original = event(
        AuditCategory::Network,
        AuditSeverity::Warning,
        AuditAction::Detected,
    );
    let cloned = original.clone();
    assert_eq!(cloned.node_id, original.node_id);
    assert_eq!(cloned.message, original.message);
}

#[test]
fn audit_event_debug_contains_struct_name() {
    let rendered = format!(
        "{:?}",
        event(
            AuditCategory::Network,
            AuditSeverity::Warning,
            AuditAction::Detected
        )
    );
    assert!(rendered.contains("AuditEvent"));
}

#[test]
fn audit_event_allows_empty_strings() {
    let ev = AuditEvent::new(
        String::new(),
        AuditCategory::Node,
        AuditSeverity::Info,
        AuditAction::Started,
        String::new(),
    );
    assert!(ev.node_id.is_empty());
    assert!(ev.message.is_empty());
}

#[test]
fn audit_event_large_message_serializes() {
    let ev = AuditEvent::new(
        "n".into(),
        AuditCategory::Cloud,
        AuditSeverity::Critical,
        AuditAction::Exported,
        "x".repeat(4096),
    );
    assert_eq!(
        serde_json::to_value(ev).unwrap()["message"]
            .as_str()
            .unwrap()
            .len(),
        4096
    );
}

#[test]
fn audit_event_rejects_lowercase_enum_names() {
    assert!(serde_json::from_str::<AuditEvent>(
        r#"{"timestamp":1,"node_id":"n","category":"node","severity":"info","action":"started","message":"m"}"#
    )
    .is_err());
}
