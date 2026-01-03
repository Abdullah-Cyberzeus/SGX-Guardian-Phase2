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
