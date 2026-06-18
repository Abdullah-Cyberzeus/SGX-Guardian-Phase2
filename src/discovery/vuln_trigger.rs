use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;

/// Stub: enqueues newly-seen device IDs for the AI Threat Prediction Model
/// (Sprint 5) to review. In Sprint 6 we just log; Sprint 7 wires this to
/// the Virtual Shift correlation engine.
pub fn queue_for_ai_review(node_id: &str, new_device_ids: &[String]) {
    if new_device_ids.is_empty() {
        return;
    }
    log_audit(
        node_id,
        AuditCategory::Discovery,
        AuditSeverity::Info,
        AuditAction::Queued,
        &format!(
            "queued {} device(s) for AI vuln triage",
            new_device_ids.len()
        ),
    );
    // TODO Sprint 7: send to virtual_shift::ingest_discovery_delta(...)
}
