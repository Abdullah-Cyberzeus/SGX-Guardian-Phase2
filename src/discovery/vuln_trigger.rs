use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;

/// Stub: enqueues newly-seen device IDs for AI review.
/// The current implementation logs the event; a future integration can
/// forward it to the correlation engine.
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
    // TODO: send to virtual_shift::ingest_discovery_delta(...)
}
