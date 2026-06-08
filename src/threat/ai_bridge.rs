use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::threat::threat_alert::{Severity, ThreatAlert};

/// Forward High/Critical alerts to the AI anomaly engine.
/// Sprint 8: audit-log only. Sprint 11 will wire this to the AI engine.
pub fn forward_to_ai(node_id: &str, alert: &ThreatAlert) {
    if !matches!(alert.severity, Severity::High | Severity::Critical) {
        return;
    }

    log_audit(
        node_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Used,
        &format!(
            "forwarded sid={} sev={} to AI bridge (stub)",
            alert.signature_id,
            alert.severity.as_str()
        ),
    );
}
