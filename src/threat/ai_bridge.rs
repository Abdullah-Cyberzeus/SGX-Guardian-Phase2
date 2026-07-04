use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::threat::threat_alert::{Severity, ThreatAlert, ThreatCategory};
use chrono::{DateTime, Utc};
use std::sync::OnceLock;
use tokio::sync::broadcast;

/// Normalized feature record pushed to the anomaly engine for every
/// High/Critical Suricata alert.  Fields match what the AI FeatureTap expects:
/// timestamp, severity score, signature id, category, src/dst pair.
#[derive(Debug, Clone)]
pub struct AlertFeature {
    pub ts: DateTime<Utc>,
    pub severity_score: u8,
    pub signature_id: u32,
    pub category: ThreatCategory,
    pub src_ip: String,
    pub dst_ip: String,
}

/// Global broadcast channel.  The AI engine subscribes with `subscribe()`;
/// the eve-alert loop pushes via `forward_to_ai()`.
/// Capacity 1024: a lagging subscriber is dropped rather than blocking the pipeline.
static FEATURE_TAP: OnceLock<broadcast::Sender<AlertFeature>> = OnceLock::new();

fn tap() -> &'static broadcast::Sender<AlertFeature> {
    FEATURE_TAP.get_or_init(|| broadcast::channel(1024).0)
}

/// Called once at startup by the AI engine to receive alert features.
pub fn subscribe() -> broadcast::Receiver<AlertFeature> {
    tap().subscribe()
}

/// Forward a High/Critical alert into the AI anomaly feature tap.
/// Non-blocking: if the AI engine has no active subscriber the send is silently dropped.
pub fn forward_to_ai(node_id: &str, alert: &ThreatAlert) {
    if !matches!(alert.severity, Severity::High | Severity::Critical) {
        return;
    }

    let feature = AlertFeature {
        ts: alert.timestamp,
        severity_score: match alert.severity {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Info => 0,
        },
        signature_id: alert.signature_id,
        category: alert.category,
        src_ip: alert.src_ip.clone(),
        dst_ip: alert.dst_ip.clone(),
    };

    // send() fails only when there are no subscribers — not an error.
    let _ = tap().send(feature);

    log_audit(
        node_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Used,
        &format!(
            "alert sid={} sev={} pushed to AI feature tap",
            alert.signature_id,
            alert.severity.as_str()
        ),
    );
}
