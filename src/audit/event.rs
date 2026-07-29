//! Audit event model definitions.
//!
//! These structures define WHAT an audit event is.
//! Persistence, hashing, and verification are implemented later.
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum AuditCategory {
    Node,
    Identity,
    Did,
    Vc,
    Crl,
    Attestation,
    Policy,
    Enforcement,
    Network,
    Tls,
    Cryptography,
    Cloud,
    /// Network discovery, whitelist mismatches, and vulnerability-triage handoff.
    Discovery,
    Geofence,
    Vault,
    Xfer,
    Notify,
    Circle,
    Rules,
    Dusage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum AuditAction {
    Started,
    Succeeded,
    Failed,
    Rejected,
    Applied,
    Revoked,
    Rollback,
    Created,
    Loaded,
    Exported,
    Used,
    /// Item enqueued for downstream processing (e.g. AI vuln review).
    Queued,
    /// New device / event detected during a scan.
    Detected,
    /// Source IP added to the active block list.
    Blocked,
    /// Rule set or signature database updated.
    Updated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: u64,
    pub node_id: String,

    pub category: AuditCategory,
    pub severity: AuditSeverity,
    pub action: AuditAction,

    pub message: String,
}

impl AuditEvent {
    pub fn new(
        node_id: String,
        category: AuditCategory,
        severity: AuditSeverity,
        action: AuditAction,
        message: String,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs();

        Self {
            timestamp,
            node_id,
            category,
            severity,
            action,
            message,
        }
    }
}
