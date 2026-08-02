//! Central audit logger.
//!
//! Provides a safe, best-effort interface to emit tamper-evident audit events.
//! Audit failures must NEVER crash or block the node.

use once_cell::sync::OnceCell;
use std::env;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::audit::event::{AuditAction, AuditCategory, AuditEvent, AuditSeverity};
use crate::audit::writer::AuditWriter;

/// Global audit logger instance (append-only).
static AUDIT_LOGGER: OnceCell<Mutex<AuditWriter>> = OnceCell::new();

/// Initialize the audit logger once at startup.
///
/// Should be called from `main.rs`.
pub fn init_audit_logger(path: PathBuf) {
    let _ = AUDIT_LOGGER.set(Mutex::new(AuditWriter::new(path)));
}
/// Resolve minimum audit severity from environment.
/// Default: Info (log everything)
fn min_audit_severity() -> AuditSeverity {
    match env::var("AUDIT_MIN_SEVERITY").as_deref() {
        Ok("Critical") => AuditSeverity::Critical,
        Ok("Warning") => AuditSeverity::Warning,
        Ok("Info") => AuditSeverity::Info,
        _ => AuditSeverity::Info,
    }
}
/// Emit an audit event (best-effort).
///
/// This function:
/// - NEVER panics
/// - NEVER blocks critical paths
/// - NEVER returns error
pub fn log_audit(
    node_id: &str,
    category: AuditCategory,
    severity: AuditSeverity,
    action: AuditAction,
    message: &str,
) {
    // Severity filtering (noise control)
    let min_severity = min_audit_severity();

    if severity < min_severity {
        return;
    }
    let Some(writer) = AUDIT_LOGGER.get() else {
        // Audit logger not initialized — silently skip
        return;
    };

    let event = AuditEvent::new(
        node_id.to_string(),
        category,
        severity,
        action,
        message.to_string(),
    );

    if let Ok(mut guard) = writer.lock() {
        let _ = guard.append(&event);
    }
}

/// Log a UEP (Unified Enforcement Point) authorization decision.
///
/// This logs both allowed and denied call authorization attempts.
pub fn log_uep_decision(
    node_id: &str,
    caller_role: &str,
    target_role: &str,
    media_type: &str,
    allowed: bool,
    reason: &str,
) {
    let (severity, action) = if allowed {
        (AuditSeverity::Info, AuditAction::Succeeded)
    } else {
        (AuditSeverity::Warning, AuditAction::Rejected)
    };

    let message = format!(
        "UEP call authorization: {} calling {} via {} - {} ({})",
        caller_role,
        target_role,
        media_type,
        if allowed { "ALLOWED" } else { "DENIED" },
        reason
    );

    log_audit(
        node_id,
        AuditCategory::Enforcement,
        severity,
        action,
        &message,
    );
}
