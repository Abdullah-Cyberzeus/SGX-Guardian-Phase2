//! Nebula Certificate Expiry Monitor
//! Runs as background task and periodically checks certificate expiry.

use crate::logging::{log_error, log_event};
use crate::nebula::health::NebulaHealth;
use tokio::time::{sleep, Duration};

/// Outcome of evaluating a single expiry check. Returned so the decision logic
/// can be tested without driving the background loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryAction {
    /// Certificate already expired; cert/key removal was attempted.
    Expired { regenerable: bool },
    /// Expiring within a week.
    Critical,
    /// Expiring within a month.
    Warning,
    /// More than 30 days remaining.
    Healthy,
    /// Expiry could not be determined from the health report.
    Unknown,
}

/// Classify the remaining certificate lifetime.
pub fn classify_days_remaining(days: Option<i64>) -> Option<ExpiryAction> {
    match days {
        None => Some(ExpiryAction::Unknown),
        Some(d) if d <= 0 => None, // caller must handle removal to know `regenerable`
        Some(d) if d <= 7 => Some(ExpiryAction::Critical),
        Some(d) if d <= 30 => Some(ExpiryAction::Warning),
        Some(_) => Some(ExpiryAction::Healthy),
    }
}

/// Delete an expired certificate/key pair so a fresh one can be issued on the
/// next start. A missing file counts as removed.
pub fn remove_expired_material(nebula_base_dir: &str, node_name: &str) -> bool {
    let nodes_dir = format!("{}/nodes", nebula_base_dir);
    let cert_path = format!("{}/{}.crt", nodes_dir, node_name);
    let key_path = format!("{}/{}.key", nodes_dir, node_name);

    let cert_removed =
        !std::path::Path::new(&cert_path).exists() || std::fs::remove_file(&cert_path).is_ok();
    let key_removed =
        !std::path::Path::new(&key_path).exists() || std::fs::remove_file(&key_path).is_ok();

    cert_removed && key_removed
}

/// Run one expiry evaluation: log, audit, and (when expired) clear the stale
/// material. Returns the action that was taken.
pub fn evaluate_once(nebula_base_dir: &str, node_name: &str, days: Option<i64>) -> ExpiryAction {
    match classify_days_remaining(days) {
        Some(ExpiryAction::Unknown) => {
            let msg = "⚠️ Could not determine Guardian Mesh certificate expiry".to_string();
            println!("{}", msg);
            log_event(node_name, &msg);
            crate::audit::logger::log_audit(
                node_name,
                crate::audit::event::AuditCategory::Tls,
                crate::audit::event::AuditSeverity::Warning,
                crate::audit::event::AuditAction::Failed,
                "Guardian Mesh certificate expiry could not be determined",
            );
            ExpiryAction::Unknown
        }
        Some(ExpiryAction::Critical) => {
            // Generic message for stdout (CodeQL: avoid logging precise day count)
            println!("🚨 CRITICAL: Guardian Mesh certificate is nearing expiration");
            let msg = format!(
                "Guardian Mesh certificate expires in {} days",
                days.unwrap_or_default()
            );
            log_error(node_name, &msg);
            crate::audit::logger::log_audit(
                node_name,
                crate::audit::event::AuditCategory::Tls,
                crate::audit::event::AuditSeverity::Critical,
                crate::audit::event::AuditAction::Succeeded,
                &msg,
            );
            ExpiryAction::Critical
        }
        Some(ExpiryAction::Warning) => {
            // Generic message for stdout (CodeQL: avoid logging precise day count)
            println!("⚠️ WARNING: Guardian Mesh certificate will expire soon");
            let msg = format!(
                "Guardian Mesh certificate expires in {} days",
                days.unwrap_or_default()
            );
            log_event(node_name, &msg);
            crate::audit::logger::log_audit(
                node_name,
                crate::audit::event::AuditCategory::Tls,
                crate::audit::event::AuditSeverity::Warning,
                crate::audit::event::AuditAction::Succeeded,
                &msg,
            );
            ExpiryAction::Warning
        }
        Some(ExpiryAction::Healthy) => {
            // Generic message for stdout (CodeQL: avoid logging precise day count)
            println!("✅ Guardian Mesh certificate healthy");
            let msg = format!(
                "Guardian Mesh certificate healthy ({} days remaining)",
                days.unwrap_or_default()
            );
            log_event(node_name, &msg);
            ExpiryAction::Healthy
        }
        Some(ExpiryAction::Expired { .. }) | None => {
            let msg =
        "❌ CRITICAL: Guardian Mesh certificate has EXPIRED. Please restart Guardian immediately to obtain a new certificate."
            .to_string();
            println!("{}", msg);
            log_error(node_name, &msg);

            crate::audit::logger::log_audit(
                node_name,
                crate::audit::event::AuditCategory::Tls,
                crate::audit::event::AuditSeverity::Critical,
                crate::audit::event::AuditAction::Failed,
                "Guardian Mesh certificate expired",
            );

            let regenerable = remove_expired_material(nebula_base_dir, node_name);
            if regenerable {
                log_event(
                    node_name,
                    "Expired Guardian Mesh certificate deleted for regeneration",
                );
            } else {
                log_error(
                    node_name,
                    "Failed to delete expired Guardian Mesh cert/key for regeneration",
                );
            }
            ExpiryAction::Expired { regenerable }
        }
    }
}

pub struct ExpiryMonitor;

impl ExpiryMonitor {
    /// Start background expiry monitoring task
    pub fn start(nebula_base_dir: String, node_name: String) {
        tokio::spawn(async move {
            loop {
                let report = NebulaHealth::check(&nebula_base_dir, &node_name);
                evaluate_once(&nebula_base_dir, &node_name, report.cert_days_remaining);
                sleep(Duration::from_secs(3600)).await; // 1 Hour interval for Guardian Health check testing
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sgx-cert-lifecycle-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("nodes")).unwrap();
        dir
    }

    #[test]
    fn classify_covers_every_band() {
        assert_eq!(classify_days_remaining(None), Some(ExpiryAction::Unknown));
        assert_eq!(classify_days_remaining(Some(0)), None);
        assert_eq!(classify_days_remaining(Some(-5)), None);
        assert_eq!(
            classify_days_remaining(Some(1)),
            Some(ExpiryAction::Critical)
        );
        assert_eq!(
            classify_days_remaining(Some(7)),
            Some(ExpiryAction::Critical)
        );
        assert_eq!(
            classify_days_remaining(Some(8)),
            Some(ExpiryAction::Warning)
        );
        assert_eq!(
            classify_days_remaining(Some(30)),
            Some(ExpiryAction::Warning)
        );
        assert_eq!(
            classify_days_remaining(Some(31)),
            Some(ExpiryAction::Healthy)
        );
    }

    #[test]
    fn remove_expired_material_is_ok_when_files_absent() {
        let dir = temp_dir("absent");
        assert!(remove_expired_material(dir.to_str().unwrap(), "nodeA"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_expired_material_deletes_cert_and_key() {
        let dir = temp_dir("present");
        let nodes = dir.join("nodes");
        std::fs::write(nodes.join("nodeA.crt"), b"cert").unwrap();
        std::fs::write(nodes.join("nodeA.key"), b"key").unwrap();

        assert!(remove_expired_material(dir.to_str().unwrap(), "nodeA"));
        assert!(!nodes.join("nodeA.crt").exists());
        assert!(!nodes.join("nodeA.key").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evaluate_once_handles_all_actions() {
        let dir = temp_dir("evaluate");
        let base = dir.to_str().unwrap().to_string();

        assert_eq!(evaluate_once(&base, "nodeA", None), ExpiryAction::Unknown);
        assert_eq!(
            evaluate_once(&base, "nodeA", Some(365)),
            ExpiryAction::Healthy
        );
        assert_eq!(
            evaluate_once(&base, "nodeA", Some(20)),
            ExpiryAction::Warning
        );
        assert_eq!(
            evaluate_once(&base, "nodeA", Some(3)),
            ExpiryAction::Critical
        );

        let nodes = dir.join("nodes");
        std::fs::write(nodes.join("nodeA.crt"), b"cert").unwrap();
        std::fs::write(nodes.join("nodeA.key"), b"key").unwrap();
        assert_eq!(
            evaluate_once(&base, "nodeA", Some(0)),
            ExpiryAction::Expired { regenerable: true }
        );
        assert!(!nodes.join("nodeA.crt").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn start_spawns_without_panicking() {
        let dir = temp_dir("spawn");
        ExpiryMonitor::start(dir.to_str().unwrap().to_string(), "nodeA".to_string());
        tokio::task::yield_now().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
