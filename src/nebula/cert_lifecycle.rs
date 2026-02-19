//! Nebula Certificate Expiry Monitor
//! Runs as background task and periodically checks certificate expiry.

use crate::logging::{log_error, log_event};
use crate::nebula::health::NebulaHealth;
use tokio::time::{sleep, Duration};

pub struct ExpiryMonitor;

impl ExpiryMonitor {
    /// Start background expiry monitoring task
    pub fn start(nebula_base_dir: String, node_name: String) {
        tokio::spawn(async move {
            loop {
                let report = NebulaHealth::check(&nebula_base_dir, &node_name);

                if let Some(days) = report.cert_days_remaining {
                    if days <= 0 {
                        let msg =
        "❌ CRITICAL: Nebula certificate has EXPIRED. Please restart Guardian immediately to obtain a new certificate."
            .to_string();
                        println!("{}", msg);
                        log_error(&node_name, &msg);

                        crate::audit::logger::log_audit(
                            &node_name,
                            crate::audit::event::AuditCategory::Tls,
                            crate::audit::event::AuditSeverity::Critical,
                            crate::audit::event::AuditAction::Failed,
                            "Nebula certificate expired",
                        );

                        // === Auto delete expired cert ===
                        let nodes_dir = format!("{}/nodes", nebula_base_dir);
                        let cert_path = format!("{}/{}.crt", nodes_dir, node_name);
                        let key_path = format!("{}/{}.key", nodes_dir, node_name);

                        if std::path::Path::new(&cert_path).exists() {
                            let _ = std::fs::remove_file(&cert_path);
                        }

                        if std::path::Path::new(&key_path).exists() {
                            let _ = std::fs::remove_file(&key_path);
                        }

                        log_event(
                            &node_name,
                            "Expired Nebula certificate deleted for regeneration",
                        );
                    }
                    else if days <= 7 {
                        let msg =
                            format!("🚨 CRITICAL: Nebula certificate expires in {} days", days);
                        println!("{}", msg);
                        log_error(&node_name, &msg);
                        crate::audit::logger::log_audit(
                            &node_name,
                            crate::audit::event::AuditCategory::Tls,
                            crate::audit::event::AuditSeverity::Critical,
                            crate::audit::event::AuditAction::Succeeded,
                            &format!("Nebula certificate expires in {} days", days),
                        );
                    } else if days <= 30 {
                        let msg =
                            format!("⚠️ WARNING: Nebula certificate expires in {} days", days);
                        println!("{}", msg);
                        log_event(&node_name, &msg);
                        crate::audit::logger::log_audit(
                            &node_name,
                            crate::audit::event::AuditCategory::Tls,
                            crate::audit::event::AuditSeverity::Warning,
                            crate::audit::event::AuditAction::Succeeded,
                            &format!("Nebula certificate expires in {} days", days),
                        );
                    } else {
                        let msg =
                            format!("✅ Nebula certificate healthy ({} days remaining)", days);
                        println!("{}", msg);
                        log_event(&node_name, &msg);
                    }
                } else {
                    let msg = "⚠️ Could not determine Nebula certificate expiry".to_string();
                    println!("{}", msg);
                    log_event(&node_name, &msg);
                    crate::audit::logger::log_audit(
                        &node_name,
                        crate::audit::event::AuditCategory::Tls,
                        crate::audit::event::AuditSeverity::Warning,
                        crate::audit::event::AuditAction::Failed,
                        "Nebula certificate expiry could not be determined",
                    );
                }

                sleep(Duration::from_secs(3600)).await; // 1 Hour interval for Guardian Health check testing
            }
        });
    }
}
