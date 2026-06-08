use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::threat::error::{ThreatError, ThreatResult};
use std::io::ErrorKind;
use tokio::process::Command;

pub struct RuleManager;

impl RuleManager {
    pub async fn update_rules(node_id: &str) -> ThreatResult<String> {
        if which::which("suricata-update").is_err() {
            return Err(ThreatError::BinaryMissing);
        }

        let output = Command::new("suricata-update")
            .output()
            .await
            .map_err(map_spawn_error)?;

        if !output.status.success() {
            return Err(ThreatError::ServiceStart(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }

        Self::validate_config("/etc/suricata/suricata.yaml").await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let summary = stdout
            .lines()
            .find(|line| line.contains("Loaded "))
            .or_else(|| stdout.lines().rev().find(|line| !line.trim().is_empty()))
            .unwrap_or("rules updated")
            .to_string();

        let _ = Command::new("systemctl")
            .args(["reload", "suricata"])
            .output()
            .await;

        log_audit(
            node_id,
            AuditCategory::Network,
            AuditSeverity::Info,
            AuditAction::Updated,
            &format!("suricata-update: {}", summary),
        );

        Ok(summary)
    }

    pub async fn validate_config(yaml_path: &str) -> ThreatResult<()> {
        let output = Command::new("suricata")
            .args(["-T", "-c", yaml_path])
            .output()
            .await
            .map_err(map_spawn_error)?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = stderr
            .lines()
            .chain(stdout.lines())
            .take(3)
            .collect::<Vec<_>>()
            .join(" | ");

        Err(ThreatError::BadConfig(detail))
    }
}

fn map_spawn_error(err: std::io::Error) -> ThreatError {
    if err.kind() == ErrorKind::NotFound {
        ThreatError::BinaryMissing
    } else {
        ThreatError::Io(err)
    }
}
