use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::threat::error::{ThreatError, ThreatResult};
use std::io::ErrorKind;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

/// Bundled Suricata install prefix.  All sub-commands use paths relative to
/// this so the host Python installation is never touched.
const OPT_SURICATA: &str = "/opt/suricata";

pub struct RuleManager;

impl RuleManager {
    pub async fn update_rules(node_id: &str) -> ThreatResult<String> {
        let binary = format!("{}/bin/suricata-update", OPT_SURICATA);
        if !std::path::Path::new(&binary).exists() {
            return Err(ThreatError::BinaryMissing);
        }

        // Env vars scoped to this Command only — never set globally via profile.d.
        // The suricata package lives at /opt/suricata/lib/python3/dist-packages/
        // (confirmed on board via find), NOT python3.10/site-packages.
        // LD_LIBRARY_PATH is also scoped here — setting it globally segfaulted
        // system tools board-wide in a prior incident.
        let python_lib = format!("{}/lib", OPT_SURICATA);
        let pythonpath = format!("{}/lib/python3/dist-packages", OPT_SURICATA);

        let fut = Command::new(&binary)
            .env("PYTHONPATH", &pythonpath)
            .env("LD_LIBRARY_PATH", &python_lib)
            .kill_on_drop(true)
            .output();

        let output = timeout(Duration::from_secs(300), fut)
            .await
            .map_err(|_| ThreatError::ServiceStart("suricata-update timed out (300s)".into()))?
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
            .kill_on_drop(true)
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
        let binary = format!("{}/bin/suricata", OPT_SURICATA);

        let fut = Command::new(&binary)
            .args(["-T", "-c", yaml_path])
            .kill_on_drop(true)
            .output();

        let output = timeout(Duration::from_secs(60), fut)
            .await
            .map_err(|_| ThreatError::BadConfig("suricata config-test timed out (60s)".into()))?
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
