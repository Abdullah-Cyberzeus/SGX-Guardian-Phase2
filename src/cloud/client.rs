use anyhow::Result;
use chrono::Utc;
use reqwest::Client;
use serde_json::json;

use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;

pub async fn send_heartbeat(node_id: &str, endpoint: &str) -> Result<()> {
    log_audit(
        node_id,
        AuditCategory::Cloud,
        AuditSeverity::Info,
        AuditAction::Started,
        "Cloud uplink heartbeat started",
    );

    // WAIT for mock cloud server to be ready (startup race fix)
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let client = Client::builder().use_rustls_tls().build()?;

    let payload = json!({
        "node_id": node_id,
        "timestamp": Utc::now().timestamp(),
        "status": "alive"
    });

    let resp = client.post(endpoint).json(&payload).send().await;

    match resp {
        Ok(r) if r.status().is_success() => {
            log_audit(
                node_id,
                AuditCategory::Cloud,
                AuditSeverity::Info,
                AuditAction::Succeeded,
                "Cloud uplink heartbeat succeeded",
            );
            Ok(())
        }
        Ok(r) => {
            log_audit(
                node_id,
                AuditCategory::Cloud,
                AuditSeverity::Warning,
                AuditAction::Failed,
                &format!("Cloud uplink failed with status {}", r.status()),
            );
            Ok(())
        }
        Err(e) => {
            log_audit(
                node_id,
                AuditCategory::Cloud,
                AuditSeverity::Warning,
                AuditAction::Failed,
                &format!("Cloud uplink error: {}", e),
            );
            Ok(())
        }
    }
}
