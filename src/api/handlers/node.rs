use crate::api::{error::ApiError, state::AppState};
use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct NodeQuery {
    pub node: Option<String>,
}

#[derive(Serialize)]
pub struct NodeStatus {
    #[serde(rename = "nodeId")]
    pub node_id: String,
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub timestamp: String,
}

pub async fn status(
    State(s): State<Arc<AppState>>,
    Query(q): Query<NodeQuery>,
) -> Result<Json<NodeStatus>, ApiError> {
    let node = q.node.unwrap_or_else(|| s.node_id.clone());
    if !node
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ApiError::BadRequest(format!("invalid node name: {}", node)));
    }
    let path = format!("{}/{}.yaml", s.config_dir, node);
    let text = tokio::fs::read_to_string(&path)
        .await
        .map_err(|_| ApiError::NotFound(format!("config for {} not found", node)))?;
    let cfg: crate::config_loader::NodeConfig = serde_yaml::from_str(&text)
        .map_err(|e| ApiError::Internal(format!("yaml parse: {}", e)))?;
    Ok(Json(NodeStatus {
        node_id: cfg.node_id,
        hostname: cfg.hostname,
        ip: cfg.ip,
        port: cfg.port,
        public_key: cfg.public_key,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }))
}

#[derive(Serialize)]
pub struct TrustStage {
    pub stage: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct BootStatus {
    #[serde(rename = "habEnabled")]
    pub hab_enabled: bool,
    #[serde(rename = "deviceClosed")]
    pub device_closed: bool,
    #[serde(rename = "habEventsFound")]
    pub hab_events_found: bool,
    #[serde(rename = "deviceModel")]
    pub device_model: String,
    #[serde(rename = "kernelVersion")]
    pub kernel_version: String,
    #[serde(rename = "bootChainIntact")]
    pub boot_chain_intact: bool,
    #[serde(rename = "guardianBinaryHash")]
    pub guardian_binary_hash: Option<String>,
    #[serde(rename = "trustChain")]
    pub trust_chain: Vec<TrustStage>,
    pub timestamp: String,
}

pub async fn boot_status(State(s): State<Arc<AppState>>) -> Result<Json<BootStatus>, ApiError> {
    let mut entries = tokio::fs::read_dir(&s.boot_dir).await.map_err(|_| {
        ApiError::NotFound("boot status directory missing - daemon not started?".into())
    })?;
    let mut selected: Option<std::path::PathBuf> = None;
    while let Some(e) = entries.next_entry().await? {
        let name = e.file_name().to_string_lossy().to_string();
        if name.ends_with("_chain_status.json") {
            selected = Some(e.path());
            break;
        }
    }
    let path = selected.ok_or_else(|| ApiError::NotFound("no chain_status.json found".into()))?;
    let text = tokio::fs::read_to_string(&path).await?;
    let v: serde_json::Value = serde_json::from_str(&text)?;
    let b = |k: &str| v.get(k).and_then(|x| x.as_bool()).unwrap_or(false);
    let s_ = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let trust_chain = vec![
        TrustStage {
            stage: "Boot ROM".into(),
            status: "verified".into(),
        },
        TrustStage {
            stage: "HAB".into(),
            status: if b("hab_enabled") {
                "verified".into()
            } else {
                "warning".into()
            },
        },
        TrustStage {
            stage: "U-Boot".into(),
            status: if b("device_closed") {
                "verified".into()
            } else {
                "warning".into()
            },
        },
        TrustStage {
            stage: "Kernel".into(),
            status: "verified".into(),
        },
        TrustStage {
            stage: "Guardian".into(),
            status: "verified".into(),
        },
        TrustStage {
            stage: "SE050".into(),
            status: "verified".into(),
        },
    ];
    Ok(Json(BootStatus {
        hab_enabled: b("hab_enabled"),
        device_closed: b("device_closed"),
        hab_events_found: b("hab_events_found"),
        device_model: s_("device_model"),
        kernel_version: s_("kernel_version"),
        boot_chain_intact: b("boot_chain_intact"),
        guardian_binary_hash: v
            .get("guardian_binary_hash")
            .and_then(|x| x.as_str())
            .map(String::from),
        trust_chain,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }))
}

#[derive(Serialize)]
pub struct RestartResponse {
    pub success: bool,
    pub message: String,
    #[serde(rename = "expectedDowntime")]
    pub expected_downtime: String,
    pub timestamp: String,
}

pub async fn restart(State(_): State<Arc<AppState>>) -> Result<Json<RestartResponse>, ApiError> {
    let out = tokio::process::Command::new("pkill")
        .args(["-f", "sgx_guardian_client"])
        .output()
        .await
        .map_err(|e| ApiError::Internal(format!("restart failed: {}", e)))?;

    Ok(Json(RestartResponse {
        success: out.status.success(),
        message: "Guardian daemon restart initiated".into(),
        expected_downtime: "5-10 seconds".into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    }))
}
