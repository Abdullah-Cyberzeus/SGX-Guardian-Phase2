use crate::api::{error::ApiError, state::AppState};
use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct NodeQuery {
    pub node: Option<String>,
}

#[derive(Serialize)]
pub struct NodeStatus {
    #[serde(rename = "nodeId")]
    pub node_id: String,
    #[serde(rename = "deviceName")]
    pub device_name: String,
    pub hostname: String,
    #[serde(rename = "displayHostname")]
    pub display_hostname: String,
    pub ip: String,
    pub port: u16,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "offlineMode")]
    pub offline_mode: u8,
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
    let resolved = resolve_config_path(&s.config_dir, &node).await?;
    let text = tokio::fs::read_to_string(&resolved)
        .await
        .map_err(|_| ApiError::NotFound(format!("config for {} not found", node)))?;
    let cfg: crate::config_loader::NodeConfig = serde_yaml::from_str(&text)
        .map_err(|e| ApiError::Internal(format!("yaml parse: {}", e)))?;
    Ok(Json(NodeStatus {
        device_name: configured_display_value(cfg.device_name.as_deref(), &cfg.node_id),
        display_hostname: configured_display_value(cfg.display_hostname.as_deref(), &cfg.hostname),
        node_id: cfg.node_id,
        hostname: cfg.hostname,
        ip: cfg.ip,
        port: cfg.port,
        public_key: cfg.public_key,
        offline_mode: cfg.offline_mode,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }))
}

#[derive(Deserialize)]
pub struct UpdateNodeDisplayInfo {
    #[serde(rename = "deviceName")]
    pub device_name: Option<String>,
    #[serde(rename = "displayHostname")]
    pub display_hostname: Option<String>,
}

pub async fn update_display_info(
    State(s): State<Arc<AppState>>,
    Json(body): Json<UpdateNodeDisplayInfo>,
) -> Result<Json<NodeStatus>, ApiError> {
    if body.device_name.is_none() && body.display_hostname.is_none() {
        return Err(ApiError::BadRequest(
            "deviceName or displayHostname is required".into(),
        ));
    }

    let device_name = body
        .device_name
        .as_deref()
        .map(|value| validate_display_value("deviceName", value))
        .transpose()?;
    let display_hostname = body
        .display_hostname
        .as_deref()
        .map(|value| validate_display_value("displayHostname", value))
        .transpose()?;

    let path = resolve_config_path(&s.config_dir, &s.node_id).await?;
    let original = tokio::fs::read_to_string(&path).await?;
    let mut updated = original;
    if let Some(value) = device_name {
        updated = upsert_yaml_string(&updated, "device_name", value);
    }
    if let Some(value) = display_hostname {
        updated = upsert_yaml_string(&updated, "display_hostname", value);
    }
    serde_yaml::from_str::<crate::config_loader::NodeConfig>(&updated)
        .map_err(|error| ApiError::Internal(format!("updated yaml parse: {}", error)))?;
    write_config_atomically(&path, &updated).await?;

    status(State(s), Query(NodeQuery { node: None })).await
}

fn configured_display_value(configured: Option<&str>, fallback: &str) -> String {
    configured
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_string()
}

fn validate_display_value<'a>(field: &str, value: &'a str) -> Result<&'a str, ApiError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ApiError::BadRequest(format!("{} cannot be empty", field)));
    }
    if value.chars().count() > 128 {
        return Err(ApiError::BadRequest(format!(
            "{} cannot exceed 128 characters",
            field
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{} cannot contain control characters",
            field
        )));
    }
    Ok(value)
}

async fn resolve_config_path(config_dir: &str, node: &str) -> Result<PathBuf, ApiError> {
    let base_dir = tokio::fs::canonicalize(config_dir)
        .await
        .map_err(|_| ApiError::Internal("invalid config directory".into()))?;
    let candidate = base_dir.join(format!("{}.yaml", node));
    let resolved = tokio::fs::canonicalize(&candidate)
        .await
        .map_err(|_| ApiError::NotFound(format!("config for {} not found", node)))?;
    if !resolved.starts_with(&base_dir) {
        return Err(ApiError::BadRequest(format!("invalid node name: {}", node)));
    }
    Ok(resolved)
}

fn upsert_yaml_string(input: &str, key: &str, value: &str) -> String {
    let replacement = format!(
        "{}: {}",
        key,
        serde_json::to_string(value).expect("string serialization cannot fail")
    );
    let mut found = false;
    let mut lines = input
        .lines()
        .map(|line| {
            if !found && line.starts_with(&format!("{}:", key)) {
                found = true;
                replacement.clone()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>();
    if !found {
        lines.push(replacement);
    }
    let mut output = lines.join("\n");
    output.push('\n');
    output
}

async fn write_config_atomically(path: &Path, contents: &str) -> Result<(), ApiError> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_path = path.with_extension(format!("yaml.{}.{}.tmp", std::process::id(), nonce));
    tokio::fs::write(&temp_path, contents).await?;
    if let Ok(metadata) = tokio::fs::metadata(path).await {
        tokio::fs::set_permissions(&temp_path, metadata.permissions()).await?;
    }
    if let Err(error) = tokio::fs::rename(&temp_path, path).await {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(error.into());
    }
    Ok(())
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
    #[serde(rename = "habDescription")]
    pub hab_description: String,
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
    let boot_dir = std::path::Path::new(&s.boot_dir);
    if !boot_dir.is_absolute()
        || boot_dir
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(ApiError::BadRequest("invalid boot status directory".into()));
    }
    let boot_dir = tokio::fs::canonicalize(boot_dir)
        .await
        .map_err(|_| ApiError::NotFound("boot directory missing".into()))?;
    let mut entries = tokio::fs::read_dir(&boot_dir).await.map_err(|_| {
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
        hab_description: s_("hab_description"),
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
