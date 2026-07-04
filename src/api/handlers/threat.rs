use super::dkp::{run_cli, ActionResponse};
use crate::api::{error::ApiError, state::AppState};
use crate::threat::{
    blocker::load_block_records,
    config::{BlockMode, SuricataConfig},
    threat_alert::{Severity, ThreatAlert},
};
use axum::{
    extract::{Query, State},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct AlertsQuery {
    pub limit: Option<usize>,
    pub severity: Option<String>,
}

pub async fn list_alerts(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AlertsQuery>,
) -> Result<Json<Vec<ThreatAlert>>, ApiError> {
    let path = PathBuf::from(&state.threat_state_dir).join("alerts.jsonl");
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|_| ApiError::NotFound("no alerts yet - has Suricata produced events?".into()))?;

    let mut alerts: Vec<ThreatAlert> = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_slice(line).ok())
        .collect();

    if let Some(severity) = query.severity.as_deref() {
        alerts.retain(|alert| severity_matches(alert.severity, severity));
    }

    let limit = query.limit.unwrap_or(500).min(10_000);
    if alerts.len() > limit {
        alerts.drain(..alerts.len() - limit);
    }

    Ok(Json(alerts))
}

#[derive(Serialize)]
pub struct BlocksResponse {
    pub blocked: Vec<String>,
}

pub async fn list_blocks(
    State(state): State<Arc<AppState>>,
) -> Result<Json<BlocksResponse>, ApiError> {
    let mut blocked = nft_blocked_ips().await.unwrap_or_default();
    if blocked.is_empty() {
        let path = PathBuf::from(&state.threat_state_dir).join("blocked_ips.json");
        blocked = load_block_records(&path)
            .unwrap_or_default()
            .into_iter()
            .map(|record| record.ip)
            .collect();
    }
    blocked.sort();
    blocked.dedup();
    Ok(Json(BlocksResponse { blocked }))
}

#[derive(Deserialize)]
pub struct UnblockReq {
    pub ip: String,
}

pub async fn unblock(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<UnblockReq>,
) -> Result<Json<ActionResponse>, ApiError> {
    Ok(Json(run_cli(&["threat", "unblock", &body.ip]).await?))
}

pub async fn update_rules(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<ActionResponse>, ApiError> {
    Ok(Json(run_cli(&["threat", "rules-update"]).await?))
}

pub async fn validate_config(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<ActionResponse>, ApiError> {
    Ok(Json(run_cli(&["threat", "validate"]).await?))
}

// ── New endpoints ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ThreatStatusResponse {
    pub suricata: String,
    pub enabled: bool,
    pub block_mode: String,
    pub alert_count: usize,
    pub block_count: usize,
}

pub async fn status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ThreatStatusResponse>, ApiError> {
    let cfg = SuricataConfig::load(Path::new(&state.threat_config_path)).unwrap_or_default();

    let suricata = tokio::process::Command::new("systemctl")
        .args(["is-active", "suricata"])
        .output()
        .await
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let alerts_path = PathBuf::from(&state.threat_state_dir).join("alerts.jsonl");
    let alert_count = tokio::fs::read_to_string(&alerts_path)
        .await
        .map(|text| text.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0);

    let blocks_path = PathBuf::from(&state.threat_state_dir).join("blocked_ips.json");
    let block_count = load_block_records(&blocks_path).unwrap_or_default().len();

    Ok(Json(ThreatStatusResponse {
        suricata,
        enabled: cfg.enabled,
        block_mode: cfg.block_mode.as_str().to_string(),
        alert_count,
        block_count,
    }))
}

pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SuricataConfig>, ApiError> {
    let cfg = SuricataConfig::load(Path::new(&state.threat_config_path))
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(cfg))
}

#[derive(Deserialize)]
pub struct ThreatConfigPatch {
    pub enabled: Option<bool>,
    pub block_mode: Option<BlockMode>,
    pub rule_update_hours: Option<u64>,
    pub block_ttl_secs: Option<u64>,
    pub block_exempt: Option<Vec<String>>,
}

pub async fn set_config(
    State(state): State<Arc<AppState>>,
    Json(patch): Json<ThreatConfigPatch>,
) -> Result<Json<ActionResponse>, ApiError> {
    let config_path = Path::new(&state.threat_config_path);
    let mut cfg = SuricataConfig::load(config_path).unwrap_or_default();

    if let Some(v) = patch.enabled {
        cfg.enabled = v;
    }
    if let Some(v) = patch.block_mode {
        cfg.block_mode = v;
    }
    if let Some(v) = patch.rule_update_hours {
        cfg.rule_update_hours = v;
    }
    if let Some(v) = patch.block_ttl_secs {
        cfg.block_ttl_secs = v;
    }
    if let Some(v) = patch.block_exempt {
        cfg.block_exempt = v;
    }

    cfg.validate()
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let yaml = serde_yaml::to_string(&cfg).map_err(|e| ApiError::Internal(e.to_string()))?;
    tokio::fs::write(&state.threat_config_path, yaml)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(ActionResponse {
        success: true,
        stdout: "config updated — effective within 5 seconds".into(),
        stderr: String::new(),
        restart_required: false,
        timestamp: Utc::now().to_rfc3339(),
    }))
}

#[derive(Deserialize)]
pub struct BlockReq {
    pub ip: String,
}

pub async fn block_ip(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<BlockReq>,
) -> Result<Json<ActionResponse>, ApiError> {
    Ok(Json(run_cli(&["threat", "block", &body.ip]).await?))
}

pub async fn start(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<ActionResponse>, ApiError> {
    let output = tokio::process::Command::new("systemctl")
        .args(["start", "suricata"])
        .output()
        .await
        .map_err(|e| ApiError::Internal(format!("systemctl: {}", e)))?;

    let success = output.status.success();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Ok(Json(ActionResponse {
        success,
        stdout: if success { "suricata started".into() } else { String::new() },
        stderr,
        restart_required: false,
        timestamp: Utc::now().to_rfc3339(),
    }))
}

fn severity_matches(actual: Severity, expected: &str) -> bool {
    actual.as_str().eq_ignore_ascii_case(expected)
        || format!("{:?}", actual).eq_ignore_ascii_case(expected)
}

async fn nft_blocked_ips() -> Result<Vec<String>, ApiError> {
    let output = tokio::process::Command::new("nft")
        .args(["-a", "list", "chain", "inet", "sgx_threat", "input"])
        .output()
        .await
        .map_err(|err| ApiError::Internal(format!("nft list: {}", err)))?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .lines()
        .filter_map(parse_nft_block_ip)
        .collect::<Vec<_>>())
}

fn parse_nft_block_ip(line: &str) -> Option<String> {
    let tokens = line.split_whitespace().collect::<Vec<_>>();
    tokens
        .windows(3)
        .find(|window| (window[0] == "ip" || window[0] == "ip6") && window[1] == "saddr")
        .map(|window| window[2].trim_end_matches(',').to_string())
}
