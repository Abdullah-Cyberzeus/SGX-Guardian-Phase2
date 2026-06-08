use super::dkp::{run_cli, ActionResponse};
use crate::api::{error::ApiError, state::AppState};
use crate::threat::{
    blocker::load_block_records,
    threat_alert::{Severity, ThreatAlert},
};
use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
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
