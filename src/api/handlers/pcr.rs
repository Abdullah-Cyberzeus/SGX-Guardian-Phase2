use crate::api::{error::ApiError, state::AppState};
use axum::{extract::State, Json};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Serialize)]
pub struct PcrRegister {
    pub index: usize,
    pub name: String,
    pub value: String,
}

#[derive(Serialize)]
pub struct PcrStatus {
    pub node: String,
    pub registers: Vec<PcrRegister>,
    #[serde(rename = "compositeDigest")]
    pub composite_digest: String,
    #[serde(rename = "compositeSignature", skip_serializing_if = "Option::is_none")]
    pub composite_signature: Option<String>,
    #[serde(rename = "integrityStatus")]
    pub integrity_status: String,
    #[serde(rename = "deviceUid")]
    pub device_uid: String,
    #[serde(rename = "keyVersion")]
    pub key_version: u32,
    #[serde(rename = "measuredAt")]
    pub measured_at: String,
    #[serde(rename = "schemaVersion")]
    pub schema_version: u8,
}

const PCR_NAMES: [&str; 5] = [
    "BIOS/Bootloader",
    "Firmware/DTB",
    "Kernel",
    "RootFS",
    "Configuration",
];

#[derive(Serialize)]
pub struct PcrBaselineRegister {
    pub index: usize,
    pub value: String,
    pub description: String,
}

#[derive(Serialize)]
pub struct PcrBaselineResponse {
    pub id: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub registers: Vec<PcrBaselineRegister>,
    pub version: String,
    pub hash: String,
}

#[derive(Serialize)]
pub struct PcrHistoryEntryResponse {
    pub id: String,
    pub timestamp: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registers: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mismatches: Option<u32>,
    #[serde(rename = "matchCount", skip_serializing_if = "Option::is_none")]
    pub match_count: Option<u32>,
    #[serde(rename = "totalCount", skip_serializing_if = "Option::is_none")]
    pub total_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
}

fn baseline_path(state: &AppState) -> PathBuf {
    Path::new(&state.pcr_baseline_dir).join(format!("pcr_{}_baseline.json", state.node_id))
}

fn history_path(state: &AppState) -> PathBuf {
    Path::new(&state.log_dir_primary).join("attestation_results.json")
}

fn read_pcr_baseline(
    state: &AppState,
) -> Result<crate::secure_element::pcr::PcrBaseline, ApiError> {
    use crate::secure_element::pcr::PcrBaseline;

    let base = Path::new(&state.pcr_baseline_dir)
        .canonicalize()
        .map_err(|_| ApiError::NotFound("no PCR baseline found".into()))?;
    let path = baseline_path(state);
    let resolved = path
        .canonicalize()
        .map_err(|_| ApiError::NotFound("no PCR baseline found".into()))?;
    if !resolved.starts_with(&base) {
        return Err(ApiError::NotFound("no PCR baseline found".into()));
    }
    Ok(PcrBaseline::load(
        resolved
            .to_str()
            .ok_or_else(|| ApiError::Internal("invalid PCR baseline path".into()))?,
    )
    .map_err(ApiError::Internal)?)
}

pub async fn baseline_read(
    State(s): State<Arc<AppState>>,
) -> Result<Json<PcrBaselineResponse>, ApiError> {
    let baseline = read_pcr_baseline(&s)?;
    let registers = baseline
        .pcr_values
        .iter()
        .enumerate()
        .map(|(index, value)| PcrBaselineRegister {
            index,
            value: value.clone(),
            description: PCR_NAMES.get(index).copied().unwrap_or("?").to_string(),
        })
        .collect();

    Ok(Json(PcrBaselineResponse {
        id: format!("pcr-{}-baseline", s.node_id),
        created_at: baseline.created_at,
        registers,
        version: format!("v{}", baseline.key_version),
        hash: baseline.composite_digest,
    }))
}

pub async fn history_read(
    State(s): State<Arc<AppState>>,
) -> Result<Json<Vec<PcrHistoryEntryResponse>>, ApiError> {
    let path = history_path(&s);
    let text = match tokio::fs::read_to_string(&path).await {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Json(vec![])),
        Err(err) => return Err(ApiError::from(err)),
    };

    let entries: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap_or_default();
    let history = entries
        .into_iter()
        .enumerate()
        .map(|(idx, entry)| {
            let peer = entry
                .get("peer")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_string();
            let verified = entry
                .get("verified")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            let pcr_match = entry
                .get("pcr_match")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            let reason = entry
                .get("reason")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_string();
            let timestamp = entry
                .get("timestamp")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_string();
            PcrHistoryEntryResponse {
                id: format!("{}-{}", timestamp, idx),
                timestamp,
                status: if verified {
                    "pass".into()
                } else {
                    "fail".into()
                },
                registers: Some(5),
                mismatches: if pcr_match { Some(0) } else { Some(5) },
                match_count: Some(if pcr_match { 5 } else { 0 }),
                total_count: Some(5),
                reason: (!reason.is_empty()).then_some(reason),
                peer: (!peer.is_empty()).then_some(peer),
            }
        })
        .collect();

    Ok(Json(history))
}

pub async fn status(State(s): State<Arc<AppState>>) -> Result<Json<PcrStatus>, ApiError> {
    if !s
        .node_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ApiError::NotFound(
            "no PCR snapshot - daemon not started?".into(),
        ));
    }
    let base = std::path::Path::new(&s.pcr_dir)
        .canonicalize()
        .map_err(|_| ApiError::NotFound("no PCR snapshot - daemon not started?".into()))?;
    let path = base.join(format!("{}_current.json", s.node_id));
    let resolved = path
        .canonicalize()
        .map_err(|_| ApiError::NotFound("no PCR snapshot - daemon not started?".into()))?;
    if !resolved.starts_with(&base) {
        return Err(ApiError::NotFound(
            "no PCR snapshot - daemon not started?".into(),
        ));
    }
    let text = tokio::fs::read_to_string(&resolved)
        .await
        .map_err(|_| ApiError::NotFound("no PCR snapshot - daemon not started?".into()))?;
    let v: serde_json::Value = serde_json::from_str(&text)?;
    let empty: Vec<serde_json::Value> = vec![];
    let values = v
        .get("pcr_values")
        .and_then(|x| x.as_array())
        .unwrap_or(&empty);
    let registers: Vec<PcrRegister> = values
        .iter()
        .enumerate()
        .map(|(i, val)| PcrRegister {
            index: i,
            name: PCR_NAMES.get(i).copied().unwrap_or("?").to_string(),
            value: val.as_str().unwrap_or("").to_string(),
        })
        .collect();
    Ok(Json(PcrStatus {
        node: s.node_id.clone(),
        registers,
        composite_digest: v
            .get("composite_digest")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        composite_signature: v
            .get("composite_signature")
            .and_then(|x| x.as_str())
            .map(String::from),
        integrity_status: v
            .get("integrity_status")
            .and_then(|x| x.as_str())
            .unwrap_or("UNKNOWN")
            .to_string(),
        device_uid: v
            .get("device_uid")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        key_version: v.get("key_version").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        measured_at: v
            .get("measured_at")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        schema_version: v
            .get("schema_version")
            .and_then(|x| x.as_u64())
            .unwrap_or(1) as u8,
    }))
}

use super::dkp::{run_cli, ActionResponse};

pub async fn baseline_create(
    State(_): State<Arc<AppState>>,
) -> Result<Json<ActionResponse>, ApiError> {
    Ok(Json(run_cli(&["pcr-baseline-create"]).await?))
}
pub async fn baseline_verify(
    State(_): State<Arc<AppState>>,
) -> Result<Json<ActionResponse>, ApiError> {
    Ok(Json(run_cli(&["pcr-baseline-verify"]).await?))
}
