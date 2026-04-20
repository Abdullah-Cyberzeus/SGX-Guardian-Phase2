use crate::api::{error::ApiError, state::AppState};
use axum::{extract::State, Json};
use serde::Serialize;
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

pub async fn status(State(s): State<Arc<AppState>>) -> Result<Json<PcrStatus>, ApiError> {
    let path = format!("{}/{}_current.json", s.pcr_dir, s.node_id);
    let text = tokio::fs::read_to_string(&path)
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
