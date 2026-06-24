use crate::api::{error::ApiError, state::AppState};
use crate::did::{DidRecord, DEFAULT_DID_PATH};
use crate::policy;
use crate::secure_element::pcr::{read_dkp_key_version, PcrSnapshot};
use crate::virtual_id::{observe_runtime_virtual_id, RuntimeVirtualIdInputs};
use axum::{extract::State, Json};
use serde::Serialize;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Serialize)]
pub struct VidShowResponse {
    pub node: String,
    pub did: String,
    #[serde(rename = "dkpBytes")]
    pub dkp_bytes: usize,
    #[serde(rename = "dkpVersion")]
    pub dkp_version: u32,
    #[serde(rename = "pcrDigest")]
    pub pcr_digest: String,
    #[serde(rename = "policyDigest")]
    pub policy_digest: String,
    #[serde(rename = "nonceI")]
    pub nonce_i: String,
    #[serde(rename = "nonceR")]
    pub nonce_r: String,
    #[serde(rename = "virtualId")]
    pub virtual_id: String,
    #[serde(rename = "changeReason")]
    pub change_reason: String,
    #[serde(rename = "sessionExpiresAt")]
    pub session_expires_at: String,
    #[serde(rename = "sessionTtl")]
    pub session_ttl: i64,
}

#[derive(Debug, Serialize)]
pub struct VidPeersResponse {
    pub peers: Vec<VidPeer>,
}

#[derive(Debug, Serialize)]
pub struct VidPeer {
    pub did: String,
    #[serde(rename = "virtualId")]
    pub virtual_id: String,
    #[serde(rename = "observedAt")]
    pub observed_at: String,
    #[serde(rename = "lastRotationReason", skip_serializing_if = "Option::is_none")]
    pub last_rotation_reason: Option<String>,
}

pub async fn show(State(state): State<Arc<AppState>>) -> Result<Json<VidShowResponse>, ApiError> {
    let pcr_snapshot = read_pcr_snapshot(&state);
    let status = observe_runtime_virtual_id(RuntimeVirtualIdInputs {
        node: state.node_id.clone(),
        state_path: None,
        did: DidRecord::load(DEFAULT_DID_PATH)
            .map(|record| record.did)
            .unwrap_or_default(),
        dkp_pubkey_der: std::fs::read(Path::new(&state.keys_dir).join("dkp_pub.der"))
            .unwrap_or_default(),
        dkp_version: read_dkp_key_version(),
        pcr_values: pcr_snapshot
            .as_ref()
            .map(|snapshot| snapshot.pcr_values.clone())
            .unwrap_or_default(),
        pcr_digest: pcr_snapshot
            .as_ref()
            .map(|snapshot| snapshot.composite_digest.clone())
            .unwrap_or_default(),
        policy_digest: policy::load_effective_policy_material().digest_hex,
    })
    .map_err(|e| ApiError::Internal(format!("VID show: {}", e)))?;

    Ok(Json(VidShowResponse {
        node: status.node,
        did: status.did,
        dkp_bytes: status.dkp_bytes,
        dkp_version: status.dkp_version,
        pcr_digest: status.pcr_digest,
        policy_digest: status.policy_digest,
        nonce_i: status.nonce_i,
        nonce_r: status.nonce_r,
        virtual_id: status.virtual_id,
        change_reason: status.change_reason,
        session_expires_at: status.session_expires_at,
        session_ttl: status.session_ttl,
    }))
}

fn read_pcr_snapshot(state: &AppState) -> Option<PcrSnapshot> {
    let path = Path::new(&state.pcr_dir).join(format!("{}_current.json", state.node_id));
    PcrSnapshot::load(path.to_string_lossy().as_ref()).ok()
}

pub async fn peers(State(state): State<Arc<AppState>>) -> Result<Json<VidPeersResponse>, ApiError> {
    let mut peers: Vec<VidPeer> = state
        .vid_cache
        .snapshot()
        .await
        .into_iter()
        .map(|(did, cached)| VidPeer {
            did,
            virtual_id: cached.vid_hex,
            observed_at: cached.observed_at.to_rfc3339(),
            last_rotation_reason: cached
                .last_rotation_reason
                .map(|reason| reason.as_str().to_string()),
        })
        .collect();
    peers.sort_by(|a, b| a.did.cmp(&b.did));
    Ok(Json(VidPeersResponse { peers }))
}
