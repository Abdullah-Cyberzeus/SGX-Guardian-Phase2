use crate::api::{error::ApiError, state::AppState};
use axum::{extract::State, Json};
use serde::Serialize;
use std::sync::Arc;

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
            last_rotation_reason: cached.last_rotation_reason,
        })
        .collect();
    peers.sort_by(|a, b| a.did.cmp(&b.did));
    Ok(Json(VidPeersResponse { peers }))
}
