use crate::api::{error::ApiError, state::AppState};
use crate::virtual_id::read_runtime_virtual_id_status;
use axum::{extract::State, Json};
use serde::Serialize;
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
    let status = read_runtime_virtual_id_status(&state.node_id, None)
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_state(base: &std::path::Path) -> Arc<AppState> {
        let config_dir = base.join("config");
        std::fs::create_dir_all(&config_dir).expect("config dir");
        AppState::for_tests(base, "nodeA", config_dir.display().to_string())
    }

    #[tokio::test]
    async fn peers_reports_the_cache_sorted_by_did() {
        let temp = TempDir::new().expect("tempdir");
        let state = test_state(temp.path());
        state
            .vid_cache
            .observe("did:guardian:zeta", "aa00")
            .await;
        state
            .vid_cache
            .observe("did:guardian:alpha", "bb11")
            .await;

        let response = peers(State(state)).await.expect("peer listing");
        let dids: Vec<&str> = response
            .0
            .peers
            .iter()
            .map(|peer| peer.did.as_str())
            .collect();
        assert_eq!(dids, vec!["did:guardian:alpha", "did:guardian:zeta"]);
        let alpha = &response.0.peers[0];
        assert_eq!(alpha.virtual_id, "bb11");
        assert!(!alpha.observed_at.is_empty());
        // The very first observation is recorded as such rather than as a
        // rotation, which is what the UI keys its "new peer" badge off.
        assert_eq!(alpha.last_rotation_reason.as_deref(), Some("initial_observation"));
    }

    #[tokio::test]
    async fn peers_is_empty_before_anything_has_been_observed() {
        let temp = TempDir::new().expect("tempdir");
        let state = test_state(temp.path());
        let response = peers(State(state)).await.expect("peer listing");
        assert!(response.0.peers.is_empty());
    }

    #[tokio::test]
    async fn show_reports_an_error_when_no_runtime_virtual_id_exists() {
        let temp = TempDir::new().expect("tempdir");
        let state = test_state(temp.path());
        let previous = std::env::var_os(crate::virtual_id::RUNTIME_VID_STATE_DIR_ENV);
        std::env::set_var(
            crate::virtual_id::RUNTIME_VID_STATE_DIR_ENV,
            temp.path().join("virtual-id"),
        );
        let result = show(State(state)).await;
        match previous {
            Some(value) => {
                std::env::set_var(crate::virtual_id::RUNTIME_VID_STATE_DIR_ENV, value)
            }
            None => std::env::remove_var(crate::virtual_id::RUNTIME_VID_STATE_DIR_ENV),
        }
        assert!(matches!(result, Err(ApiError::Internal(msg)) if msg.contains("VID show")));
    }
}
