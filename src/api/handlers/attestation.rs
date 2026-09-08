use crate::api::{error::ApiError, state::AppState};
use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

#[derive(Clone, Serialize)]
pub struct ApiLastAttestation {
    #[serde(rename = "peerId")]
    pub peer_id: String,
    #[serde(rename = "policyDigest")]
    pub policy_digest: String,
    pub result: String,
    pub timestamp: String,
    #[serde(rename = "peerDid", skip_serializing_if = "Option::is_none")]
    pub peer_did: Option<String>,
    #[serde(rename = "virtualId", skip_serializing_if = "Option::is_none")]
    pub virtual_id: Option<String>,
    #[serde(rename = "dkpPubkeySha256B16", skip_serializing_if = "Option::is_none")]
    pub dkp_pubkey_sha256_b16: Option<String>,
    #[serde(rename = "pcrCompositeDigest", skip_serializing_if = "Option::is_none")]
    pub pcr_composite_digest: Option<String>,
    pub count: u64,
}

pub async fn latest_for_peer(state: &AppState, peer_did: &str) -> Option<ApiLastAttestation> {
    let text = match read_json_from_dir(&state.log_dir_primary, "last_attestation.json").await {
        Ok(text) => text,
        Err(_) => read_json_from_dir(&state.log_dir_fallback, "last_attestation.json")
            .await
            .ok()?,
    };
    let records = if let Ok(records) =
        serde_json::from_str::<Vec<crate::attestation_service::LastAttestation>>(&text)
    {
        records
    } else if let Ok(mut record) =
        serde_json::from_str::<crate::attestation_service::LastAttestation>(&text)
    {
        record.count = 1;
        vec![record]
    } else {
        return None;
    };

    records
        .into_iter()
        .filter(|record| {
            record
                .peer_did
                .as_deref()
                .is_some_and(|did| did.eq_ignore_ascii_case(peer_did))
        })
        .max_by(|left, right| left.timestamp.cmp(&right.timestamp))
        .map(|record| ApiLastAttestation {
            peer_id: record.peer_id,
            policy_digest: record.policy_digest,
            result: record.result,
            timestamp: record.timestamp,
            peer_did: record.peer_did,
            virtual_id: record.virtual_id,
            dkp_pubkey_sha256_b16: record.dkp_pubkey_sha256_b16,
            pcr_composite_digest: record.pcr_composite_digest,
            count: record.count,
        })
}

#[derive(Deserialize)]
pub struct AttestationQuery {
    pub peer_did: Option<String>,
    pub result: Option<String>,
}

/// Read a JSON file from a base directory with path-traversal protection.
async fn read_json_from_dir(base_dir: &str, filename: &str) -> Result<String, ApiError> {
    let base = tokio::fs::canonicalize(Path::new(base_dir))
        .await
        .map_err(|_| ApiError::NotFound("directory not found".into()))?;
    let candidate = base.join(filename);
    let resolved = tokio::fs::canonicalize(&candidate)
        .await
        .map_err(|_| ApiError::NotFound("file not found".into()))?;
    if !resolved.starts_with(&base) {
        return Err(ApiError::NotFound("path traversal blocked".into()));
    }
    tokio::fs::read_to_string(&resolved)
        .await
        .map_err(|_| ApiError::NotFound("file unreadable".into()))
}

pub async fn last(
    State(s): State<Arc<AppState>>,
    Query(q): Query<AttestationQuery>,
) -> Result<Json<Vec<ApiLastAttestation>>, ApiError> {
    let text = match read_json_from_dir(&s.log_dir_primary, "last_attestation.json").await {
        Ok(t) => t,
        Err(_) => read_json_from_dir(&s.log_dir_fallback, "last_attestation.json")
            .await
            .map_err(|_| ApiError::NotFound("no attestation result recorded yet".into()))?,
    };

    let list = if text.trim().is_empty() {
        Vec::new()
    } else if let Ok(parsed_list) =
        serde_json::from_str::<Vec<crate::attestation_service::LastAttestation>>(&text)
    {
        parsed_list
    } else if let Ok(single) =
        serde_json::from_str::<crate::attestation_service::LastAttestation>(&text)
    {
        let mut migrated = single;
        migrated.count = 1;
        vec![migrated]
    } else {
        Vec::new()
    };

    let mut response_list = Vec::new();
    for item in list {
        if let Some(ref peer_did_filter) = q.peer_did {
            match &item.peer_did {
                Some(did) => {
                    if !did.eq_ignore_ascii_case(peer_did_filter) {
                        continue;
                    }
                }
                None => continue,
            }
        }

        if let Some(ref result_filter) = q.result {
            if !item.result.eq_ignore_ascii_case(result_filter) {
                continue;
            }
        }

        response_list.push(ApiLastAttestation {
            peer_id: item.peer_id,
            policy_digest: item.policy_digest,
            result: item.result,
            timestamp: item.timestamp,
            peer_did: item.peer_did,
            virtual_id: item.virtual_id,
            dkp_pubkey_sha256_b16: item.dkp_pubkey_sha256_b16,
            pcr_composite_digest: item.pcr_composite_digest,
            count: item.count,
        });
    }

    Ok(Json(response_list))
}
