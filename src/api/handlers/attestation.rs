use crate::api::{error::ApiError, state::AppState};
use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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

async fn read_log_json(state: &AppState, filename: &str) -> Option<String> {
    match read_json_from_dir(&state.log_dir_primary, filename).await {
        Ok(text) => Some(text),
        Err(_) => read_json_from_dir(&state.log_dir_fallback, filename)
            .await
            .ok(),
    }
}

fn attestation_result_from_status(status: &str) -> String {
    match status.trim().to_ascii_lowercase().as_str() {
        "verified" | "success" | "succeeded" | "pass" | "passed" | "attested" => {
            "success".to_string()
        }
        "failed" | "failure" | "error" | "rejected" => "failed".to_string(),
        _ => "pending".to_string(),
    }
}

fn str_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn trusted_peer_record(value: &Value) -> Option<ApiLastAttestation> {
    let peer_id = str_field(
        value,
        &["node_id", "nodeId", "peer_id", "peerId", "ip", "did"],
    )?;
    let status = str_field(value, &["status", "result"]).unwrap_or_else(|| "pending".to_string());
    Some(ApiLastAttestation {
        peer_id,
        policy_digest: str_field(value, &["policy_digest", "policyDigest"]).unwrap_or_default(),
        result: attestation_result_from_status(&status),
        timestamp: str_field(
            value,
            &[
                "last_attested_at",
                "lastAttestedAt",
                "timestamp",
                "attested_at",
                "attestedAt",
            ],
        )
        .unwrap_or_default(),
        peer_did: str_field(value, &["did", "peer_did", "peerDid"]),
        virtual_id: str_field(value, &["virtual_id", "virtualId"]),
        dkp_pubkey_sha256_b16: str_field(value, &["dkp_pubkey_sha256_b16", "dkpPubkeySha256B16"]),
        pcr_composite_digest: str_field(value, &["pcr_composite_digest", "pcrCompositeDigest"]),
        count: 1,
    })
}

fn trusted_peer_records(text: &str) -> Vec<ApiLastAttestation> {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };

    match value {
        Value::Array(items) => items.iter().filter_map(trusted_peer_record).collect(),
        Value::Object(map) => {
            for key in ["peers", "trusted_peers", "trustedPeers"] {
                if let Some(Value::Array(items)) = map.get(key) {
                    return items.iter().filter_map(trusted_peer_record).collect();
                }
            }
            let single = Value::Object(map.clone());
            if let Some(record) = trusted_peer_record(&single) {
                return vec![record];
            }
            map.values().filter_map(trusted_peer_record).collect()
        }
        _ => Vec::new(),
    }
}

fn last_attestation_records(text: &str) -> Vec<ApiLastAttestation> {
    let list = if text.trim().is_empty() {
        Vec::new()
    } else if let Ok(parsed_list) =
        serde_json::from_str::<Vec<crate::attestation_service::LastAttestation>>(text)
    {
        parsed_list
    } else if let Ok(single) =
        serde_json::from_str::<crate::attestation_service::LastAttestation>(text)
    {
        let mut migrated = single;
        migrated.count = 1;
        vec![migrated]
    } else {
        Vec::new()
    };

    list.into_iter()
        .map(|item| ApiLastAttestation {
            peer_id: item.peer_id,
            policy_digest: item.policy_digest,
            result: attestation_result_from_status(&item.result),
            timestamp: item.timestamp,
            peer_did: item.peer_did,
            virtual_id: item.virtual_id,
            dkp_pubkey_sha256_b16: item.dkp_pubkey_sha256_b16,
            pcr_composite_digest: item.pcr_composite_digest,
            count: item.count,
        })
        .collect()
}

async fn attestation_records(state: &AppState) -> Vec<ApiLastAttestation> {
    let mut records = read_log_json(state, "trusted_peers.json")
        .await
        .map(|text| trusted_peer_records(&text))
        .unwrap_or_default();

    if records.is_empty() {
        if let Some(text) = read_log_json(state, "last_attestation.json").await {
            records = last_attestation_records(&text);
        }
    }

    records.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
    records
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
    let mut response_list = Vec::new();
    for item in attestation_records(&s).await {
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

        response_list.push(item);
    }

    Ok(Json(response_list))
}
