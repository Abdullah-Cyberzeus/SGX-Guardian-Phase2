use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::cert_service::{ApprovalDecision, CertRequestYaml};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct CertRequestInfo {
    pub node_id: String,
    pub requested_at: String,
    pub overlay_ip: String,
    pub public_key_fingerprint: String,
    pub requested_role: String,
    pub approve: String,
}

#[derive(Debug, Deserialize)]
pub struct ApproveRequestPayload {
    pub node_id: String,
    pub decision: String, // "false", "member", "lighthouse", "relay", "lh_relay"
}

fn get_nebula_base_dir() -> String {
    std::env::var("SGX_NEBULA_DIR").unwrap_or("/var/lib/sgx-guardian/nebula".to_string())
}

/// GET /api/v1/cert/requests
pub async fn list_requests(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<Vec<CertRequestInfo>>, ApiError> {
    let base_dir = get_nebula_base_dir();
    let requests_dir = format!("{}/requests", base_dir);

    let mut list = Vec::new();

    if let Ok(entries) = fs::read_dir(requests_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|s| s == "yaml").unwrap_or(false) {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(yaml) = serde_yaml::from_str::<CertRequestYaml>(&content) {
                        let approve_str = match yaml.approve {
                            ApprovalDecision::False => "false",
                            ApprovalDecision::Member => "member",
                            ApprovalDecision::Lighthouse => "lighthouse",
                            ApprovalDecision::Relay => "relay",
                            ApprovalDecision::LhRelay => "lh_relay",
                        }
                        .to_string();

                        list.push(CertRequestInfo {
                            node_id: yaml.node_id,
                            requested_at: yaml.requested_at,
                            overlay_ip: yaml.overlay_ip,
                            public_key_fingerprint: yaml.public_key_fingerprint,
                            requested_role: yaml.requested_role,
                            approve: approve_str,
                        });
                    }
                }
            }
        }
    }

    // Sort requests by requested_at for a stable listing
    list.sort_by(|a, b| a.requested_at.cmp(&b.requested_at));

    Ok(Json(list))
}

/// POST /api/v1/cert/approve
pub async fn approve_request(
    State(_state): State<Arc<AppState>>,
    Json(payload): Json<ApproveRequestPayload>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Validate node_id to prevent path traversal
    if payload.node_id.is_empty()
        || payload.node_id.contains('/')
        || payload.node_id.contains('\\')
        || payload.node_id.contains("..")
    {
        return Err(ApiError::BadRequest("Invalid node_id".to_string()));
    }

    let decision = match payload.decision.trim().to_ascii_lowercase().as_str() {
        "false" | "reject" | "deny" | "no" => ApprovalDecision::False,
        "member" => ApprovalDecision::Member,
        "lighthouse" | "lh" => ApprovalDecision::Lighthouse,
        "relay" => ApprovalDecision::Relay,
        "lh_relay" | "lhrelay" | "relay_lh" => ApprovalDecision::LhRelay,
        _ => return Err(ApiError::BadRequest(
            "Invalid decision. Must be one of: reject/false, member, lighthouse, relay, lh_relay"
                .to_string(),
        )),
    };

    let base_dir = get_nebula_base_dir();
    let yaml_path = format!("{}/requests/{}.yaml", base_dir, payload.node_id);

    if !std::path::Path::new(&yaml_path).exists() {
        return Err(ApiError::NotFound(format!(
            "Request for node {} not found",
            payload.node_id
        )));
    }

    let content = fs::read_to_string(&yaml_path)
        .map_err(|e| ApiError::Internal(format!("Failed to read request file: {}", e)))?;

    let mut yaml: CertRequestYaml = serde_yaml::from_str(&content)
        .map_err(|e| ApiError::Internal(format!("Failed to parse request file: {}", e)))?;

    yaml.approve = decision;

    let updated_content = serde_yaml::to_string(&yaml)
        .map_err(|e| ApiError::Internal(format!("Failed to serialize request file: {}", e)))?;

    fs::write(&yaml_path, updated_content)
        .map_err(|e| ApiError::Internal(format!("Failed to write request file: {}", e)))?;

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": format!("Request for node {} set to {:?}", payload.node_id, decision)
    })))
}
