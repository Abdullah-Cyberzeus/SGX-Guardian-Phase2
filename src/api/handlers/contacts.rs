use crate::api::{error::ApiError, state::AppState};
use crate::contacts::store::{self, Contact, ContactDraft, ContactPatch};
use axum::{
    extract::{Path, State},
    Json,
};
use serde::Serialize;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Serialize)]
pub struct ContactsResponse {
    pub contacts: Vec<Contact>,
    pub total: usize,
    pub timestamp: String,
}

#[derive(Serialize)]
pub struct ContactMutationResponse {
    pub success: bool,
    pub contact: Contact,
}

#[derive(Serialize)]
pub struct ContactDeleteResponse {
    pub success: bool,
    pub did: String,
}

fn contacts_path(state: &AppState) -> std::path::PathBuf {
    std::path::Path::new(&state.admin_dir).join("contacts.json")
}

fn normalize_contact_did(did: &str) -> Result<String, ApiError> {
    let value = did.trim();
    if value.is_empty() {
        return Err(ApiError::BadRequest("DID is required".to_string()));
    }
    if !value.starts_with("did:") {
        return Err(ApiError::BadRequest("DID must start with did:".to_string()));
    }
    Ok(value.to_string())
}

async fn read_peer_registry(filename: &str, state: &AppState) -> Vec<serde_json::Value> {
    for base_dir in [&state.log_dir_primary, &state.log_dir_fallback] {
        let path = std::path::Path::new(base_dir).join(filename);
        let Ok(text) = tokio::fs::read_to_string(path).await else {
            continue;
        };
        if let Ok(values) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
            return values;
        }
    }
    Vec::new()
}

async fn known_trusted_peer_dids(state: &AppState) -> HashSet<String> {
    let mut peers = read_peer_registry("trusted_peers.json", state).await;
    let per_node_filename = format!("trusted_peers_{}.json", state.node_id);
    let per_node_peers = read_peer_registry(&per_node_filename, state).await;

    for peer in &mut peers {
        if peer.get("did").and_then(|value| value.as_str()).is_some() {
            continue;
        }
        let Some(peer_id) = peer.get("peer_id").and_then(|value| value.as_str()) else {
            continue;
        };
        if let Some(did) = per_node_peers.iter().find_map(|candidate| {
            let same_peer = candidate
                .get("peer_id")
                .and_then(|value| value.as_str())
                .is_some_and(|value| value == peer_id);
            same_peer
                .then(|| candidate.get("did").and_then(|value| value.as_str()))
                .flatten()
                .map(str::trim)
                .filter(|value| !value.is_empty())
        }) {
            peer["did"] = serde_json::Value::String(did.to_string());
        }
    }

    peers
        .into_iter()
        .chain(per_node_peers)
        .filter(|peer| {
            peer.get("peer_id")
                .and_then(|value| value.as_str())
                .is_some_and(|peer_id| peer_id != state.node_id)
        })
        .filter(|peer| {
            peer.get("status")
                .and_then(|value| value.as_str())
                .is_some_and(|status| matches!(status, "verified" | "trusted" | "success"))
        })
        .filter(|peer| {
            peer.get("virtual_id")
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.trim().is_empty())
        })
        .filter_map(|peer| {
            peer.get("did")
                .and_then(|value| value.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .collect()
}

async fn ensure_saveable_contact_did(state: &AppState, did: &str) -> Result<(), ApiError> {
    let did = normalize_contact_did(did)?;
    let circle_peer_dids = crate::api::auth::authorization::local_circle_contact_dids(
        &state.node_id,
        &state.device_did,
    )
    .map_err(ApiError::Internal)?;
    let is_browser_member = is_active_browser_member_contact(state, &did).await?;
    if !circle_peer_dids.contains(&did) && !is_browser_member {
        return Err(ApiError::BadRequest(format!(
            "DID {} is not an active peer in any Circle shared with this Guardian",
            did
        )));
    }

    if is_browser_member {
        return Ok(());
    }

    let known_peer_dids = known_trusted_peer_dids(state).await;
    if !known_peer_dids.contains(&did) {
        return Err(ApiError::BadRequest(format!(
            "DID {} is not a known trusted peer for this Guardian",
            did
        )));
    }
    Ok(())
}

async fn is_active_browser_member_contact(state: &AppState, did: &str) -> Result<bool, ApiError> {
    let local_circle_ids =
        crate::api::auth::authorization::local_active_circle_ids(&state.node_id, &state.device_did)
            .map_err(ApiError::Internal)?;
    Ok(matches!(
        crate::api::handlers::browser_member::state_for_did(state, did, &local_circle_ids).await?,
        Some(crate::api::handlers::browser_member::BrowserMemberState::Active)
    ))
}

pub async fn list(State(state): State<Arc<AppState>>) -> Result<Json<ContactsResponse>, ApiError> {
    let contacts = store::list(&contacts_path(&state)).await?;
    let total = contacts.len();
    Ok(Json(ContactsResponse {
        contacts,
        total,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }))
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
) -> Result<Json<Contact>, ApiError> {
    Ok(Json(store::get(&contacts_path(&state), &did).await?))
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    Json(draft): Json<ContactDraft>,
) -> Result<Json<ContactMutationResponse>, ApiError> {
    ensure_saveable_contact_did(&state, &draft.did).await?;
    let contact = store::create(&contacts_path(&state), draft).await?;
    Ok(Json(ContactMutationResponse {
        success: true,
        contact,
    }))
}

pub async fn update(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    Json(patch): Json<ContactPatch>,
) -> Result<Json<ContactMutationResponse>, ApiError> {
    let contact = store::update(&contacts_path(&state), &did, patch).await?;
    Ok(Json(ContactMutationResponse {
        success: true,
        contact,
    }))
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
) -> Result<Json<ContactDeleteResponse>, ApiError> {
    store::delete(&contacts_path(&state), &did).await?;
    Ok(Json(ContactDeleteResponse { success: true, did }))
}
