use crate::api::auth::middleware::AuthenticatedSession;
use crate::api::{error::ApiError, state::AppState};
use crate::contacts::store::{self, Contact, ContactDraft, ContactPatch};
use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::Serialize;
use std::collections::HashSet;
use std::sync::Arc;

/// A member's contacts are restricted to DIDs sharing a Circle with them —
/// unlike the admin/owner, who can save any known trusted peer. `None` means
/// unrestricted (the caller is the Guardian device itself, i.e. admin/owner).
fn member_circle_scope(session: &Option<Extension<AuthenticatedSession>>) -> Option<Vec<String>> {
    session.as_ref().and_then(|Extension(session)| {
        (session.claims.role == "member").then(|| session.claims.circle_ids.clone())
    })
}

/// Who a saved contact belongs to: `None` for the Guardian device itself
/// (admin/owner), `Some(member_did)` for a specific browser member. Contacts
/// are strictly private per-owner — the admin and every member each keep
/// their own separate address book, even though it's one shared store file.
fn contact_owner(session: &Option<Extension<AuthenticatedSession>>) -> Option<String> {
    crate::api::handlers::browser_member::did_from_session(session)
}

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

async fn ensure_saveable_contact_did(
    state: &AppState,
    did: &str,
    member_circle_scope: Option<&[String]>,
) -> Result<(), ApiError> {
    let did = normalize_contact_did(did)?;
    // A member always shares a Circle with the Guardian that hosts them —
    // that's the whole premise of being a registered member — even though
    // the Guardian's own DID is deliberately excluded from the VC-derived
    // "other peers in my Circle" set below (it isn't a peer of itself).
    if member_circle_scope.is_some() && did == state.device_did {
        return Ok(());
    }
    let scope_ids: &[String] = member_circle_scope.unwrap_or(&[]);
    let circle_peer_dids = crate::api::auth::authorization::scoped_circle_contact_dids(
        &state.node_id,
        &state.device_did,
        scope_ids,
    )
    .map_err(ApiError::Internal)?;
    let is_browser_member =
        is_active_browser_member_contact(state, &did, member_circle_scope).await?;
    let denied_message = if member_circle_scope.is_some() {
        format!("DID {} is not an active peer in any Circle you share", did)
    } else {
        format!(
            "DID {} is not an active peer in any Circle shared with this Guardian",
            did
        )
    };
    if !circle_peer_dids.contains(&did) && !is_browser_member {
        return Err(ApiError::BadRequest(denied_message));
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

async fn is_active_browser_member_contact(
    state: &AppState,
    did: &str,
    member_circle_scope: Option<&[String]>,
) -> Result<bool, ApiError> {
    let circle_ids: HashSet<String> = match member_circle_scope {
        Some(ids) => ids.iter().cloned().collect(),
        None => crate::api::auth::authorization::local_active_circle_ids(
            &state.node_id,
            &state.device_did,
        )
        .map_err(ApiError::Internal)?,
    };
    Ok(matches!(
        crate::api::handlers::browser_member::state_for_did(state, did, &circle_ids).await?,
        Some(crate::api::handlers::browser_member::BrowserMemberState::Active)
    ))
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<Json<ContactsResponse>, ApiError> {
    let owner = contact_owner(&session);
    let contacts = store::list(&contacts_path(&state), owner.as_deref()).await?;
    let total = contacts.len();
    Ok(Json(ContactsResponse {
        contacts,
        total,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }))
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Path(did): Path<String>,
) -> Result<Json<Contact>, ApiError> {
    let owner = contact_owner(&session);
    let contact = store::get(&contacts_path(&state), owner.as_deref(), &did).await?;
    Ok(Json(contact))
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Json(draft): Json<ContactDraft>,
) -> Result<Json<ContactMutationResponse>, ApiError> {
    let scope_ids = member_circle_scope(&session);
    ensure_saveable_contact_did(&state, &draft.did, scope_ids.as_deref()).await?;
    let owner = contact_owner(&session);
    let contact = store::create(&contacts_path(&state), owner.as_deref(), draft).await?;
    Ok(Json(ContactMutationResponse {
        success: true,
        contact,
    }))
}

pub async fn update(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Path(did): Path<String>,
    Json(patch): Json<ContactPatch>,
) -> Result<Json<ContactMutationResponse>, ApiError> {
    let owner = contact_owner(&session);
    let contact = store::update(&contacts_path(&state), owner.as_deref(), &did, patch).await?;
    Ok(Json(ContactMutationResponse {
        success: true,
        contact,
    }))
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Path(did): Path<String>,
) -> Result<Json<ContactDeleteResponse>, ApiError> {
    let owner = contact_owner(&session);
    store::delete(&contacts_path(&state), owner.as_deref(), &did).await?;
    Ok(Json(ContactDeleteResponse { success: true, did }))
}
