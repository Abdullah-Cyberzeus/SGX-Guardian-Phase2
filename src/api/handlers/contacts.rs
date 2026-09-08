use crate::api::auth::middleware::AuthenticatedSession;
use crate::api::{error::ApiError, state::AppState};
use crate::contacts::store::{self, Contact, ContactDraft, ContactPatch};
use axum::{
    Extension, Json,
    extract::{Path, State},
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

/// Who a saved contact belongs to: the authenticated user's `user_id`.
/// Contacts are strictly private per account — the admin and every member
/// each keep their own separate address book, even though it's one shared
/// store file.
fn contact_owner(session: &Option<Extension<AuthenticatedSession>>) -> Option<String> {
    session
        .as_ref()
        .map(|Extension(session)| session.claims.sub.clone())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::auth::session::Claims;

    fn member_session(registration_id: &str, circle_ids: Vec<String>) -> AuthenticatedSession {
        AuthenticatedSession {
            claims: Claims {
                sub: registration_id.to_string(),
                role: "member".to_string(),
                scopes: vec![],
                circle_ids,
                browser_registration_id: Some(registration_id.to_string()),
                guardian_fingerprint: None,
                iss: "test".into(),
                iat: 0,
                exp: 0,
                jti: "jti".into(),
            },
            token: "test-token".into(),
        }
    }

    fn as_member(
        registration_id: &str,
        circle_ids: Vec<String>,
    ) -> Option<Extension<AuthenticatedSession>> {
        Some(Extension(member_session(registration_id, circle_ids)))
    }

    fn test_state() -> (tempfile::TempDir, Arc<AppState>) {
        let temp = tempfile::tempdir().expect("tempdir");
        let config_dir = temp.path().join("config");
        std::fs::create_dir_all(&config_dir).expect("config dir");
        let state = AppState::for_tests(
            temp.path(),
            "nodeContactsTest",
            config_dir.display().to_string(),
        );
        (temp, state)
    }

    #[test]
    fn normalize_contact_did_validates_format() {
        assert!(normalize_contact_did("").is_err());
        assert!(normalize_contact_did("   ").is_err());
        assert!(normalize_contact_did("not-a-did").is_err());
        assert_eq!(
            normalize_contact_did(" did:guardian:x ").unwrap(),
            "did:guardian:x"
        );
    }

    #[tokio::test]
    async fn member_can_always_save_their_own_guardians_did_as_a_contact() {
        let (_temp, state) = test_state();
        let session = as_member("did:guardian:member1", vec!["circle-1".to_string()]);
        let Json(response) = create(
            State(state.clone()),
            session.clone(),
            Json(ContactDraft {
                did: state.device_did.clone(),
                name: Some("My Guardian".to_string()),
                alias: None,
                notes: None,
            }),
        )
        .await
        .expect("member can save their own guardian's DID");
        assert!(response.success);
        assert_eq!(response.contact.did, state.device_did);

        let Json(listed) = list(State(state.clone()), session.clone())
            .await
            .expect("list contacts");
        assert_eq!(listed.total, 1);

        let Json(fetched) = get(
            State(state.clone()),
            session.clone(),
            Path(state.device_did.clone()),
        )
        .await
        .expect("get contact");
        assert_eq!(fetched.did, state.device_did);

        let Json(updated) = update(
            State(state.clone()),
            session.clone(),
            Path(state.device_did.clone()),
            Json(ContactPatch {
                name: Some("Renamed".to_string()),
                alias: None,
                notes: None,
            }),
        )
        .await
        .expect("update contact");
        assert_eq!(updated.contact.name.as_deref(), Some("Renamed"));

        let Json(deleted) = delete(
            State(state.clone()),
            session.clone(),
            Path(state.device_did.clone()),
        )
        .await
        .expect("delete contact");
        assert!(deleted.success);

        let Json(after_delete) = list(State(state.clone()), session)
            .await
            .expect("list after delete");
        assert_eq!(after_delete.total, 0);
    }

    #[tokio::test]
    async fn admin_contacts_are_a_separate_address_book_from_member_contacts() {
        let (_temp, state) = test_state();
        // Seed one contact directly via the store as the admin/owner (session=None), and one
        // as a member — they must not see each other's entries.
        store::create(
            &contacts_path(&state),
            None,
            ContactDraft {
                did: "did:guardian:admin-contact".to_string(),
                name: None,
                alias: None,
                notes: None,
            },
        )
        .await
        .expect("seed admin contact");
        let member_owner_did =
            crate::api::handlers::browser_member::did_for_registration("member1");
        store::create(
            &contacts_path(&state),
            Some(member_owner_did.as_str()),
            ContactDraft {
                did: "did:guardian:member-contact".to_string(),
                name: None,
                alias: None,
                notes: None,
            },
        )
        .await
        .expect("seed member contact");

        let Json(admin_view) = list(State(state.clone()), None).await.expect("admin list");
        assert_eq!(admin_view.total, 1);
        assert_eq!(admin_view.contacts[0].did, "did:guardian:admin-contact");

        let member_session = as_member("member1", vec![]);
        let Json(member_view) = list(State(state.clone()), member_session)
            .await
            .expect("member list");
        assert_eq!(member_view.total, 1);
        assert_eq!(member_view.contacts[0].did, "did:guardian:member-contact");
    }

    #[tokio::test]
    async fn create_rejects_an_invalid_did_before_any_membership_check() {
        let (_temp, state) = test_state();
        let err = create(
            State(state),
            None,
            Json(ContactDraft {
                did: "not-a-did".to_string(),
                name: None,
                alias: None,
                notes: None,
            }),
        )
        .await
        .err()
        .expect("invalid DID format");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn create_fails_closed_for_an_unverified_did_with_no_circle_or_peer_data() {
        // With no real circle/VC/trusted-peer data on disk, ensure_saveable_contact_did can't
        // verify this DID belongs to any shared Circle or known trusted peer — it must not be
        // saved silently.
        let (_temp, state) = test_state();
        let err = create(
            State(state),
            None,
            Json(ContactDraft {
                did: "did:guardian:totally-unverified".to_string(),
                name: None,
                alias: None,
                notes: None,
            }),
        )
        .await
        .err()
        .expect("unverified DID must not be saveable");
        assert!(matches!(
            err,
            ApiError::BadRequest(_) | ApiError::Internal(_)
        ));
    }

    #[tokio::test]
    async fn get_and_delete_report_not_found_for_an_unknown_did() {
        let (_temp, state) = test_state();
        let err = get(
            State(state.clone()),
            None,
            Path("did:guardian:ghost".to_string()),
        )
        .await
        .err()
        .expect("unknown contact");
        assert!(matches!(err, ApiError::NotFound(_)));

        let err = delete(State(state), None, Path("did:guardian:ghost".to_string()))
            .await
            .err()
            .expect("unknown contact");
        assert!(matches!(err, ApiError::NotFound(_)));
    }

    fn write_registry(state: &AppState, filename: &str, peers: serde_json::Value) {
        let path = std::path::Path::new(&state.log_dir_primary).join(filename);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("log dir");
        std::fs::write(&path, serde_json::to_vec(&peers).expect("serialize")).expect("write");
    }

    fn registry_state(temp: &tempfile::TempDir) -> std::sync::Arc<AppState> {
        let config_dir = temp.path().join("config");
        std::fs::create_dir_all(&config_dir).expect("config dir");
        AppState::for_tests(temp.path(), "nodeA", config_dir.display().to_string())
    }

    #[tokio::test]
    async fn read_peer_registry_is_empty_for_missing_and_malformed_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = registry_state(&temp);

        assert!(read_peer_registry("absent.json", &state).await.is_empty());

        write_registry(&state, "bad.json", serde_json::json!({"not": "an array"}));
        assert!(
            read_peer_registry("bad.json", &state).await.is_empty(),
            "a JSON document that is not an array reads as empty"
        );
    }

    /// The filter chain that decides which peers may be saved as contacts:
    /// a peer must not be this node, must be attested, must carry a non-empty
    /// virtual id, and must resolve to a non-empty DID.
    #[tokio::test]
    async fn known_trusted_peer_dids_applies_every_filter() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = registry_state(&temp);

        write_registry(
            &state,
            "trusted_peers.json",
            serde_json::json!([
                {"peer_id": "nodeB", "status": "verified", "virtual_id": "vid-b", "did": "did:guardian:b"},
                {"peer_id": "nodeC", "status": "trusted",  "virtual_id": "vid-c", "did": "did:guardian:c"},
                {"peer_id": "nodeD", "status": "success",  "virtual_id": "vid-d", "did": "did:guardian:d"},
                // Excluded: this node itself.
                {"peer_id": "nodeA", "status": "verified", "virtual_id": "vid-a", "did": "did:guardian:a"},
                // Excluded: not attested.
                {"peer_id": "nodeE", "status": "unknown",  "virtual_id": "vid-e", "did": "did:guardian:e"},
                // Excluded: no attested virtual id.
                {"peer_id": "nodeF", "status": "verified", "virtual_id": "   ",   "did": "did:guardian:f"},
                // Excluded: blank DID.
                {"peer_id": "nodeG", "status": "verified", "virtual_id": "vid-g", "did": "   "},
                // Excluded: no peer_id at all.
                {"status": "verified", "virtual_id": "vid-h", "did": "did:guardian:h"}
            ]),
        );

        let dids = known_trusted_peer_dids(&state).await;
        let mut found: Vec<&str> = dids.iter().map(String::as_str).collect();
        found.sort();
        assert_eq!(
            found,
            vec!["did:guardian:b", "did:guardian:c", "did:guardian:d"],
            "all three attested statuses are accepted and every other entry is filtered"
        );
    }

    /// The merged global registry can drop the DID for a peer that the
    /// per-node file still knows, so the DID is backfilled by `peer_id`.
    #[tokio::test]
    async fn known_trusted_peer_dids_backfills_a_missing_did_from_the_per_node_registry() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = registry_state(&temp);

        write_registry(
            &state,
            "trusted_peers.json",
            serde_json::json!([
                {"peer_id": "nodeB", "status": "verified", "virtual_id": "vid-b"},
                {"peer_id": "nodeC", "status": "verified", "virtual_id": "vid-c"}
            ]),
        );
        write_registry(
            &state,
            "trusted_peers_nodeA.json",
            serde_json::json!([
                {"peer_id": "nodeB", "status": "verified", "virtual_id": "vid-b", "did": "did:guardian:b"},
                // Blank DID: not a usable backfill source.
                {"peer_id": "nodeC", "status": "verified", "virtual_id": "vid-c", "did": "  "}
            ]),
        );

        let dids = known_trusted_peer_dids(&state).await;
        assert!(
            dids.contains("did:guardian:b"),
            "nodeB's DID is recovered from the per-node registry: {dids:?}"
        );
        assert_eq!(
            dids.len(),
            1,
            "nodeC has no usable DID in either file: {dids:?}"
        );
    }

    #[tokio::test]
    async fn known_trusted_peer_dids_is_empty_without_any_registry() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = registry_state(&temp);
        assert!(known_trusted_peer_dids(&state).await.is_empty());
    }

    /// This helper only trims and requires the `did:` scheme — it deliberately
    /// does not check the method. A `did:other:...` value passes here and is
    /// rejected later by `ensure_saveable_contact_did`, because it will not be
    /// a member of any Circle.
    #[test]
    fn normalize_contact_did_trims_and_requires_only_the_did_scheme() {
        assert_eq!(
            normalize_contact_did("  did:guardian:abc  ").expect("valid"),
            "did:guardian:abc"
        );
        assert_eq!(
            normalize_contact_did("did:other:abc").expect("any method passes this check"),
            "did:other:abc"
        );

        for invalid in ["", "   ", "not-a-did", "guardian:abc"] {
            assert!(
                normalize_contact_did(invalid).is_err(),
                "{invalid:?} must be rejected"
            );
        }
    }
}
