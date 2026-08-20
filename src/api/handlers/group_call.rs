//! Browser API for trusted full-mesh group calls.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Json, Path, Query, State,
    },
    http::{HeaderMap, StatusCode},
    response::{sse::Event, sse::KeepAlive, IntoResponse, Sse},
    Extension,
};
use futures_util::{stream, SinkExt, StreamExt};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::convert::Infallible;
use std::sync::Arc;

static COMPLETED_OPERATIONS: Lazy<dashmap::DashMap<String, GroupSession>> =
    Lazy::new(dashmap::DashMap::new);
static CREATED_OPERATIONS: Lazy<dashmap::DashMap<String, CreateGroupCallResponse>> =
    Lazy::new(dashmap::DashMap::new);

use crate::api::auth::middleware::AuthenticatedSession;
use crate::api::handlers::call::{browser_call_actor_id, local_virtual_id_for_actor};
use crate::api::state::AppState;
use crate::call::{
    GroupCallState, GroupMemberState, GroupParticipant, GroupRole, GroupSession, GroupWireMessage,
    MediaType, ModerationAction, SignalKind, MAX_GROUP_PARTICIPANTS,
};

#[derive(Debug, Deserialize)]
pub struct CreateGroupCallRequest {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub member_ids: Vec<String>,
    #[serde(default)]
    pub call_all: bool,
    pub media: Vec<MediaType>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateGroupCallResponse {
    pub session: GroupSession,
    pub failed_invites: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct GroupSignalRequest {
    pub target_device_id: String,
    #[serde(rename = "type")]
    pub kind: SignalKind,
    pub payload: Value,
    #[serde(default)]
    pub operation_id: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct Cursor {
    #[serde(default)]
    pub after: u64,
}

#[derive(Debug, Deserialize, Default)]
pub struct SocketCursor {
    #[serde(default)]
    pub after: u64,
}

#[derive(Debug, Serialize)]
pub struct GroupSignalsResponse {
    pub signals: Vec<crate::call::BrowserSignal>,
}

#[derive(Debug, Serialize)]
pub struct GroupCallsResponse {
    pub groups: Vec<GroupSession>,
    pub total: usize,
    pub local_device_id: String,
}

#[derive(Debug, Deserialize)]
struct TrustedGroupPeer {
    peer_id: String,
    #[serde(default)]
    did: Option<String>,
    ip: String,
    status: String,
    #[serde(default)]
    virtual_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct ApiError {
    error: String,
}

fn error(status: StatusCode, message: impl Into<String>) -> axum::response::Response {
    (
        status,
        Json(ApiError {
            error: message.into(),
        }),
    )
        .into_response()
}

fn operation_key(
    headers: &HeaderMap,
    node_id: &str,
    action: &str,
    group_id: Option<&str>,
) -> Option<String> {
    if COMPLETED_OPERATIONS.len() > 4096 {
        COMPLETED_OPERATIONS.clear();
    }
    if CREATED_OPERATIONS.len() > 1024 {
        CREATED_OPERATIONS.clear();
    }
    let value = headers.get("idempotency-key")?.to_str().ok()?.trim();
    (!value.is_empty() && value.len() <= 128)
        .then(|| format!("{node_id}:{action}:{}:{value}", group_id.unwrap_or("new")))
}

/// The anchor group-session lookups reconcile a participant's map key
/// against (see `reconcile_participant_key` in `call::group`) — needed even
/// for this node's own self-action calls in case its own entry hasn't been
/// corrected yet (e.g. acting on a group before any snapshot has propagated).
async fn local_nebula_ip(state: &AppState) -> Result<String, Box<axum::response::Response>> {
    state
        .call_nebula_signaling
        .get_local_nebula_ip()
        .await
        .map_err(|error_value| {
            Box::new(error(
                StatusCode::SERVICE_UNAVAILABLE,
                error_value.to_string(),
            ))
        })
}

async fn trusted_group_peers(state: &AppState) -> Result<Vec<TrustedGroupPeer>, String> {
    for base in [&state.log_dir_primary, &state.log_dir_fallback] {
        let path = std::path::Path::new(base).join("trusted_peers.json");
        let Ok(bytes) = tokio::fs::read(path).await else {
            continue;
        };
        let peers: Vec<TrustedGroupPeer> =
            serde_json::from_slice(&bytes).map_err(|_| "Trusted peer registry is malformed")?;
        return Ok(peers
            .into_iter()
            .filter(|peer| {
                matches!(peer.status.as_str(), "verified" | "trusted" | "success")
                    && peer.ip.parse::<std::net::IpAddr>().is_ok()
                    && peer
                        .virtual_id
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty())
            })
            .collect());
    }
    Ok(vec![])
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    session: Option<Extension<AuthenticatedSession>>,
    Json(request): Json<CreateGroupCallRequest>,
) -> impl IntoResponse {
    let operation = operation_key(&headers, &state.node_id, "create", None);
    if let Some(cached) = operation
        .as_ref()
        .and_then(|key| CREATED_OPERATIONS.get(key).map(|value| value.clone()))
    {
        return (StatusCode::OK, Json(cached)).into_response();
    }
    if request.media.is_empty() {
        return error(StatusCode::BAD_REQUEST, "Audio or video is required");
    }
    if !state
        .call_session_manager
        .get_active_sessions()
        .await
        .is_empty()
        || !state
            .group_session_manager
            .active_for(&state.node_id)
            .await
            .is_empty()
    {
        return error(StatusCode::CONFLICT, "Another call is already active");
    }
    let actor_id = browser_call_actor_id(&state, &session);
    let virtual_id = match local_virtual_id_for_actor(&state, &actor_id) {
        Ok(value) => value,
        Err(error_value) => return error(StatusCode::SERVICE_UNAVAILABLE, error_value.error),
    };
    let trusted = match trusted_group_peers(&state).await {
        Ok(peers) => peers,
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, message),
    };
    let member_contacts = if session
        .as_ref()
        .is_some_and(|Extension(session)| session.claims.role == "member")
    {
        match crate::api::auth::authorization::scoped_circle_contact_dids(
            &state.node_id,
            &state.device_did,
            session
                .as_ref()
                .map(|Extension(session)| session.claims.circle_ids.as_slice())
                .unwrap_or(&[]),
        ) {
            Ok(contacts) => Some(contacts),
            Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, message),
        }
    } else {
        None
    };
    // Browser Circle members hosted on this same Guardian have no Nebula
    // identity and never appear in `trusted_group_peers`; they're resolved
    // the same way 1:1 local browser calls are, by DID against this node's
    // own active-user/circle registry.
    let local_circle_ids = match crate::api::auth::authorization::local_active_circle_ids(
        &state.node_id,
        &state.device_did,
    ) {
        Ok(ids) => ids,
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, message),
    };
    let local_browser_dids =
        match crate::api::handlers::browser_member::dids_for_circles(&state, &local_circle_ids)
            .await
        {
            Ok(dids) => dids,
            Err(error_value) => {
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("{:?}", error_value),
                )
            }
        };
    // A member caller can only reach browser members of Circles they
    // themselves belong to — not every Circle this Guardian happens to
    // host. This mirrors `member_contacts` above (the analogous VC-contact
    // scope): `local_browser_dids` is every browser member this Guardian
    // hosts across all Circles (used for a device/admin caller's full
    // reach), while `member_browser_dids` narrows that to the caller's own
    // Circles and is what a member session is actually authorized against.
    let member_browser_dids = match session.as_ref() {
        Some(Extension(session)) if session.claims.role == "member" => {
            let member_circle_ids: std::collections::HashSet<String> =
                session.claims.circle_ids.iter().cloned().collect();
            let scoped_circle_ids: std::collections::HashSet<String> = local_circle_ids
                .intersection(&member_circle_ids)
                .cloned()
                .collect();
            match crate::api::handlers::browser_member::dids_for_circles(
                &state,
                &scoped_circle_ids,
            )
            .await
            {
                Ok(dids) => dids,
                Err(error_value) => {
                    return error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("{:?}", error_value),
                    )
                }
            }
        }
        _ => local_browser_dids.clone(),
    };
    if let Some(contacts) = member_contacts.as_ref() {
        // Browser members never carry a VC, so they never appear in
        // `contacts` — being in `member_browser_dids` (a Circle the caller
        // themselves belongs to) is its own sufficient authorization, the
        // same way chat's `sibling_browser_member` check treats a shared
        // Circle as an alternative to a VC contact, not an additional
        // requirement on top of it.
        let unauthorized_requested = !request.call_all
            && (trusted.iter().any(|peer| {
                request.member_ids.contains(&peer.peer_id)
                    && !peer.did.as_ref().is_some_and(|did| contacts.contains(did))
            }) || request.member_ids.iter().any(|id| {
                local_browser_dids.contains(id) && !member_browser_dids.contains(id)
            }));
        if unauthorized_requested {
            if let Some(Extension(session)) = session.as_ref() {
                crate::api::auth::authorization::audit_member_resource_denied(
                    &state.node_id,
                    &session.claims.sub,
                    "Circle group-call target",
                );
            }
            return error(
                StatusCode::FORBIDDEN,
                "A requested call target does not share a Circle with this Guardian",
            );
        }
    }
    let selected: Vec<_> = trusted
        .into_iter()
        .filter(|peer| {
            (request.call_all || request.member_ids.contains(&peer.peer_id))
                && member_contacts.as_ref().map_or(true, |contacts| {
                    peer.did.as_ref().is_some_and(|did| contacts.contains(did))
                })
        })
        .collect();
    let selected_browser: Vec<String> = local_browser_dids
        .into_iter()
        .filter(|did| {
            (request.call_all || request.member_ids.contains(did))
                && (member_contacts.is_none() || member_browser_dids.contains(did))
        })
        .collect();
    if selected.is_empty() && selected_browser.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "Select at least one trusted member",
        );
    }
    let host_is_browser = actor_id != state.node_id;
    // +1 for the host, and when the host is a browser member, +1 more for
    // the Guardian device seat added below so it gets rung too.
    let extra_seats = if host_is_browser { 2 } else { 1 };
    if selected.len() + selected_browser.len() + extra_seats > MAX_GROUP_PARTICIPANTS {
        return error(
            StatusCode::BAD_REQUEST,
            format!("Group limit is {MAX_GROUP_PARTICIPANTS} participants"),
        );
    }
    let host = GroupParticipant {
        device_id: actor_id.clone(),
        virtual_id,
        nebula_ip: match state.call_nebula_signaling.get_local_nebula_ip().await {
            Ok(ip) => ip,
            Err(error_value) => {
                return error(StatusCode::SERVICE_UNAVAILABLE, error_value.to_string())
            }
        },
        role: GroupRole::Host,
        state: GroupMemberState::Joined,
        audio_allowed: request.media.contains(&MediaType::Audio),
        video_allowed: request.media.contains(&MediaType::Video),
        media_ready: false,
        joined_at: None,
        last_seen_at: Some(chrono::Utc::now()),
        is_local_browser: host_is_browser,
    };
    let mut invitees: Vec<_> = selected
        .iter()
        .map(|peer| GroupParticipant {
            device_id: peer.peer_id.clone(),
            virtual_id: peer.virtual_id.clone().unwrap_or_default(),
            nebula_ip: peer.ip.clone(),
            role: GroupRole::Member,
            state: GroupMemberState::Invited,
            audio_allowed: request.media.contains(&MediaType::Audio),
            video_allowed: request.media.contains(&MediaType::Video),
            media_ready: false,
            joined_at: None,
            last_seen_at: None,
            is_local_browser: false,
        })
        .collect();
    for did in &selected_browser {
        let virtual_id = match local_virtual_id_for_actor(&state, did) {
            Ok(value) => value,
            Err(error_value) => return error(StatusCode::SERVICE_UNAVAILABLE, error_value.error),
        };
        invitees.push(GroupParticipant {
            device_id: did.clone(),
            virtual_id,
            nebula_ip: String::new(),
            role: GroupRole::Member,
            state: GroupMemberState::Invited,
            audio_allowed: request.media.contains(&MediaType::Audio),
            video_allowed: request.media.contains(&MediaType::Video),
            media_ready: false,
            joined_at: None,
            last_seen_at: None,
            is_local_browser: true,
        });
    }
    // The Guardian device/admin console is itself a Circle participant and
    // must be rung too, same as every other member — but when a browser
    // member places the call, the device is neither the host nor a browser
    // member, so it's otherwise never added to the session at all and the
    // admin's `/group-call/active` poll (GroupCallContext) never sees it.
    if host_is_browser {
        let device_virtual_id = match local_virtual_id_for_actor(&state, &state.node_id) {
            Ok(value) => value,
            Err(error_value) => return error(StatusCode::SERVICE_UNAVAILABLE, error_value.error),
        };
        let device_nebula_ip = match state.call_nebula_signaling.get_local_nebula_ip().await {
            Ok(ip) => ip,
            Err(error_value) => {
                return error(StatusCode::SERVICE_UNAVAILABLE, error_value.to_string())
            }
        };
        invitees.push(GroupParticipant {
            device_id: state.node_id.clone(),
            virtual_id: device_virtual_id,
            nebula_ip: device_nebula_ip,
            role: GroupRole::Member,
            state: GroupMemberState::Invited,
            audio_allowed: request.media.contains(&MediaType::Audio),
            video_allowed: request.media.contains(&MediaType::Video),
            media_ready: false,
            joined_at: None,
            last_seen_at: None,
            is_local_browser: false,
        });
    }
    let session = match state
        .group_session_manager
        .create(request.title, host, invitees, request.media)
        .await
    {
        Ok(session) => session,
        Err(error_value) => return error(StatusCode::BAD_REQUEST, error_value.to_string()),
    };
    let invitation = GroupWireMessage::Invite {
        session: session.clone(),
    };
    let host = &session.participants[&session.host_device_id];
    let mut failed_invites = vec![];
    for participant in session.participants.values() {
        // A browser member's invite is already visible to them, and so is
        // the Guardian device's own entry (added above when a member is the
        // host): both share this exact in-process session store, no gRPC
        // delivery needed — only remote trusted-peer Guardians need one.
        if participant.role == GroupRole::Host
            || participant.is_local_browser
            || participant.device_id == state.node_id
        {
            continue;
        }
        if let Err(error_value) = state
            .call_nebula_signaling
            .send_group_control(
                &invitation,
                &session.group_id,
                &state.node_id,
                &host.virtual_id,
                &participant.nebula_ip,
            )
            .await
        {
            failed_invites.push(participant.device_id.clone());
            state.group_session_manager.record_log(
                "group_invite_failed",
                &session.group_id,
                &state.node_id,
                Some(&participant.device_id),
                &error_value.to_string(),
            );
        }
    }
    let response = CreateGroupCallResponse {
        session,
        failed_invites,
    };
    if let Some(operation) = operation {
        CREATED_OPERATIONS.insert(operation, response.clone());
    }
    (StatusCode::CREATED, Json(response)).into_response()
}

pub async fn active(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
) -> impl IntoResponse {
    let actor_id = browser_call_actor_id(&state, &session);
    let groups = state.group_session_manager.active_for(&actor_id).await;
    Json(GroupCallsResponse {
        total: groups.len(),
        groups,
        local_device_id: actor_id,
    })
}

pub async fn join(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<String>,
    headers: HeaderMap,
    session: Option<Extension<AuthenticatedSession>>,
) -> impl IntoResponse {
    let actor_id = browser_call_actor_id(&state, &session);
    let operation = operation_key(&headers, &actor_id, "join", Some(&group_id));
    if let Some(cached) = operation
        .as_ref()
        .and_then(|key| COMPLETED_OPERATIONS.get(key).map(|value| value.clone()))
    {
        return Json(cached).into_response();
    }
    if !state
        .call_session_manager
        .get_active_sessions()
        .await
        .is_empty()
    {
        return error(
            StatusCode::CONFLICT,
            "End the current one-to-one call before joining a group",
        );
    }
    let nebula_ip = match local_nebula_ip(&state).await {
        Ok(ip) => ip,
        Err(response) => return *response,
    };
    let session = match state
        .group_session_manager
        .join(&group_id, &actor_id, &nebula_ip)
        .await
    {
        Ok(session) => session,
        Err(error_value) => return error(StatusCode::CONFLICT, error_value.to_string()),
    };
    let local = &session.participants[&actor_id];
    let host = &session.participants[&session.host_device_id];
    let message = GroupWireMessage::Join {
        group_id: group_id.clone(),
        device_id: actor_id.clone(),
    };
    // This check is about which PROCESS hosts the group, not who the acting
    // user is: a browser member here is always co-located with the host (its
    // session can only exist if this same Guardian created it — see
    // `create`), so the update above already happened in the shared,
    // in-process session store. What's left is notifying any real remote
    // participants, which is the host process's job regardless of which
    // local identity (admin or browser member) triggered this request.
    let propagated = if session.host_device_id == state.node_id {
        state
            .call_nebula_signaling
            .broadcast_group_snapshot(&session, &state.node_id)
            .await
    } else {
        state
            .call_nebula_signaling
            .send_group_control(
                &message,
                &group_id,
                &actor_id,
                &local.virtual_id,
                &host.nebula_ip,
            )
            .await
    };
    match propagated {
        Ok(()) => {
            if let Some(operation) = operation {
                COMPLETED_OPERATIONS.insert(operation, session.clone());
            }
            Json(session).into_response()
        }
        Err(error_value) => error(StatusCode::BAD_GATEWAY, error_value.to_string()),
    }
}

pub async fn heartbeat(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<String>,
    session: Option<Extension<AuthenticatedSession>>,
) -> impl IntoResponse {
    let actor_id = browser_call_actor_id(&state, &session);
    match record_heartbeat(&state, &group_id, &actor_id).await {
        Ok(session) => Json(session).into_response(),
        Err(response) => response,
    }
}

async fn record_heartbeat(
    state: &Arc<AppState>,
    group_id: &str,
    actor_id: &str,
) -> Result<GroupSession, axum::response::Response> {
    let nebula_ip = local_nebula_ip(state).await.map_err(|response| *response)?;
    let session = state
        .group_session_manager
        .heartbeat(group_id, actor_id, &nebula_ip)
        .await
        .map_err(|error_value| error(StatusCode::CONFLICT, error_value.to_string()))?;
    if session.host_device_id != state.node_id {
        let local = &session.participants[actor_id];
        let host = &session.participants[&session.host_device_id];
        let message = GroupWireMessage::Heartbeat {
            group_id: group_id.to_string(),
            device_id: actor_id.to_string(),
        };
        state
            .call_nebula_signaling
            .send_group_control(
                &message,
                group_id,
                actor_id,
                &local.virtual_id,
                &host.nebula_ip,
            )
            .await
            .map_err(|error_value| error(StatusCode::BAD_GATEWAY, error_value.to_string()))?;
    }
    Ok(session)
}

/// Primary browser signaling path. The HTTP `/signals` endpoint remains as a
/// compatibility fallback for older clients and transient WebSocket failures.
pub async fn socket(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<String>,
    Query(cursor): Query<SocketCursor>,
    session: Option<Extension<AuthenticatedSession>>,
) -> impl IntoResponse {
    let actor_id = browser_call_actor_id(&state, &session);
    let group_session = match state.group_session_manager.get(&group_id).await {
        Ok(session) => session,
        Err(error_value) => return error(StatusCode::NOT_FOUND, error_value.to_string()),
    };
    if !group_session.participants.contains_key(&actor_id) {
        return error(StatusCode::FORBIDDEN, "Local node is not a group member");
    }
    ws.on_upgrade(move |socket| run_socket(socket, state, group_id, cursor.after, actor_id))
        .into_response()
}

async fn run_socket(
    socket: WebSocket,
    state: Arc<AppState>,
    group_id: String,
    after: u64,
    actor_id: String,
) {
    let (mut sender, mut receiver) = socket.split();
    for signal in state.call_signal_hub.list_after(&group_id, after).await {
        let payload = serde_json::json!({"type":"signal","signal":signal}).to_string();
        if sender.send(Message::Text(payload.into())).await.is_err() {
            return;
        }
    }

    let mut live = state.call_signal_hub.subscribe();
    let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(15));
    loop {
        tokio::select! {
            incoming = receiver.next() => match incoming {
                Some(Ok(Message::Text(text))) => {
                    if serde_json::from_str::<Value>(&text)
                        .ok()
                        .and_then(|value| value.get("type").and_then(Value::as_str).map(str::to_owned))
                        .as_deref() == Some("heartbeat")
                    {
                        let _ = record_heartbeat(&state, &group_id, &actor_id).await;
                    }
                }
                Some(Ok(Message::Ping(bytes))) => {
                    if sender.send(Message::Pong(bytes)).await.is_err() { break; }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            },
            signal = live.recv() => match signal {
                Ok(signal) if signal.session_id == group_id => {
                    let payload = serde_json::json!({"type":"signal","signal":signal}).to_string();
                    if sender.send(Message::Text(payload.into())).await.is_err() { break; }
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            },
            _ = keepalive.tick() => {
                if sender.send(Message::Ping(Vec::new().into())).await.is_err() { break; }
            }
        }
    }
}

pub async fn decline(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<String>,
    headers: HeaderMap,
    session: Option<Extension<AuthenticatedSession>>,
) -> impl IntoResponse {
    let actor_id = browser_call_actor_id(&state, &session);
    let operation = operation_key(&headers, &actor_id, "decline", Some(&group_id));
    if let Some(cached) = operation
        .as_ref()
        .and_then(|key| COMPLETED_OPERATIONS.get(key).map(|value| value.clone()))
    {
        return Json(cached).into_response();
    }
    let nebula_ip = match local_nebula_ip(&state).await {
        Ok(ip) => ip,
        Err(response) => return *response,
    };
    let session = match state
        .group_session_manager
        .decline(&group_id, &actor_id, &nebula_ip)
        .await
    {
        Ok(session) => session,
        Err(error_value) => return error(StatusCode::CONFLICT, error_value.to_string()),
    };
    let local = &session.participants[&actor_id];
    let host = &session.participants[&session.host_device_id];
    let message = GroupWireMessage::Decline {
        group_id: group_id.clone(),
        device_id: actor_id.clone(),
    };
    // See `join`'s comment: this is about which process hosts the group.
    if session.host_device_id == state.node_id {
        let _ = state
            .call_nebula_signaling
            .broadcast_group_snapshot(&session, &state.node_id)
            .await;
    } else {
        let _ = state
            .call_nebula_signaling
            .send_group_control(
                &message,
                &group_id,
                &actor_id,
                &local.virtual_id,
                &host.nebula_ip,
            )
            .await;
    }
    if let Some(operation) = operation {
        COMPLETED_OPERATIONS.insert(operation, session.clone());
    }
    Json(session).into_response()
}

pub async fn leave(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<String>,
    headers: HeaderMap,
    session: Option<Extension<AuthenticatedSession>>,
) -> impl IntoResponse {
    let actor_id = browser_call_actor_id(&state, &session);
    let operation = operation_key(&headers, &actor_id, "leave", Some(&group_id));
    if let Some(cached) = operation
        .as_ref()
        .and_then(|key| COMPLETED_OPERATIONS.get(key).map(|value| value.clone()))
    {
        return Json(cached).into_response();
    }
    let nebula_ip = match local_nebula_ip(&state).await {
        Ok(ip) => ip,
        Err(response) => return *response,
    };
    let session = match state
        .group_session_manager
        .leave(&group_id, &actor_id, &nebula_ip)
        .await
    {
        Ok(session) => session,
        Err(error_value) => return error(StatusCode::CONFLICT, error_value.to_string()),
    };
    let local = &session.participants[&actor_id];
    let host = &session.participants[&session.host_device_id];
    let message = GroupWireMessage::Leave {
        group_id: group_id.clone(),
        device_id: actor_id.clone(),
    };
    // See `join`'s comment: this is about which process hosts the group.
    if session.host_device_id == state.node_id {
        let _ = state
            .call_nebula_signaling
            .broadcast_group_snapshot(&session, &state.node_id)
            .await;
    } else {
        let _ = state
            .call_nebula_signaling
            .send_group_control(
                &message,
                &group_id,
                &actor_id,
                &local.virtual_id,
                &host.nebula_ip,
            )
            .await;
    }
    state.call_signal_hub.clear(&group_id).await;
    if let Some(operation) = operation {
        COMPLETED_OPERATIONS.insert(operation, session.clone());
    }
    Json(session).into_response()
}

pub async fn moderate(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<String>,
    headers: HeaderMap,
    Json(action): Json<ModerationAction>,
) -> impl IntoResponse {
    let operation = operation_key(&headers, &state.node_id, "moderate", Some(&group_id));
    if let Some(cached) = operation
        .as_ref()
        .and_then(|key| COMPLETED_OPERATIONS.get(key).map(|value| value.clone()))
    {
        return Json(cached).into_response();
    }
    let session = match state
        .group_session_manager
        .moderate(&group_id, &state.node_id, action)
        .await
    {
        Ok(session) => session,
        Err(error_value) => return error(StatusCode::FORBIDDEN, error_value.to_string()),
    };
    match state
        .call_nebula_signaling
        .broadcast_group_snapshot(&session, &state.node_id)
        .await
    {
        Ok(()) => {
            if let Some(operation) = operation {
                COMPLETED_OPERATIONS.insert(operation, session.clone());
            }
            Json(session).into_response()
        }
        Err(error_value) => error(StatusCode::BAD_GATEWAY, error_value.to_string()),
    }
}

pub async fn end(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<String>,
    headers: HeaderMap,
    session_auth: Option<Extension<AuthenticatedSession>>,
) -> impl IntoResponse {
    let actor_id = browser_call_actor_id(&state, &session_auth);
    let operation = operation_key(&headers, &actor_id, "end", Some(&group_id));
    if let Some(cached) = operation
        .as_ref()
        .and_then(|key| COMPLETED_OPERATIONS.get(key).map(|value| value.clone()))
    {
        return Json(cached).into_response();
    }
    let current = match state.group_session_manager.get(&group_id).await {
        Ok(session) => session,
        Err(error_value) => return error(StatusCode::NOT_FOUND, error_value.to_string()),
    };
    let Some(actor) = current.participants.get(&actor_id) else {
        return error(
            StatusCode::FORBIDDEN,
            "Local caller is not a group participant",
        );
    };
    if !matches!(
        actor.state,
        GroupMemberState::Joined | GroupMemberState::Reconnecting | GroupMemberState::Disconnected
    ) {
        return error(
            StatusCode::FORBIDDEN,
            "Only active group participants can end this call",
        );
    }
    let remotely_hosted = current.host_device_id != state.node_id;
    let result = if current.host_device_id == state.node_id {
        Ok(())
    } else {
        let Some(host) = current.participants.get(&current.host_device_id) else {
            return error(StatusCode::CONFLICT, "Group host participant is missing");
        };
        let message = GroupWireMessage::End {
            group_id: group_id.clone(),
            device_id: actor_id.clone(),
        };
        state
            .call_nebula_signaling
            .send_group_control(
                &message,
                &group_id,
                &actor_id,
                &actor.virtual_id,
                &host.nebula_ip,
            )
            .await
    };
    if let Err(error_value) = result {
        return error(StatusCode::BAD_GATEWAY, error_value.to_string());
    }
    let session = match state.group_session_manager.end(&group_id, &actor_id).await {
        Ok(session) => session,
        // The host can deliver its terminal snapshot before the outbound
        // control send completes. In that race the local manager has already
        // removed the call, so return the equivalent terminal snapshot.
        Err(_) if remotely_hosted => {
            let mut ended = current.clone();
            let now = chrono::Utc::now();
            ended.state = GroupCallState::Ended;
            ended.updated_at = now;
            ended.ended_at = Some(now);
            ended
        }
        Err(error_value) => return error(StatusCode::FORBIDDEN, error_value.to_string()),
    };
    let result = if current.host_device_id == state.node_id {
        state
            .call_nebula_signaling
            .broadcast_group_snapshot(&session, &state.node_id)
            .await
    } else {
        Ok(())
    };
    state.call_signal_hub.clear(&group_id).await;
    if let Err(error_value) = result {
        tracing::warn!(
            %group_id,
            %error_value,
            "Group ended locally but one or more terminal notifications failed"
        );
    }
    state.group_session_manager.remove_ended(&group_id).await;
    if let Some(operation) = operation {
        COMPLETED_OPERATIONS.insert(operation, session.clone());
    }
    Json(session).into_response()
}

pub async fn submit_signal(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<String>,
    headers: HeaderMap,
    session: Option<Extension<AuthenticatedSession>>,
    Json(request): Json<GroupSignalRequest>,
) -> impl IntoResponse {
    let actor_id = browser_call_actor_id(&state, &session);
    let operation = operation_key(&headers, &actor_id, "signal", Some(&group_id)).or_else(|| {
        request
            .operation_id
            .as_ref()
            .map(|value| format!("{}:signal:{}:{}", actor_id, group_id, value))
    });
    if operation
        .as_ref()
        .is_some_and(|key| COMPLETED_OPERATIONS.contains_key(key))
    {
        return (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({"status":"already_sent"})),
        )
            .into_response();
    }
    if !matches!(
        request.kind,
        SignalKind::SdpOffer
            | SignalKind::SdpAnswer
            | SignalKind::IceCandidate
            | SignalKind::IceComplete
    ) {
        return error(StatusCode::BAD_REQUEST, "Unsupported group media signal");
    }
    let group_session = match state.group_session_manager.get(&group_id).await {
        Ok(session) => session,
        Err(error_value) => return error(StatusCode::NOT_FOUND, error_value.to_string()),
    };
    let Some(local) = group_session.participants.get(&actor_id) else {
        return error(StatusCode::FORBIDDEN, "Local node is not a group member");
    };
    let Some(target) = group_session.participants.get(&request.target_device_id) else {
        return error(StatusCode::BAD_REQUEST, "Target is not a group member");
    };
    if local.state != GroupMemberState::Joined || target.state != GroupMemberState::Joined {
        return error(
            StatusCode::CONFLICT,
            "Both members must join before signaling",
        );
    }
    // Two participants local to this same Guardian (e.g. the host and one of
    // its browser members, or two of its browser members) share this
    // process's signal queue directly. That includes browser-member -> local
    // Guardian replies/candidates: sending those over Nebula loops through the
    // wrong transport boundary and can break mixed local group media setup.
    let target_is_local_process = target.is_local_browser || target.device_id == state.node_id;
    let delivery = if target_is_local_process {
        let envelope = crate::call::SignalingEnvelope::new(
            request.kind,
            &group_id,
            &actor_id,
            &local.virtual_id,
            1,
            uuid::Uuid::new_v4().to_string(),
            request.payload,
        );
        state
            .call_signal_hub
            .push_remote(&envelope)
            .await
            .map(|_| ())
            .map_err(|error_value| error_value.to_string())
    } else {
        state
            .call_nebula_signaling
            .send_browser_signal(
                request.kind,
                &group_id,
                &actor_id,
                &local.virtual_id,
                request.payload,
                &target.nebula_ip,
            )
            .await
            .map_err(|error_value| error_value.to_string())
    };
    match delivery {
        Ok(()) => {
            if let Some(operation) = operation {
                COMPLETED_OPERATIONS.insert(operation, group_session);
            }
            state.group_session_manager.record_log(
                "group_signal_sent",
                &group_id,
                &actor_id,
                Some(&request.target_device_id),
                &format!("{:?}", request.kind),
            );
            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({"status":"sent"})),
            )
                .into_response()
        }
        Err(error_value) => {
            state.group_session_manager.record_log(
                "group_signal_failed",
                &group_id,
                &actor_id,
                Some(&request.target_device_id),
                &error_value,
            );
            error(StatusCode::BAD_GATEWAY, error_value)
        }
    }
}

pub async fn signals(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<String>,
    Query(cursor): Query<Cursor>,
) -> impl IntoResponse {
    if state.group_session_manager.get(&group_id).await.is_err() {
        return error(StatusCode::NOT_FOUND, "Group not found");
    }
    Json(GroupSignalsResponse {
        signals: state
            .call_signal_hub
            .list_after(&group_id, cursor.after)
            .await,
    })
    .into_response()
}

pub async fn media_ready(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<String>,
    session: Option<Extension<AuthenticatedSession>>,
) -> impl IntoResponse {
    let actor_id = browser_call_actor_id(&state, &session);
    let nebula_ip = match local_nebula_ip(&state).await {
        Ok(ip) => ip,
        Err(response) => return *response,
    };
    let session = match state
        .group_session_manager
        .mark_media_ready(&group_id, &actor_id, true, &nebula_ip)
        .await
    {
        Ok(session) => session,
        Err(error_value) => return error(StatusCode::CONFLICT, error_value.to_string()),
    };
    let local = &session.participants[&actor_id];
    // Local participants (host or other browser members on this same
    // Guardian) share this in-process session and its SSE broadcast, so they
    // already saw this update — only genuinely remote peers need a signal.
    for target in session.participants.values().filter(|participant| {
        participant.device_id != actor_id
            && participant.device_id != state.node_id
            && !participant.is_local_browser
            && participant.state == GroupMemberState::Joined
    }) {
        if let Err(error_value) = state
            .call_nebula_signaling
            .send_browser_signal(
                SignalKind::MediaReady,
                &group_id,
                &actor_id,
                &local.virtual_id,
                serde_json::json!({}),
                &target.nebula_ip,
            )
            .await
        {
            return error(StatusCode::BAD_GATEWAY, error_value.to_string());
        }
    }
    Json(session).into_response()
}

pub async fn events(
    State(state): State<Arc<AppState>>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let receiver = state.group_session_manager.subscribe();
    let stream = stream::unfold(receiver, |mut receiver| async move {
        let event = match receiver.recv().await {
            Ok(event) => Event::default()
                .event(&event.event)
                .json_data(event)
                .unwrap_or_else(|_| Event::default().event("serialization_error")),
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                Event::default().event("resync").data("{}")
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
        };
        Some((Ok(event), receiver))
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}
