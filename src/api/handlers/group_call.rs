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

use crate::api::state::AppState;
use crate::api::auth::middleware::AuthenticatedSession;
use crate::call::{
    GroupMemberState, GroupParticipant, GroupRole, GroupSession, GroupWireMessage, MediaType,
    ModerationAction, SignalKind, MAX_GROUP_PARTICIPANTS,
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

fn local_virtual_id(state: &AppState) -> Result<String, Box<axum::response::Response>> {
    match crate::virtual_id::read_runtime_virtual_id_status(&state.node_id, None) {
        Ok(status) if !status.virtual_id.trim().is_empty() => Ok(status.virtual_id),
        _ => Err(Box::new(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Local attested VirtualID is unavailable",
        ))),
    }
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
    let virtual_id = match local_virtual_id(&state) {
        Ok(value) => value,
        Err(response) => return *response,
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
    if let Some(contacts) = member_contacts.as_ref() {
        let unauthorized_requested = !request.call_all
            && trusted.iter().any(|peer| {
                request.member_ids.contains(&peer.peer_id)
                    && !peer.did.as_ref().is_some_and(|did| contacts.contains(did))
            });
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
    if selected.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "Select at least one trusted member",
        );
    }
    if selected.len() + 1 > MAX_GROUP_PARTICIPANTS {
        return error(
            StatusCode::BAD_REQUEST,
            format!("Group limit is {MAX_GROUP_PARTICIPANTS} participants"),
        );
    }
    let host = GroupParticipant {
        device_id: state.node_id.clone(),
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
    };
    let invitees: Vec<_> = selected
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
        })
        .collect();
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
        if participant.role == GroupRole::Host {
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

pub async fn active(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let groups = state.group_session_manager.active_for(&state.node_id).await;
    Json(GroupCallsResponse {
        total: groups.len(),
        groups,
    })
}

pub async fn join(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = operation_key(&headers, &state.node_id, "join", Some(&group_id));
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
    let session = match state
        .group_session_manager
        .join(&group_id, &state.node_id)
        .await
    {
        Ok(session) => session,
        Err(error_value) => return error(StatusCode::CONFLICT, error_value.to_string()),
    };
    let local = &session.participants[&state.node_id];
    let host = &session.participants[&session.host_device_id];
    let message = GroupWireMessage::Join {
        group_id: group_id.clone(),
        device_id: state.node_id.clone(),
    };
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
                &state.node_id,
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
) -> impl IntoResponse {
    match record_heartbeat(&state, &group_id).await {
        Ok(session) => Json(session).into_response(),
        Err(response) => response,
    }
}

async fn record_heartbeat(
    state: &Arc<AppState>,
    group_id: &str,
) -> Result<GroupSession, axum::response::Response> {
    let session = state
        .group_session_manager
        .heartbeat(group_id, &state.node_id)
        .await
        .map_err(|error_value| error(StatusCode::CONFLICT, error_value.to_string()))?;
    if session.host_device_id != state.node_id {
        let local = &session.participants[&state.node_id];
        let host = &session.participants[&session.host_device_id];
        let message = GroupWireMessage::Heartbeat {
            group_id: group_id.to_string(),
            device_id: state.node_id.clone(),
        };
        state
            .call_nebula_signaling
            .send_group_control(
                &message,
                group_id,
                &state.node_id,
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
) -> impl IntoResponse {
    let session = match state.group_session_manager.get(&group_id).await {
        Ok(session) => session,
        Err(error_value) => return error(StatusCode::NOT_FOUND, error_value.to_string()),
    };
    if !session.participants.contains_key(&state.node_id) {
        return error(StatusCode::FORBIDDEN, "Local node is not a group member");
    }
    ws.on_upgrade(move |socket| run_socket(socket, state, group_id, cursor.after))
        .into_response()
}

async fn run_socket(socket: WebSocket, state: Arc<AppState>, group_id: String, after: u64) {
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
                        let _ = record_heartbeat(&state, &group_id).await;
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
) -> impl IntoResponse {
    let operation = operation_key(&headers, &state.node_id, "decline", Some(&group_id));
    if let Some(cached) = operation
        .as_ref()
        .and_then(|key| COMPLETED_OPERATIONS.get(key).map(|value| value.clone()))
    {
        return Json(cached).into_response();
    }
    let session = match state
        .group_session_manager
        .decline(&group_id, &state.node_id)
        .await
    {
        Ok(session) => session,
        Err(error_value) => return error(StatusCode::CONFLICT, error_value.to_string()),
    };
    let local = &session.participants[&state.node_id];
    let host = &session.participants[&session.host_device_id];
    let message = GroupWireMessage::Decline {
        group_id: group_id.clone(),
        device_id: state.node_id.clone(),
    };
    let _ = state
        .call_nebula_signaling
        .send_group_control(
            &message,
            &group_id,
            &state.node_id,
            &local.virtual_id,
            &host.nebula_ip,
        )
        .await;
    if let Some(operation) = operation {
        COMPLETED_OPERATIONS.insert(operation, session.clone());
    }
    Json(session).into_response()
}

pub async fn leave(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = operation_key(&headers, &state.node_id, "leave", Some(&group_id));
    if let Some(cached) = operation
        .as_ref()
        .and_then(|key| COMPLETED_OPERATIONS.get(key).map(|value| value.clone()))
    {
        return Json(cached).into_response();
    }
    let session = match state
        .group_session_manager
        .leave(&group_id, &state.node_id)
        .await
    {
        Ok(session) => session,
        Err(error_value) => return error(StatusCode::CONFLICT, error_value.to_string()),
    };
    let local = &session.participants[&state.node_id];
    let host = &session.participants[&session.host_device_id];
    let message = GroupWireMessage::Leave {
        group_id: group_id.clone(),
        device_id: state.node_id.clone(),
    };
    let _ = state
        .call_nebula_signaling
        .send_group_control(
            &message,
            &group_id,
            &state.node_id,
            &local.virtual_id,
            &host.nebula_ip,
        )
        .await;
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
) -> impl IntoResponse {
    let operation = operation_key(&headers, &state.node_id, "end", Some(&group_id));
    if let Some(cached) = operation
        .as_ref()
        .and_then(|key| COMPLETED_OPERATIONS.get(key).map(|value| value.clone()))
    {
        return Json(cached).into_response();
    }
    let session = match state
        .group_session_manager
        .end(&group_id, &state.node_id)
        .await
    {
        Ok(session) => session,
        Err(error_value) => return error(StatusCode::FORBIDDEN, error_value.to_string()),
    };
    let result = state
        .call_nebula_signaling
        .broadcast_group_snapshot(&session, &state.node_id)
        .await;
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
    Json(request): Json<GroupSignalRequest>,
) -> impl IntoResponse {
    let operation =
        operation_key(&headers, &state.node_id, "signal", Some(&group_id)).or_else(|| {
            request
                .operation_id
                .as_ref()
                .map(|value| format!("{}:signal:{}:{}", state.node_id, group_id, value))
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
    let session = match state.group_session_manager.get(&group_id).await {
        Ok(session) => session,
        Err(error_value) => return error(StatusCode::NOT_FOUND, error_value.to_string()),
    };
    let Some(local) = session.participants.get(&state.node_id) else {
        return error(StatusCode::FORBIDDEN, "Local node is not a group member");
    };
    let Some(target) = session.participants.get(&request.target_device_id) else {
        return error(StatusCode::BAD_REQUEST, "Target is not a group member");
    };
    if local.state != GroupMemberState::Joined || target.state != GroupMemberState::Joined {
        return error(
            StatusCode::CONFLICT,
            "Both members must join before signaling",
        );
    }
    match state
        .call_nebula_signaling
        .send_browser_signal(
            request.kind,
            &group_id,
            &state.node_id,
            &local.virtual_id,
            request.payload,
            &target.nebula_ip,
        )
        .await
    {
        Ok(()) => {
            if let Some(operation) = operation {
                COMPLETED_OPERATIONS.insert(operation, session);
            }
            state.group_session_manager.record_log(
                "group_signal_sent",
                &group_id,
                &state.node_id,
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
                &state.node_id,
                Some(&request.target_device_id),
                &error_value.to_string(),
            );
            error(StatusCode::BAD_GATEWAY, error_value.to_string())
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
) -> impl IntoResponse {
    let session = match state
        .group_session_manager
        .mark_media_ready(&group_id, &state.node_id, true)
        .await
    {
        Ok(session) => session,
        Err(error_value) => return error(StatusCode::CONFLICT, error_value.to_string()),
    };
    let local = &session.participants[&state.node_id];
    for target in session.participants.values().filter(|participant| {
        participant.device_id != state.node_id && participant.state == GroupMemberState::Joined
    }) {
        if let Err(error_value) = state
            .call_nebula_signaling
            .send_browser_signal(
                SignalKind::MediaReady,
                &group_id,
                &state.node_id,
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
