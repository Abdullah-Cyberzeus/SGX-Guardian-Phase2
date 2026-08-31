//! REST API handlers for call operations.
//! Endpoints for initiating, accepting, rejecting, and ending calls.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Json, Path, Query, State,
    },
    http::StatusCode,
    response::{sse::Event, sse::KeepAlive, IntoResponse, Sse},
    Extension, Router,
};
use chrono::{DateTime, Utc};
use futures_util::{stream, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::convert::Infallible;
use std::sync::Arc;
use uuid::Uuid;

use crate::api::auth::middleware::AuthenticatedSession;
use crate::api::state::AppState;
use crate::audit::logger::log_uep_decision;
use crate::call::{
    CallAnswer, CallOffer, CallSession, CallState as CallStateEnum, MediaType, SignalingEnvelope,
};
use crate::enforcement::uep::{Role, UepEngine};
use crate::policy_state;

static COMPLETED_CALL_SIGNALS: once_cell::sync::Lazy<dashmap::DashSet<String>> =
    once_cell::sync::Lazy::new(dashmap::DashSet::new);

#[derive(Debug, Deserialize, Default)]
pub struct CallSocketCursor {
    #[serde(default)]
    pub after: u64,
}

pub async fn signal_socket(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Query(cursor): Query<CallSocketCursor>,
    session_auth: Option<Extension<AuthenticatedSession>>,
) -> impl IntoResponse {
    let session = match state.call_session_manager.get_session(&session_id).await {
        Ok(session) => session,
        Err(error) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": error.to_string()})),
            )
                .into_response()
        }
    };
    let actor_id = browser_call_actor_id(&state, &session_auth);
    if session.initiator.device_id != actor_id && session.receiver.device_id != actor_id {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"Authenticated caller is not a call participant"})),
        )
            .into_response();
    }
    ws.on_upgrade(move |socket| run_signal_socket(socket, state, session_id, cursor.after))
        .into_response()
}

async fn run_signal_socket(
    socket: WebSocket,
    state: Arc<AppState>,
    session_id: String,
    after: u64,
) {
    let (mut sender, mut receiver) = socket.split();
    for signal in state.call_signal_hub.list_after(&session_id, after).await {
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
                Some(Ok(Message::Ping(bytes))) => {
                    if sender.send(Message::Pong(bytes)).await.is_err() { break; }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            },
            signal = live.recv() => match signal {
                Ok(signal) if signal.session_id == session_id => {
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

/// Request to initiate a new call
#[derive(Debug, Deserialize, Serialize)]
pub struct InitiateCallRequest {
    pub initiator_device_id: String,
    pub initiator_virtual_id: String,
    pub receiver_device_id: String,
    pub receiver_virtual_id: String,
    pub receiver_nebula_ip: String,
    pub requested_media: Vec<MediaType>,
}

/// Response with call initiation result
#[derive(Debug, Serialize)]
pub struct InitiateCallResponse {
    pub session_id: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct BrowserInitiateCallRequest {
    pub target_peer_id: String,
    pub media: Vec<MediaType>,
}

#[derive(Debug, Deserialize)]
struct TrustedCallTarget {
    peer_id: String,
    #[serde(default)]
    did: Option<String>,
    ip: String,
    status: String,
    #[serde(default)]
    virtual_id: Option<String>,
}

async fn trusted_call_target(
    state: &AppState,
    peer_id: &str,
) -> Result<TrustedCallTarget, ErrorResponse> {
    for base in [&state.log_dir_primary, &state.log_dir_fallback] {
        let path = std::path::Path::new(base).join("trusted_peers.json");
        let Ok(bytes) = tokio::fs::read(path).await else {
            continue;
        };
        let peers: Vec<TrustedCallTarget> =
            serde_json::from_slice(&bytes).map_err(|_| ErrorResponse {
                error: "Trusted peer registry is malformed".into(),
            })?;
        if let Some(peer) = peers.into_iter().find(|peer| peer.peer_id == peer_id) {
            if !matches!(peer.status.as_str(), "verified" | "trusted" | "success") {
                return Err(ErrorResponse {
                    error: "Target peer is not currently trusted".into(),
                });
            }
            if peer.ip.parse::<std::net::IpAddr>().is_err() {
                return Err(ErrorResponse {
                    error: "Target peer has no valid Nebula address".into(),
                });
            }
            if peer.virtual_id.as_deref().unwrap_or_default().is_empty() {
                return Err(ErrorResponse {
                    error: "Target peer has no attested VirtualID".into(),
                });
            }
            return Ok(peer);
        }
    }
    Err(ErrorResponse {
        error: "Target peer is not in the trusted registry".into(),
    })
}

pub(crate) fn browser_call_actor_id(
    state: &AppState,
    session: &Option<Extension<AuthenticatedSession>>,
) -> String {
    crate::api::handlers::browser_member::did_from_session(session)
        .unwrap_or_else(|| state.node_id.clone())
}

pub(crate) fn local_virtual_id_for_actor(
    state: &AppState,
    actor_id: &str,
) -> Result<String, ErrorResponse> {
    if actor_id != state.node_id {
        return Ok(actor_id.to_string());
    }
    crate::virtual_id::read_runtime_virtual_id_status(&state.node_id, None)
        .map_err(|_| ErrorResponse {
            error: "Local attested VirtualID is unavailable".into(),
        })
        .and_then(|status| {
            if status.virtual_id.is_empty() {
                Err(ErrorResponse {
                    error: "Local attested VirtualID is unavailable".into(),
                })
            } else {
                Ok(status.virtual_id)
            }
        })
}

pub(crate) async fn browser_member_state_for_call(
    state: &AppState,
    did: &str,
) -> Result<Option<crate::api::handlers::browser_member::BrowserMemberState>, ErrorResponse> {
    let local_circle_ids =
        crate::api::auth::authorization::local_active_circle_ids(&state.node_id, &state.device_did)
            .map_err(|error| ErrorResponse { error })?;
    crate::api::handlers::browser_member::state_for_did(state, did, &local_circle_ids)
        .await
        .map_err(|error| ErrorResponse {
            error: format!("{:?}", error),
        })
}

async fn is_browser_member_call_participant(
    state: &AppState,
    device_id: &str,
) -> Result<bool, ErrorResponse> {
    if device_id == state.node_id {
        return Ok(false);
    }
    Ok(browser_member_state_for_call(state, device_id)
        .await?
        .is_some())
}

async fn is_local_browser_call(
    state: &AppState,
    session: &CallSession,
) -> Result<bool, ErrorResponse> {
    Ok(
        is_browser_member_call_participant(state, &session.initiator.device_id).await?
            || is_browser_member_call_participant(state, &session.receiver.device_id).await?,
    )
}

async fn initiate_local_browser_call(
    state: Arc<AppState>,
    initiator_device_id: String,
    receiver_device_id: String,
    requested_media: Vec<MediaType>,
) -> impl IntoResponse {
    let initiator_virtual_id = match local_virtual_id_for_actor(&state, &initiator_device_id) {
        Ok(value) => value,
        Err(error) => return (StatusCode::SERVICE_UNAVAILABLE, Json(error)).into_response(),
    };
    let receiver_virtual_id = match local_virtual_id_for_actor(&state, &receiver_device_id) {
        Ok(value) => value,
        Err(error) => return (StatusCode::SERVICE_UNAVAILABLE, Json(error)).into_response(),
    };
    let caller_label = initiator_device_id.clone();
    let nonce = Uuid::new_v4().to_string();
    let session_id = match state
        .call_session_manager
        .create_session(
            initiator_device_id,
            initiator_virtual_id,
            receiver_device_id,
            receiver_virtual_id,
            requested_media,
            nonce,
        )
        .await
    {
        Ok(id) => id,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: error.to_string(),
                }),
            )
                .into_response()
        }
    };
    if let Err(error) = state
        .call_session_manager
        .update_session_state(
            &session_id,
            CallStateEnum::OfferReceived,
            "Local browser member call offered".into(),
        )
        .await
    {
        let _ = state.call_session_manager.end_session(&session_id).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: error.to_string(),
            }),
        )
            .into_response();
    }
    crate::notify::publish_circle_incoming_call(&caller_label, &caller_label, &session_id);
    (
        StatusCode::OK,
        Json(InitiateCallResponse {
            session_id,
            status: "offer_received".to_string(),
        }),
    )
        .into_response()
}

/// Browser-oriented initiation derives the caller identity and all routing
/// data from authenticated local state rather than accepting authoritative
/// identity/IP fields from the browser.
pub async fn initiate_browser_call(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Json(request): Json<BrowserInitiateCallRequest>,
) -> impl IntoResponse {
    if request.target_peer_id.trim().is_empty() || request.media.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Target peer and media are required".into(),
            }),
        )
            .into_response();
    }
    if !state
        .call_session_manager
        .get_active_sessions()
        .await
        .is_empty()
    {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "A call is already active".into(),
            }),
        )
            .into_response();
    }
    if !state
        .group_session_manager
        .active_for(&state.node_id)
        .await
        .is_empty()
    {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "A group call is already active".into(),
            }),
        )
            .into_response();
    }
    let actor_id = browser_call_actor_id(&state, &session);
    if request.target_peer_id == state.node_id {
        if actor_id != state.node_id {
            return initiate_local_browser_call(
                state,
                actor_id,
                request.target_peer_id,
                request.media,
            )
            .await
            .into_response();
        }
    } else {
        match browser_member_state_for_call(&state, &request.target_peer_id).await {
            Ok(Some(_)) => {
                return initiate_local_browser_call(
                    state,
                    actor_id,
                    request.target_peer_id,
                    request.media,
                )
                .await
                .into_response();
            }
            Ok(None) => {}
            Err(error) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response(),
        }
    }
    let target = match trusted_call_target(&state, &request.target_peer_id).await {
        Ok(target) => target,
        Err(error) => return (StatusCode::FORBIDDEN, Json(error)).into_response(),
    };
    if session
        .as_ref()
        .is_some_and(|Extension(session)| session.claims.role == "member")
    {
        let allowed = match crate::api::auth::authorization::scoped_circle_contact_dids(
            &state.node_id,
            &state.device_did,
            session
                .as_ref()
                .map(|Extension(session)| session.claims.circle_ids.as_slice())
                .unwrap_or(&[]),
        ) {
            Ok(allowed) => allowed,
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse { error }),
                )
                    .into_response()
            }
        };
        if !target.did.as_ref().is_some_and(|did| allowed.contains(did)) {
            if let Some(Extension(session)) = session.as_ref() {
                crate::api::auth::authorization::audit_member_resource_denied(
                    &state.node_id,
                    &session.claims.sub,
                    "Circle call target",
                );
            }
            return (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Call target does not share a Circle with this Guardian".into(),
                }),
            )
                .into_response();
        }
    }
    let local_virtual_id =
        match crate::virtual_id::read_runtime_virtual_id_status(&state.node_id, None) {
            Ok(status) if !status.virtual_id.is_empty() => status.virtual_id,
            _ => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ErrorResponse {
                        error: "Local attested VirtualID is unavailable".into(),
                    }),
                )
                    .into_response()
            }
        };
    initiate_call(
        State(state.clone()),
        Json(InitiateCallRequest {
            initiator_device_id: state.node_id.clone(),
            initiator_virtual_id: local_virtual_id,
            receiver_device_id: target.peer_id,
            receiver_virtual_id: target.virtual_id.unwrap_or_default(),
            receiver_nebula_ip: target.ip,
            requested_media: request.media,
        }),
    )
    .await
    .into_response()
}

/// Request to accept a call
#[derive(Debug, Deserialize)]
pub struct AcceptCallRequest {
    pub session_id: String,
    pub device_id: String,
    pub virtual_id: String,
    pub accepted_media: Vec<MediaType>,
}

/// Response with call acceptance result
#[derive(Debug, Serialize)]
pub struct AcceptCallResponse {
    pub session_id: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct BrowserAcceptCallRequest {
    pub accepted_media: Vec<MediaType>,
}

pub async fn accept_browser_call(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    session: Option<Extension<AuthenticatedSession>>,
    Json(request): Json<BrowserAcceptCallRequest>,
) -> impl IntoResponse {
    let actor_id = browser_call_actor_id(&state, &session);
    let virtual_id = match local_virtual_id_for_actor(&state, &actor_id) {
        Ok(value) => value,
        Err(error) => return (StatusCode::SERVICE_UNAVAILABLE, Json(error)).into_response(),
    };
    let call_session = match state.call_session_manager.get_session(&session_id).await {
        Ok(call_session) => call_session,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Session not found".into(),
                }),
            )
                .into_response();
        }
    };
    if call_session.receiver.device_id != actor_id {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Not authorized to accept this call".into(),
            }),
        )
            .into_response();
    }
    match is_local_browser_call(&state, &call_session).await {
        Ok(true) => {
            if let Err(error) = state
                .call_session_manager
                .set_receiver_acceptance(&session_id, virtual_id, request.accepted_media)
                .await
            {
                return (
                    StatusCode::CONFLICT,
                    Json(ErrorResponse {
                        error: error.to_string(),
                    }),
                )
                    .into_response();
            }
            for (next_state, reason) in [
                (
                    CallStateEnum::Verifying,
                    "Local browser member accepted call",
                ),
                (CallStateEnum::Authorizing, "Local browser call verified"),
                (CallStateEnum::Accepted, "Local browser call accepted"),
            ] {
                if let Err(error) = state
                    .call_session_manager
                    .update_session_state(&session_id, next_state, reason.into())
                    .await
                {
                    return (
                        StatusCode::CONFLICT,
                        Json(ErrorResponse {
                            error: error.to_string(),
                        }),
                    )
                        .into_response();
                }
            }
            return (
                StatusCode::OK,
                Json(serde_json::json!({ "status": "accepted" })),
            )
                .into_response();
        }
        Ok(false) => {}
        Err(error) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response(),
    }
    accept_call(
        State(state.clone()),
        Json(AcceptCallRequest {
            session_id,
            device_id: actor_id,
            virtual_id,
            accepted_media: request.accepted_media,
        }),
    )
    .await
    .into_response()
}

/// Request to reject a call
#[derive(Debug, Deserialize)]
pub struct RejectCallRequest {
    pub session_id: String,
    pub device_id: String,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct BrowserRejectCallRequest {
    #[serde(default = "default_decline_reason")]
    pub reason: String,
}

fn default_decline_reason() -> String {
    "declined".into()
}

pub async fn reject_browser_call(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    session: Option<Extension<AuthenticatedSession>>,
    Json(request): Json<BrowserRejectCallRequest>,
) -> impl IntoResponse {
    let actor_id = browser_call_actor_id(&state, &session);
    if let Ok(call_session) = state.call_session_manager.get_session(&session_id).await {
        if call_session.receiver.device_id != actor_id {
            return (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Not authorized to reject this call".into(),
                }),
            )
                .into_response();
        }
        match is_local_browser_call(&state, &call_session).await {
            Ok(true) => {
                if let Err(error) = state
                    .call_session_manager
                    .update_session_state(
                        &session_id,
                        CallStateEnum::EndCall,
                        "Local browser call rejected".into(),
                    )
                    .await
                {
                    return (
                        StatusCode::CONFLICT,
                        Json(ErrorResponse {
                            error: error.to_string(),
                        }),
                    )
                        .into_response();
                }
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({ "status": "rejected" })),
                )
                    .into_response();
            }
            Ok(false) => {}
            Err(error) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response(),
        }
    }
    reject_call(
        State(state.clone()),
        Json(RejectCallRequest {
            session_id,
            device_id: actor_id,
            reason: request.reason,
        }),
    )
    .await
    .into_response()
}

/// Browser-safe counterpart to `end_call`: the session ID comes from the URL
/// path (like `accept_browser_call`/`reject_browser_call`) instead of a
/// client-supplied body, so member sessions can hang up their own call
/// without needing the legacy admin-only `/api/v1/call/end` route.
pub async fn end_browser_call(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    session_auth: Option<Extension<AuthenticatedSession>>,
) -> impl IntoResponse {
    let actor_id = browser_call_actor_id(&state, &session_auth);
    let session = match state.call_session_manager.get_session(&session_id).await {
        Ok(session) => session,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Session not found".into(),
                }),
            )
                .into_response()
        }
    };
    if session.initiator.device_id != actor_id && session.receiver.device_id != actor_id {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Authenticated caller is not a call participant".into(),
            }),
        )
            .into_response();
    }
    if is_local_browser_call(&state, &session)
        .await
        .unwrap_or(false)
    {
        let local = if session.initiator.device_id == actor_id {
            &session.initiator
        } else {
            &session.receiver
        };
        if !session.state.is_terminal() {
            let envelope = SignalingEnvelope::new(
                crate::call::SignalKind::Hangup,
                &session_id,
                &local.device_id,
                &local.virtual_id,
                1,
                Uuid::new_v4().to_string(),
                serde_json::json!({"reason_code": "ended_by_user"}),
            );
            let _ = state.call_signal_hub.push_remote(&envelope).await;
        }
        if state
            .call_session_manager
            .end_session(&session_id)
            .await
            .is_err()
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to end session".into(),
                }),
            )
                .into_response();
        }
        state.call_signal_hub.clear(&session_id).await;
        return (
            StatusCode::OK,
            Json(serde_json::json!({"status": "ended", "peer_notified": true})),
        )
            .into_response();
    }
    end_call(State(state), Json(EndCallRequest { session_id }))
        .await
        .into_response()
}

/// Request to end a call
#[derive(Debug, Deserialize)]
pub struct EndCallRequest {
    pub session_id: String,
}

#[derive(Debug, Serialize)]
pub struct CallListResponse {
    pub calls: Vec<crate::call::CallSessionStatus>,
    pub total: usize,
}

#[derive(Debug, Deserialize)]
pub struct SubmitSignalRequest {
    #[serde(rename = "type")]
    pub kind: crate::call::SignalKind,
    pub payload: Value,
    #[serde(default)]
    pub operation_id: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct SignalCursor {
    #[serde(default)]
    pub after: u64,
}

#[derive(Debug, Serialize)]
pub struct SignalListResponse {
    pub signals: Vec<crate::call::BrowserSignal>,
}

fn local_and_remote_for_actor<'a>(
    _state: &AppState,
    actor_id: &str,
    session: &'a crate::call::CallSession,
) -> Result<(&'a crate::call::CallParticipant, &'a str), ErrorResponse> {
    if session.initiator.device_id == actor_id {
        session
            .receiver_nebula_ip
            .as_deref()
            .map(|ip| (&session.initiator, ip))
            .ok_or_else(|| ErrorResponse {
                error: "Remote Nebula endpoint is unavailable".into(),
            })
    } else if session.receiver.device_id == actor_id {
        session
            .initiator_nebula_ip
            .as_deref()
            .map(|ip| (&session.receiver, ip))
            .ok_or_else(|| ErrorResponse {
                error: "Remote Nebula endpoint is unavailable".into(),
            })
    } else {
        Err(ErrorResponse {
            error: "Authenticated caller is not a call participant".into(),
        })
    }
}

fn local_and_remote_for_session<'a>(
    state: &AppState,
    session: &'a crate::call::CallSession,
) -> Result<(&'a crate::call::CallParticipant, &'a str), ErrorResponse> {
    local_and_remote_for_actor(state, &state.node_id, session)
}

pub async fn submit_signal(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    session_auth: Option<Extension<AuthenticatedSession>>,
    Json(request): Json<SubmitSignalRequest>,
) -> impl IntoResponse {
    let actor_id = browser_call_actor_id(&state, &session_auth);
    let operation = request
        .operation_id
        .as_ref()
        .map(|operation_id| format!("{}:{}:{}", actor_id, session_id, operation_id));
    if operation
        .as_ref()
        .is_some_and(|key| COMPLETED_CALL_SIGNALS.contains(key))
    {
        return (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({"status": "already_sent"})),
        )
            .into_response();
    }
    if !matches!(
        request.kind,
        crate::call::SignalKind::SdpOffer
            | crate::call::SignalKind::SdpAnswer
            | crate::call::SignalKind::IceCandidate
            | crate::call::SignalKind::IceComplete
    ) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Unsupported browser signal type".into(),
            }),
        )
            .into_response();
    }
    let session = match state.call_session_manager.get_session(&session_id).await {
        Ok(session) => session,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Session not found".into(),
                }),
            )
                .into_response()
        }
    };
    let is_local_browser = match is_local_browser_call(&state, &session).await {
        Ok(value) => value,
        Err(error) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response(),
    };
    let local = if is_local_browser {
        if session.initiator.device_id == actor_id {
            &session.initiator
        } else if session.receiver.device_id == actor_id {
            &session.receiver
        } else {
            return (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Authenticated caller is not a call participant".into(),
                }),
            )
                .into_response();
        }
    } else {
        let (local, _) = match local_and_remote_for_actor(&state, &actor_id, &session) {
            Ok(values) => values,
            Err(error) => return (StatusCode::CONFLICT, Json(error)).into_response(),
        };
        local
    };
    let remote_ip = if is_local_browser {
        None
    } else {
        match local_and_remote_for_actor(&state, &actor_id, &session) {
            Ok((_, remote_ip)) => Some(remote_ip),
            Err(error) => return (StatusCode::CONFLICT, Json(error)).into_response(),
        }
    };
    if session.state == CallStateEnum::Accepted {
        if let Err(error) = state
            .call_session_manager
            .update_session_state(
                &session_id,
                CallStateEnum::MediaNegotiation,
                "Local browser WebRTC signaling started".into(),
            )
            .await
        {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: error.to_string(),
                }),
            )
                .into_response();
        }
    } else if session.state != CallStateEnum::MediaNegotiation {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "Call is not ready for WebRTC signaling".into(),
            }),
        )
            .into_response();
    }
    // The SDP a=fingerprint line is what this participant is cryptographically
    // committing to for their live DTLS certificate. Recording it here, at the
    // authenticated signaling boundary, is what `media-ready` later checks
    // the browser's self-reported live fingerprint against.
    if matches!(
        request.kind,
        crate::call::SignalKind::SdpOffer | crate::call::SignalKind::SdpAnswer
    ) {
        if let Some(fingerprint) = request
            .payload
            .get("sdp")
            .and_then(|value| value.as_str())
            .and_then(crate::media::dtls::extract_sdp_fingerprint)
        {
            let _ = state
                .call_session_manager
                .record_signaled_fingerprint(&session_id, &local.device_id, fingerprint)
                .await;
        }
    }
    let sent = if is_local_browser {
        let envelope = SignalingEnvelope::new(
            request.kind,
            &session_id,
            &local.device_id,
            &local.virtual_id,
            1,
            Uuid::new_v4().to_string(),
            request.payload,
        );
        state
            .call_signal_hub
            .push_remote(&envelope)
            .await
            .map(|_| ())
    } else {
        state
            .call_nebula_signaling
            .send_browser_signal(
                request.kind,
                &session_id,
                &local.device_id,
                &local.virtual_id,
                request.payload,
                remote_ip.unwrap_or_default(),
            )
            .await
    };
    match sent {
        Ok(()) => {
            if COMPLETED_CALL_SIGNALS.len() > 4096 {
                COMPLETED_CALL_SIGNALS.clear();
            }
            if let Some(operation) = operation {
                COMPLETED_CALL_SIGNALS.insert(operation);
            }
            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({"status": "sent"})),
            )
                .into_response()
        }
        Err(error) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

pub async fn list_signals(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Query(cursor): Query<SignalCursor>,
    session_auth: Option<Extension<AuthenticatedSession>>,
) -> impl IntoResponse {
    let session = match state.call_session_manager.get_session(&session_id).await {
        Ok(session) => session,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Session not found".into(),
                }),
            )
                .into_response()
        }
    };
    let actor_id = browser_call_actor_id(&state, &session_auth);
    if session.initiator.device_id != actor_id && session.receiver.device_id != actor_id {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Authenticated caller is not a call participant".into(),
            }),
        )
            .into_response();
    }
    Json(SignalListResponse {
        signals: state
            .call_signal_hub
            .list_after(&session_id, cursor.after)
            .await,
    })
    .into_response()
}

#[derive(Debug, Deserialize, Default)]
pub struct MediaReadyRequest {
    /// SHA-256 DTLS certificate fingerprint this participant's own browser
    /// reports it is actually using, extracted from `RTCPeerConnection`'s
    /// local description now that media has connected. Optional so older
    /// clients (and the no-op "{}" body already in use) keep working; without
    /// it, this session simply never reaches `encryption_verified`.
    #[serde(default)]
    pub dtls_fingerprint: Option<String>,
}

pub async fn media_ready(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    session_auth: Option<Extension<AuthenticatedSession>>,
    request: Option<Json<MediaReadyRequest>>,
) -> impl IntoResponse {
    let actor_id = browser_call_actor_id(&state, &session_auth);
    let session = match state.call_session_manager.get_session(&session_id).await {
        Ok(session) => session,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Session not found".into(),
                }),
            )
                .into_response()
        }
    };
    let is_local_browser = match is_local_browser_call(&state, &session).await {
        Ok(value) => value,
        Err(error) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response(),
    };
    let (local, remote_ip) = match local_and_remote_for_actor(&state, &actor_id, &session) {
        Ok(values) => values,
        Err(error) if is_local_browser => {
            let local = if session.initiator.device_id == actor_id {
                &session.initiator
            } else if session.receiver.device_id == actor_id {
                &session.receiver
            } else {
                return (StatusCode::CONFLICT, Json(error)).into_response();
            };
            (local, "")
        }
        Err(error) => return (StatusCode::CONFLICT, Json(error)).into_response(),
    };
    if let Some(fingerprint) = request
        .and_then(|Json(body)| body.dtls_fingerprint)
        .filter(|value| !value.trim().is_empty())
    {
        let _ = state
            .call_session_manager
            .confirm_dtls_fingerprint(&session_id, &local.device_id, fingerprint)
            .await;
    }
    let sent = if is_local_browser {
        let envelope = SignalingEnvelope::new(
            crate::call::SignalKind::MediaReady,
            &session_id,
            &local.device_id,
            &local.virtual_id,
            1,
            Uuid::new_v4().to_string(),
            serde_json::json!({}),
        );
        state
            .call_signal_hub
            .push_remote(&envelope)
            .await
            .map(|_| ())
    } else {
        state
            .call_nebula_signaling
            .send_browser_signal(
                crate::call::SignalKind::MediaReady,
                &session_id,
                &local.device_id,
                &local.virtual_id,
                serde_json::json!({}),
                remote_ip,
            )
            .await
    };
    if let Err(error) = sent {
        return (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse {
                error: error.to_string(),
            }),
        )
            .into_response();
    }
    let media_ready_side = if is_local_browser {
        session.initiator.device_id == actor_id
    } else {
        true
    };
    match state
        .call_session_manager
        .mark_media_ready(&session_id, media_ready_side)
        .await
    {
        Ok(connected) => Json(serde_json::json!({
            "status": if connected { "connected" } else { "waiting_for_peer" }
        }))
        .into_response(),
        Err(error) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

pub async fn report_quality(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(report): Json<crate::call::QualityReport>,
) -> impl IntoResponse {
    let session = match state.call_session_manager.get_session(&session_id).await {
        Ok(session) => session,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Session not found".into(),
                }),
            )
                .into_response()
        }
    };
    if session.state != CallStateEnum::Connected {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "Quality reports are accepted only for connected calls".into(),
            }),
        )
            .into_response();
    }
    match state
        .call_signal_hub
        .record_quality(&session_id, report)
        .await
    {
        Ok(()) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({"status": "recorded"})),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: error.to_string(),
            }),
        )
            .into_response(),
    }
}

pub async fn list_calls(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let calls = state.call_session_manager.list_statuses().await;
    Json(CallListResponse {
        total: calls.len(),
        calls,
    })
}

#[derive(Debug, Serialize)]
pub struct CallHistoryResponse {
    pub calls: Vec<crate::call::CallHistoryRecord>,
    pub total: usize,
}

pub async fn call_history(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
) -> impl IntoResponse {
    let mut calls = state.call_session_manager.call_history().list();
    // A member only sees calls they were actually part of, and only calls
    // created after that browser member account existed. Never fall back to
    // the Guardian node id here; doing so leaks the Guardian's older call log.
    if let Some(Extension(auth)) = session
        .as_ref()
        .filter(|Extension(auth)| auth.claims.role == "member")
    {
        let own_did = crate::api::handlers::browser_member::did_from_session(&session);
        let member_created_at = member_account_created_at(&state, &auth.claims.sub).await;
        calls = match (own_did, member_created_at) {
            (Some(own_did), Some(member_created_at)) => {
                visible_member_call_history(calls, &own_did, member_created_at)
            }
            _ => Vec::new(),
        };
    }
    Json(CallHistoryResponse {
        total: calls.len(),
        calls,
    })
}

async fn member_account_created_at(state: &AppState, actor_id: &str) -> Option<DateTime<Utc>> {
    let user = state
        .admin
        .users
        .find_by_id(actor_id)
        .await
        .ok()
        .flatten()?;
    DateTime::parse_from_rfc3339(&user.created_at)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn visible_member_call_history(
    calls: Vec<crate::call::CallHistoryRecord>,
    own_did: &str,
    member_created_at: DateTime<Utc>,
) -> Vec<crate::call::CallHistoryRecord> {
    calls
        .into_iter()
        .filter(|call| call.started_at >= member_created_at)
        .filter(|call| call.participant_ids.iter().any(|id| id == own_did))
        .collect()
}

pub async fn active_calls(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let calls: Vec<_> = state
        .call_session_manager
        .get_active_sessions()
        .await
        .into_iter()
        .map(|session| session.status_snapshot())
        .collect();
    Json(CallListResponse {
        total: calls.len(),
        calls,
    })
}

/// Authenticated server-sent event stream used by the global frontend call
/// coordinator. A lagged subscriber receives a resync event and must fetch
/// `/calls/active`; session state remains authoritative.
pub async fn call_events(
    State(state): State<Arc<AppState>>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let receiver = state.call_session_manager.subscribe();
    let events = stream::unfold(receiver, |mut receiver| async move {
        let event = match receiver.recv().await {
            Ok(update) => Event::default()
                .event(&update.event)
                .json_data(update)
                .unwrap_or_else(|_| Event::default().event("resync")),
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                Event::default().event("resync")
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
        };
        Some((Ok(event), receiver))
    });
    Sse::new(events).keep_alive(KeepAlive::default())
}

/// Return local signaling and media-session state without revealing secrets.
pub async fn call_status(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    match state.call_session_manager.get_session(&session_id).await {
        Ok(session) => (StatusCode::OK, Json(session.status_snapshot())).into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Session not found".to_string(),
            }),
        )
            .into_response(),
    }
}

/// Request to check if a call is authorized by policy
#[derive(Debug, Deserialize)]
pub struct PolicyCheckRequest {
    pub caller_role: String,
    pub target_role: String,
    pub media_type: String,
}

/// Response with policy check result
#[derive(Debug, Serialize)]
pub struct PolicyCheckResponse {
    pub allowed: bool,
    pub reason: String,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Initiate a new call
pub async fn initiate_call(
    State(state): State<Arc<AppState>>,
    Json(req): Json<InitiateCallRequest>,
) -> impl IntoResponse {
    // Validate inputs
    if req.initiator_device_id.is_empty() || req.receiver_device_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid device IDs".to_string(),
            }),
        )
            .into_response();
    }

    // Create nonce
    let nonce = Uuid::new_v4().to_string();

    // Create session
    let session_id = match state
        .call_session_manager
        .create_session(
            req.initiator_device_id.clone(),
            req.initiator_virtual_id.clone(),
            req.receiver_device_id,
            req.receiver_virtual_id.clone(),
            req.requested_media.clone(),
            nonce.clone(),
        )
        .await
    {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to create session".to_string(),
                }),
            )
                .into_response();
        }
    };

    let initiator_nebula_ip = match state.call_nebula_signaling.get_local_nebula_ip().await {
        Ok(ip) => ip,
        Err(error) => {
            let _ = state.call_session_manager.end_session(&session_id).await;
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: format!("Nebula overlay unavailable: {}", error),
                }),
            )
                .into_response();
        }
    };
    if let Err(error) = state
        .call_session_manager
        .set_nebula_endpoints(
            &session_id,
            Some(initiator_nebula_ip),
            Some(req.receiver_nebula_ip.clone()),
        )
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: error.to_string(),
            }),
        )
            .into_response();
    }

    // The FSM requires the initiator to pass through the local policy gate
    // before an offer may be sent (Idle -> LocalPolicyCheck -> OfferSent).
    // Without this transition, the later OfferSent update is rejected.
    if let Err(error) = state
        .call_session_manager
        .update_session_state(
            &session_id,
            CallStateEnum::LocalPolicyCheck,
            "Local policy check passed".to_string(),
        )
        .await
    {
        let _ = state.call_session_manager.end_session(&session_id).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to start local policy check: {}", error),
            }),
        )
            .into_response();
    }

    // Create and send offer via Nebula
    let offer = match CallOffer::new(
        req.initiator_device_id.clone(),
        req.initiator_virtual_id.clone(),
        session_id.clone(),
        nonce,
        req.requested_media,
        &state.signer,
    )
    .await
    {
        Ok(o) => o,
        Err(_) => {
            let _ = state.call_session_manager.end_session(&session_id).await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to create offer".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Send offer via Nebula
    if let Err(error) = state
        .call_nebula_signaling
        .send_offer(&offer, &req.receiver_nebula_ip)
        .await
    {
        let _ = state.call_session_manager.end_session(&session_id).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to send offer via Nebula: {}", error),
            }),
        )
            .into_response();
    }

    // Update session state to OfferSent
    if state
        .call_session_manager
        .update_session_state(
            &session_id,
            CallStateEnum::OfferSent,
            "Offer sent".to_string(),
        )
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update session state".to_string(),
            }),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(InitiateCallResponse {
            session_id,
            status: "offer_sent".to_string(),
        }),
    )
        .into_response()
}

/// Accept a call
pub async fn accept_call(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AcceptCallRequest>,
) -> impl IntoResponse {
    // Get session
    let session = match state
        .call_session_manager
        .get_session(&req.session_id)
        .await
    {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Session not found".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Verify device is receiver
    if session.receiver.device_id != req.device_id {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Not authorized to accept this call".to_string(),
            }),
        )
            .into_response();
    }

    // Create acceptance answer
    let answer = match CallAnswer::accept(
        req.device_id,
        req.virtual_id,
        req.session_id.clone(),
        session.nonce.clone(),
        req.accepted_media.clone(),
        &state.signer,
    )
    .await
    {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to create answer".to_string(),
                }),
            )
                .into_response();
        }
    };

    // An incoming offer must complete verification and authorization before
    // an acceptance is emitted over the Nebula control plane.
    for (state_transition, reason) in [
        (CallStateEnum::Verifying, "Verifying incoming call offer"),
        (
            CallStateEnum::Authorizing,
            "Authorizing incoming call offer",
        ),
    ] {
        if let Err(error) = state
            .call_session_manager
            .update_session_state(&req.session_id, state_transition, reason.to_string())
            .await
        {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: format!("Cannot accept call: {}", error),
                }),
            )
                .into_response();
        }
    }

    // Send answer via Nebula
    let initiator_nebula_ip = match session.initiator_nebula_ip.as_deref() {
        Some(ip) => ip,
        None => {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "Initiator Nebula address is unavailable".to_string(),
                }),
            )
                .into_response()
        }
    };
    if let Err(error) = state
        .call_nebula_signaling
        .send_answer(&answer, initiator_nebula_ip)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to send answer via Nebula: {}", error),
            }),
        )
            .into_response();
    }

    if let Err(error) = state
        .call_session_manager
        .set_receiver_acceptance(
            &req.session_id,
            answer.virtual_id.clone(),
            req.accepted_media.clone(),
        )
        .await
    {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: format!("Failed to store accepted media: {}", error),
            }),
        )
            .into_response();
    }

    // Update session state
    if state
        .call_session_manager
        .update_session_state(
            &req.session_id,
            CallStateEnum::Accepted,
            "Call accepted".to_string(),
        )
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update session state".to_string(),
            }),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(AcceptCallResponse {
            session_id: req.session_id,
            status: "accepted".to_string(),
        }),
    )
        .into_response()
}

/// Reject a call
pub async fn reject_call(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RejectCallRequest>,
) -> impl IntoResponse {
    // Get session
    let session = match state
        .call_session_manager
        .get_session(&req.session_id)
        .await
    {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Session not found".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Verify device is receiver
    if session.receiver.device_id != req.device_id {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Not authorized to reject this call".to_string(),
            }),
        )
            .into_response();
    }

    let receiver_virtual_id = if session.receiver.virtual_id.trim().is_empty() {
        match local_virtual_id_for_actor(&state, &req.device_id) {
            Ok(value) => value,
            Err(error) => return (StatusCode::SERVICE_UNAVAILABLE, Json(error)).into_response(),
        }
    } else {
        session.receiver.virtual_id.clone()
    };

    // Create rejection answer
    let answer = match CallAnswer::reject(
        req.device_id,
        receiver_virtual_id,
        req.session_id.clone(),
        session.nonce,
        req.reason.clone(),
        &state.signer,
    )
    .await
    {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to create rejection".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Send rejection via Nebula
    let initiator_nebula_ip = match session.initiator_nebula_ip.as_deref() {
        Some(ip) => ip,
        None => {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "Initiator Nebula address is unavailable".to_string(),
                }),
            )
                .into_response()
        }
    };
    if let Err(error) = state
        .call_nebula_signaling
        .send_answer(&answer, initiator_nebula_ip)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to send rejection via Nebula: {}", error),
            }),
        )
            .into_response();
    }

    // Update session state
    if state
        .call_session_manager
        .update_session_state(
            &req.session_id,
            CallStateEnum::EndCall,
            "Call rejected".to_string(),
        )
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update session state".to_string(),
            }),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "rejected" })),
    )
        .into_response()
}

/// End a call
pub async fn end_call(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EndCallRequest>,
) -> impl IntoResponse {
    // Get session
    match state
        .call_session_manager
        .get_session(&req.session_id)
        .await
    {
        Ok(session) => {
            let mut peer_notified = false;
            if !session.state.is_terminal() {
                if let Ok((local, remote_ip)) = local_and_remote_for_session(&state, &session) {
                    peer_notified = state
                        .call_nebula_signaling
                        .send_browser_signal(
                            crate::call::SignalKind::Hangup,
                            &req.session_id,
                            &local.device_id,
                            &local.virtual_id,
                            serde_json::json!({"reason_code": "ended_by_user"}),
                            remote_ip,
                        )
                        .await
                        .is_ok();
                }
            }
            // End the session
            if state
                .call_session_manager
                .end_session(&req.session_id)
                .await
                .is_err()
            {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to end session".to_string(),
                    }),
                )
                    .into_response();
            }
            state.call_signal_hub.clear(&req.session_id).await;

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "ended",
                    "peer_notified": peer_notified
                })),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Session not found".to_string(),
            }),
        )
            .into_response(),
    }
}

/// Check if a call is authorized by UEP (Unified Enforcement Point) policy
pub async fn policy_check(Json(req): Json<PolicyCheckRequest>) -> axum::response::Response {
    // Parse roles and media type
    let caller_role = match Role::parse_str(&req.caller_role) {
        Some(role) => role,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid caller_role: {}", req.caller_role),
                }),
            )
                .into_response()
        }
    };

    let target_role = match Role::parse_str(&req.target_role) {
        Some(role) => role,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid target_role: {}", req.target_role),
                }),
            )
                .into_response()
        }
    };

    let media_type = match req.media_type.to_lowercase().as_str() {
        "voice" | "audio" => crate::enforcement::uep::MediaType::Voice,
        "video" => crate::enforcement::uep::MediaType::Video,
        "screen_share" | "screen" => crate::enforcement::uep::MediaType::ScreenShare,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "Invalid media_type: {} (use 'audio'/'voice'/'video'/'screen_share')",
                        req.media_type
                    ),
                }),
            )
                .into_response()
        }
    };

    // Load RBAC rules and evaluate
    match policy_state::load_rbac_rules() {
        Ok(rules) => {
            let engine = UepEngine::new(rules);
            let decision = engine.check_call(caller_role, target_role, media_type);

            // Log the UEP decision
            if let Ok(node_config) = std::env::var("GUARDIAN_NODE_ID") {
                log_uep_decision(
                    &node_config,
                    caller_role.as_str(),
                    target_role.as_str(),
                    media_type.as_str(),
                    decision.allowed,
                    &decision.reason,
                );
            }

            (
                StatusCode::OK,
                Json(PolicyCheckResponse {
                    allowed: decision.allowed,
                    reason: decision.reason,
                }),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to load policy: {}", e),
            }),
        )
            .into_response(),
    }
}

/// Create call handlers router
pub fn create_call_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/initiate", axum::routing::post(initiate_call))
        .route("/accept", axum::routing::post(accept_call))
        .route("/reject", axum::routing::post(reject_call))
        .route("/end", axum::routing::post(end_call))
        .route("/policy-check", axum::routing::post(policy_check))
}

/// Return authenticated STUN/TURN configuration to browser call clients.
/// Example:
/// SGX_WEBRTC_ICE_SERVERS='[{"urls":["stun:stun.example:3478",
/// "turns:turn.example:5349"],"username":"user","credential":"secret"}]'
pub async fn ice_servers() -> axum::response::Response {
    let Some(raw) = std::env::var("SGX_WEBRTC_ICE_SERVERS").ok() else {
        return Json(serde_json::json!({
            "ice_servers": [],
            "configured": false
        }))
        .into_response();
    };
    let servers = match serde_json::from_str::<Vec<Value>>(&raw) {
        Ok(servers) => servers,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error":"SGX_WEBRTC_ICE_SERVERS is not a valid JSON array"
                })),
            )
                .into_response()
        }
    };
    for server in &servers {
        let has_turn = server
            .get("urls")
            .map(|urls| urls.to_string().contains("turn:") || urls.to_string().contains("turns:"))
            .unwrap_or(false);
        if has_turn
            && (server.get("username").and_then(Value::as_str).is_none()
                || server.get("credential").and_then(Value::as_str).is_none())
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error":"TURN servers require username and credential"
                })),
            )
                .into_response();
        }
    }
    Json(serde_json::json!({
        "configured": !servers.is_empty(),
        "ice_servers": servers
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: Option<&str>) -> Self {
            let guard = Self {
                key,
                previous: std::env::var_os(key),
            };
            if let Some(value) = value {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
            guard
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(value) = self.previous.as_ref() {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    async fn response_json(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        serde_json::from_slice(&bytes).expect("response body is JSON")
    }

    #[test]
    fn test_initiate_request_serialization() {
        let req = InitiateCallRequest {
            initiator_device_id: "device-1".to_string(),
            initiator_virtual_id: "virtual-1".to_string(),
            receiver_device_id: "device-2".to_string(),
            receiver_virtual_id: "virtual-2".to_string(),
            receiver_nebula_ip: "192.168.100.2".to_string(),
            requested_media: vec![MediaType::Audio],
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: InitiateCallRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.initiator_device_id, "device-1");
    }

    #[test]
    fn member_call_history_excludes_old_and_unrelated_records() {
        let member_did = "did:guardian:browser-member";
        let created_at = Utc::now();
        let old_call = crate::call::CallHistoryRecord {
            id: "old".into(),
            kind: "direct".into(),
            outcome: "completed".into(),
            media: vec![MediaType::Audio],
            participant_ids: vec![member_did.into(), "nodeA".into()],
            started_at: created_at - chrono::Duration::minutes(5),
            ended_at: created_at - chrono::Duration::minutes(4),
            duration_seconds: 60,
        };
        let unrelated_call = crate::call::CallHistoryRecord {
            id: "unrelated".into(),
            kind: "direct".into(),
            outcome: "completed".into(),
            media: vec![MediaType::Video],
            participant_ids: vec!["nodeA".into(), "nodeB".into()],
            started_at: created_at + chrono::Duration::minutes(1),
            ended_at: created_at + chrono::Duration::minutes(2),
            duration_seconds: 60,
        };
        let visible_call = crate::call::CallHistoryRecord {
            id: "visible".into(),
            kind: "group".into(),
            outcome: "completed".into(),
            media: vec![MediaType::Audio, MediaType::Video],
            participant_ids: vec![member_did.into(), "nodeA".into()],
            started_at: created_at + chrono::Duration::minutes(3),
            ended_at: created_at + chrono::Duration::minutes(4),
            duration_seconds: 60,
        };

        let visible = visible_member_call_history(
            vec![old_call, unrelated_call, visible_call],
            member_did,
            created_at,
        );

        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].id, "visible");
    }

    #[test]
    fn browser_request_defaults_and_cursors_are_stable() {
        let reject: BrowserRejectCallRequest =
            serde_json::from_str("{}").expect("deserialize default rejection reason");
        assert_eq!(reject.reason, "declined");

        let call_cursor: CallSocketCursor =
            serde_json::from_str("{}").expect("deserialize call cursor");
        let signal_cursor: SignalCursor =
            serde_json::from_str("{}").expect("deserialize signal cursor");
        assert_eq!(call_cursor.after, 0);
        assert_eq!(signal_cursor.after, 0);

        let call_cursor: CallSocketCursor =
            serde_json::from_str(r#"{"after":42}"#).expect("deserialize explicit cursor");
        assert_eq!(call_cursor.after, 42);
        let _router = create_call_router();
    }

    #[tokio::test]
    async fn policy_check_rejects_invalid_roles_and_media_before_loading_policy() {
        let cases = [
            ("invalid", "operator", "audio", "Invalid caller_role"),
            ("admin", "invalid", "audio", "Invalid target_role"),
            ("admin", "operator", "data", "Invalid media_type"),
        ];

        for (caller_role, target_role, media_type, expected_error) in cases {
            let response = policy_check(Json(PolicyCheckRequest {
                caller_role: caller_role.into(),
                target_role: target_role.into(),
                media_type: media_type.into(),
            }))
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = response_json(response).await;
            assert!(body["error"]
                .as_str()
                .expect("error string")
                .contains(expected_error));
        }
    }

    #[tokio::test]
    async fn ice_servers_covers_missing_malformed_turn_and_valid_configuration() {
        let _guard = EnvGuard::set("SGX_WEBRTC_ICE_SERVERS", None);
        let response = ice_servers().await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["configured"], false);
        assert_eq!(body["ice_servers"], serde_json::json!([]));

        std::env::set_var("SGX_WEBRTC_ICE_SERVERS", "not-json");
        let response = ice_servers().await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = response_json(response).await;
        assert!(body["error"]
            .as_str()
            .expect("error string")
            .contains("valid JSON"));

        std::env::set_var(
            "SGX_WEBRTC_ICE_SERVERS",
            r#"[{"urls":["turn:relay.example:3478"]}]"#,
        );
        let response = ice_servers().await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = response_json(response).await;
        assert!(body["error"]
            .as_str()
            .expect("error string")
            .contains("require username and credential"));

        std::env::set_var(
            "SGX_WEBRTC_ICE_SERVERS",
            r#"[
                {"urls":["stun:stun.example:3478"]},
                {"urls":"turns:relay.example:5349","username":"user","credential":"secret"}
            ]"#,
        );
        let response = ice_servers().await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["configured"], true);
        assert_eq!(
            body["ice_servers"].as_array().expect("server array").len(),
            2
        );
    }
}
