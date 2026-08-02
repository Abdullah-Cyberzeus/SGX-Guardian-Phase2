//! REST API handlers for call operations.
//! Endpoints for initiating, accepting, rejecting, and ending calls.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Json, Path, Query, State,
    },
    http::StatusCode,
    response::{sse::Event, sse::KeepAlive, IntoResponse, Sse},
    Router,
};
use futures_util::{stream, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::convert::Infallible;
use std::sync::Arc;
use uuid::Uuid;

use crate::api::state::AppState;
use crate::audit::logger::log_uep_decision;
use crate::call::{CallAnswer, CallOffer, CallState as CallStateEnum, MediaType};
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
    if session.initiator.device_id != state.node_id && session.receiver.device_id != state.node_id {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"Local node is not a call participant"})),
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

/// Browser-oriented initiation derives the caller identity and all routing
/// data from authenticated local state rather than accepting authoritative
/// identity/IP fields from the browser.
pub async fn initiate_browser_call(
    State(state): State<Arc<AppState>>,
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
    let target = match trusted_call_target(&state, &request.target_peer_id).await {
        Ok(target) => target,
        Err(error) => return (StatusCode::FORBIDDEN, Json(error)).into_response(),
    };
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
    Json(request): Json<BrowserAcceptCallRequest>,
) -> impl IntoResponse {
    let virtual_id = match crate::virtual_id::read_runtime_virtual_id_status(&state.node_id, None) {
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
    accept_call(
        State(state.clone()),
        Json(AcceptCallRequest {
            session_id,
            device_id: state.node_id.clone(),
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
    Json(request): Json<BrowserRejectCallRequest>,
) -> impl IntoResponse {
    reject_call(
        State(state.clone()),
        Json(RejectCallRequest {
            session_id,
            device_id: state.node_id.clone(),
            reason: request.reason,
        }),
    )
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

fn local_and_remote_for_session<'a>(
    state: &AppState,
    session: &'a crate::call::CallSession,
) -> Result<(&'a crate::call::CallParticipant, &'a str), ErrorResponse> {
    if session.initiator.device_id == state.node_id {
        session
            .receiver_nebula_ip
            .as_deref()
            .map(|ip| (&session.initiator, ip))
            .ok_or_else(|| ErrorResponse {
                error: "Remote Nebula endpoint is unavailable".into(),
            })
    } else if session.receiver.device_id == state.node_id {
        session
            .initiator_nebula_ip
            .as_deref()
            .map(|ip| (&session.receiver, ip))
            .ok_or_else(|| ErrorResponse {
                error: "Remote Nebula endpoint is unavailable".into(),
            })
    } else {
        Err(ErrorResponse {
            error: "Local Guardian is not a call participant".into(),
        })
    }
}

pub async fn submit_signal(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(request): Json<SubmitSignalRequest>,
) -> impl IntoResponse {
    let operation = request
        .operation_id
        .as_ref()
        .map(|operation_id| format!("{}:{}:{}", state.node_id, session_id, operation_id));
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
    let (local, remote_ip) = match local_and_remote_for_session(&state, &session) {
        Ok(values) => values,
        Err(error) => return (StatusCode::CONFLICT, Json(error)).into_response(),
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
    match state
        .call_nebula_signaling
        .send_browser_signal(
            request.kind,
            &session_id,
            &local.device_id,
            &local.virtual_id,
            request.payload,
            remote_ip,
        )
        .await
    {
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
) -> impl IntoResponse {
    if state
        .call_session_manager
        .get_session(&session_id)
        .await
        .is_err()
    {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Session not found".into(),
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

pub async fn media_ready(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
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
    let (local, remote_ip) = match local_and_remote_for_session(&state, &session) {
        Ok(values) => values,
        Err(error) => return (StatusCode::CONFLICT, Json(error)).into_response(),
    };
    if let Err(error) = state
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
    {
        return (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse {
                error: error.to_string(),
            }),
        )
            .into_response();
    }
    match state
        .call_session_manager
        .mark_media_ready(&session_id, true)
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

    // Create rejection answer
    let answer = match CallAnswer::reject(
        req.device_id,
        session.receiver.virtual_id,
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
}
