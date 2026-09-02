//! HTTP and WebSocket handlers for the VPS enrollment broker.

use crate::models::{EnrollmentRequest, EnrollmentResponse, HealthResponse, WsEnvelope};
use crate::state::AppState;
use axum::{
    extract::{
        ws::{Message, WebSocket},
        Query, State, WebSocketUpgrade,
    },
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

// ────────────────────────────────────────────────────────────────────
// GET /health
// ────────────────────────────────────────────────────────────────────

pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        ca_connected: state.is_ca_connected(),
        uptime_secs: state.uptime_secs(),
    })
}

// ────────────────────────────────────────────────────────────────────
// POST /api/v1/enroll  —  called by Node C (remote board)
// ────────────────────────────────────────────────────────────────────

/// Enrollment timeout: how long to hold Node C's HTTP connection
/// while waiting for Node A to sign the certificate.
const ENROLL_TIMEOUT_SECS: u64 = 60;

pub async fn handle_enroll(
    State(state): State<AppState>,
    Json(payload): Json<EnrollmentRequest>,
) -> Result<Json<EnrollmentResponse>, StatusCode> {
    tracing::info!(
        "📥 Enrollment request from node={} circle={}",
        payload.node_id,
        payload.circle_id
    );

    // Validate required fields
    if payload.node_id.is_empty() || payload.circle_id.is_empty() {
        tracing::warn!("Rejected: empty node_id or circle_id");
        return Err(StatusCode::BAD_REQUEST);
    }
    if payload.public_key_pem.is_empty() {
        tracing::warn!("Rejected: empty public_key_pem");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Look up the CA WebSocket for this circle
    let ca_tx = match state.get_ca_sender(&payload.circle_id) {
        Some(sender) => sender,
        None => {
            tracing::error!(
                "❌ No CA bridge connected for circle: {}",
                payload.circle_id
            );
            return Ok(Json(EnrollmentResponse {
                status: "ERROR".to_string(),
                overlay_ip: String::new(),
                cert: String::new(),
                key: String::new(),
                ca_cert: String::new(),
                config: String::new(),
                message: "Home CA node is not connected. Please ensure Node A is running and connected to the broker.".to_string(),
            }));
        }
    };

    // Create a correlation ID and oneshot channel for the response
    let request_id = format!("req-{}", uuid::Uuid::new_v4());
    let (resp_tx, resp_rx) = oneshot::channel();
    state.insert_pending(&request_id, resp_tx);

    // Build the WS envelope to forward to Node A
    let envelope = WsEnvelope {
        event: "ENROLLMENT_REQUEST".to_string(),
        request_id: request_id.clone(),
        payload: Some(payload.clone()),
        response: None,
    };

    let msg_json = match serde_json::to_string(&envelope) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!("Failed to serialize envelope: {}", e);
            state.remove_pending(&request_id);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Forward to Node A via WebSocket
    if let Err(e) = ca_tx.send(msg_json).await {
        tracing::error!("Failed to send to CA WebSocket: {}", e);
        state.remove_pending(&request_id);
        return Ok(Json(EnrollmentResponse {
            status: "ERROR".to_string(),
            overlay_ip: String::new(),
            cert: String::new(),
            key: String::new(),
            ca_cert: String::new(),
            config: String::new(),
            message: "Failed to forward request to Home CA. Connection may have dropped.".to_string(),
        }));
    }

    tracing::info!(
        "⏳ Forwarded to Node A (request_id={}), awaiting response (timeout={}s)...",
        request_id,
        ENROLL_TIMEOUT_SECS
    );

    // Hold the HTTP connection until Node A responds or timeout
    match tokio::time::timeout(Duration::from_secs(ENROLL_TIMEOUT_SECS), resp_rx).await {
        Ok(Ok(response)) => {
            tracing::info!(
                "✅ Enrollment {} for node={} (status={})",
                request_id,
                payload.node_id,
                response.status
            );
            Ok(Json(response))
        }
        Ok(Err(_)) => {
            // Sender dropped (Node A disconnected mid-request)
            tracing::error!("CA bridge dropped while waiting for request_id={}", request_id);
            state.remove_pending(&request_id);
            Ok(Json(EnrollmentResponse {
                status: "ERROR".to_string(),
                overlay_ip: String::new(),
                cert: String::new(),
                key: String::new(),
                ca_cert: String::new(),
                config: String::new(),
                message: "Home CA disconnected while processing request.".to_string(),
            }))
        }
        Err(_) => {
            // Timeout
            tracing::warn!(
                "⏰ Timeout waiting for Node A response (request_id={})",
                request_id
            );
            state.remove_pending(&request_id);
            Ok(Json(EnrollmentResponse {
                status: "ERROR".to_string(),
                overlay_ip: String::new(),
                cert: String::new(),
                key: String::new(),
                ca_cert: String::new(),
                config: String::new(),
                message: format!(
                    "Timeout after {}s waiting for Home CA to sign certificate.",
                    ENROLL_TIMEOUT_SECS
                ),
            }))
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// GET /ws/ca-bridge  —  persistent WebSocket from Node A (Home CA)
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct WsConnectParams {
    pub circle_id: String,
    pub node_id: String,
    /// Optional pre-shared auth token
    #[serde(default)]
    pub token: String,
}

pub async fn handle_ca_ws(
    ws: WebSocketUpgrade,
    Query(params): Query<WsConnectParams>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    tracing::info!(
        "🔌 CA bridge upgrade request: circle={} node={}",
        params.circle_id,
        params.node_id
    );

    if params.circle_id.is_empty() || params.node_id.is_empty() {
        tracing::warn!("Rejected WS upgrade: missing circle_id or node_id");
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Optional token check
    let expected_token = std::env::var("SGX_BROKER_TOKEN").unwrap_or_default();
    if !expected_token.is_empty() && params.token != expected_token {
        tracing::warn!("Rejected WS upgrade: invalid auth token");
        return StatusCode::UNAUTHORIZED.into_response();
    }

    ws.on_upgrade(move |socket| ca_bridge_session(socket, state, params.circle_id, params.node_id))
        .into_response()
}

/// Manages the persistent WebSocket session with Node A.
///
/// Two concurrent flows:
/// 1. Outbound: VPS forwards pending enrollment requests to Node A
/// 2. Inbound: Node A sends back signed certificate responses
async fn ca_bridge_session(
    socket: WebSocket,
    state: AppState,
    circle_id: String,
    node_id: String,
) {
    let (mut ws_sink, mut ws_stream) = socket.split();

    // Channel for sending messages to Node A through this WebSocket
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<String>(64);

    // Register this CA sender
    state.register_ca(&circle_id, outbound_tx);
    tracing::info!(
        "✅ CA bridge active: circle={} node={}",
        circle_id,
        node_id
    );

    // Spawn a task that forwards outbound messages to the WS sink
    let sink_circle = circle_id.clone();
    let sink_task = tokio::spawn(async move {
        while let Some(msg) = outbound_rx.recv().await {
            if let Err(e) = ws_sink.send(Message::Text(msg.into())).await {
                tracing::error!(
                    "❌ WS send error (circle={}): {}",
                    sink_circle,
                    e
                );
                break;
            }
        }
    });

    // Main loop: read inbound messages from Node A
    while let Some(msg_result) = ws_stream.next().await {
        match msg_result {
            Ok(Message::Text(text)) => {
                handle_ca_inbound_message(&state, &text);
            }
            Ok(Message::Ping(data)) => {
                tracing::trace!("WS ping received (circle={})", circle_id);
                // Pong is handled automatically by axum
                let _ = data;
            }
            Ok(Message::Close(_)) => {
                tracing::info!(
                    "🔌 CA bridge closed by peer: circle={} node={}",
                    circle_id,
                    node_id
                );
                break;
            }
            Err(e) => {
                tracing::error!(
                    "❌ WS read error (circle={} node={}): {}",
                    circle_id,
                    node_id,
                    e
                );
                break;
            }
            _ => {}
        }
    }

    // Cleanup
    state.unregister_ca(&circle_id);
    sink_task.abort();
    tracing::info!(
        "🔌 CA bridge session ended: circle={} node={}",
        circle_id,
        node_id
    );
}

/// Parse an inbound WebSocket message from Node A and resolve the
/// corresponding pending enrollment request.
fn handle_ca_inbound_message(state: &AppState, text: &str) {
    let envelope: WsEnvelope = match serde_json::from_str(text) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("Failed to parse WS message from CA: {}", e);
            return;
        }
    };

    if envelope.event != "ENROLLMENT_RESPONSE" {
        tracing::debug!("Ignoring WS event: {}", envelope.event);
        return;
    }

    let response = match envelope.response {
        Some(r) => r,
        None => {
            tracing::warn!(
                "ENROLLMENT_RESPONSE missing response body (request_id={})",
                envelope.request_id
            );
            return;
        }
    };

    if state.resolve_pending(&envelope.request_id, response) {
        tracing::info!(
            "✅ Resolved pending request: {}",
            envelope.request_id
        );
    }
}
