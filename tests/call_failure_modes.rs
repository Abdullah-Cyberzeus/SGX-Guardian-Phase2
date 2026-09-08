use async_trait::async_trait;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use sgx_guardian_client::api::handlers::call::{
    ice_servers, policy_check, BrowserAcceptCallRequest, BrowserInitiateCallRequest,
    BrowserRejectCallRequest, CallHistoryResponse, CallListResponse, ErrorResponse,
    InitiateCallRequest, InitiateCallResponse, MediaReadyRequest, PolicyCheckRequest,
    SubmitSignalRequest,
};
use sgx_guardian_client::call::history::{CallHistoryRecord, CallHistoryStore};
use sgx_guardian_client::call::identity::{
    PeerIdentityResolver, RejectUnknownPeerResolver, TrustedPeerIdentity,
};
use sgx_guardian_client::call::media_state::{
    AudioStream, CallMediaState, MediaStats, MediaStreamState, ScreenShareStream, VideoStream,
};
use sgx_guardian_client::call::nebula_signaling::SignalingMessage;
use sgx_guardian_client::call::policy::{AllowAllEnforcer, PolicyEnforcer};
use sgx_guardian_client::call::protocol::{
    ReplayProtector, SignalKind, SignalingEnvelope, CALL_PROTOCOL_VERSION, MAX_SIGNAL_AGE_SECS,
    MAX_SIGNAL_PAYLOAD_BYTES,
};
use sgx_guardian_client::call::signaling::{CallAnswer, CallOffer as WireCallOffer};
use sgx_guardian_client::call::verify::{MediaGate, VerificationRequirements, VerificationState};
use sgx_guardian_client::call::{
    extract_role_from_subject, CallError, CallOffer, CallSession, CallState, MediaType,
    SessionManager, UepGateError,
};
use sgx_guardian_client::key_manager::KeyManager;
use std::sync::Arc;
use tempfile::tempdir;

struct DenyEnforcer;

#[async_trait]
impl PolicyEnforcer for DenyEnforcer {
    async fn allow_call(
        &self,
        _session: &CallSession,
    ) -> sgx_guardian_client::call::CallResult<bool> {
        Ok(false)
    }
}

#[test]
fn test_empty_requested_media_fails() {
    let result = CallSession::new(
        "device1".to_string(),
        "virtual1".to_string(),
        "device2".to_string(),
        "virtual2".to_string(),
        vec![],
        "nonce123".to_string(),
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn test_policy_denied_call_state() {
    let manager = SessionManager::with_enforcer(Arc::new(DenyEnforcer));
    let session_id = manager
        .create_session(
            "device1".to_string(),
            "virtual1".to_string(),
            "device2".to_string(),
            "virtual2".to_string(),
            vec![MediaType::Audio],
            "nonce123".to_string(),
        )
        .await
        .expect("create session");

    let result = manager
        .update_session_state(
            &session_id,
            CallState::Accepted,
            "policy denied".to_string(),
        )
        .await;
    assert!(result.is_err());
}

#[test]
fn test_invalid_state_transition_fails() {
    let mut session = CallSession::new(
        "device1".to_string(),
        "virtual1".to_string(),
        "device2".to_string(),
        "virtual2".to_string(),
        vec![MediaType::Audio],
        "nonce123".to_string(),
    )
    .unwrap();

    let result = session.transition(CallState::Connected, "invalid jump".to_string());
    assert!(result.is_err());
}

#[tokio::test]
async fn test_receiver_acceptance_rejects_empty_media() {
    let mut session = CallSession::new(
        "device1".to_string(),
        "virtual1".to_string(),
        "device2".to_string(),
        "virtual2".to_string(),
        vec![MediaType::Audio],
        "nonce123".to_string(),
    )
    .unwrap();

    let result = session.receiver_accepted(vec![]);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_offer_signature_rejects_missing_fields() {
    let temp = tempdir().expect("create temp dir");
    let key_path = temp.path().join("offline_key.pk8");
    let key_manager = KeyManager::load_or_generate(key_path.to_str().unwrap()).expect("load key");

    let offer = CallOffer::new(
        "".to_string(),
        "virtual1".to_string(),
        "session1".to_string(),
        "nonce123".to_string(),
        vec![MediaType::Audio],
        &key_manager,
    )
    .await;
    assert!(offer.is_err());
}

async fn body_json(response: Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn initiate_call_request_round_trips() {
    let req = InitiateCallRequest {
        initiator_device_id: "d1".into(),
        initiator_virtual_id: "v1".into(),
        receiver_device_id: "d2".into(),
        receiver_virtual_id: "v2".into(),
        receiver_nebula_ip: "192.168.100.2".into(),
        requested_media: vec![MediaType::Audio, MediaType::Video],
    };
    let parsed: InitiateCallRequest =
        serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
    assert_eq!(parsed.requested_media.len(), 2);
}

#[test]
fn initiate_response_serializes_status() {
    let res = InitiateCallResponse {
        session_id: "s".into(),
        status: "pending".into(),
    };
    assert!(serde_json::to_string(&res).unwrap().contains("pending"));
}

#[test]
fn browser_initiate_deserializes_empty_media() {
    let req: BrowserInitiateCallRequest =
        serde_json::from_str(r#"{"target_peer_id":"p","media":[]}"#).unwrap();
    assert!(req.media.is_empty());
}

#[test]
fn browser_accept_deserializes_media() {
    let req: BrowserAcceptCallRequest =
        serde_json::from_str(r#"{"accepted_media":["audio"]}"#).unwrap();
    assert_eq!(req.accepted_media, vec![MediaType::Audio]);
}

#[test]
fn browser_reject_default_reason_is_applied() {
    let req: BrowserRejectCallRequest = serde_json::from_str("{}").unwrap();
    assert_eq!(req.reason, "declined");
}

#[test]
fn submit_signal_deserializes_operation_id() {
    let req: SubmitSignalRequest =
        serde_json::from_str(r#"{"type":"ice_candidate","payload":{"x":1},"operation_id":"op"}"#)
            .unwrap();
    assert_eq!(req.operation_id.as_deref(), Some("op"));
}

#[test]
fn media_ready_deserializes_optional_dtls() {
    let req: MediaReadyRequest = serde_json::from_str(r#"{"session_id":"s","device_id":"d","virtual_id":"v","media":["Audio"],"dtls_fingerprint":"fp"}"#).unwrap();
    assert_eq!(req.dtls_fingerprint.as_deref(), Some("fp"));
}

#[test]
fn call_list_response_serializes_empty() {
    let response = CallListResponse {
        calls: vec![],
        total: 0,
    };
    assert!(serde_json::to_string(&response)
        .unwrap()
        .contains("\"total\":0"));
}

#[test]
fn call_history_response_serializes_empty() {
    let response = CallHistoryResponse {
        calls: vec![],
        total: 0,
    };
    assert!(serde_json::to_string(&response)
        .unwrap()
        .contains("\"calls\":[]"));
}

#[test]
fn error_response_serializes_error() {
    let response = ErrorResponse {
        error: "bad".into(),
    };
    assert_eq!(serde_json::to_value(response).unwrap()["error"], "bad");
}

#[tokio::test]
async fn policy_check_rejects_bad_caller_role() {
    let response = policy_check(axum::Json(PolicyCheckRequest {
        caller_role: "bad".into(),
        target_role: "member".into(),
        media_type: "audio".into(),
    }))
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn policy_check_rejects_bad_target_role() {
    let response = policy_check(axum::Json(PolicyCheckRequest {
        caller_role: "owner".into(),
        target_role: "bad".into(),
        media_type: "audio".into(),
    }))
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn policy_check_rejects_bad_media_type() {
    let response = policy_check(axum::Json(PolicyCheckRequest {
        caller_role: "owner".into(),
        target_role: "member".into(),
        media_type: "laser".into(),
    }))
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ice_servers_empty_when_env_missing() {
    let prev = std::env::var_os("SGX_WEBRTC_ICE_SERVERS");
    std::env::remove_var("SGX_WEBRTC_ICE_SERVERS");
    let value = body_json(ice_servers().await.into_response()).await;
    assert_eq!(value["configured"], false);
    if let Some(value) = prev {
        std::env::set_var("SGX_WEBRTC_ICE_SERVERS", value);
    }
}

#[tokio::test]
async fn ice_servers_rejects_invalid_json() {
    let prev = std::env::var_os("SGX_WEBRTC_ICE_SERVERS");
    std::env::set_var("SGX_WEBRTC_ICE_SERVERS", "{");
    let response = ice_servers().await.into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    if let Some(value) = prev {
        std::env::set_var("SGX_WEBRTC_ICE_SERVERS", value);
    } else {
        std::env::remove_var("SGX_WEBRTC_ICE_SERVERS");
    }
}

#[tokio::test]
async fn ice_servers_accepts_stun_without_credentials() {
    let prev = std::env::var_os("SGX_WEBRTC_ICE_SERVERS");
    std::env::set_var(
        "SGX_WEBRTC_ICE_SERVERS",
        r#"[{"urls":["stun:example:3478"]}]"#,
    );
    let value = body_json(ice_servers().await.into_response()).await;
    assert_eq!(value["configured"], true);
    if let Some(value) = prev {
        std::env::set_var("SGX_WEBRTC_ICE_SERVERS", value);
    } else {
        std::env::remove_var("SGX_WEBRTC_ICE_SERVERS");
    }
}

#[tokio::test]
async fn ice_servers_rejects_turn_without_credentials() {
    let prev = std::env::var_os("SGX_WEBRTC_ICE_SERVERS");
    std::env::set_var(
        "SGX_WEBRTC_ICE_SERVERS",
        r#"[{"urls":["turn:example:3478"]}]"#,
    );
    assert_eq!(
        ice_servers().await.into_response().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    if let Some(value) = prev {
        std::env::set_var("SGX_WEBRTC_ICE_SERVERS", value);
    } else {
        std::env::remove_var("SGX_WEBRTC_ICE_SERVERS");
    }
}

macro_rules! browser_initiate_cases {
    ($($name:ident => $peer:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            let json = serde_json::json!({"target_peer_id": $peer, "media": ["audio"]});
            let req: BrowserInitiateCallRequest = serde_json::from_value(json).unwrap();
            assert_eq!(req.target_peer_id, $peer);
        }
    )+};
}

browser_initiate_cases! {
    browser_peer_empty => "",
    browser_peer_did => "did:guardian:peer",
    browser_peer_uuid => "550e8400-e29b-41d4-a716-446655440000",
    browser_peer_space => "peer space",
    browser_peer_long => "peer-abcdefghijklmnopqrstuvwxyz",
}

fn envelope(kind: SignalKind) -> SignalingEnvelope {
    SignalingEnvelope {
        version: 1,
        kind,
        session_id: "session".into(),
        sender_device_id: "device".into(),
        sender_virtual_id: "virtual".into(),
        sequence: 1,
        timestamp: Utc::now(),
        nonce: "nonce".into(),
        payload: serde_json::json!({}),
        signature: "sig".into(),
    }
}

fn wire_offer(session: &str, device: &str) -> WireCallOffer {
    WireCallOffer {
        device_id: device.into(),
        virtual_id: "virtual".into(),
        session_id: session.into(),
        timestamp: Utc::now(),
        nonce: "nonce".into(),
        requested_media: vec![sgx_guardian_client::call::signaling::MediaType::Audio],
        signature: "sig".into(),
    }
}

fn wire_answer(session: &str, device: &str) -> CallAnswer {
    CallAnswer {
        device_id: device.into(),
        virtual_id: "virtual".into(),
        session_id: session.into(),
        timestamp: Utc::now(),
        nonce: "nonce".into(),
        accepted_media: vec![sgx_guardian_client::call::signaling::MediaType::Video],
        accepted: true,
        rejection_reason: None,
        signature: "sig".into(),
    }
}

#[test]
fn signaling_message_envelope_session_id() {
    assert_eq!(
        SignalingMessage::Envelope(envelope(SignalKind::Offer)).session_id(),
        "session"
    );
}

#[test]
fn signaling_message_envelope_device_id() {
    assert_eq!(
        SignalingMessage::Envelope(envelope(SignalKind::Offer)).device_id(),
        "device"
    );
}

#[test]
fn signaling_message_offer_session_id() {
    assert_eq!(
        SignalingMessage::Offer(wire_offer("s1", "d1")).session_id(),
        "s1"
    );
}

#[test]
fn signaling_message_offer_device_id() {
    assert_eq!(
        SignalingMessage::Offer(wire_offer("s1", "d1")).device_id(),
        "d1"
    );
}

#[test]
fn signaling_message_answer_session_id() {
    assert_eq!(
        SignalingMessage::Answer(wire_answer("s2", "d2")).session_id(),
        "s2"
    );
}

#[test]
fn signaling_message_answer_device_id() {
    assert_eq!(
        SignalingMessage::Answer(wire_answer("s2", "d2")).device_id(),
        "d2"
    );
}

#[test]
fn signaling_message_debug_mentions_envelope() {
    assert!(format!(
        "{:?}",
        SignalingMessage::Envelope(envelope(SignalKind::Heartbeat))
    )
    .contains("Envelope"));
}

macro_rules! signal_kind_browser_tests {
    ($($name:ident => $kind:expr, $expected:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            assert_eq!($kind.is_browser_signal(), $expected);
        }
    )+};
}

signal_kind_browser_tests! {
    signal_offer_not_browser => SignalKind::Offer, false,
    signal_answer_not_browser => SignalKind::Answer, false,
    signal_sdp_offer_browser => SignalKind::SdpOffer, true,
    signal_sdp_answer_browser => SignalKind::SdpAnswer, true,
    signal_ice_candidate_browser => SignalKind::IceCandidate, true,
    signal_ice_complete_browser => SignalKind::IceComplete, true,
    signal_media_ready_browser => SignalKind::MediaReady, true,
    signal_hangup_browser => SignalKind::Hangup, true,
    signal_heartbeat_not_browser => SignalKind::Heartbeat, false,
    signal_error_browser => SignalKind::Error, true,
    signal_group_control_not_browser => SignalKind::GroupControl, false,
}

#[test]
fn signaling_envelope_serializes_kind_as_type() {
    let json = serde_json::to_string(&envelope(SignalKind::SdpOffer)).unwrap();
    assert!(json.contains("\"type\":\"sdp_offer\""));
}

#[test]
fn signaling_envelope_deserializes_snake_case_kind() {
    let json = serde_json::to_string(&envelope(SignalKind::IceCandidate)).unwrap();
    let parsed: SignalingEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.kind, SignalKind::IceCandidate);
}

#[test]
fn wire_offer_json_round_trips() {
    let offer = wire_offer("s", "d");
    assert_eq!(
        WireCallOffer::from_json(&offer.to_json().unwrap())
            .unwrap()
            .session_id,
        "s"
    );
}

#[test]
fn wire_answer_json_round_trips() {
    let answer = wire_answer("s", "d");
    assert_eq!(
        CallAnswer::from_json(&answer.to_json().unwrap())
            .unwrap()
            .device_id,
        "d"
    );
}

#[test]
fn wire_offer_from_bad_json_errors() {
    assert!(WireCallOffer::from_json("{").is_err());
}

#[test]
fn wire_answer_from_bad_json_errors() {
    assert!(CallAnswer::from_json("{").is_err());
}

#[test]
fn call_error_display_covers_data_bearing_variants() {
    let cases = [
        (
            CallError::InvalidStateTransition {
                from: "Idle".into(),
                to: "Connected".into(),
            },
            "Invalid call state: cannot transition from Idle to Connected",
        ),
        (
            CallError::SessionNotFound {
                session_id: "missing".into(),
            },
            "Session not found: missing",
        ),
        (
            CallError::InvalidOffer {
                reason: "bad media".into(),
            },
            "Offer invalid: bad media",
        ),
        (
            CallError::NonceReused { nonce: "n1".into() },
            "Nonce already used: n1",
        ),
        (
            CallError::UnauthorizedDevice {
                reason: "not trusted".into(),
            },
            "Device not authorized for call: not trusted",
        ),
        (
            CallError::SessionTimeout { seconds: 30 },
            "Session timeout after 30 seconds",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn call_error_display_covers_simple_and_wrapped_variants() {
    assert_eq!(
        CallError::SignatureVerificationFailed.to_string(),
        "Signature verification failed"
    );
    assert_eq!(
        CallError::NebulaError {
            reason: "offline".into()
        }
        .to_string(),
        "Guardian Mesh send failed: offline"
    );
    assert_eq!(
        CallError::CallRejected {
            reason: "busy".into()
        }
        .to_string(),
        "Call rejected: busy"
    );
    assert_eq!(
        CallError::SerializationError("json".into()).to_string(),
        "Serialization error: json"
    );
    assert_eq!(
        CallError::KeyManagerError("key".into()).to_string(),
        "Key manager error: key"
    );
    assert_eq!(
        CallError::AuditError("audit".into()).to_string(),
        "Audit error: audit"
    );
    assert_eq!(
        CallError::InternalError("internal".into()).to_string(),
        "Internal error: internal"
    );
}

#[test]
fn media_stream_state_as_str_covers_all_states() {
    assert_eq!(MediaStreamState::Inactive.as_str(), "inactive");
    assert_eq!(MediaStreamState::Active.as_str(), "active");
    assert_eq!(MediaStreamState::Paused.as_str(), "paused");
    assert_eq!(MediaStreamState::Error.as_str(), "error");
}

#[test]
fn media_stats_default_has_zero_counters() {
    let stats = MediaStats::default();
    assert_eq!(stats.bytes_sent, 0);
    assert_eq!(stats.bytes_received, 0);
    assert_eq!(stats.packets_sent, 0);
    assert_eq!(stats.packets_received, 0);
    assert_eq!(stats.packet_loss_percent, 0.0);
    assert_eq!(stats.rtt_ms, 0);
    assert_eq!(stats.jitter_ms, 0);
}

#[test]
fn audio_stream_constructor_and_transitions_are_stable() {
    let mut audio = AudioStream::new("opus".into(), 48_000, 2, 128);
    assert_eq!(audio.state, MediaStreamState::Inactive);
    assert_eq!(audio.codec, "opus");
    assert_eq!(audio.sample_rate, 48_000);
    assert_eq!(audio.channels, 2);
    assert_eq!(audio.bitrate_kbps, 128);
    audio.activate();
    assert_eq!(audio.state, MediaStreamState::Active);
    audio.pause();
    assert_eq!(audio.state, MediaStreamState::Paused);
    audio.deactivate();
    assert_eq!(audio.state, MediaStreamState::Inactive);
}

#[test]
fn video_stream_constructor_resolution_and_transitions_are_stable() {
    let mut video = VideoStream::new("h264".into(), 1920, 1080, 30, 2500);
    assert_eq!(video.resolution(), "1920x1080");
    assert_eq!(video.fps, 30);
    video.activate();
    assert_eq!(video.state, MediaStreamState::Active);
    video.pause();
    assert_eq!(video.state, MediaStreamState::Paused);
    video.deactivate();
    assert_eq!(video.state, MediaStreamState::Inactive);
}

#[test]
fn screen_share_constructor_and_transitions_are_stable() {
    let mut screen = ScreenShareStream::new("vp8".into(), 1280, 720, 15, 1200);
    assert_eq!(screen.width, 1280);
    assert_eq!(screen.height, 720);
    screen.activate();
    assert_eq!(screen.state, MediaStreamState::Active);
    screen.pause();
    assert_eq!(screen.state, MediaStreamState::Paused);
    screen.deactivate();
    assert_eq!(screen.state, MediaStreamState::Inactive);
}

#[test]
fn call_media_state_reports_inactive_when_streams_missing_or_paused() {
    let mut state = CallMediaState::new("session-media".into());
    assert_eq!(state.session_id, "session-media");
    assert!(!state.is_audio_active());
    assert!(!state.is_video_active());
    assert!(!state.is_screen_share_active());
    assert!(!state.is_any_stream_active());

    let mut audio = AudioStream::new("opus".into(), 48_000, 1, 64);
    audio.pause();
    state.add_audio(audio);
    assert!(!state.is_any_stream_active());
}

#[test]
fn call_media_state_reports_each_active_stream() {
    let mut state = CallMediaState::new("session-media-active".into());
    let mut audio = AudioStream::new("opus".into(), 48_000, 2, 128);
    audio.activate();
    state.add_audio(audio);
    assert!(state.is_audio_active());
    assert!(state.is_any_stream_active());

    let mut video = VideoStream::new("vp9".into(), 640, 360, 24, 600);
    video.activate();
    state.add_video(video);
    assert!(state.is_video_active());

    let mut screen = ScreenShareStream::new("h264".into(), 800, 600, 5, 400);
    screen.activate();
    state.add_screen_share(screen);
    assert!(state.is_screen_share_active());
}

#[test]
fn call_media_state_serializes_optional_streams() {
    let mut state = CallMediaState::new("serde-session".into());
    state.add_audio(AudioStream::new("opus".into(), 16_000, 1, 24));
    let encoded = serde_json::to_string(&state).unwrap();
    let decoded: CallMediaState = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded.session_id, "serde-session");
    assert_eq!(decoded.audio.unwrap().codec, "opus");
    assert!(decoded.video.is_none());
}

#[test]
fn call_state_wire_strings_cover_all_states() {
    let expected = [
        (CallState::Idle, "idle", "Idle"),
        (
            CallState::LocalPolicyCheck,
            "local_policy_check",
            "LocalPolicyCheck",
        ),
        (CallState::OfferSent, "offer_sent", "OfferSent"),
        (CallState::OfferReceived, "offer_received", "OfferReceived"),
        (CallState::Verifying, "verifying", "Verifying"),
        (CallState::Authorizing, "authorizing", "Authorizing"),
        (CallState::Accepted, "accepted", "Accepted"),
        (
            CallState::MediaNegotiation,
            "media_negotiation",
            "MediaNegotiation",
        ),
        (CallState::Connected, "connected", "Connected"),
        (CallState::EndCall, "ended", "EndCall"),
    ];
    for (state, wire, display) in expected {
        assert_eq!(state.as_wire_str(), wire);
        assert_eq!(state.to_string(), display);
    }
}

#[test]
fn call_state_reachable_sets_are_exact_for_branch_edges() {
    assert_eq!(
        CallState::Idle.reachable_from(),
        vec![
            CallState::LocalPolicyCheck,
            CallState::OfferReceived,
            CallState::EndCall
        ]
    );
    assert_eq!(
        CallState::Connected.reachable_from(),
        vec![CallState::EndCall]
    );
    assert!(CallState::EndCall.reachable_from().is_empty());
}

#[test]
fn call_state_accepts_each_terminal_escape_path() {
    for state in [
        CallState::Idle,
        CallState::LocalPolicyCheck,
        CallState::OfferSent,
        CallState::OfferReceived,
        CallState::Verifying,
        CallState::Authorizing,
        CallState::Accepted,
        CallState::MediaNegotiation,
        CallState::Connected,
    ] {
        assert!(state.validate_transition(CallState::EndCall).is_ok());
    }
}

#[test]
fn call_state_rejects_self_transitions_and_terminal_exit() {
    for state in [
        CallState::Idle,
        CallState::LocalPolicyCheck,
        CallState::OfferSent,
        CallState::OfferReceived,
        CallState::Verifying,
        CallState::Authorizing,
        CallState::Accepted,
        CallState::MediaNegotiation,
        CallState::Connected,
        CallState::EndCall,
    ] {
        assert!(state.validate_transition(state).is_err());
    }
    assert!(CallState::EndCall
        .validate_transition(CallState::Idle)
        .is_err());
}

#[test]
fn signaling_envelope_new_sets_defaults_and_payload() {
    let env = SignalingEnvelope::new(
        SignalKind::Answer,
        "s",
        "d",
        "v",
        9,
        "n",
        serde_json::json!({"b": 2, "a": 1}),
    );
    assert_eq!(env.version, CALL_PROTOCOL_VERSION);
    assert_eq!(env.kind, SignalKind::Answer);
    assert_eq!(env.sequence, 9);
    assert_eq!(env.signature, "");
    assert_eq!(env.payload["a"], 1);
}

#[test]
fn signaling_envelope_freshness_accepts_exact_boundary() {
    let mut env = envelope(SignalKind::Heartbeat);
    let now = Utc::now();
    env.timestamp = now - chrono::Duration::seconds(MAX_SIGNAL_AGE_SECS);
    assert!(env.validate_freshness(now).is_ok());
}

#[test]
fn signaling_envelope_freshness_rejects_beyond_boundary() {
    let mut env = envelope(SignalKind::Heartbeat);
    let now = Utc::now();
    env.timestamp = now - chrono::Duration::seconds(MAX_SIGNAL_AGE_SECS + 1);
    assert!(env.validate_freshness(now).is_err());
}

#[test]
fn signaling_envelope_canonical_bytes_are_deterministic_for_nested_maps() {
    let mut a = envelope(SignalKind::GroupControl);
    a.payload = serde_json::json!({"z": [3, 2], "a": {"b": true, "a": null}});
    let mut b = a.clone();
    b.payload = serde_json::from_str(r#"{"a":{"a":null,"b":true},"z":[3,2]}"#).unwrap();
    assert_eq!(a.canonical_bytes().unwrap(), b.canonical_bytes().unwrap());
}

#[test]
fn signaling_envelope_sign_rejects_empty_required_fields() {
    let temp = tempdir().unwrap();
    let key = KeyManager::load_or_generate(temp.path().join("k.pk8").to_str().unwrap()).unwrap();
    let mut env = envelope(SignalKind::Offer);
    env.session_id = " ".into();
    assert!(env.sign(&key).is_err());
}

#[test]
fn signaling_envelope_sign_rejects_zero_sequence() {
    let temp = tempdir().unwrap();
    let key = KeyManager::load_or_generate(temp.path().join("k.pk8").to_str().unwrap()).unwrap();
    let mut env = envelope(SignalKind::Offer);
    env.sequence = 0;
    assert!(env.sign(&key).is_err());
}

#[test]
fn signaling_envelope_sign_rejects_oversized_payload() {
    let temp = tempdir().unwrap();
    let key = KeyManager::load_or_generate(temp.path().join("k.pk8").to_str().unwrap()).unwrap();
    let mut env = envelope(SignalKind::Offer);
    env.payload = serde_json::json!({"blob": "x".repeat(MAX_SIGNAL_PAYLOAD_BYTES)});
    assert!(env.sign(&key).is_err());
}

#[test]
fn signaling_envelope_verify_rejects_bad_signature_hex() {
    let temp = tempdir().unwrap();
    let key = KeyManager::load_or_generate(temp.path().join("k.pk8").to_str().unwrap()).unwrap();
    let mut env = envelope(SignalKind::Offer);
    env.signature = "not hex".into();
    assert!(env.verify(&key.pubkey_der().unwrap()).is_err());
}

#[tokio::test]
async fn replay_protector_allows_same_sequence_for_different_sessions() {
    let replay = ReplayProtector::default();
    let first = SignalingEnvelope::new(
        SignalKind::Heartbeat,
        "s1",
        "d",
        "v",
        1,
        "n1",
        serde_json::json!({}),
    );
    let second = SignalingEnvelope::new(
        SignalKind::Heartbeat,
        "s2",
        "d",
        "v",
        1,
        "n1",
        serde_json::json!({}),
    );
    replay.check_and_record(&first).await.unwrap();
    replay.check_and_record(&second).await.unwrap();
}

#[tokio::test]
async fn replay_protector_allows_same_sequence_for_different_sender() {
    let replay = ReplayProtector::default();
    let first = SignalingEnvelope::new(
        SignalKind::Heartbeat,
        "s",
        "d1",
        "v",
        1,
        "n",
        serde_json::json!({}),
    );
    let second = SignalingEnvelope::new(
        SignalKind::Heartbeat,
        "s",
        "d2",
        "v",
        1,
        "n",
        serde_json::json!({}),
    );
    replay.check_and_record(&first).await.unwrap();
    replay.check_and_record(&second).await.unwrap();
}

#[tokio::test]
async fn replay_protector_rejects_new_nonce_with_lower_sequence() {
    let replay = ReplayProtector::default();
    let first = SignalingEnvelope::new(
        SignalKind::Heartbeat,
        "s",
        "d",
        "v",
        5,
        "n5",
        serde_json::json!({}),
    );
    let older = SignalingEnvelope::new(
        SignalKind::Heartbeat,
        "s",
        "d",
        "v",
        4,
        "n4",
        serde_json::json!({}),
    );
    replay.check_and_record(&first).await.unwrap();
    assert!(matches!(
        replay.check_and_record(&older).await,
        Err(CallError::NonceReused { .. })
    ));
}

#[tokio::test]
async fn reject_unknown_peer_resolver_mentions_device_id() {
    let resolver = RejectUnknownPeerResolver;
    let error = resolver.resolve("device-x", "10.0.0.5").await.unwrap_err();
    assert!(error.to_string().contains("device-x"));
}

#[test]
fn trusted_peer_identity_clone_and_equality_are_value_based() {
    let identity = TrustedPeerIdentity {
        device_id: "d".into(),
        did: "did:guardian:d".into(),
        public_key_point: vec![4, 1, 2, 3],
    };
    assert_eq!(identity.clone(), identity);
}

#[test]
fn history_store_default_path_is_guardian_log_path() {
    let store = CallHistoryStore::default();
    assert!(store
        .path()
        .to_string_lossy()
        .ends_with("call_history.json"));
}

#[test]
fn history_store_lists_empty_for_missing_or_malformed_file() {
    let dir = tempdir().unwrap();
    let missing = CallHistoryStore::new(dir.path().join("missing.json"));
    assert!(missing.list().is_empty());
    let malformed_path = dir.path().join("history.json");
    std::fs::write(&malformed_path, "{").unwrap();
    assert!(CallHistoryStore::new(malformed_path).list().is_empty());
}

#[test]
fn history_record_serializes_and_deserializes_media() {
    let record = CallHistoryRecord {
        id: "id".into(),
        kind: "direct".into(),
        outcome: "completed".into(),
        media: vec![MediaType::Audio, MediaType::Video],
        participant_ids: vec!["a".into(), "b".into()],
        started_at: Utc::now(),
        ended_at: Utc::now(),
        duration_seconds: 3,
    };
    let decoded: CallHistoryRecord =
        serde_json::from_str(&serde_json::to_string(&record).unwrap()).unwrap();
    assert_eq!(decoded, record);
}

#[test]
fn history_store_records_direct_completed_when_media_connected() {
    let dir = tempdir().unwrap();
    let store = CallHistoryStore::new(dir.path().join("history.json"));
    let mut session = CallSession::new(
        "a".into(),
        "va".into(),
        "b".into(),
        "vb".into(),
        vec![MediaType::Audio],
        "n".into(),
    )
    .unwrap();
    session
        .transition(CallState::LocalPolicyCheck, "policy".into())
        .unwrap();
    session
        .transition(CallState::OfferSent, "offer".into())
        .unwrap();
    session
        .transition(CallState::Verifying, "verify".into())
        .unwrap();
    session
        .transition(CallState::Authorizing, "auth".into())
        .unwrap();
    session
        .transition(CallState::Accepted, "accept".into())
        .unwrap();
    session
        .transition(CallState::MediaNegotiation, "media".into())
        .unwrap();
    session
        .transition(CallState::Connected, "connected".into())
        .unwrap();
    let status = session.status_snapshot();
    store.record_direct(&status);
    let records = store.list();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].outcome, "completed");
}

#[test]
fn history_store_records_direct_cancelled_when_ended_without_duration() {
    let dir = tempdir().unwrap();
    let store = CallHistoryStore::new(dir.path().join("history.json"));
    let mut session = CallSession::new(
        "a".into(),
        "va".into(),
        "b".into(),
        "vb".into(),
        vec![MediaType::Audio],
        "n".into(),
    )
    .unwrap();
    session
        .transition(CallState::EndCall, "cancel".into())
        .unwrap();
    store.record_direct(&session.status_snapshot());
    assert_eq!(store.list()[0].outcome, "cancelled");
}

#[test]
fn history_store_record_direct_prefers_accepted_media() {
    let dir = tempdir().unwrap();
    let store = CallHistoryStore::new(dir.path().join("history.json"));
    let mut session = CallSession::new(
        "a".into(),
        "va".into(),
        "b".into(),
        "vb".into(),
        vec![MediaType::Audio],
        "n".into(),
    )
    .unwrap();
    session.receiver_accepted(vec![MediaType::Video]).unwrap();
    store.record_direct(&session.status_snapshot());
    assert_eq!(store.list()[0].media, vec![MediaType::Video]);
}

#[test]
fn uep_role_extraction_trims_parts_and_is_case_sensitive() {
    assert_eq!(
        extract_role_from_subject("CN=node, O=Guardian, role=operator"),
        Some(sgx_guardian_client::enforcement::uep::Role::Operator)
    );
    assert_eq!(extract_role_from_subject("CN=node,role=Admin"), None);
    assert_eq!(extract_role_from_subject("CN=node,role="), None);
}

#[test]
fn uep_gate_error_display_covers_all_variants() {
    assert_eq!(
        UepGateError::DeniedByPolicy("blocked".into()).to_string(),
        "Call denied by policy: blocked"
    );
    assert_eq!(
        UepGateError::MissingCallerRole.to_string(),
        "Cannot determine caller role from certificate"
    );
    assert_eq!(
        UepGateError::MissingTargetRole.to_string(),
        "Cannot determine target role"
    );
    assert_eq!(
        UepGateError::RbacLoadFailed("missing".into()).to_string(),
        "Failed to load RBAC rules: missing"
    );
}

#[tokio::test]
async fn allow_all_enforcer_allows_emptyish_but_valid_session() {
    let session = CallSession::new(
        "initiator".into(),
        "".into(),
        "receiver".into(),
        "".into(),
        vec![MediaType::Audio],
        "nonce".into(),
    )
    .unwrap();
    assert!(AllowAllEnforcer.allow_call(&session).await.unwrap());
}

#[test]
fn verification_state_strings_cover_all_states() {
    assert_eq!(VerificationState::Pending.as_str(), "pending");
    assert_eq!(
        VerificationState::AttestationComplete.as_str(),
        "attestation_complete"
    );
    assert_eq!(
        VerificationState::AuthorizationComplete.as_str(),
        "authorization_complete"
    );
    assert_eq!(
        VerificationState::PolicyCheckComplete.as_str(),
        "policy_check_complete"
    );
    assert_eq!(VerificationState::Verified.as_str(), "verified");
    assert_eq!(VerificationState::Failed.as_str(), "failed");
}

#[test]
fn media_gate_default_requirements_require_all_checks() {
    let req = VerificationRequirements::default();
    assert!(req.require_attestation);
    assert!(req.require_authorization);
    assert!(req.require_policy_check);
}

#[test]
fn media_gate_full_verification_allows_active_media() {
    let mut gate = MediaGate::new("gate-session".into());
    gate.verify_attestation().unwrap();
    gate.verify_authorization().unwrap();
    gate.verify_policy().unwrap();
    let mut media = CallMediaState::new("gate-session".into());
    let mut audio = AudioStream::new("opus".into(), 48_000, 2, 96);
    audio.activate();
    media.add_audio(audio);
    assert!(gate.check_media_stream(&media).is_ok());
}

#[test]
fn media_gate_rejects_active_media_before_verification() {
    let gate = MediaGate::new("gate-session".into());
    let mut media = CallMediaState::new("gate-session".into());
    let mut audio = AudioStream::new("opus".into(), 48_000, 2, 96);
    audio.activate();
    media.add_audio(audio);
    let error = gate.check_media_stream(&media).unwrap_err();
    assert!(error.to_string().contains("pending"));
}

#[test]
fn media_gate_rejects_verified_but_inactive_media() {
    let mut gate = MediaGate::new("gate-session".into());
    gate.verify_attestation().unwrap();
    gate.verify_authorization().unwrap();
    gate.verify_policy().unwrap();
    let media = CallMediaState::new("gate-session".into());
    assert!(gate
        .check_media_stream(&media)
        .unwrap_err()
        .to_string()
        .contains("No active"));
}

#[test]
fn media_gate_rejects_repeated_attestation_after_progress() {
    let mut gate = MediaGate::new("gate-session".into());
    gate.verify_attestation().unwrap();
    assert!(gate.verify_attestation().is_err());
}

#[test]
fn media_gate_rejects_policy_before_authorization() {
    let mut gate = MediaGate::new("gate-session".into());
    gate.verify_attestation().unwrap();
    assert!(gate.verify_policy().is_err());
}

#[test]
fn media_gate_custom_no_policy_requirement_verifies_after_authorization() {
    let mut gate = MediaGate::with_requirements(
        "gate-session".into(),
        VerificationRequirements {
            require_attestation: true,
            require_authorization: true,
            require_policy_check: false,
        },
    );
    gate.verify_attestation().unwrap();
    gate.verify_authorization().unwrap();
    assert_eq!(gate.state(), VerificationState::Verified);
}

#[test]
fn media_gate_deny_sets_failed_state_and_blocks_streams() {
    let mut gate = MediaGate::new("gate-session".into());
    assert!(gate
        .deny("blocked")
        .unwrap_err()
        .to_string()
        .contains("blocked"));
    assert_eq!(gate.state(), VerificationState::Failed);
    assert!(gate
        .check_media_stream(&CallMediaState::new("gate-session".into()))
        .is_err());
}
