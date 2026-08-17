//! Nebula-based call signaling transport.
//! All call offers and answers are sent via Nebula overlay network.
//! No fallback paths - Nebula is the only transport.

use crate::call::error::{CallError, CallResult};
use crate::call::identity::{PeerIdentityResolver, RejectUnknownPeerResolver};
use crate::call::protocol::{ReplayProtector, SignalKind, SignalingEnvelope};
use crate::call::signaling::{CallAnswer, CallOffer};
use crate::call::{GroupMemberState, GroupSessionManager, GroupWireMessage};
use crate::key_manager::KeyManager;
use crate::nebula::interface::NebulaInterface;
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

const SIGNALING_TIMEOUT_SECS: u64 = 5;
const MAX_SIGNALING_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_OFFER_AGE_SECS: i64 = 300;

fn signaling_port() -> u16 {
    std::env::var("SGX_CALL_SIGNALING_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(50065)
}

/// Nebula transport client for call signaling.
pub struct NebulaClient;

impl NebulaClient {
    pub async fn send_message(&self, ip: &str, msg: &str) -> Result<(), String> {
        let addr = format!("{}:{}", ip, signaling_port());
        let mut stream = timeout(
            Duration::from_secs(SIGNALING_TIMEOUT_SECS),
            TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| format!("Timeout connecting to {}", addr))?
        .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

        stream
            .write_all(msg.as_bytes())
            .await
            .map_err(|e| format!("Failed to write message: {}", e))?;
        stream
            .shutdown()
            .await
            .map_err(|e| format!("Failed to shutdown connection: {}", e))
    }

    pub async fn get_local_ip(&self) -> Result<String, String> {
        NebulaInterface::get_overlay_ip()
            .and_then(|cidr| cidr.split('/').next().map(str::to_owned))
            .ok_or_else(|| "Nebula overlay interface unavailable".to_string())
    }

    pub async fn is_peer_reachable(&self, ip: &str) -> Result<bool, String> {
        Ok(NebulaInterface::ping_peer(ip))
    }
}

/// Nebula signaling transport for calls
pub struct NebulaSignaling {
    nebula_client: Arc<NebulaClient>,
    signer: Option<Arc<KeyManager>>,
    peer_identities: Arc<dyn PeerIdentityResolver>,
    replay: ReplayProtector,
    outbound_sequence: AtomicU64,
}

impl NebulaSignaling {
    /// Create new Nebula signaling transport
    pub fn new(nebula_client: Arc<NebulaClient>) -> Self {
        NebulaSignaling {
            nebula_client,
            signer: None,
            peer_identities: Arc::new(RejectUnknownPeerResolver),
            replay: ReplayProtector::default(),
            outbound_sequence: AtomicU64::new(1),
        }
    }

    /// Construct the production signaling transport. Unlike `new`, inbound
    /// messages must resolve to an attested DID key and outbound messages use
    /// the signed, versioned envelope.
    pub fn new_secure(
        nebula_client: Arc<NebulaClient>,
        signer: Arc<KeyManager>,
        peer_identities: Arc<dyn PeerIdentityResolver>,
    ) -> Self {
        Self {
            nebula_client,
            signer: Some(signer),
            peer_identities,
            replay: ReplayProtector::default(),
            outbound_sequence: AtomicU64::new(1),
        }
    }

    /// Run the inbound signaling listener on the local Nebula interface.
    /// Binding specifically to the overlay address prevents the call control
    /// plane from being exposed through LAN/WAN interfaces.
    pub async fn run_listener(
        self: Arc<Self>,
        session_manager: Arc<crate::call::session::SessionManager>,
        signal_hub: Arc<crate::call::CallSignalHub>,
        group_sessions: Arc<GroupSessionManager>,
        local_device_id: String,
    ) -> CallResult<()> {
        let local_ip = self.get_local_nebula_ip().await?;
        let bind_addr = format!("{}:{}", local_ip, signaling_port());
        let listener = TcpListener::bind(&bind_addr)
            .await
            .map_err(|e| CallError::NebulaError {
                reason: format!("Failed to bind signaling listener on {}: {}", bind_addr, e),
            })?;

        tracing::info!(%bind_addr, "Nebula call signaling listener started");
        loop {
            let (stream, peer) = listener
                .accept()
                .await
                .map_err(|e| CallError::NebulaError {
                    reason: format!("Failed to accept signaling connection: {}", e),
                })?;

            if !is_nebula_overlay_peer(peer.ip()) {
                tracing::warn!(peer = %peer, "Rejected call signaling connection outside the Nebula overlay");
                continue;
            }

            let signaling = self.clone();
            let sessions = session_manager.clone();
            let signal_hub = signal_hub.clone();
            let group_sessions = group_sessions.clone();
            let local_device_id = local_device_id.clone();
            tokio::spawn(async move {
                if let Err(error) = signaling
                    .receive_connection(
                        stream,
                        peer.ip().to_string(),
                        sessions,
                        signal_hub,
                        group_sessions,
                        local_device_id,
                    )
                    .await
                {
                    eprintln!(
                        "❌ Rejected Nebula call signaling message from {}: {}",
                        peer, error
                    );
                    tracing::warn!(peer = %peer, %error, "Rejected Nebula call signaling message");
                }
            });
        }
    }

    async fn receive_connection(
        &self,
        stream: TcpStream,
        peer_ip: String,
        session_manager: Arc<crate::call::session::SessionManager>,
        signal_hub: Arc<crate::call::CallSignalHub>,
        group_sessions: Arc<GroupSessionManager>,
        local_device_id: String,
    ) -> CallResult<()> {
        let mut payload = Vec::new();
        timeout(
            Duration::from_secs(SIGNALING_TIMEOUT_SECS),
            stream
                .take((MAX_SIGNALING_MESSAGE_BYTES + 1) as u64)
                .read_to_end(&mut payload),
        )
        .await
        .map_err(|_| CallError::NebulaError {
            reason: "Timed out reading signaling message".to_string(),
        })?
        .map_err(|e| CallError::NebulaError {
            reason: format!("Failed to read signaling message: {}", e),
        })?;

        if payload.len() > MAX_SIGNALING_MESSAGE_BYTES {
            return Err(CallError::SerializationError(
                "Signaling message exceeds 64 KiB limit".to_string(),
            ));
        }
        // A zero-byte connection is the authenticated-overlay liveness probe
        // used by the peers API. The source-address CIDR check already ran in
        // the listener before this connection reached us.
        if payload.is_empty() {
            return Ok(());
        }
        let payload = std::str::from_utf8(&payload).map_err(|_| {
            CallError::SerializationError("Signaling message is not UTF-8".to_string())
        })?;

        match self.handle_message(payload).await? {
            SignalingMessage::Envelope(envelope) => {
                self.process_envelope(
                    envelope,
                    peer_ip,
                    session_manager,
                    signal_hub,
                    group_sessions,
                    local_device_id,
                )
                .await
            }
            SignalingMessage::Offer(offer) => {
                if self.signer.is_some() {
                    return Err(CallError::SerializationError(
                        "Legacy call_offer is disabled on secure signaling".into(),
                    ));
                }
                if offer.signature.is_empty() {
                    return Err(CallError::SignatureVerificationFailed);
                }
                if (chrono::Utc::now() - offer.timestamp).num_seconds().abs() > MAX_OFFER_AGE_SECS {
                    return Err(CallError::InvalidOffer {
                        reason: "Offer timestamp is stale".to_string(),
                    });
                }
                session_manager
                    .register_incoming_offer(&offer, local_device_id, peer_ip)
                    .await
            }
            SignalingMessage::Answer(answer) => {
                if self.signer.is_some() {
                    return Err(CallError::SerializationError(
                        "Legacy call_answer is disabled on secure signaling".into(),
                    ));
                }
                if answer.signature.is_empty() {
                    return Err(CallError::SignatureVerificationFailed);
                }
                let session = session_manager.get_session(&answer.session_id).await?;
                // The receiver's device_id is not known to the initiator until now
                // (the session was provisioned from the trusted-peer registry, which
                // is keyed by Nebula IP, not by the remote's self-asserted ID), so
                // identity is anchored to the Nebula endpoint the answer arrived on.
                if session.receiver_nebula_ip.as_deref() != Some(peer_ip.as_str())
                    || session.nonce != answer.nonce
                {
                    return Err(CallError::InvalidOffer {
                        reason: "Answer does not match the active session".to_string(),
                    });
                }
                if answer.accepted {
                    session_manager
                        .set_receiver_acceptance_with_device(
                            &answer.session_id,
                            answer.virtual_id.clone(),
                            answer.accepted_media.clone(),
                            Some(answer.device_id.clone()),
                        )
                        .await?;
                    session_manager
                        .update_session_state(
                            &answer.session_id,
                            crate::call::state::CallState::Verifying,
                            "Answer received".to_string(),
                        )
                        .await?;
                    session_manager
                        .update_session_state(
                            &answer.session_id,
                            crate::call::state::CallState::Authorizing,
                            "Answer verified".to_string(),
                        )
                        .await?;
                    session_manager
                        .update_session_state(
                            &answer.session_id,
                            crate::call::state::CallState::Accepted,
                            "Call accepted by peer".to_string(),
                        )
                        .await
                } else {
                    session_manager
                        .update_session_state(
                            &answer.session_id,
                            crate::call::state::CallState::EndCall,
                            "Call rejected by peer".to_string(),
                        )
                        .await
                }
            }
        }
    }

    async fn process_envelope(
        &self,
        envelope: SignalingEnvelope,
        peer_ip: String,
        session_manager: Arc<crate::call::session::SessionManager>,
        signal_hub: Arc<crate::call::CallSignalHub>,
        group_sessions: Arc<GroupSessionManager>,
        local_device_id: String,
    ) -> CallResult<()> {
        envelope.validate_freshness(chrono::Utc::now())?;
        let _identity = self
            .peer_identities
            .resolve(&envelope.sender_device_id, &peer_ip)
            .await?;
        // Attestation and Nebula authenticate this peer before call traffic.
        // Avoid reopening SE050 for each call-control message.
        self.replay.check_and_record(&envelope).await?;

        if envelope.kind == SignalKind::GroupControl {
            return self
                .process_group_control(envelope, group_sessions, local_device_id)
                .await;
        }

        match envelope.kind {
            SignalKind::Offer => {
                let offer: CallOffer = serde_json::from_value(envelope.payload.clone())
                    .map_err(|_| CallError::SerializationError("Invalid offer payload".into()))?;
                if offer.session_id != envelope.session_id
                    || offer.device_id != envelope.sender_device_id
                    || offer.virtual_id != envelope.sender_virtual_id
                {
                    return Err(CallError::InvalidOffer {
                        reason: "Offer fields do not match the authenticated envelope".into(),
                    });
                }
                let is_retry = session_manager.get_session(&offer.session_id).await.is_ok();
                let busy = !is_retry
                    && (!session_manager.get_active_sessions().await.is_empty()
                        || !group_sessions.active_for(&local_device_id).await.is_empty());
                if busy {
                    let local_virtual_id =
                        crate::virtual_id::read_runtime_virtual_id_status(&local_device_id, None)
                            .map(|status| status.virtual_id)
                            .unwrap_or_default();
                    self.send_browser_signal(
                        SignalKind::Error,
                        &offer.session_id,
                        &local_device_id,
                        &local_virtual_id,
                        serde_json::json!({
                            "code": "busy",
                            "message": "Target Guardian is busy in another call"
                        }),
                        &peer_ip,
                    )
                    .await?;
                    return Ok(());
                }
                session_manager
                    .register_incoming_offer(&offer, local_device_id, peer_ip)
                    .await
            }
            SignalKind::Answer => {
                let answer: CallAnswer = serde_json::from_value(envelope.payload.clone())
                    .map_err(|_| CallError::SerializationError("Invalid answer payload".into()))?;
                if answer.session_id != envelope.session_id
                    || answer.device_id != envelope.sender_device_id
                    || answer.virtual_id != envelope.sender_virtual_id
                {
                    return Err(CallError::InvalidOffer {
                        reason: "Answer fields do not match the authenticated envelope".into(),
                    });
                }
                let session = session_manager.get_session(&answer.session_id).await?;
                // The receiver's device_id is not known to the initiator until now
                // (the session was provisioned from the trusted-peer registry, which
                // is keyed by Nebula IP, not by the remote's self-asserted ID), so
                // identity is anchored to the Nebula endpoint the answer arrived on.
                if session.receiver_nebula_ip.as_deref() != Some(peer_ip.as_str())
                    || session.nonce != answer.nonce
                {
                    return Err(CallError::InvalidOffer {
                        reason: "Answer does not match the active session".into(),
                    });
                }
                if answer.accepted {
                    session_manager
                        .set_receiver_acceptance_with_device(
                            &answer.session_id,
                            answer.virtual_id.clone(),
                            answer.accepted_media.clone(),
                            Some(answer.device_id.clone()),
                        )
                        .await?;
                    for (state, reason) in [
                        (crate::call::state::CallState::Verifying, "Answer received"),
                        (
                            crate::call::state::CallState::Authorizing,
                            "Answer verified",
                        ),
                        (
                            crate::call::state::CallState::Accepted,
                            "Call accepted by peer",
                        ),
                    ] {
                        session_manager
                            .update_session_state(&answer.session_id, state, reason.into())
                            .await?;
                    }
                    Ok(())
                } else {
                    session_manager
                        .update_session_state(
                            &answer.session_id,
                            crate::call::state::CallState::EndCall,
                            "Call rejected by peer".into(),
                        )
                        .await
                }
            }
            SignalKind::SdpOffer
            | SignalKind::SdpAnswer
            | SignalKind::IceCandidate
            | SignalKind::IceComplete => {
                if let Ok(session) = session_manager.get_session(&envelope.session_id).await {
                    if session.initiator.device_id != envelope.sender_device_id
                        && session.receiver.device_id != envelope.sender_device_id
                    {
                        return Err(CallError::UnauthorizedDevice {
                            reason: "Media signal sender is not a session participant".into(),
                        });
                    }
                    if session.state == crate::call::state::CallState::Accepted {
                        session_manager
                            .update_session_state(
                                &envelope.session_id,
                                crate::call::state::CallState::MediaNegotiation,
                                "Authenticated WebRTC signaling started".into(),
                            )
                            .await?;
                    } else if session.state != crate::call::state::CallState::MediaNegotiation {
                        return Err(CallError::InvalidStateTransition {
                            from: session.state.to_string(),
                            to: "MediaNegotiation".into(),
                        });
                    }
                    signal_hub.push_remote(&envelope).await?;
                    return session_manager
                        .notify(&envelope.session_id, "call_signal")
                        .await;
                }
                let group = group_sessions.get(&envelope.session_id).await?;
                let sender = group
                    .participants
                    .get(&envelope.sender_device_id)
                    .ok_or_else(|| CallError::UnauthorizedDevice {
                        reason: "Group media sender is not a member".into(),
                    })?;
                if sender.state != GroupMemberState::Joined {
                    return Err(CallError::UnauthorizedDevice {
                        reason: "Group media sender has not joined".into(),
                    });
                }
                signal_hub.push_remote(&envelope).await?;
                Ok(())
            }
            SignalKind::MediaReady => {
                signal_hub.push_remote(&envelope).await?;
                if session_manager
                    .get_session(&envelope.session_id)
                    .await
                    .is_ok()
                {
                    session_manager
                        .mark_media_ready(&envelope.session_id, false)
                        .await
                        .map(|_| ())
                } else {
                    group_sessions
                        .mark_media_ready(&envelope.session_id, &envelope.sender_device_id, true)
                        .await
                        .map(|_| ())
                }
            }
            SignalKind::Hangup => {
                signal_hub.push_remote(&envelope).await?;
                let result = session_manager.end_session(&envelope.session_id).await;
                self.replay.forget_session(&envelope.session_id).await;
                result
            }
            SignalKind::Heartbeat => {
                session_manager
                    .notify(&envelope.session_id, "call_heartbeat")
                    .await
            }
            SignalKind::Error => {
                signal_hub.push_remote(&envelope).await?;
                session_manager.end_session(&envelope.session_id).await
            }
            SignalKind::GroupControl => unreachable!("handled before call signal dispatch"),
        }
    }

    async fn process_group_control(
        &self,
        envelope: SignalingEnvelope,
        group_sessions: Arc<GroupSessionManager>,
        local_device_id: String,
    ) -> CallResult<()> {
        let message: GroupWireMessage = serde_json::from_value(envelope.payload)
            .map_err(|_| CallError::SerializationError("Invalid group control payload".into()))?;
        match message {
            GroupWireMessage::Invite { session } => {
                if session.host_device_id != envelope.sender_device_id
                    || session.group_id != envelope.session_id
                {
                    return Err(CallError::UnauthorizedDevice {
                        reason: "Group invitation host mismatch".into(),
                    });
                }
                group_sessions
                    .register_invite(session, &local_device_id)
                    .await
                    .map(|_| ())
            }
            GroupWireMessage::Join {
                group_id,
                device_id,
            } => {
                if device_id != envelope.sender_device_id || group_id != envelope.session_id {
                    return Err(CallError::UnauthorizedDevice {
                        reason: "Group join sender mismatch".into(),
                    });
                }
                let snapshot = group_sessions.join(&group_id, &device_id).await?;
                self.broadcast_group_snapshot(&snapshot, &local_device_id)
                    .await
            }
            GroupWireMessage::Decline {
                group_id,
                device_id,
            } => {
                if device_id != envelope.sender_device_id || group_id != envelope.session_id {
                    return Err(CallError::UnauthorizedDevice {
                        reason: "Group decline sender mismatch".into(),
                    });
                }
                let snapshot = group_sessions.decline(&group_id, &device_id).await?;
                self.broadcast_group_snapshot(&snapshot, &local_device_id)
                    .await
            }
            GroupWireMessage::Leave {
                group_id,
                device_id,
            } => {
                if device_id != envelope.sender_device_id || group_id != envelope.session_id {
                    return Err(CallError::UnauthorizedDevice {
                        reason: "Group leave sender mismatch".into(),
                    });
                }
                let snapshot = group_sessions.leave(&group_id, &device_id).await?;
                self.broadcast_group_snapshot(&snapshot, &local_device_id)
                    .await
            }
            GroupWireMessage::Heartbeat {
                group_id,
                device_id,
            } => {
                if device_id != envelope.sender_device_id || group_id != envelope.session_id {
                    return Err(CallError::UnauthorizedDevice {
                        reason: "Group heartbeat sender mismatch".into(),
                    });
                }
                let snapshot = group_sessions.heartbeat(&group_id, &device_id).await?;
                self.broadcast_group_snapshot(&snapshot, &local_device_id)
                    .await
            }
            GroupWireMessage::Snapshot { session } => {
                if session.host_device_id != envelope.sender_device_id
                    || session.group_id != envelope.session_id
                {
                    return Err(CallError::UnauthorizedDevice {
                        reason: "Group snapshot host mismatch".into(),
                    });
                }
                group_sessions
                    .apply_snapshot(session, &local_device_id)
                    .await
                    .map(|_| ())
            }
        }
    }

    pub async fn send_group_control(
        &self,
        message: &GroupWireMessage,
        group_id: &str,
        sender_device_id: &str,
        sender_virtual_id: &str,
        receiver_nebula_ip: &str,
    ) -> CallResult<()> {
        let sequence = self.outbound_sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let envelope = SignalingEnvelope::new(
            SignalKind::GroupControl,
            group_id,
            sender_device_id,
            sender_virtual_id,
            sequence,
            uuid::Uuid::new_v4().to_string(),
            serde_json::to_value(message)
                .map_err(|e| CallError::SerializationError(e.to_string()))?,
        );
        self.send_envelope(&envelope, receiver_nebula_ip).await
    }

    pub async fn broadcast_group_snapshot(
        &self,
        session: &crate::call::GroupSession,
        local_device_id: &str,
    ) -> CallResult<()> {
        let host = session
            .participants
            .get(&session.host_device_id)
            .ok_or_else(|| CallError::InvalidOffer {
                reason: "Group host participant is missing".into(),
            })?;
        let message = GroupWireMessage::Snapshot {
            session: session.clone(),
        };
        let mut first_error = None;
        for participant in session.participants.values() {
            if participant.device_id == local_device_id
                || matches!(
                    participant.state,
                    GroupMemberState::Declined | GroupMemberState::Left
                )
            {
                continue;
            }
            if let Err(error) = self
                .send_group_control(
                    &message,
                    &session.group_id,
                    &session.host_device_id,
                    &host.virtual_id,
                    &participant.nebula_ip,
                )
                .await
            {
                tracing::warn!(
                    group_id = %session.group_id,
                    participant = %participant.device_id,
                    %error,
                    "Failed to deliver group snapshot"
                );
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub async fn send_browser_signal(
        &self,
        kind: SignalKind,
        session_id: &str,
        sender_device_id: &str,
        sender_virtual_id: &str,
        payload: serde_json::Value,
        receiver_nebula_ip: &str,
    ) -> CallResult<()> {
        if !kind.is_browser_signal() && kind != SignalKind::Heartbeat && kind != SignalKind::Error {
            return Err(CallError::InvalidOffer {
                reason: "Unsupported browser signaling type".into(),
            });
        }
        let sequence = self.outbound_sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let envelope = SignalingEnvelope::new(
            kind,
            session_id,
            sender_device_id,
            sender_virtual_id,
            sequence,
            uuid::Uuid::new_v4().to_string(),
            payload,
        );
        self.send_envelope(&envelope, receiver_nebula_ip).await
    }

    /// Send call offer via Nebula overlay
    pub async fn send_offer(&self, offer: &CallOffer, receiver_nebula_ip: &str) -> CallResult<()> {
        if self.signer.is_some() {
            let envelope = SignalingEnvelope::new(
                SignalKind::Offer,
                &offer.session_id,
                &offer.device_id,
                &offer.virtual_id,
                1,
                uuid::Uuid::new_v4().to_string(),
                serde_json::to_value(offer).map_err(|e| {
                    CallError::SerializationError(format!("Failed to encode offer: {}", e))
                })?,
            );
            return self.send_envelope(&envelope, receiver_nebula_ip).await;
        }
        let payload = json!({
            "type": "call_offer",
            "device_id": offer.device_id,
            "virtual_id": offer.virtual_id,
            "session_id": offer.session_id,
            "timestamp": offer.timestamp.to_rfc3339(),
            "nonce": offer.nonce,
            "requested_media": offer.requested_media,
            "signature": offer.signature,
        });

        self.nebula_client
            .send_message(receiver_nebula_ip, &payload.to_string())
            .await
            .map_err(|e| CallError::NebulaError {
                reason: format!("Failed to send offer: {}", e),
            })
    }

    /// Send call answer via Nebula overlay
    pub async fn send_answer(
        &self,
        answer: &CallAnswer,
        receiver_nebula_ip: &str,
    ) -> CallResult<()> {
        if self.signer.is_some() {
            let envelope = SignalingEnvelope::new(
                SignalKind::Answer,
                &answer.session_id,
                &answer.device_id,
                &answer.virtual_id,
                1,
                uuid::Uuid::new_v4().to_string(),
                serde_json::to_value(answer).map_err(|e| {
                    CallError::SerializationError(format!("Failed to encode answer: {}", e))
                })?,
            );
            return self.send_envelope(&envelope, receiver_nebula_ip).await;
        }
        let payload = json!({
            "type": "call_answer",
            "device_id": answer.device_id,
            "virtual_id": answer.virtual_id,
            "session_id": answer.session_id,
            "timestamp": answer.timestamp.to_rfc3339(),
            "nonce": answer.nonce,
            "accepted_media": answer.accepted_media,
            "accepted": answer.accepted,
            "rejection_reason": answer.rejection_reason,
            "signature": answer.signature,
        });

        self.nebula_client
            .send_message(receiver_nebula_ip, &payload.to_string())
            .await
            .map_err(|e| CallError::NebulaError {
                reason: format!("Failed to send answer: {}", e),
            })
    }

    async fn send_envelope(
        &self,
        envelope: &SignalingEnvelope,
        receiver_nebula_ip: &str,
    ) -> CallResult<()> {
        let payload = serde_json::to_string(envelope)
            .map_err(|e| CallError::SerializationError(e.to_string()))?;
        self.nebula_client
            .send_message(receiver_nebula_ip, &payload)
            .await
            .map_err(|e| CallError::NebulaError {
                reason: format!("Failed to send secure call message: {}", e),
            })
    }

    /// Receive call messages from Nebula (listener pattern)
    /// This would be integrated with Nebula's message handler
    pub async fn handle_message(&self, message: &str) -> CallResult<SignalingMessage> {
        let json: serde_json::Value = serde_json::from_str(message)
            .map_err(|_| CallError::SerializationError("Invalid message format".to_string()))?;

        let msg_type = json
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CallError::SerializationError("Missing message type".to_string()))?;

        if json.get("version").is_some() {
            let envelope: SignalingEnvelope = serde_json::from_value(json).map_err(|_| {
                CallError::SerializationError("Invalid versioned call envelope".into())
            })?;
            return Ok(SignalingMessage::Envelope(envelope));
        }

        match msg_type {
            "call_offer" => {
                let offer_json = serde_json::to_string(&json).map_err(|_| {
                    CallError::SerializationError("Failed to serialize offer".to_string())
                })?;
                let offer = CallOffer::from_json(&offer_json)?;
                Ok(SignalingMessage::Offer(offer))
            }
            "call_answer" => {
                let answer_json = serde_json::to_string(&json).map_err(|_| {
                    CallError::SerializationError("Failed to serialize answer".to_string())
                })?;
                let answer = CallAnswer::from_json(&answer_json)?;
                Ok(SignalingMessage::Answer(answer))
            }
            _ => Err(CallError::SerializationError(format!(
                "Unknown message type: {}",
                msg_type
            ))),
        }
    }

    /// Get local Nebula IP address
    pub async fn get_local_nebula_ip(&self) -> CallResult<String> {
        self.nebula_client
            .get_local_ip()
            .await
            .map_err(|e| CallError::NebulaError {
                reason: format!("Failed to get local IP: {}", e),
            })
    }

    /// Verify remote device is reachable via Nebula
    pub async fn verify_peer_reachable(&self, nebula_ip: &str) -> CallResult<bool> {
        self.nebula_client
            .is_peer_reachable(nebula_ip)
            .await
            .map_err(|e| CallError::NebulaError {
                reason: format!("Failed to verify peer: {}", e),
            })
    }
}

fn is_nebula_overlay_peer(ip: std::net::IpAddr) -> bool {
    matches!(ip, std::net::IpAddr::V4(ip) if ip.octets()[0..3] == [192, 168, 100])
}

/// Parsed signaling message from Nebula
#[derive(Debug, Clone)]
pub enum SignalingMessage {
    Envelope(SignalingEnvelope),
    Offer(CallOffer),
    Answer(CallAnswer),
}

impl SignalingMessage {
    pub fn session_id(&self) -> &str {
        match self {
            SignalingMessage::Envelope(envelope) => &envelope.session_id,
            SignalingMessage::Offer(offer) => &offer.session_id,
            SignalingMessage::Answer(answer) => &answer.session_id,
        }
    }

    pub fn device_id(&self) -> &str {
        match self {
            SignalingMessage::Envelope(envelope) => &envelope.sender_device_id,
            SignalingMessage::Offer(offer) => &offer.device_id,
            SignalingMessage::Answer(answer) => &answer.device_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::identity::TrustedPeerIdentity;
    use crate::call::signaling::MediaType;
    use async_trait::async_trait;
    use chrono::Utc;
    use tempfile::tempdir;

    struct StaticIdentity(TrustedPeerIdentity);

    #[async_trait]
    impl PeerIdentityResolver for StaticIdentity {
        async fn resolve(&self, device_id: &str, _peer_ip: &str) -> CallResult<TrustedPeerIdentity> {
            if self.0.device_id == device_id {
                Ok(self.0.clone())
            } else {
                Err(CallError::UnauthorizedDevice {
                    reason: "unknown peer".into(),
                })
            }
        }
    }

    #[test]
    fn test_signaling_message_offer() {
        let offer = CallOffer {
            device_id: "device-1".to_string(),
            virtual_id: "virtual-1".to_string(),
            session_id: "session-123".to_string(),
            timestamp: Utc::now(),
            nonce: "nonce-abc".to_string(),
            requested_media: vec![MediaType::Audio],
            signature: "sig-xyz".to_string(),
        };

        let msg = SignalingMessage::Offer(offer);
        assert_eq!(msg.session_id(), "session-123");
        assert_eq!(msg.device_id(), "device-1");
    }

    #[test]
    fn test_signaling_message_answer() {
        let answer = CallAnswer {
            device_id: "device-2".to_string(),
            virtual_id: "virtual-1".to_string(),
            session_id: "session-123".to_string(),
            timestamp: Utc::now(),
            nonce: "nonce-abc".to_string(),
            accepted_media: vec![MediaType::Audio],
            accepted: true,
            rejection_reason: None,
            signature: "sig-xyz".to_string(),
        };

        let msg = SignalingMessage::Answer(answer);
        assert_eq!(msg.session_id(), "session-123");
        assert_eq!(msg.device_id(), "device-2");
    }

    #[tokio::test]
    async fn secure_envelope_verifies_before_registering_offer() {
        let caller_dir = tempdir().unwrap();
        let receiver_dir = tempdir().unwrap();
        let caller = Arc::new(
            KeyManager::load_or_generate(caller_dir.path().join("caller.pk8").to_str().unwrap())
                .unwrap(),
        );
        let receiver = Arc::new(
            KeyManager::load_or_generate(
                receiver_dir.path().join("receiver.pk8").to_str().unwrap(),
            )
            .unwrap(),
        );
        let identity = Arc::new(StaticIdentity(TrustedPeerIdentity {
            device_id: "device-a".into(),
            did: "did:guardian:test-a".into(),
            public_key_point: caller.pubkey_der().unwrap(),
        }));
        let signaling = NebulaSignaling::new_secure(Arc::new(NebulaClient), receiver, identity);
        let offer = CallOffer::new(
            "device-a".into(),
            "virtual-a".into(),
            "session-secure".into(),
            "session-nonce".into(),
            vec![MediaType::Audio],
            &caller,
        )
        .await
        .unwrap();
        let envelope = SignalingEnvelope::new(
            SignalKind::Offer,
            &offer.session_id,
            &offer.device_id,
            &offer.virtual_id,
            1,
            "message-nonce",
            serde_json::to_value(&offer).unwrap(),
        )
        .sign(&caller)
        .unwrap();
        let sessions = Arc::new(crate::call::session::SessionManager::new());
        let signal_hub = Arc::new(crate::call::CallSignalHub::default());

        signaling
            .process_envelope(
                envelope.clone(),
                "192.168.100.10".into(),
                sessions.clone(),
                signal_hub.clone(),
                Arc::new(GroupSessionManager::new(
                    receiver_dir.path().join("group.log"),
                )),
                "device-b".into(),
            )
            .await
            .unwrap();
        assert_eq!(
            sessions.get_session("session-secure").await.unwrap().state,
            crate::call::state::CallState::OfferReceived
        );
        assert!(signaling
            .process_envelope(
                envelope,
                "192.168.100.10".into(),
                sessions,
                signal_hub,
                Arc::new(GroupSessionManager::new(
                    receiver_dir.path().join("group-replay.log"),
                )),
                "device-b".into(),
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn trusted_group_invite_and_media_signal_reach_receiver_queue() {
        let dir = tempdir().unwrap();
        let caller = Arc::new(
            KeyManager::load_or_generate(dir.path().join("caller.pk8").to_str().unwrap()).unwrap(),
        );
        let receiver = Arc::new(
            KeyManager::load_or_generate(dir.path().join("receiver.pk8").to_str().unwrap())
                .unwrap(),
        );
        let identity = Arc::new(StaticIdentity(TrustedPeerIdentity {
            device_id: "nodeA".into(),
            did: "did:guardian:node-a".into(),
            public_key_point: caller.pubkey_der().unwrap(),
        }));
        let signaling = NebulaSignaling::new_secure(Arc::new(NebulaClient), receiver, identity);
        let host_groups = GroupSessionManager::new(dir.path().join("host-group.log"));
        let group = host_groups
            .create(
                "Media room".into(),
                crate::call::GroupParticipant {
                    device_id: "nodeA".into(),
                    virtual_id: "vid-a".into(),
                    nebula_ip: "192.168.100.1".into(),
                    role: crate::call::GroupRole::Host,
                    state: GroupMemberState::Joined,
                    audio_allowed: true,
                    video_allowed: true,
                    media_ready: false,
                    joined_at: None,
                    last_seen_at: None,
                },
                vec![crate::call::GroupParticipant {
                    device_id: "nodeB".into(),
                    virtual_id: "vid-b".into(),
                    nebula_ip: "192.168.100.2".into(),
                    role: crate::call::GroupRole::Member,
                    state: GroupMemberState::Invited,
                    audio_allowed: true,
                    video_allowed: true,
                    media_ready: false,
                    joined_at: None,
                    last_seen_at: None,
                }],
                vec![MediaType::Audio, MediaType::Video],
            )
            .await
            .unwrap();
        let receiver_groups = Arc::new(GroupSessionManager::new(dir.path().join("node-b.log")));
        let sessions = Arc::new(crate::call::SessionManager::new());
        let signals = Arc::new(crate::call::CallSignalHub::default());
        let invite = SignalingEnvelope::new(
            SignalKind::GroupControl,
            &group.group_id,
            "nodeA",
            "vid-a",
            1,
            "group-invite",
            serde_json::to_value(GroupWireMessage::Invite {
                session: group.clone(),
            })
            .unwrap(),
        );
        signaling
            .process_envelope(
                invite,
                "192.168.100.1".into(),
                sessions.clone(),
                signals.clone(),
                receiver_groups.clone(),
                "nodeB".into(),
            )
            .await
            .unwrap();
        receiver_groups
            .join(&group.group_id, "nodeB")
            .await
            .unwrap();

        let sdp = SignalingEnvelope::new(
            SignalKind::SdpOffer,
            &group.group_id,
            "nodeA",
            "vid-a",
            2,
            "group-sdp",
            serde_json::json!({"type":"offer","sdp":"v=0\r\nm=audio\r\nm=video"}),
        );
        signaling
            .process_envelope(
                sdp,
                "192.168.100.1".into(),
                sessions,
                signals.clone(),
                receiver_groups,
                "nodeB".into(),
            )
            .await
            .unwrap();
        let queued = signals.list_after(&group.group_id, 0).await;
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].sender_device_id, "nodeA");
        assert_eq!(queued[0].kind, SignalKind::SdpOffer);
    }
}
