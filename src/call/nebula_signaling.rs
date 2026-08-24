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
        // No `nebula0` TUN interface exists in a CI/sandbox test run (no
        // hardware overlay network) — same class of gap as SE050 hardware
        // signing, and given the same opt-in, off-by-default escape hatch
        // (`SGX_FORCE_SOFTWARE_KEYS`'s sibling for the network layer).
        if let Ok(value) = std::env::var("SGX_NEBULA_LOCAL_IP_OVERRIDE") {
            let value = value.trim();
            if !value.is_empty() {
                return Ok(value.to_string());
            }
        }
        NebulaInterface::get_overlay_ip()
            .and_then(|cidr| cidr.split('/').next().map(str::to_owned))
            .ok_or_else(|| "Guardian Mesh overlay interface unavailable".to_string())
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

    /// Sign an outbound envelope with this node's device key. Every envelope
    /// that leaves over Nebula must carry a real signature: `process_envelope`
    /// verifies it against the sender's trusted public key on receipt.
    fn sign_envelope(&self, envelope: SignalingEnvelope) -> CallResult<SignalingEnvelope> {
        let signer = self.signer.as_ref().ok_or_else(|| {
            CallError::KeyManagerError("No signer configured for secure call signaling".into())
        })?;
        envelope.sign(signer)
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

        tracing::info!(%bind_addr, "Guardian Mesh call signaling listener started");
        loop {
            let (stream, peer) = listener
                .accept()
                .await
                .map_err(|e| CallError::NebulaError {
                    reason: format!("Failed to accept signaling connection: {}", e),
                })?;

            if !is_nebula_overlay_peer(peer.ip()) {
                tracing::warn!(peer = %peer, "Rejected call signaling connection outside the Guardian Mesh overlay");
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
                        "❌ Rejected Guardian Mesh call signaling message from {}: {}",
                        peer, error
                    );
                    tracing::warn!(peer = %peer, %error, "Rejected Guardian Mesh call signaling message");
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
        let identity = self
            .peer_identities
            .resolve(&envelope.sender_device_id, &peer_ip)
            .await?;
        // peer_ip + trusted-peer lookup establishes WHO the sender claims to
        // be; the signature proves the message actually came from them and
        // was not forged/altered by anything else reachable on the overlay.
        envelope.verify(&identity.public_key_point)?;
        // Attestation and Nebula authenticate this peer before call traffic.
        // Avoid reopening SE050 for each call-control message.
        self.replay.check_and_record(&envelope).await?;

        if envelope.kind == SignalKind::GroupControl {
            return self
                .process_group_control(envelope, peer_ip, group_sessions, local_device_id)
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
                // The envelope signature already authenticates the transport
                // message; this additionally binds the offer's own content to
                // the sender's key, independent of how it was carried.
                offer.verify_signature(&identity.public_key_point)?;
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
                // The envelope signature already authenticates the transport
                // message; this additionally binds the answer's own content to
                // the sender's key, independent of how it was carried.
                answer.verify_signature(&identity.public_key_point)?;
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
                        .mark_media_ready(
                            &envelope.session_id,
                            &envelope.sender_device_id,
                            true,
                            &peer_ip,
                        )
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
        peer_ip: String,
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
                // We're the invitee here, reconciling our OWN participant
                // entry, so the anchor is our own Nebula IP, not the sender's.
                let local_nebula_ip = self.get_local_nebula_ip().await.unwrap_or_default();
                group_sessions
                    .register_invite(session, &local_device_id, &local_nebula_ip)
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
                // We're the host here, reconciling the SENDER's participant
                // entry, so the anchor is the IP this message actually
                // arrived from — the sender's real, unspoofable Nebula IP.
                let snapshot = group_sessions.join(&group_id, &device_id, &peer_ip).await?;
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
                let snapshot = group_sessions
                    .decline(&group_id, &device_id, &peer_ip)
                    .await?;
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
                let snapshot = group_sessions
                    .leave(&group_id, &device_id, &peer_ip)
                    .await?;
                self.broadcast_group_snapshot(&snapshot, &local_device_id)
                    .await
            }
            GroupWireMessage::End {
                group_id,
                device_id,
            } => {
                if device_id != envelope.sender_device_id || group_id != envelope.session_id {
                    return Err(CallError::UnauthorizedDevice {
                        reason: "Group end sender mismatch".into(),
                    });
                }
                let snapshot = group_sessions.end(&group_id, &device_id).await?;
                let result = self
                    .broadcast_group_snapshot(&snapshot, &local_device_id)
                    .await;
                group_sessions.remove_ended(&group_id).await;
                result
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
                let snapshot = group_sessions
                    .heartbeat(&group_id, &device_id, &peer_ip)
                    .await?;
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
                // We're a participant receiving the host's view here,
                // reconciling our OWN entry against our own Nebula IP.
                let local_nebula_ip = self.get_local_nebula_ip().await.unwrap_or_default();
                group_sessions
                    .apply_snapshot(session, &local_device_id, &local_nebula_ip)
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
        let envelope = self.sign_envelope(SignalingEnvelope::new(
            SignalKind::GroupControl,
            group_id,
            sender_device_id,
            sender_virtual_id,
            sequence,
            uuid::Uuid::new_v4().to_string(),
            serde_json::to_value(message)
                .map_err(|e| CallError::SerializationError(e.to_string()))?,
        ))?;
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
                || participant.is_local_browser
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
        let envelope = self.sign_envelope(SignalingEnvelope::new(
            kind,
            session_id,
            sender_device_id,
            sender_virtual_id,
            sequence,
            uuid::Uuid::new_v4().to_string(),
            payload,
        ))?;
        self.send_envelope(&envelope, receiver_nebula_ip).await
    }

    /// Send call offer via Nebula overlay
    pub async fn send_offer(&self, offer: &CallOffer, receiver_nebula_ip: &str) -> CallResult<()> {
        if self.signer.is_some() {
            let envelope = self.sign_envelope(SignalingEnvelope::new(
                SignalKind::Offer,
                &offer.session_id,
                &offer.device_id,
                &offer.virtual_id,
                1,
                uuid::Uuid::new_v4().to_string(),
                serde_json::to_value(offer).map_err(|e| {
                    CallError::SerializationError(format!("Failed to encode offer: {}", e))
                })?,
            ))?;
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
            let envelope = self.sign_envelope(SignalingEnvelope::new(
                SignalKind::Answer,
                &answer.session_id,
                &answer.device_id,
                &answer.virtual_id,
                1,
                uuid::Uuid::new_v4().to_string(),
                serde_json::to_value(answer).map_err(|e| {
                    CallError::SerializationError(format!("Failed to encode answer: {}", e))
                })?,
            ))?;
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
    use crate::call::{
        CallSignalHub, CallState, GroupCallState, GroupParticipant, GroupRole, GroupSession,
        SessionManager,
    };
    use async_trait::async_trait;
    use chrono::Utc;
    use std::collections::HashMap;
    use tempfile::tempdir;

    struct StaticIdentity(TrustedPeerIdentity);

    #[async_trait]
    impl PeerIdentityResolver for StaticIdentity {
        async fn resolve(
            &self,
            device_id: &str,
            _peer_ip: &str,
        ) -> CallResult<TrustedPeerIdentity> {
            if self.0.device_id == device_id {
                Ok(self.0.clone())
            } else {
                Err(CallError::UnauthorizedDevice {
                    reason: "unknown peer".into(),
                })
            }
        }
    }

    fn participant(
        device_id: &str,
        nebula_ip: &str,
        role: GroupRole,
        state: GroupMemberState,
    ) -> GroupParticipant {
        GroupParticipant {
            device_id: device_id.into(),
            virtual_id: format!("vid-{device_id}"),
            nebula_ip: nebula_ip.into(),
            role,
            state,
            audio_allowed: true,
            video_allowed: true,
            media_ready: false,
            joined_at: None,
            last_seen_at: None,
            is_local_browser: false,
        }
    }

    fn group_session(group_id: &str) -> GroupSession {
        let now = Utc::now();
        let mut participants = HashMap::new();
        participants.insert(
            "host".into(),
            participant(
                "host",
                "127.0.0.1",
                GroupRole::Host,
                GroupMemberState::Joined,
            ),
        );
        participants.insert(
            "member".into(),
            participant(
                "member",
                "127.0.0.1",
                GroupRole::Member,
                GroupMemberState::Joined,
            ),
        );
        GroupSession {
            group_id: group_id.into(),
            title: "Coverage room".into(),
            host_device_id: "host".into(),
            requested_media: vec![MediaType::Audio],
            state: GroupCallState::Active,
            participants,
            created_at: now,
            updated_at: now,
            ended_at: None,
        }
    }

    fn envelope(
        signer: &KeyManager,
        kind: SignalKind,
        session_id: &str,
        sender_device_id: &str,
        sequence: u64,
        nonce: &str,
        payload: serde_json::Value,
    ) -> SignalingEnvelope {
        SignalingEnvelope::new(
            kind,
            session_id,
            sender_device_id,
            format!("vid-{sender_device_id}"),
            sequence,
            nonce,
            payload,
        )
        .sign(signer)
        .unwrap()
    }

    fn secure_signaling(
        signer: Arc<KeyManager>,
        trusted_device_id: &str,
        trusted_key: &KeyManager,
    ) -> NebulaSignaling {
        NebulaSignaling::new_secure(
            Arc::new(NebulaClient),
            signer,
            Arc::new(StaticIdentity(TrustedPeerIdentity {
                device_id: trusted_device_id.into(),
                did: format!("did:guardian:{trusted_device_id}"),
                public_key_point: trusted_key.pubkey_der().unwrap(),
            })),
        )
    }

    async fn stream_containing(payload: &[u8]) -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut writer = TcpStream::connect(address).await.unwrap();
        let (reader, _) = listener.accept().await.unwrap();
        writer.write_all(payload).await.unwrap();
        writer.shutdown().await.unwrap();
        reader
    }

    async fn outgoing_session(manager: &SessionManager, nonce: &str, peer_ip: &str) -> String {
        let session_id = manager
            .create_session(
                "local".into(),
                "vid-local".into(),
                "peer-placeholder".into(),
                String::new(),
                vec![MediaType::Audio],
                nonce.into(),
            )
            .await
            .unwrap();
        manager
            .set_nebula_endpoints(&session_id, None, Some(peer_ip.into()))
            .await
            .unwrap();
        for state in [CallState::LocalPolicyCheck, CallState::OfferSent] {
            manager
                .update_session_state(&session_id, state, format!("advance to {state}"))
                .await
                .unwrap();
        }
        session_id
    }

    fn group_control_envelope(
        message: GroupWireMessage,
        group_id: &str,
        sender_device_id: &str,
    ) -> SignalingEnvelope {
        SignalingEnvelope::new(
            SignalKind::GroupControl,
            group_id,
            sender_device_id,
            format!("vid-{sender_device_id}"),
            1,
            format!("{group_id}-{sender_device_id}"),
            serde_json::to_value(message).unwrap(),
        )
    }

    async fn local_group(manager: &GroupSessionManager, title: &str) -> GroupSession {
        let mut member = participant(
            "member",
            "192.168.100.2",
            GroupRole::Member,
            GroupMemberState::Invited,
        );
        member.is_local_browser = true;
        manager
            .create(
                title.into(),
                participant(
                    "host",
                    "192.168.100.1",
                    GroupRole::Host,
                    GroupMemberState::Joined,
                ),
                vec![member],
                vec![MediaType::Audio],
            )
            .await
            .unwrap()
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
    async fn message_parser_covers_envelopes_legacy_messages_and_rejections() {
        let signaling = NebulaSignaling::new(Arc::new(NebulaClient));
        assert!(signaling.handle_message("not json").await.is_err());
        assert!(signaling.handle_message(r#"{"value":1}"#).await.is_err());
        assert!(signaling
            .handle_message(r#"{"type":"unknown"}"#)
            .await
            .is_err());
        assert!(signaling
            .handle_message(r#"{"type":"offer","version":1}"#)
            .await
            .is_err());

        let versioned = SignalingEnvelope::new(
            SignalKind::Heartbeat,
            "envelope-session",
            "device-envelope",
            "vid-envelope",
            1,
            "envelope-nonce",
            serde_json::json!({"alive": true}),
        );
        let parsed = signaling
            .handle_message(&serde_json::to_string(&versioned).unwrap())
            .await
            .unwrap();
        assert!(matches!(parsed, SignalingMessage::Envelope(_)));
        assert_eq!(parsed.session_id(), "envelope-session");
        assert_eq!(parsed.device_id(), "device-envelope");

        let offer = CallOffer {
            device_id: "legacy-caller".into(),
            virtual_id: "legacy-caller-vid".into(),
            session_id: "legacy-offer".into(),
            timestamp: Utc::now(),
            nonce: "legacy-offer-nonce".into(),
            requested_media: vec![MediaType::Audio],
            signature: "present".into(),
        };
        let mut offer_json = serde_json::to_value(&offer).unwrap();
        offer_json["type"] = serde_json::json!("call_offer");
        let parsed = signaling
            .handle_message(&offer_json.to_string())
            .await
            .unwrap();
        assert!(matches!(parsed, SignalingMessage::Offer(_)));

        let answer = CallAnswer {
            device_id: "legacy-receiver".into(),
            virtual_id: "legacy-receiver-vid".into(),
            session_id: "legacy-answer".into(),
            timestamp: Utc::now(),
            nonce: "legacy-answer-nonce".into(),
            accepted_media: vec![MediaType::Audio],
            accepted: true,
            rejection_reason: None,
            signature: "present".into(),
        };
        let mut answer_json = serde_json::to_value(&answer).unwrap();
        answer_json["type"] = serde_json::json!("call_answer");
        let parsed = signaling
            .handle_message(&answer_json.to_string())
            .await
            .unwrap();
        assert!(matches!(parsed, SignalingMessage::Answer(_)));
    }

    #[tokio::test]
    async fn connection_reader_accepts_probe_and_rejects_bad_frames() {
        let dir = tempdir().unwrap();
        let signaling = NebulaSignaling::new(Arc::new(NebulaClient));
        let sessions = Arc::new(SessionManager::new());
        let signals = Arc::new(CallSignalHub::default());
        let groups = Arc::new(GroupSessionManager::new(dir.path().join("frames.log")));

        signaling
            .receive_connection(
                stream_containing(&[]).await,
                "192.168.100.8".into(),
                sessions.clone(),
                signals.clone(),
                groups.clone(),
                "local".into(),
            )
            .await
            .unwrap();

        let invalid_utf8 = signaling
            .receive_connection(
                stream_containing(&[0xff, 0xfe]).await,
                "192.168.100.8".into(),
                sessions.clone(),
                signals.clone(),
                groups.clone(),
                "local".into(),
            )
            .await;
        assert!(matches!(
            invalid_utf8,
            Err(CallError::SerializationError(_))
        ));

        let oversized = vec![b'x'; MAX_SIGNALING_MESSAGE_BYTES + 1];
        let too_large = signaling
            .receive_connection(
                stream_containing(&oversized).await,
                "192.168.100.8".into(),
                sessions.clone(),
                signals.clone(),
                groups.clone(),
                "local".into(),
            )
            .await;
        assert!(matches!(too_large, Err(CallError::SerializationError(_))));

        let malformed = signaling
            .receive_connection(
                stream_containing(br#"{"type":"unknown"}"#).await,
                "192.168.100.8".into(),
                sessions,
                signals,
                groups,
                "local".into(),
            )
            .await;
        assert!(matches!(malformed, Err(CallError::SerializationError(_))));
    }

    #[tokio::test]
    async fn connection_reader_handles_legacy_offer_and_answer_lifecycle() {
        let dir = tempdir().unwrap();
        let signaling = NebulaSignaling::new(Arc::new(NebulaClient));
        let sessions = Arc::new(SessionManager::new());
        let signals = Arc::new(CallSignalHub::default());
        let groups = Arc::new(GroupSessionManager::new(dir.path().join("legacy.log")));
        let peer_ip = "192.168.100.40";

        let offer = CallOffer {
            device_id: "legacy-peer".into(),
            virtual_id: "legacy-peer-vid".into(),
            session_id: "legacy-incoming".into(),
            timestamp: Utc::now(),
            nonce: "legacy-incoming-nonce".into(),
            requested_media: vec![MediaType::Audio],
            signature: "legacy-signature".into(),
        };
        let mut offer_payload = serde_json::to_value(&offer).unwrap();
        offer_payload["type"] = serde_json::json!("call_offer");
        signaling
            .receive_connection(
                stream_containing(offer_payload.to_string().as_bytes()).await,
                peer_ip.into(),
                sessions.clone(),
                signals.clone(),
                groups.clone(),
                "local".into(),
            )
            .await
            .unwrap();
        assert_eq!(
            sessions.get_session("legacy-incoming").await.unwrap().state,
            CallState::OfferReceived
        );

        let outgoing_id = outgoing_session(&sessions, "legacy-answer-nonce", peer_ip).await;
        let answer = CallAnswer {
            device_id: "legacy-peer".into(),
            virtual_id: "legacy-peer-vid".into(),
            session_id: outgoing_id.clone(),
            timestamp: Utc::now(),
            nonce: "legacy-answer-nonce".into(),
            accepted_media: vec![MediaType::Audio],
            accepted: true,
            rejection_reason: None,
            signature: "legacy-signature".into(),
        };
        let mut answer_payload = serde_json::to_value(&answer).unwrap();
        answer_payload["type"] = serde_json::json!("call_answer");
        signaling
            .receive_connection(
                stream_containing(answer_payload.to_string().as_bytes()).await,
                peer_ip.into(),
                sessions.clone(),
                signals.clone(),
                groups.clone(),
                "local".into(),
            )
            .await
            .unwrap();
        assert_eq!(
            sessions.get_session(&outgoing_id).await.unwrap().state,
            CallState::Accepted
        );

        let rejected_id = outgoing_session(&sessions, "legacy-reject-nonce", peer_ip).await;
        let rejected = CallAnswer {
            session_id: rejected_id.clone(),
            nonce: "legacy-reject-nonce".into(),
            accepted_media: vec![],
            accepted: false,
            rejection_reason: Some("declined".into()),
            ..answer
        };
        let mut rejected_payload = serde_json::to_value(&rejected).unwrap();
        rejected_payload["type"] = serde_json::json!("call_answer");
        signaling
            .receive_connection(
                stream_containing(rejected_payload.to_string().as_bytes()).await,
                peer_ip.into(),
                sessions.clone(),
                signals.clone(),
                groups.clone(),
                "local".into(),
            )
            .await
            .unwrap();
        assert_eq!(
            sessions.get_session(&rejected_id).await.unwrap().state,
            CallState::EndCall
        );

        let mut unsigned_offer = offer.clone();
        unsigned_offer.session_id = "unsigned-offer".into();
        unsigned_offer.signature.clear();
        let mut unsigned_payload = serde_json::to_value(unsigned_offer).unwrap();
        unsigned_payload["type"] = serde_json::json!("call_offer");
        assert!(matches!(
            signaling
                .receive_connection(
                    stream_containing(unsigned_payload.to_string().as_bytes()).await,
                    peer_ip.into(),
                    sessions.clone(),
                    signals.clone(),
                    groups.clone(),
                    "local".into(),
                )
                .await,
            Err(CallError::SignatureVerificationFailed)
        ));

        let mut stale_offer = offer;
        stale_offer.session_id = "stale-offer".into();
        stale_offer.timestamp = Utc::now() - chrono::Duration::seconds(MAX_OFFER_AGE_SECS + 1);
        let mut stale_payload = serde_json::to_value(stale_offer).unwrap();
        stale_payload["type"] = serde_json::json!("call_offer");
        assert!(matches!(
            signaling
                .receive_connection(
                    stream_containing(stale_payload.to_string().as_bytes()).await,
                    peer_ip.into(),
                    sessions,
                    signals,
                    groups,
                    "local".into(),
                )
                .await,
            Err(CallError::InvalidOffer { .. })
        ));
    }

    #[tokio::test]
    async fn outbound_secure_messages_use_the_tcp_transport() {
        let _env_guard = crate::test_utils::TEST_ENV_LOCK.lock().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let previous_port = std::env::var("SGX_CALL_SIGNALING_PORT").ok();
        std::env::set_var("SGX_CALL_SIGNALING_PORT", port.to_string());

        let receiver = tokio::spawn(async move {
            let mut messages = Vec::new();
            for _ in 0..5 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut payload = String::new();
                stream.read_to_string(&mut payload).await.unwrap();
                messages.push(payload);
            }
            messages
        });

        let dir = tempdir().unwrap();
        let sender = Arc::new(
            KeyManager::load_or_generate(dir.path().join("sender.pk8").to_str().unwrap()).unwrap(),
        );
        let signaling = secure_signaling(sender.clone(), "sender", &sender);
        let offer = CallOffer::new(
            "sender".into(),
            "vid-sender".into(),
            "outbound-offer".into(),
            "offer-nonce".into(),
            vec![MediaType::Audio],
            &sender,
        )
        .await
        .unwrap();
        signaling.send_offer(&offer, "127.0.0.1").await.unwrap();

        let answer = CallAnswer::accept(
            "sender".into(),
            "vid-sender".into(),
            "outbound-answer".into(),
            "answer-nonce".into(),
            vec![MediaType::Audio],
            &sender,
        )
        .await
        .unwrap();
        signaling.send_answer(&answer, "127.0.0.1").await.unwrap();
        signaling
            .send_browser_signal(
                SignalKind::IceCandidate,
                "browser-session",
                "sender",
                "vid-sender",
                serde_json::json!({"candidate":"candidate:1"}),
                "127.0.0.1",
            )
            .await
            .unwrap();
        signaling
            .send_group_control(
                &GroupWireMessage::Heartbeat {
                    group_id: "outbound-group".into(),
                    device_id: "sender".into(),
                },
                "outbound-group",
                "sender",
                "vid-sender",
                "127.0.0.1",
            )
            .await
            .unwrap();

        let mut group = group_session("broadcast-group");
        group.participants.insert(
            "declined".into(),
            participant(
                "declined",
                "127.0.0.1",
                GroupRole::Member,
                GroupMemberState::Declined,
            ),
        );
        let mut local_browser =
            participant("browser", "", GroupRole::Member, GroupMemberState::Joined);
        local_browser.is_local_browser = true;
        group.participants.insert("browser".into(), local_browser);
        signaling
            .broadcast_group_snapshot(&group, "host")
            .await
            .unwrap();

        let messages = receiver.await.unwrap();
        match previous_port {
            Some(value) => std::env::set_var("SGX_CALL_SIGNALING_PORT", value),
            None => std::env::remove_var("SGX_CALL_SIGNALING_PORT"),
        }
        assert_eq!(messages.len(), 5);
        assert!(messages
            .iter()
            .all(|message| message.contains("\"version\":1")));

        assert!(signaling
            .send_browser_signal(
                SignalKind::Offer,
                "bad-kind",
                "sender",
                "vid-sender",
                serde_json::json!({}),
                "127.0.0.1",
            )
            .await
            .is_err());
        let insecure = NebulaSignaling::new(Arc::new(NebulaClient));
        assert!(insecure
            .send_browser_signal(
                SignalKind::Heartbeat,
                "unsigned",
                "sender",
                "vid-sender",
                serde_json::json!({}),
                "127.0.0.1",
            )
            .await
            .is_err());
        let mut missing_host = group;
        missing_host.participants.remove("host");
        assert!(signaling
            .broadcast_group_snapshot(&missing_host, "host")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn overlay_configuration_and_listener_bind_fail_closed() {
        let _env_guard = crate::test_utils::TEST_ENV_LOCK.lock().await;
        let previous_ip = std::env::var("SGX_NEBULA_LOCAL_IP_OVERRIDE").ok();
        let previous_port = std::env::var("SGX_CALL_SIGNALING_PORT").ok();
        std::env::set_var("SGX_NEBULA_LOCAL_IP_OVERRIDE", " 127.0.0.1 ");

        std::env::set_var("SGX_CALL_SIGNALING_PORT", "invalid");
        assert_eq!(signaling_port(), 50065);
        std::env::set_var("SGX_CALL_SIGNALING_PORT", "0");
        assert_eq!(signaling_port(), 50065);

        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let occupied_port = occupied.local_addr().unwrap().port();
        std::env::set_var("SGX_CALL_SIGNALING_PORT", occupied_port.to_string());
        assert_eq!(signaling_port(), occupied_port);

        let signaling = Arc::new(NebulaSignaling::new(Arc::new(NebulaClient)));
        assert_eq!(signaling.get_local_nebula_ip().await.unwrap(), "127.0.0.1");
        let result = signaling
            .run_listener(
                Arc::new(SessionManager::new()),
                Arc::new(CallSignalHub::default()),
                Arc::new(GroupSessionManager::new(
                    tempdir().unwrap().path().join("listener.log"),
                )),
                "local".into(),
            )
            .await;
        assert!(matches!(result, Err(CallError::NebulaError { .. })));

        assert!(is_nebula_overlay_peer("192.168.100.7".parse().unwrap()));
        assert!(!is_nebula_overlay_peer("192.168.101.7".parse().unwrap()));
        assert!(!is_nebula_overlay_peer("::1".parse().unwrap()));

        match previous_ip {
            Some(value) => std::env::set_var("SGX_NEBULA_LOCAL_IP_OVERRIDE", value),
            None => std::env::remove_var("SGX_NEBULA_LOCAL_IP_OVERRIDE"),
        }
        match previous_port {
            Some(value) => std::env::set_var("SGX_CALL_SIGNALING_PORT", value),
            None => std::env::remove_var("SGX_CALL_SIGNALING_PORT"),
        }
    }

    #[tokio::test]
    async fn authenticated_answers_accept_reject_and_validate_session_binding() {
        let dir = tempdir().unwrap();
        let peer = Arc::new(
            KeyManager::load_or_generate(dir.path().join("peer.pk8").to_str().unwrap()).unwrap(),
        );
        let local = Arc::new(
            KeyManager::load_or_generate(dir.path().join("local.pk8").to_str().unwrap()).unwrap(),
        );
        let signaling = secure_signaling(local, "peer", &peer);
        let groups = Arc::new(GroupSessionManager::new(dir.path().join("answers.log")));
        let signals = Arc::new(CallSignalHub::default());
        let peer_ip = "192.168.100.20";

        let accepted_sessions = Arc::new(SessionManager::new());
        let accepted_id = outgoing_session(&accepted_sessions, "accept-nonce", peer_ip).await;
        let accepted = CallAnswer::accept(
            "peer".into(),
            "vid-peer".into(),
            accepted_id.clone(),
            "accept-nonce".into(),
            vec![MediaType::Audio],
            &peer,
        )
        .await
        .unwrap();
        signaling
            .process_envelope(
                envelope(
                    &peer,
                    SignalKind::Answer,
                    &accepted_id,
                    "peer",
                    1,
                    "accepted-envelope",
                    serde_json::to_value(&accepted).unwrap(),
                ),
                peer_ip.into(),
                accepted_sessions.clone(),
                signals.clone(),
                groups.clone(),
                "local".into(),
            )
            .await
            .unwrap();
        let accepted_session = accepted_sessions.get_session(&accepted_id).await.unwrap();
        assert_eq!(accepted_session.state, CallState::Accepted);
        assert_eq!(accepted_session.receiver.device_id, "peer");

        let rejected_sessions = Arc::new(SessionManager::new());
        let rejected_id = outgoing_session(&rejected_sessions, "reject-nonce", peer_ip).await;
        let rejected = CallAnswer::reject(
            "peer".into(),
            "vid-peer".into(),
            rejected_id.clone(),
            "reject-nonce".into(),
            "not now".into(),
            &peer,
        )
        .await
        .unwrap();
        signaling
            .process_envelope(
                envelope(
                    &peer,
                    SignalKind::Answer,
                    &rejected_id,
                    "peer",
                    2,
                    "rejected-envelope",
                    serde_json::to_value(&rejected).unwrap(),
                ),
                peer_ip.into(),
                rejected_sessions.clone(),
                signals.clone(),
                groups.clone(),
                "local".into(),
            )
            .await
            .unwrap();
        assert_eq!(
            rejected_sessions
                .get_session(&rejected_id)
                .await
                .unwrap()
                .state,
            CallState::EndCall
        );

        let mismatched_sessions = Arc::new(SessionManager::new());
        let mismatched_id = outgoing_session(&mismatched_sessions, "mismatch-nonce", peer_ip).await;
        let mismatched = CallAnswer::accept(
            "peer".into(),
            "vid-peer".into(),
            mismatched_id.clone(),
            "wrong-nonce".into(),
            vec![MediaType::Audio],
            &peer,
        )
        .await
        .unwrap();
        let result = signaling
            .process_envelope(
                envelope(
                    &peer,
                    SignalKind::Answer,
                    &mismatched_id,
                    "peer",
                    3,
                    "mismatched-envelope",
                    serde_json::to_value(&mismatched).unwrap(),
                ),
                peer_ip.into(),
                mismatched_sessions,
                signals.clone(),
                groups.clone(),
                "local".into(),
            )
            .await;
        assert!(matches!(result, Err(CallError::InvalidOffer { .. })));

        let malformed = signaling
            .process_envelope(
                envelope(
                    &peer,
                    SignalKind::Answer,
                    "malformed-answer",
                    "peer",
                    4,
                    "malformed-envelope",
                    serde_json::json!({"accepted": true}),
                ),
                peer_ip.into(),
                Arc::new(SessionManager::new()),
                signals,
                groups,
                "local".into(),
            )
            .await;
        assert!(matches!(malformed, Err(CallError::SerializationError(_))));
    }

    #[tokio::test]
    async fn authenticated_media_dispatches_state_ready_heartbeat_and_hangup() {
        let dir = tempdir().unwrap();
        let peer = Arc::new(
            KeyManager::load_or_generate(dir.path().join("media-peer.pk8").to_str().unwrap())
                .unwrap(),
        );
        let local = Arc::new(
            KeyManager::load_or_generate(dir.path().join("media-local.pk8").to_str().unwrap())
                .unwrap(),
        );
        let signaling = secure_signaling(local, "peer", &peer);
        let sessions = Arc::new(SessionManager::new());
        let session_id = outgoing_session(&sessions, "media-nonce", "192.168.100.20").await;
        sessions
            .set_receiver_acceptance_with_device(
                &session_id,
                "vid-peer".into(),
                vec![MediaType::Audio],
                Some("peer".into()),
            )
            .await
            .unwrap();
        for state in [
            CallState::Verifying,
            CallState::Authorizing,
            CallState::Accepted,
        ] {
            sessions
                .update_session_state(&session_id, state, format!("advance to {state}"))
                .await
                .unwrap();
        }
        let signals = Arc::new(CallSignalHub::default());
        let groups = Arc::new(GroupSessionManager::new(dir.path().join("media.log")));

        signaling
            .process_envelope(
                envelope(
                    &peer,
                    SignalKind::SdpOffer,
                    &session_id,
                    "peer",
                    1,
                    "media-sdp",
                    serde_json::json!({"type":"offer","sdp":"v=0"}),
                ),
                "192.168.100.20".into(),
                sessions.clone(),
                signals.clone(),
                groups.clone(),
                "local".into(),
            )
            .await
            .unwrap();
        assert_eq!(
            sessions.get_session(&session_id).await.unwrap().state,
            CallState::MediaNegotiation
        );

        signaling
            .process_envelope(
                envelope(
                    &peer,
                    SignalKind::MediaReady,
                    &session_id,
                    "peer",
                    2,
                    "media-ready",
                    serde_json::json!({"ready":true}),
                ),
                "192.168.100.20".into(),
                sessions.clone(),
                signals.clone(),
                groups.clone(),
                "local".into(),
            )
            .await
            .unwrap();
        assert!(
            sessions
                .get_session(&session_id)
                .await
                .unwrap()
                .remote_media_ready
        );

        signaling
            .process_envelope(
                envelope(
                    &peer,
                    SignalKind::Heartbeat,
                    &session_id,
                    "peer",
                    3,
                    "heartbeat",
                    serde_json::json!({}),
                ),
                "192.168.100.20".into(),
                sessions.clone(),
                signals.clone(),
                groups.clone(),
                "local".into(),
            )
            .await
            .unwrap();

        signaling
            .process_envelope(
                envelope(
                    &peer,
                    SignalKind::Hangup,
                    &session_id,
                    "peer",
                    4,
                    "hangup",
                    serde_json::json!({"reason":"done"}),
                ),
                "192.168.100.20".into(),
                sessions.clone(),
                signals.clone(),
                groups,
                "local".into(),
            )
            .await
            .unwrap();
        assert_eq!(
            sessions.get_session(&session_id).await.unwrap().state,
            CallState::EndCall
        );
        assert_eq!(signals.list_after(&session_id, 0).await.len(), 3);
    }

    #[tokio::test]
    async fn authenticated_media_rejects_nonparticipants_and_wrong_state() {
        let dir = tempdir().unwrap();
        let peer = Arc::new(
            KeyManager::load_or_generate(dir.path().join("outsider.pk8").to_str().unwrap())
                .unwrap(),
        );
        let local = Arc::new(
            KeyManager::load_or_generate(dir.path().join("target.pk8").to_str().unwrap()).unwrap(),
        );
        let signaling = secure_signaling(local, "outsider", &peer);
        let sessions = Arc::new(SessionManager::new());
        let session_id = sessions
            .create_session(
                "caller".into(),
                "vid-caller".into(),
                "receiver".into(),
                "vid-receiver".into(),
                vec![MediaType::Audio],
                "authorization-nonce".into(),
            )
            .await
            .unwrap();
        let result = signaling
            .process_envelope(
                envelope(
                    &peer,
                    SignalKind::IceCandidate,
                    &session_id,
                    "outsider",
                    1,
                    "outsider-media",
                    serde_json::json!({"candidate":"candidate:2"}),
                ),
                "192.168.100.30".into(),
                sessions.clone(),
                Arc::new(CallSignalHub::default()),
                Arc::new(GroupSessionManager::new(dir.path().join("outsider.log"))),
                "receiver".into(),
            )
            .await;
        assert!(matches!(result, Err(CallError::UnauthorizedDevice { .. })));

        let participant_signaling = secure_signaling(
            Arc::new(
                KeyManager::load_or_generate(dir.path().join("target-2.pk8").to_str().unwrap())
                    .unwrap(),
            ),
            "caller",
            &peer,
        );
        let wrong_state = participant_signaling
            .process_envelope(
                envelope(
                    &peer,
                    SignalKind::IceComplete,
                    &session_id,
                    "caller",
                    1,
                    "wrong-state-media",
                    serde_json::json!({}),
                ),
                "192.168.100.30".into(),
                sessions,
                Arc::new(CallSignalHub::default()),
                Arc::new(GroupSessionManager::new(dir.path().join("wrong-state.log"))),
                "receiver".into(),
            )
            .await;
        assert!(matches!(
            wrong_state,
            Err(CallError::InvalidStateTransition { .. })
        ));
    }

    #[tokio::test]
    async fn group_control_rejects_malformed_and_spoofed_messages() {
        let dir = tempdir().unwrap();
        let signaling = NebulaSignaling::new(Arc::new(NebulaClient));
        let groups = Arc::new(GroupSessionManager::new(dir.path().join("spoofed.log")));
        let sample = group_session("spoofed-group");

        let malformed = SignalingEnvelope::new(
            SignalKind::GroupControl,
            "spoofed-group",
            "member",
            "vid-member",
            1,
            "malformed-group-control",
            serde_json::json!({"action":"not_a_group_action"}),
        );
        assert!(matches!(
            signaling
                .process_group_control(
                    malformed,
                    "192.168.100.2".into(),
                    groups.clone(),
                    "host".into(),
                )
                .await,
            Err(CallError::SerializationError(_))
        ));

        let spoofed = [
            GroupWireMessage::Invite {
                session: sample.clone(),
            },
            GroupWireMessage::Join {
                group_id: "different-group".into(),
                device_id: "member".into(),
            },
            GroupWireMessage::Decline {
                group_id: "different-group".into(),
                device_id: "member".into(),
            },
            GroupWireMessage::Leave {
                group_id: "different-group".into(),
                device_id: "member".into(),
            },
            GroupWireMessage::End {
                group_id: "different-group".into(),
                device_id: "member".into(),
            },
            GroupWireMessage::Heartbeat {
                group_id: "different-group".into(),
                device_id: "member".into(),
            },
            GroupWireMessage::Snapshot { session: sample },
        ];
        for (index, message) in spoofed.into_iter().enumerate() {
            let result = signaling
                .process_group_control(
                    group_control_envelope(message, "spoofed-group", "member"),
                    "192.168.100.2".into(),
                    groups.clone(),
                    "host".into(),
                )
                .await;
            assert!(
                matches!(result, Err(CallError::UnauthorizedDevice { .. })),
                "spoofed group-control case {index} should fail closed"
            );
        }
    }

    #[tokio::test]
    async fn group_control_dispatches_join_decline_leave_heartbeat_and_end() {
        let dir = tempdir().unwrap();
        let signaling = NebulaSignaling::new(Arc::new(NebulaClient));

        let join_groups = Arc::new(GroupSessionManager::new(dir.path().join("join.log")));
        let join_group = local_group(&join_groups, "Join").await;
        signaling
            .process_group_control(
                group_control_envelope(
                    GroupWireMessage::Join {
                        group_id: join_group.group_id.clone(),
                        device_id: "member".into(),
                    },
                    &join_group.group_id,
                    "member",
                ),
                "192.168.100.2".into(),
                join_groups.clone(),
                "host".into(),
            )
            .await
            .unwrap();
        assert_eq!(
            join_groups
                .get(&join_group.group_id)
                .await
                .unwrap()
                .participants["member"]
                .state,
            GroupMemberState::Joined
        );

        signaling
            .process_group_control(
                group_control_envelope(
                    GroupWireMessage::Heartbeat {
                        group_id: join_group.group_id.clone(),
                        device_id: "member".into(),
                    },
                    &join_group.group_id,
                    "member",
                ),
                "192.168.100.2".into(),
                join_groups.clone(),
                "host".into(),
            )
            .await
            .unwrap();
        signaling
            .process_group_control(
                group_control_envelope(
                    GroupWireMessage::Leave {
                        group_id: join_group.group_id.clone(),
                        device_id: "member".into(),
                    },
                    &join_group.group_id,
                    "member",
                ),
                "192.168.100.2".into(),
                join_groups.clone(),
                "host".into(),
            )
            .await
            .unwrap();
        assert_eq!(
            join_groups
                .get(&join_group.group_id)
                .await
                .unwrap()
                .participants["member"]
                .state,
            GroupMemberState::Left
        );

        let decline_groups = Arc::new(GroupSessionManager::new(dir.path().join("decline.log")));
        let decline_group = local_group(&decline_groups, "Decline").await;
        signaling
            .process_group_control(
                group_control_envelope(
                    GroupWireMessage::Decline {
                        group_id: decline_group.group_id.clone(),
                        device_id: "member".into(),
                    },
                    &decline_group.group_id,
                    "member",
                ),
                "192.168.100.2".into(),
                decline_groups.clone(),
                "host".into(),
            )
            .await
            .unwrap();
        assert_eq!(
            decline_groups
                .get(&decline_group.group_id)
                .await
                .unwrap()
                .participants["member"]
                .state,
            GroupMemberState::Declined
        );

        let end_groups = Arc::new(GroupSessionManager::new(dir.path().join("end.log")));
        let end_group = local_group(&end_groups, "End").await;
        signaling
            .process_group_control(
                group_control_envelope(
                    GroupWireMessage::End {
                        group_id: end_group.group_id.clone(),
                        device_id: "host".into(),
                    },
                    &end_group.group_id,
                    "host",
                ),
                "192.168.100.1".into(),
                end_groups.clone(),
                "host".into(),
            )
            .await
            .unwrap();
        assert!(end_groups.get(&end_group.group_id).await.is_err());
    }

    #[tokio::test]
    async fn group_media_ready_requires_joined_members() {
        let dir = tempdir().unwrap();
        let member_key = Arc::new(
            KeyManager::load_or_generate(dir.path().join("group-member.pk8").to_str().unwrap())
                .unwrap(),
        );
        let local_key = Arc::new(
            KeyManager::load_or_generate(dir.path().join("group-host.pk8").to_str().unwrap())
                .unwrap(),
        );
        let signaling = secure_signaling(local_key, "member", &member_key);
        let groups = Arc::new(GroupSessionManager::new(dir.path().join("group-media.log")));
        let group = local_group(&groups, "Group media").await;
        let sessions = Arc::new(SessionManager::new());
        let signals = Arc::new(CallSignalHub::default());

        let not_joined = signaling
            .process_envelope(
                envelope(
                    &member_key,
                    SignalKind::SdpAnswer,
                    &group.group_id,
                    "member",
                    1,
                    "group-media-before-join",
                    serde_json::json!({"type":"answer","sdp":"v=0"}),
                ),
                "192.168.100.2".into(),
                sessions.clone(),
                signals.clone(),
                groups.clone(),
                "host".into(),
            )
            .await;
        assert!(matches!(
            not_joined,
            Err(CallError::UnauthorizedDevice { .. })
        ));

        groups
            .join(&group.group_id, "member", "192.168.100.2")
            .await
            .unwrap();
        signaling
            .process_envelope(
                envelope(
                    &member_key,
                    SignalKind::MediaReady,
                    &group.group_id,
                    "member",
                    2,
                    "group-media-ready",
                    serde_json::json!({"ready":true}),
                ),
                "192.168.100.2".into(),
                sessions,
                signals,
                groups.clone(),
                "host".into(),
            )
            .await
            .unwrap();
        assert!(groups.get(&group.group_id).await.unwrap().participants["member"].media_ready);
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
                    is_local_browser: false,
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
                    is_local_browser: false,
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
        )
        .sign(&caller)
        .unwrap();
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
            .join(&group.group_id, "nodeB", "192.168.100.2")
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
        )
        .sign(&caller)
        .unwrap();
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
