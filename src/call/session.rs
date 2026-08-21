//! Call session tracking - maintains state of active calls and participants.
//! Integrates with audit module for logging all state transitions.

use crate::audit::logger::log_audit;
use crate::call::error::{CallError, CallResult};
use crate::call::history::CallHistoryStore;
use crate::call::policy::{AllowAllEnforcer, SharedEnforcer};
use crate::call::signaling::{CallOffer, MediaType};
use crate::call::state::CallState;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

/// Represents one side of a call (initiator or receiver)
#[derive(Debug, Clone)]
pub struct CallParticipant {
    pub device_id: String,
    pub virtual_id: String,
    pub accepted: bool,
    pub requested_media: Vec<MediaType>,
    /// SHA-256 DTLS certificate fingerprint this participant published in the
    /// SDP they signaled (extracted from their SdpOffer/SdpAnswer at the
    /// authenticated `submit_signal` boundary — not self-reported later).
    pub dtls_fingerprint_signaled: Option<String>,
    /// SHA-256 DTLS certificate fingerprint this participant's own browser
    /// reports it is actually using once WebRTC media connects. Encryption is
    /// only considered verified when this equals `dtls_fingerprint_signaled`:
    /// the live connection must use exactly the certificate that was
    /// cryptographically committed to at signaling time.
    pub dtls_fingerprint_confirmed: Option<String>,
}

/// Active call session
#[derive(Debug, Clone)]
pub struct CallSession {
    pub session_id: String,
    pub initiator: CallParticipant,
    pub receiver: CallParticipant,
    pub state: CallState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub nonce: String,
    pub nonce_used: bool,
    /// Nebula endpoint learned from the authenticated signaling connection.
    /// This is deliberately separate from a device ID: device IDs are not
    /// network addresses and must never be used as such for reply routing.
    pub initiator_nebula_ip: Option<String>,
    pub receiver_nebula_ip: Option<String>,
    pub call_history: Vec<CallStateTransition>,
    pub local_media_ready: bool,
    pub remote_media_ready: bool,
}

/// Record of a state transition for audit trail
#[derive(Debug, Clone)]
pub struct CallStateTransition {
    pub from_state: CallState,
    pub to_state: CallState,
    pub timestamp: DateTime<Utc>,
    pub reason: String,
}

/// Non-sensitive call status exposed through the authenticated REST API.
/// Deliberately excludes nonces, Nebula addresses, signatures, and media keys.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CallSessionStatus {
    pub session_id: String,
    pub state: String,
    pub terminal: bool,
    pub media_connected: bool,
    pub initiator_device_id: String,
    pub receiver_device_id: String,
    pub requested_media: Vec<MediaType>,
    pub accepted_media: Vec<MediaType>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub duration_seconds: u64,
    pub local_media_ready: bool,
    pub remote_media_ready: bool,
    /// True only once both sides' live WebRTC media connection is confirmed
    /// to be using exactly the DTLS certificate each signaled in their SDP.
    pub encryption_verified: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CallSessionEvent {
    pub event: String,
    pub session: CallSessionStatus,
}

impl CallSession {
    /// Create a new call session
    pub fn new(
        initiator_device_id: String,
        initiator_virtual_id: String,
        receiver_device_id: String,
        receiver_virtual_id: String,
        requested_media: Vec<MediaType>,
        nonce: String,
    ) -> CallResult<Self> {
        if requested_media.is_empty() {
            return Err(CallError::InvalidOffer {
                reason: "No media types requested".to_string(),
            });
        }

        Ok(CallSession {
            session_id: Uuid::new_v4().to_string(),
            initiator: CallParticipant {
                device_id: initiator_device_id,
                virtual_id: initiator_virtual_id,
                accepted: false,
                requested_media: requested_media.clone(),
                dtls_fingerprint_signaled: None,
                dtls_fingerprint_confirmed: None,
            },
            receiver: CallParticipant {
                device_id: receiver_device_id,
                virtual_id: receiver_virtual_id,
                accepted: false,
                requested_media: vec![],
                dtls_fingerprint_signaled: None,
                dtls_fingerprint_confirmed: None,
            },
            state: CallState::Idle,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            started_at: None,
            ended_at: None,
            nonce: nonce.clone(),
            nonce_used: false,
            initiator_nebula_ip: None,
            receiver_nebula_ip: None,
            call_history: vec![],
            local_media_ready: false,
            remote_media_ready: false,
        })
    }

    /// Transition to new state
    pub fn transition(&mut self, new_state: CallState, reason: String) -> CallResult<()> {
        let current_state = self.state;
        current_state.validate_transition(new_state)?;

        self.call_history.push(CallStateTransition {
            from_state: current_state,
            to_state: new_state,
            timestamp: Utc::now(),
            reason,
        });

        self.state = new_state;
        self.updated_at = Utc::now();

        if new_state == CallState::Connected {
            self.started_at = Some(Utc::now());
        }

        if new_state == CallState::EndCall {
            self.ended_at = Some(Utc::now());
        }

        Ok(())
    }

    /// Mark nonce as used
    pub fn use_nonce(&mut self) -> CallResult<()> {
        if self.nonce_used {
            return Err(CallError::NonceReused {
                nonce: self.nonce.clone(),
            });
        }
        self.nonce_used = true;
        Ok(())
    }

    /// Mark receiver as accepted
    pub fn receiver_accepted(&mut self, accepted_media: Vec<MediaType>) -> CallResult<()> {
        if accepted_media.is_empty() {
            return Err(CallError::InvalidOffer {
                reason: "No media types accepted".to_string(),
            });
        }
        self.receiver.accepted = true;
        self.receiver.requested_media = accepted_media;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// True once BOTH participants' live media connection is confirmed using
    /// exactly the DTLS certificate they each committed to in their signaled
    /// SDP — not merely that a fingerprint was reported, but that it matches.
    pub fn encryption_verified(&self) -> bool {
        [&self.initiator, &self.receiver]
            .into_iter()
            .all(|participant| {
                participant.dtls_fingerprint_confirmed.is_some()
                    && participant.dtls_fingerprint_confirmed
                        == participant.dtls_fingerprint_signaled
            })
    }

    /// Get call duration in seconds (0 if not started)
    pub fn duration_seconds(&self) -> u64 {
        match (self.started_at, self.ended_at) {
            (Some(start), Some(end)) => (end - start).num_seconds() as u64,
            (Some(start), None) => (Utc::now() - start).num_seconds() as u64,
            _ => 0,
        }
    }

    /// Get all state transitions as string for audit log
    pub fn get_state_history(&self) -> String {
        self.call_history
            .iter()
            .map(|t| {
                format!(
                    "{} -> {} at {}",
                    t.from_state,
                    t.to_state,
                    t.timestamp.to_rfc3339()
                )
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Return only dashboard-safe session information.
    pub fn status_snapshot(&self) -> CallSessionStatus {
        CallSessionStatus {
            session_id: self.session_id.clone(),
            state: self.state.as_wire_str().to_string(),
            terminal: self.state.is_terminal(),
            // This state can only be entered by a future verified media peer.
            // Current signaling-only calls therefore remain false.
            media_connected: self.state == CallState::Connected,
            initiator_device_id: self.initiator.device_id.clone(),
            receiver_device_id: self.receiver.device_id.clone(),
            requested_media: self.initiator.requested_media.clone(),
            accepted_media: self.receiver.requested_media.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            started_at: self.started_at,
            ended_at: self.ended_at,
            duration_seconds: self.duration_seconds(),
            local_media_ready: self.local_media_ready,
            remote_media_ready: self.remote_media_ready,
            encryption_verified: self.encryption_verified(),
        }
    }
}

/// Thread-safe session manager
pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, CallSession>>>,
    enforcer: SharedEnforcer,
    events: broadcast::Sender<CallSessionEvent>,
    history: Arc<CallHistoryStore>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    /// Create new session manager
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(256);
        SessionManager {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            enforcer: Arc::new(AllowAllEnforcer),
            events,
            history: Arc::new(CallHistoryStore::default()),
        }
    }

    /// Create a session manager with a custom policy enforcer.
    pub fn with_enforcer(enforcer: SharedEnforcer) -> Self {
        let (events, _) = broadcast::channel(256);
        SessionManager {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            enforcer,
            events,
            history: Arc::new(CallHistoryStore::default()),
        }
    }

    pub fn with_history_store(history: Arc<CallHistoryStore>) -> Self {
        let (events, _) = broadcast::channel(256);
        SessionManager {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            enforcer: Arc::new(AllowAllEnforcer),
            events,
            history,
        }
    }

    pub fn call_history(&self) -> Arc<CallHistoryStore> {
        self.history.clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<CallSessionEvent> {
        self.events.subscribe()
    }

    fn publish(&self, event: &str, session: &CallSession) {
        let _ = self.events.send(CallSessionEvent {
            event: event.to_string(),
            session: session.status_snapshot(),
        });
    }

    pub async fn notify(&self, session_id: &str, event: &str) -> CallResult<()> {
        let session = self.get_session(session_id).await?;
        self.publish(event, &session);
        Ok(())
    }

    /// Record readiness reported by a real browser WebRTC connection. The call
    /// becomes connected only after both authenticated endpoints are ready.
    pub async fn mark_media_ready(&self, session_id: &str, local: bool) -> CallResult<bool> {
        let snapshot = {
            let mut sessions = self.sessions.write().await;
            let session = sessions
                .get_mut(session_id)
                .ok_or(CallError::SessionNotFound {
                    session_id: session_id.to_string(),
                })?;
            if session.state != CallState::MediaNegotiation && session.state != CallState::Connected
            {
                return Err(CallError::InvalidStateTransition {
                    from: session.state.to_string(),
                    to: "Connected".into(),
                });
            }
            if local {
                session.local_media_ready = true;
            } else {
                session.remote_media_ready = true;
            }
            if session.local_media_ready
                && session.remote_media_ready
                && session.state == CallState::MediaNegotiation
            {
                session.transition(
                    CallState::Connected,
                    "Both WebRTC endpoints reported media ready".into(),
                )?;
            }
            session.clone()
        };
        let connected = snapshot.state == CallState::Connected;
        self.publish(
            if connected {
                "call_connected"
            } else {
                "media_ready_changed"
            },
            &snapshot,
        );
        Ok(connected)
    }

    /// Record the DTLS certificate fingerprint a participant published in
    /// their signaled SDP. Called at the authenticated `submit_signal`
    /// boundary as SdpOffer/SdpAnswer pass through, so this reflects what the
    /// participant cryptographically committed to, not a later self-report.
    pub async fn record_signaled_fingerprint(
        &self,
        session_id: &str,
        device_id: &str,
        fingerprint: String,
    ) -> CallResult<()> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or(CallError::SessionNotFound {
                session_id: session_id.to_string(),
            })?;
        if session.initiator.device_id == device_id {
            session.initiator.dtls_fingerprint_signaled = Some(fingerprint);
        } else if session.receiver.device_id == device_id {
            session.receiver.dtls_fingerprint_signaled = Some(fingerprint);
        }
        Ok(())
    }

    /// Record the DTLS certificate fingerprint a participant's own browser
    /// reports it is actually using now that WebRTC media has connected.
    /// Returns whether the session is now fully encryption-verified (both
    /// sides confirmed, each matching what they themselves signaled).
    pub async fn confirm_dtls_fingerprint(
        &self,
        session_id: &str,
        device_id: &str,
        fingerprint: String,
    ) -> CallResult<bool> {
        let snapshot = {
            let mut sessions = self.sessions.write().await;
            let session = sessions
                .get_mut(session_id)
                .ok_or(CallError::SessionNotFound {
                    session_id: session_id.to_string(),
                })?;
            let participant = if session.initiator.device_id == device_id {
                &mut session.initiator
            } else if session.receiver.device_id == device_id {
                &mut session.receiver
            } else {
                return Err(CallError::UnauthorizedDevice {
                    reason: "Not a session participant".into(),
                });
            };
            if participant.dtls_fingerprint_signaled.is_some()
                && participant.dtls_fingerprint_signaled.as_deref() != Some(fingerprint.as_str())
            {
                tracing::warn!(
                    session_id,
                    device_id,
                    signaled = ?participant.dtls_fingerprint_signaled,
                    confirmed = %fingerprint,
                    "DTLS fingerprint reported at media-ready does not match what this participant signaled in their SDP"
                );
            }
            participant.dtls_fingerprint_confirmed = Some(fingerprint);
            session.clone()
        };
        let verified = snapshot.encryption_verified();
        if verified {
            self.publish("call_encryption_verified", &snapshot);
        }
        Ok(verified)
    }

    /// Create and store new session
    pub async fn create_session(
        &self,
        initiator_device_id: String,
        initiator_virtual_id: String,
        receiver_device_id: String,
        receiver_virtual_id: String,
        requested_media: Vec<MediaType>,
        nonce: String,
    ) -> CallResult<String> {
        let session = CallSession::new(
            initiator_device_id,
            initiator_virtual_id,
            receiver_device_id,
            receiver_virtual_id,
            requested_media,
            nonce,
        )?;

        let session_id = session.session_id.clone();
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), session.clone());
        }
        self.publish("call_created", &session);

        // Audit: session created (best-effort)
        log_audit(
            "local-node",
            crate::audit::event::AuditCategory::Network,
            crate::audit::event::AuditSeverity::Info,
            crate::audit::event::AuditAction::Created,
            &format!("Call session {} created", session_id),
        );

        Ok(session_id)
    }

    /// Record the Nebula endpoints selected for a locally-created session.
    pub async fn set_nebula_endpoints(
        &self,
        session_id: &str,
        initiator_nebula_ip: Option<String>,
        receiver_nebula_ip: Option<String>,
    ) -> CallResult<()> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or(CallError::SessionNotFound {
                session_id: session_id.to_string(),
            })?;
        session.initiator_nebula_ip = initiator_nebula_ip;
        session.receiver_nebula_ip = receiver_nebula_ip;
        Ok(())
    }

    pub async fn set_receiver_acceptance(
        &self,
        session_id: &str,
        virtual_id: String,
        accepted_media: Vec<MediaType>,
    ) -> CallResult<()> {
        self.set_receiver_acceptance_with_device(session_id, virtual_id, accepted_media, None)
            .await
    }

    /// Same as `set_receiver_acceptance`, but additionally corrects the
    /// receiver's `device_id` when it becomes known for the first time.
    ///
    /// The initiator creates its session record before the receiver has ever
    /// spoken, so `receiver.device_id` is provisionally filled from the
    /// initiator's own trusted-peer registry (keyed by Nebula IP, not by the
    /// remote device's self-asserted ID). The remote's authenticated answer
    /// is the first message that actually carries that self-asserted ID, so
    /// this is where the placeholder gets reconciled. Later signaling
    /// (SDP/ICE) is matched against `sender_device_id`, so without this
    /// correction every subsequent authenticated message from the receiver
    /// would fail the "is a session participant" check.
    pub async fn set_receiver_acceptance_with_device(
        &self,
        session_id: &str,
        virtual_id: String,
        accepted_media: Vec<MediaType>,
        verified_device_id: Option<String>,
    ) -> CallResult<()> {
        if virtual_id.trim().is_empty() {
            return Err(CallError::InvalidOffer {
                reason: "Receiver VirtualID is required".into(),
            });
        }
        let snapshot = {
            let mut sessions = self.sessions.write().await;
            let session = sessions
                .get_mut(session_id)
                .ok_or(CallError::SessionNotFound {
                    session_id: session_id.to_string(),
                })?;
            session.receiver_accepted(accepted_media)?;
            session.receiver.virtual_id = virtual_id;
            if let Some(device_id) = verified_device_id {
                session.receiver.device_id = device_id;
            }
            session.clone()
        };
        self.publish("call_media_accepted", &snapshot);
        Ok(())
    }

    /// Store an offer received over the Nebula-only signaling listener.
    /// The offer's session ID is retained so that replies correlate on both
    /// peers. A nonce may be retried only for the exact same offer/session.
    pub async fn register_incoming_offer(
        &self,
        offer: &CallOffer,
        receiver_device_id: String,
        initiator_nebula_ip: String,
    ) -> CallResult<()> {
        let mut sessions = self.sessions.write().await;

        if let Some(existing) = sessions.get(&offer.session_id) {
            if existing.initiator.device_id == offer.device_id
                && existing.nonce == offer.nonce
                && existing.initiator_nebula_ip.as_deref() == Some(initiator_nebula_ip.as_str())
            {
                return Ok(()); // idempotent retry after a transport failure
            }
            return Err(CallError::InvalidOffer {
                reason: "Session ID conflicts with an existing call".to_string(),
            });
        }

        if sessions
            .values()
            .any(|session| session.nonce == offer.nonce)
        {
            return Err(CallError::NonceReused {
                nonce: offer.nonce.clone(),
            });
        }

        let mut session = CallSession::new(
            offer.device_id.clone(),
            offer.virtual_id.clone(),
            receiver_device_id,
            String::new(),
            offer.requested_media.clone(),
            offer.nonce.clone(),
        )?;
        session.session_id = offer.session_id.clone();
        session.initiator_nebula_ip = Some(initiator_nebula_ip);
        session.transition(
            CallState::OfferReceived,
            "Offer received over Guardian Mesh".to_string(),
        )?;
        sessions.insert(session.session_id.clone(), session.clone());
        drop(sessions);
        self.publish("incoming_call", &session);
        Ok(())
    }

    /// Get session by ID
    pub async fn get_session(&self, session_id: &str) -> CallResult<CallSession> {
        let sessions = self.sessions.read().await;
        sessions
            .get(session_id)
            .cloned()
            .ok_or(CallError::SessionNotFound {
                session_id: session_id.to_string(),
            })
    }

    /// Update session state
    pub async fn update_session_state(
        &self,
        session_id: &str,
        new_state: CallState,
        reason: String,
    ) -> CallResult<()> {
        // If this transition requires policy checks, perform them WITHOUT holding the write lock
        if new_state == CallState::Accepted {
            // clone session for policy check
            let session_clone = {
                let sessions = self.sessions.read().await;
                sessions
                    .get(session_id)
                    .cloned()
                    .ok_or(CallError::SessionNotFound {
                        session_id: session_id.to_string(),
                    })?
            };

            // Run policy enforcer asynchronously
            let allowed = self.enforcer.allow_call(&session_clone).await?;
            if !allowed {
                // Audit deny
                log_audit(
                    "local-node",
                    crate::audit::event::AuditCategory::Enforcement,
                    crate::audit::event::AuditSeverity::Warning,
                    crate::audit::event::AuditAction::Rejected,
                    &format!("Call session {} denied by policy", session_id),
                );
                return Err(CallError::UnauthorizedDevice {
                    reason: "Policy denied call".to_string(),
                });
            }
        }

        // Perform actual state transition under write lock
        let (old_state, snapshot) = {
            let mut sessions = self.sessions.write().await;
            let session = sessions
                .get_mut(session_id)
                .ok_or(CallError::SessionNotFound {
                    session_id: session_id.to_string(),
                })?;
            let old_state = session.state;
            session.transition(new_state, reason.clone())?;
            (old_state, session.clone())
        };

        // Audit log state change (best-effort)
        log_audit(
            "local-node",
            crate::audit::event::AuditCategory::Network,
            crate::audit::event::AuditSeverity::Info,
            crate::audit::event::AuditAction::Applied,
            &format!(
                "Call session {} transitioned from {} to {} ({})",
                session_id, old_state, new_state, reason
            ),
        );
        self.publish("call_state_changed", &snapshot);
        if snapshot.state.is_terminal() {
            self.history.record_direct(&snapshot.status_snapshot());
        }

        Ok(())
    }

    /// Mark session as ended
    pub async fn end_session(&self, session_id: &str) -> CallResult<()> {
        // Hang-up requests can race with peer rejection, a timeout, or a
        // browser retry. Treat a terminal session as an acknowledged end.
        if self.get_session(session_id).await?.state.is_terminal() {
            return Ok(());
        }
        self.update_session_state(
            session_id,
            CallState::EndCall,
            "User ended call".to_string(),
        )
        .await
    }

    /// Get all active sessions
    pub async fn get_active_sessions(&self) -> Vec<CallSession> {
        let sessions = self.sessions.read().await;
        sessions
            .values()
            .filter(|s| !s.state.is_terminal())
            .cloned()
            .collect()
    }

    pub async fn list_statuses(&self) -> Vec<CallSessionStatus> {
        let sessions = self.sessions.read().await;
        let mut statuses: Vec<_> = sessions
            .values()
            .map(CallSession::status_snapshot)
            .collect();
        statuses.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        statuses
    }

    /// Clean up old ended sessions (older than 1 hour)
    pub async fn cleanup_old_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        let now = Utc::now();
        sessions.retain(|_, session| {
            if let Some(ended_at) = session.ended_at {
                (now - ended_at).num_seconds() < 3600
            } else {
                true
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::policy::PolicyEnforcer;
    use async_trait::async_trait;
    use std::sync::Arc;
    use tempfile::tempdir;

    struct DenyAllEnforcer;

    #[async_trait]
    impl PolicyEnforcer for DenyAllEnforcer {
        async fn allow_call(&self, _session: &CallSession) -> CallResult<bool> {
            Ok(false)
        }
    }

    #[tokio::test]
    async fn test_update_session_state_denied_by_policy() {
        let manager = SessionManager::with_enforcer(Arc::new(DenyAllEnforcer));
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
                "Test policy denial".to_string(),
            )
            .await;

        assert!(matches!(result, Err(CallError::UnauthorizedDevice { .. })));
    }

    #[tokio::test]
    async fn incoming_offer_keeps_the_remote_session_and_reply_endpoint() {
        let manager = SessionManager::new();
        let offer = CallOffer {
            device_id: "nodeA".to_string(),
            virtual_id: "nodeA-virtual".to_string(),
            session_id: "shared-session-id".to_string(),
            timestamp: Utc::now(),
            nonce: "unique-nonce".to_string(),
            requested_media: vec![MediaType::Audio],
            signature: "signature".to_string(),
        };

        manager
            .register_incoming_offer(&offer, "nodeB".to_string(), "192.168.100.1".to_string())
            .await
            .expect("register incoming offer");

        let session = manager
            .get_session("shared-session-id")
            .await
            .expect("stored session");
        assert_eq!(session.state, CallState::OfferReceived);
        assert_eq!(
            session.initiator_nebula_ip.as_deref(),
            Some("192.168.100.1")
        );
        assert_eq!(session.receiver.device_id, "nodeB");

        // Retrying the same transport message must be harmless, while a
        // nonce collision for another session remains a replay attempt.
        manager
            .register_incoming_offer(&offer, "nodeB".to_string(), "192.168.100.1".to_string())
            .await
            .expect("idempotent retry");
        let mut replay = offer.clone();
        replay.session_id = "different-session".to_string();
        assert!(matches!(
            manager
                .register_incoming_offer(&replay, "nodeB".to_string(), "192.168.100.1".to_string())
                .await,
            Err(CallError::NonceReused { .. })
        ));
    }

    #[test]
    fn test_session_creation() {
        let session = CallSession::new(
            "device1".to_string(),
            "virtual1".to_string(),
            "device2".to_string(),
            "virtual2".to_string(),
            vec![MediaType::Audio],
            "nonce123".to_string(),
        )
        .unwrap();

        assert_eq!(session.state, CallState::Idle);
        assert_eq!(session.initiator.device_id, "device1");
        assert_eq!(session.receiver.device_id, "device2");
    }

    #[test]
    fn status_snapshot_excludes_sensitive_transport_data() {
        let mut session = CallSession::new(
            "device1".to_string(),
            "virtual1".to_string(),
            "device2".to_string(),
            "virtual2".to_string(),
            vec![MediaType::Audio],
            "secret-nonce".to_string(),
        )
        .expect("create session");
        session.initiator_nebula_ip = Some("192.168.100.1".to_string());

        let status = session.status_snapshot();
        let value = serde_json::to_value(status).expect("serialize status");
        assert_eq!(value["state"], "idle");
        assert_eq!(value["media_connected"], false);
        assert!(value.get("nonce").is_none());
        assert!(value.get("initiator_nebula_ip").is_none());
    }

    #[tokio::test]
    async fn ending_a_terminal_session_is_idempotent() {
        let manager = SessionManager::new();
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

        manager.end_session(&session_id).await.expect("first end");
        manager.end_session(&session_id).await.expect("second end");
        assert_eq!(
            manager
                .get_session(&session_id)
                .await
                .expect("session")
                .state,
            CallState::EndCall
        );
    }

    #[tokio::test]
    async fn subscribers_receive_created_and_state_events() {
        let manager = SessionManager::new();
        let mut events = manager.subscribe();
        let session_id = manager
            .create_session(
                "device1".into(),
                "virtual1".into(),
                "device2".into(),
                "virtual2".into(),
                vec![MediaType::Audio],
                "nonce-events".into(),
            )
            .await
            .unwrap();
        let created = events.recv().await.unwrap();
        assert_eq!(created.event, "call_created");
        assert_eq!(created.session.session_id, session_id);

        manager
            .update_session_state(&session_id, CallState::LocalPolicyCheck, "checking".into())
            .await
            .unwrap();
        let changed = events.recv().await.unwrap();
        assert_eq!(changed.event, "call_state_changed");
        assert_eq!(changed.session.state, "local_policy_check");
    }

    #[tokio::test]
    async fn connected_requires_local_and_remote_media_readiness() {
        let manager = SessionManager::new();
        let session_id = manager
            .create_session(
                "device1".into(),
                "virtual1".into(),
                "device2".into(),
                "virtual2".into(),
                vec![MediaType::Audio],
                "nonce-ready".into(),
            )
            .await
            .unwrap();
        for state in [
            CallState::LocalPolicyCheck,
            CallState::OfferSent,
            CallState::Verifying,
            CallState::Authorizing,
            CallState::Accepted,
            CallState::MediaNegotiation,
        ] {
            manager
                .update_session_state(&session_id, state, "test".into())
                .await
                .unwrap();
        }
        assert!(!manager.mark_media_ready(&session_id, true).await.unwrap());
        assert_eq!(
            manager.get_session(&session_id).await.unwrap().state,
            CallState::MediaNegotiation
        );
        assert!(manager.mark_media_ready(&session_id, false).await.unwrap());
        assert_eq!(
            manager.get_session(&session_id).await.unwrap().state,
            CallState::Connected
        );
    }

    #[test]
    fn test_session_state_transition() {
        let mut session = CallSession::new(
            "device1".to_string(),
            "virtual1".to_string(),
            "device2".to_string(),
            "virtual2".to_string(),
            vec![MediaType::Audio],
            "nonce123".to_string(),
        )
        .unwrap();

        assert!(session
            .transition(CallState::LocalPolicyCheck, "Testing".to_string())
            .is_ok());
        assert_eq!(session.state, CallState::LocalPolicyCheck);
        assert_eq!(session.call_history.len(), 1);
    }

    #[test]
    fn test_invalid_state_transition() {
        let mut session = CallSession::new(
            "device1".to_string(),
            "virtual1".to_string(),
            "device2".to_string(),
            "virtual2".to_string(),
            vec![MediaType::Audio],
            "nonce123".to_string(),
        )
        .unwrap();

        // Cannot jump directly to Connected
        assert!(session
            .transition(CallState::Connected, "Invalid".to_string())
            .is_err());
    }

    #[test]
    fn test_nonce_reuse() {
        let mut session = CallSession::new(
            "device1".to_string(),
            "virtual1".to_string(),
            "device2".to_string(),
            "virtual2".to_string(),
            vec![MediaType::Audio],
            "nonce123".to_string(),
        )
        .unwrap();

        assert!(session.use_nonce().is_ok());
        assert!(session.use_nonce().is_err()); // Cannot reuse
    }

    #[test]
    fn test_receiver_acceptance() {
        let mut session = CallSession::new(
            "device1".to_string(),
            "virtual1".to_string(),
            "device2".to_string(),
            "virtual2".to_string(),
            vec![MediaType::Audio, MediaType::Video],
            "nonce123".to_string(),
        )
        .unwrap();

        assert!(session.receiver_accepted(vec![MediaType::Audio]).is_ok());
        assert!(session.receiver.accepted);
        assert_eq!(session.receiver.requested_media, vec![MediaType::Audio]);
    }

    #[test]
    fn test_empty_acceptance() {
        let mut session = CallSession::new(
            "device1".to_string(),
            "virtual1".to_string(),
            "device2".to_string(),
            "virtual2".to_string(),
            vec![MediaType::Audio],
            "nonce123".to_string(),
        )
        .unwrap();

        // Cannot accept with empty media
        assert!(session.receiver_accepted(vec![]).is_err());
    }

    #[test]
    fn test_call_duration() {
        let mut session = CallSession::new(
            "device1".to_string(),
            "virtual1".to_string(),
            "device2".to_string(),
            "virtual2".to_string(),
            vec![MediaType::Audio],
            "nonce123".to_string(),
        )
        .unwrap();

        assert_eq!(session.duration_seconds(), 0);

        session.started_at = Some(Utc::now());
        let _ = session.duration_seconds();
    }

    #[test]
    fn test_state_history() {
        let mut session = CallSession::new(
            "device1".to_string(),
            "virtual1".to_string(),
            "device2".to_string(),
            "virtual2".to_string(),
            vec![MediaType::Audio],
            "nonce123".to_string(),
        )
        .unwrap();

        let _ = session.transition(CallState::LocalPolicyCheck, "First".to_string());
        let _ = session.transition(CallState::OfferSent, "Second".to_string());

        let history = session.get_state_history();
        assert!(history.contains("Idle -> LocalPolicyCheck"));
        assert!(history.contains("LocalPolicyCheck -> OfferSent"));
    }

    #[tokio::test]
    async fn terminal_call_is_persisted_to_history() {
        let dir = tempdir().unwrap();
        let history = Arc::new(CallHistoryStore::new(dir.path().join("calls.json")));
        let manager = SessionManager::with_history_store(history.clone());
        let session_id = manager
            .create_session(
                "nodeA".into(),
                "vidA".into(),
                "nodeB".into(),
                "vidB".into(),
                vec![MediaType::Audio],
                "nonce-history".into(),
            )
            .await
            .unwrap();
        manager
            .update_session_state(&session_id, CallState::LocalPolicyCheck, "policy".into())
            .await
            .unwrap();
        manager
            .update_session_state(&session_id, CallState::OfferSent, "offer".into())
            .await
            .unwrap();
        manager.end_session(&session_id).await.unwrap();

        let records = history.list();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, session_id);
        assert_eq!(records[0].participant_ids, vec!["nodeA", "nodeB"]);
    }
}
