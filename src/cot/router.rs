// src/cot/router.rs
// ============================================================
// Multi-Transport Router — ties everything together.
// ============================================================

use crate::cot::failover::FailoverEngine;
use crate::cot::identity::DeviceIdentity;
use crate::cot::membership::CircleMembership;
use crate::cot::session_manager::SessionManager;
use crate::cot::transport_registry::TransportRegistry;
use crate::cot::transport_trait::TransportMessage;
use crate::cot::trust_engine::TrustEngine;
use crate::cot::types::{CotError, CotResult, TransportType};
use std::sync::Arc;

pub struct CotRouter {
    local_identity: DeviceIdentity,
    registry: Arc<TransportRegistry>,
    sessions: Arc<SessionManager>,
    circle: Arc<CircleMembership>,
    trust_engine: Arc<TrustEngine>,
    failover: Option<Arc<FailoverEngine>>,
}

impl CotRouter {
    pub fn new(
        local_identity: DeviceIdentity,
        registry: Arc<TransportRegistry>,
        sessions: Arc<SessionManager>,
        circle: Arc<CircleMembership>,
        trust_engine: Arc<TrustEngine>,
        failover: Option<Arc<FailoverEngine>>,
    ) -> Self {
        Self {
            local_identity,
            registry,
            sessions,
            circle,
            trust_engine,
            failover,
        }
    }

    pub async fn send_to_peer(
        &self,
        remote_device_id: &str,
        payload: Vec<u8>,
    ) -> CotResult<TransportType> {
        if !self.circle.is_member(remote_device_id).await {
            return Err(CotError::PeerNotFound(format!(
                "{} is not a member",
                remote_device_id
            )));
        }

        let member = self
            .circle
            .get_member(remote_device_id)
            .await
            .ok_or_else(|| CotError::PeerNotFound(remote_device_id.to_string()))?;

        if member.endpoints.is_empty() {
            return Err(CotError::PeerNotFound(format!(
                "No endpoints for {}",
                remote_device_id
            )));
        }

        if let Some(failover) = &self.failover {
            if let Some(active_iface) = failover.current_interface().await {
                if let Some(transport) = self.registry.get_by_interface(&active_iface).await {
                    if transport.is_available().await {
                        if let Some(endpoint) = member.endpoint_for(transport.transport_type()) {
                            let message = TransportMessage::new(
                                self.local_identity.device_id().to_string(),
                                remote_device_id.to_string(),
                                endpoint.address.clone(),
                                payload.clone(),
                            );
                            if transport.send(&message).await.is_ok() {
                                self.sessions
                                    .get_or_create(
                                        self.local_identity.device_id(),
                                        remote_device_id,
                                        endpoint.transport_type,
                                    )
                                    .await;
                                return Ok(endpoint.transport_type);
                            }
                        }
                    }
                }
            }
        }

        let mut endpoints = member.endpoints.clone();
        endpoints.sort_by_key(|ep| ep.transport_type.default_priority());

        let mut last_error = None;
        for endpoint in &endpoints {
            let transport = match self.registry.get(endpoint.transport_type).await {
                Some(t) => t,
                None => continue,
            };
            if !transport.is_available().await {
                continue;
            }

            let message = TransportMessage::new(
                self.local_identity.device_id().to_string(),
                remote_device_id.to_string(),
                endpoint.address.clone(),
                payload.clone(),
            );

            match transport.send(&message).await {
                Ok(()) => {
                    self.sessions
                        .get_or_create(
                            self.local_identity.device_id(),
                            remote_device_id,
                            endpoint.transport_type,
                        )
                        .await;
                    return Ok(endpoint.transport_type);
                }
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }

        Err(last_error.unwrap_or(CotError::NoTransportAvailable))
    }

    pub async fn status_summary(&self) -> String {
        let reg = self.registry.summary().await;
        let sess = self.sessions.summary().await;
        let circ = self.circle.summary().await;
        format!(
            "CoT Router Status:\n  Local: {}\n  Transports: {}\n  {}\n  {}",
            self.local_identity, reg, sess, circ
        )
    }

    pub fn trust_engine(&self) -> &Arc<TrustEngine> {
        &self.trust_engine
    }
    pub fn sessions(&self) -> &Arc<SessionManager> {
        &self.sessions
    }
    pub fn registry(&self) -> &Arc<TransportRegistry> {
        &self.registry
    }
    pub fn circle(&self) -> &Arc<CircleMembership> {
        &self.circle
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cot::types::PeerEndpoint;

    fn make_key(seed: u8) -> Vec<u8> {
        let mut key = vec![0x04];
        key.extend_from_slice(&[seed; 32]);
        key.extend_from_slice(&[seed + 1; 32]);
        key
    }

    #[tokio::test]
    async fn test_send_to_non_member_rejected() {
        let k = make_key(0xAA);
        let id = DeviceIdentity::from_public_key(&k).unwrap();
        let c = Arc::new(CircleMembership::new(
            "t".into(),
            id.device_id().into(),
            k.clone(),
        ));
        let r = Arc::new(TransportRegistry::new());
        let s = Arc::new(SessionManager::new());
        let t = Arc::new(TrustEngine::new(id.clone(), c.clone()));
        let router = CotRouter::new(id, r, s, c, t, None);
        assert!(router
            .send_to_peer("unknown", b"hi".to_vec())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_status_summary() {
        let k = make_key(0xAA);
        let id = DeviceIdentity::from_public_key(&k).unwrap();
        let c = Arc::new(CircleMembership::new(
            "t".into(),
            id.device_id().into(),
            k.clone(),
        ));
        let r = Arc::new(TransportRegistry::new());
        let s = Arc::new(SessionManager::new());
        let t = Arc::new(TrustEngine::new(id.clone(), c.clone()));
        let router = CotRouter::new(id, r, s, c, t, None);
        assert!(router.status_summary().await.contains("CoT Router Status"));
    }

    /// A router whose Circle contains one member, so `send_to_peer` gets past
    /// the membership gate and into endpoint selection.
    async fn router_with_member(
        endpoints: Vec<PeerEndpoint>,
    ) -> (CotRouter, Arc<CircleMembership>, String) {
        let owner_key = make_key(0xAA);
        let owner = DeviceIdentity::from_public_key(&owner_key).expect("owner identity");
        let peer_key = make_key(0xBB);
        let peer = DeviceIdentity::from_public_key(&peer_key).expect("peer identity");
        let peer_id = peer.device_id().to_string();

        let circle = Arc::new(CircleMembership::new(
            "t".into(),
            owner.device_id().into(),
            owner_key,
        ));
        circle
            .add_member(peer_id.clone(), peer_key)
            .await
            .expect("add member");
        for endpoint in endpoints {
            circle
                .update_endpoint(&peer_id, endpoint)
                .await
                .expect("update endpoint");
        }

        let registry = Arc::new(TransportRegistry::new());
        let sessions = Arc::new(SessionManager::new());
        let trust = Arc::new(TrustEngine::new(owner.clone(), circle.clone()));
        let router = CotRouter::new(owner, registry, sessions, circle.clone(), trust, None);
        (router, circle, peer_id)
    }

    #[tokio::test]
    async fn send_to_peer_rejects_a_member_with_no_endpoints() {
        let (router, _circle, peer_id) = router_with_member(Vec::new()).await;

        let error = router
            .send_to_peer(&peer_id, b"hi".to_vec())
            .await
            .err()
            .expect("a member with no endpoints cannot be reached");
        assert!(
            matches!(&error, CotError::PeerNotFound(message) if message.contains("No endpoints")),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn send_to_peer_fails_when_no_transport_is_registered_for_any_endpoint() {
        // The peer advertises two endpoints, but the registry is empty, so
        // every candidate is tried and none can carry the message.
        let (router, _circle, peer_id) = router_with_member(vec![
            PeerEndpoint::new("peer".into(), TransportType::Bluetooth, "AA:BB:CC:DD:EE:FF".into()),
            PeerEndpoint::new("peer".into(), TransportType::Ethernet, "127.0.0.1:1".into()),
        ])
        .await;

        assert!(
            router.send_to_peer(&peer_id, b"hi".to_vec()).await.is_err(),
            "with no registered transports the send must fail"
        );
    }

    #[tokio::test]
    async fn the_router_exposes_the_components_it_was_built_from() {
        let (router, circle, _peer_id) = router_with_member(Vec::new()).await;

        assert_eq!(router.circle().circle_id(), circle.circle_id());
        assert_eq!(router.registry().summary().await, {
            let empty = TransportRegistry::new();
            empty.summary().await
        });
        assert!(router.sessions().summary().await.contains("Session"));
        // The owner is a member of its own Circle, so adding one peer makes two.
        assert_eq!(router.circle().member_count().await, 2);
        let _ = router.trust_engine();
    }

    #[tokio::test]
    async fn status_summary_reports_the_local_identity_and_every_subsystem() {
        let (router, _circle, _peer_id) = router_with_member(vec![PeerEndpoint::new(
            "peer".into(),
            TransportType::Ethernet,
            "127.0.0.1:1".into(),
        )])
        .await;

        let summary = router.status_summary().await;
        assert!(summary.contains("CoT Router Status"), "{summary}");
        assert!(summary.contains("Local:"), "{summary}");
        assert!(summary.contains("Transports:"), "{summary}");
    }
}
