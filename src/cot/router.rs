// src/cot/router.rs
// ============================================================
// Multi-Transport Router — ties everything together.
// ============================================================

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
}

impl CotRouter {
    pub fn new(
        local_identity: DeviceIdentity,
        registry: Arc<TransportRegistry>,
        sessions: Arc<SessionManager>,
        circle: Arc<CircleMembership>,
        trust_engine: Arc<TrustEngine>,
    ) -> Self {
        Self {
            local_identity,
            registry,
            sessions,
            circle,
            trust_engine,
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
        let router = CotRouter::new(id, r, s, c, t);
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
        let router = CotRouter::new(id, r, s, c, t);
        assert!(router.status_summary().await.contains("CoT Router Status"));
    }
}
