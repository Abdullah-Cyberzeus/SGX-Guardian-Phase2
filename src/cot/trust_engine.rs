// src/cot/trust_engine.rs
// ============================================================
// Transport-Agnostic Trust Engine
// Trust based on cryptographic identity, not network transport.
// ============================================================

use crate::cot::identity::DeviceIdentity;
use crate::cot::membership::{CircleMembership, TrustLevel};
use crate::cot::types::TransportType;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustVerification {
    pub device_id: String,
    pub is_trusted: bool,
    pub trust_level: TrustLevel,
    pub transport_used: TransportType,
    pub verified_at: DateTime<Utc>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustDecision {
    pub device_id: String,
    pub action: String,
    pub allowed: bool,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

pub struct TrustEngine {
    local_identity: DeviceIdentity,
    circle: Arc<CircleMembership>,
    decisions: Arc<RwLock<Vec<TrustDecision>>>,
    verification_cache: Arc<RwLock<HashMap<String, TrustVerification>>>,
}

impl TrustEngine {
    pub fn new(local_identity: DeviceIdentity, circle: Arc<CircleMembership>) -> Self {
        Self {
            local_identity,
            circle,
            decisions: Arc::new(RwLock::new(Vec::new())),
            verification_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn verify_peer(
        &self,
        presented_public_key: &[u8],
        transport_used: TransportType,
    ) -> TrustVerification {
        let computed_id = DeviceIdentity::compute_id(presented_public_key);
        let now = Utc::now();

        if !self.circle.is_member(&computed_id).await {
            self.record_decision(&computed_id, "verify_peer", false, "Not a circle member")
                .await;
            return TrustVerification {
                device_id: computed_id,
                is_trusted: false,
                trust_level: TrustLevel::Unverified,
                transport_used,
                verified_at: now,
                reason: Some("Not a circle member".into()),
            };
        }

        let member = match self.circle.get_member(&computed_id).await {
            Some(m) => m,
            None => {
                self.record_decision(&computed_id, "verify_peer", false, "Member data not found")
                    .await;
                return TrustVerification {
                    device_id: computed_id,
                    is_trusted: false,
                    trust_level: TrustLevel::Unverified,
                    transport_used,
                    verified_at: now,
                    reason: Some("Member data not found".into()),
                };
            }
        };

        if member.trust_level == TrustLevel::Revoked {
            self.record_decision(&computed_id, "verify_peer", false, "Trust revoked")
                .await;
            return TrustVerification {
                device_id: computed_id,
                is_trusted: false,
                trust_level: TrustLevel::Revoked,
                transport_used,
                verified_at: now,
                reason: Some("Trust revoked".into()),
            };
        }

        if member.public_key_der != presented_public_key {
            self.record_decision(&computed_id, "verify_peer", false, "Public key mismatch")
                .await;
            return TrustVerification {
                device_id: computed_id,
                is_trusted: false,
                trust_level: TrustLevel::Unverified,
                transport_used,
                verified_at: now,
                reason: Some("Public key mismatch".into()),
            };
        }

        let result = TrustVerification {
            device_id: computed_id.clone(),
            is_trusted: true,
            trust_level: member.trust_level,
            transport_used,
            verified_at: now,
            reason: None,
        };
        self.verification_cache
            .write()
            .await
            .insert(computed_id.clone(), result.clone());
        self.record_decision(&computed_id, "verify_peer", true, "Verification passed")
            .await;
        result
    }

    pub async fn is_authorized(&self, device_id: &str, action: &str) -> bool {
        let is_trusted = self.circle.is_trusted_member(device_id).await;
        self.record_decision(
            device_id,
            action,
            is_trusted,
            if is_trusted {
                "Authorized"
            } else {
                "Not authorized"
            },
        )
        .await;
        is_trusted
    }

    pub fn local_identity(&self) -> &DeviceIdentity {
        &self.local_identity
    }

    pub async fn cached_verification(&self, device_id: &str) -> Option<TrustVerification> {
        self.verification_cache.read().await.get(device_id).cloned()
    }

    pub async fn decision_log(&self) -> Vec<TrustDecision> {
        self.decisions.read().await.clone()
    }

    async fn record_decision(&self, device_id: &str, action: &str, allowed: bool, reason: &str) {
        let mut log = self.decisions.write().await;
        log.push(TrustDecision {
            device_id: device_id.to_string(),
            action: action.to_string(),
            allowed,
            reason: reason.to_string(),
            timestamp: Utc::now(),
        });
        let current_len = log.len();
        if current_len > 1000 {
            let overflow = current_len - 1000;
            log.drain(0..overflow);
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     fn make_key(seed: u8) -> Vec<u8> {
//         let mut key = vec![0x04];
//         key.extend_from_slice(&[seed; 32]);
//         key.extend_from_slice(&[seed + 1; 32]);
//         key
//     }

//     async fn setup() -> (TrustEngine, String) {
//         let owner_key = make_key(0xAA);
//         let owner_id = DeviceIdentity::compute_id(&owner_key);
//         let local_identity = DeviceIdentity::from_public_key(&owner_key).unwrap();
//         let circle = Arc::new(CircleMembership::new(
//             "test".into(),
//             owner_id.clone(),
//             owner_key.clone(),
//         ));
//         (TrustEngine::new(local_identity, circle), owner_id)
//     }

// #[tokio::test]
// async fn test_verify_known_member() {
//     let (engine, _) = setup().await;
//     let result = engine
//         .verify_peer(&make_key(0xAA), TransportType::Ethernet)
//         .await;
//     assert!(result.is_trusted);
// }

// #[tokio::test]
// async fn test_authorization_requires_verified() {
//     let (engine, owner_id) = setup().await;
//     assert!(!engine.is_authorized(&owner_id, "send").await);
//     engine
//         .circle
//         .set_trust_level(&owner_id, TrustLevel::Verified)
//         .await
//         .unwrap();
//     assert!(engine.is_authorized(&owner_id, "send").await);
//     // }
// }
