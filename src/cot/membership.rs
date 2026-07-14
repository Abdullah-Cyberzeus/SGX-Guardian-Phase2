// src/cot/membership.rs
// ============================================================
// Circle of Trust Membership Manager
// Tracks circle members by device identity.
// Members persist across transport changes.
// ============================================================

use crate::cot::types::{CotError, CotResult, PeerEndpoint, TransportType};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

const MEMBERS_PATH: &str = "/var/lib/sgx-guardian/cot/members.json";
const MEMBERS_PATH_ENV: &str = "SGX_GUARDIAN_COT_MEMBERS_PATH";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberRole {
    Owner,
    Member,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    Unverified,
    Verified,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircleMember {
    pub device_id: String,
    pub display_name: Option<String>,
    pub role: MemberRole,
    pub trust_level: TrustLevel,
    pub endpoints: Vec<PeerEndpoint>,
    pub joined_at: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    pub public_key_der: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vc_id: Option<String>,
}

impl CircleMember {
    pub fn new(
        device_id: String,
        role: MemberRole,
        public_key_der: Vec<u8>,
        vc_id: Option<String>,
    ) -> Self {
        Self {
            device_id,
            display_name: None,
            role,
            trust_level: TrustLevel::Unverified,
            endpoints: Vec::new(),
            joined_at: Utc::now(),
            last_seen: None,
            public_key_der,
            vc_id,
        }
    }

    pub fn upsert_endpoint(&mut self, endpoint: PeerEndpoint) {
        self.endpoints
            .retain(|ep| ep.transport_type != endpoint.transport_type);
        self.endpoints.push(endpoint);
    }

    pub fn best_endpoint(&self) -> Option<&PeerEndpoint> {
        self.endpoints
            .iter()
            .filter(|ep| ep.reachable)
            .min_by_key(|ep| ep.transport_type.default_priority())
    }

    pub fn endpoint_for(&self, tt: TransportType) -> Option<&PeerEndpoint> {
        self.endpoints.iter().find(|ep| ep.transport_type == tt)
    }

    pub fn touch(&mut self) {
        self.last_seen = Some(Utc::now());
    }
}

pub struct CircleMembership {
    circle_id: String,
    members: Arc<RwLock<HashMap<String, CircleMember>>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct MembershipSnapshot {
    circle_id: String,
    members: HashMap<String, CircleMember>,
}

impl CircleMembership {
    pub fn new(circle_id: String, owner_device_id: String, owner_pubkey: Vec<u8>) -> Self {
        let mut members = HashMap::new();
        let owner = CircleMember::new(
            owner_device_id.clone(),
            MemberRole::Owner,
            owner_pubkey,
            None,
        );
        members.insert(owner_device_id, owner);
        let circle = Self {
            circle_id,
            members: Arc::new(RwLock::new(members)),
        };
        circle.persist_default_background();
        circle
    }

    pub fn circle_id(&self) -> &str {
        &self.circle_id
    }

    pub async fn add_member(&self, device_id: String, public_key_der: Vec<u8>) -> CotResult<()> {
        self.add_member_with_vc(device_id, public_key_der, None)
            .await
    }

    pub async fn add_member_with_vc(
        &self,
        device_id: String,
        public_key_der: Vec<u8>,
        vc_id: Option<String>,
    ) -> CotResult<()> {
        let mut members = self.members.write().await;
        if members.contains_key(&device_id) {
            return Err(CotError::MembershipDenied(format!(
                "{} already a member",
                device_id
            )));
        }
        members.insert(
            device_id.clone(),
            CircleMember::new(device_id, MemberRole::Member, public_key_der, vc_id),
        );
        drop(members);
        self.persist_default().await;
        Ok(())
    }

    pub async fn is_member(&self, device_id: &str) -> bool {
        self.members.read().await.contains_key(device_id)
    }

    pub async fn is_trusted_member(&self, device_id: &str) -> bool {
        let members = self.members.read().await;
        matches!(members.get(device_id), Some(m) if m.trust_level == TrustLevel::Verified)
    }

    pub async fn get_member(&self, device_id: &str) -> Option<CircleMember> {
        self.members.read().await.get(device_id).cloned()
    }

    pub async fn set_trust_level(&self, device_id: &str, level: TrustLevel) -> CotResult<()> {
        let mut members = self.members.write().await;
        match members.get_mut(device_id) {
            Some(m) => {
                m.trust_level = level;
                drop(members);
                self.persist_default().await;
                Ok(())
            }
            None => Err(CotError::PeerNotFound(device_id.to_string())),
        }
    }

    pub async fn update_endpoint(&self, device_id: &str, endpoint: PeerEndpoint) -> CotResult<()> {
        let mut members = self.members.write().await;
        match members.get_mut(device_id) {
            Some(m) => {
                m.upsert_endpoint(endpoint);
                drop(members);
                self.persist_default().await;
                Ok(())
            }
            None => Err(CotError::PeerNotFound(device_id.to_string())),
        }
    }

    pub async fn remove_member(&self, device_id: &str) -> CotResult<()> {
        let mut members = self.members.write().await;
        if members.remove(device_id).is_none() {
            return Err(CotError::PeerNotFound(device_id.to_string()));
        }
        drop(members);
        self.persist_default().await;
        Ok(())
    }

    pub async fn member_ids(&self) -> Vec<String> {
        self.members.read().await.keys().cloned().collect()
    }

    pub async fn member_count(&self) -> usize {
        self.members.read().await.len()
    }

    pub async fn summary(&self) -> String {
        let members = self.members.read().await;
        let verified = members
            .values()
            .filter(|m| m.trust_level == TrustLevel::Verified)
            .count();
        format!(
            "Circle {}: {} members ({} verified)",
            self.circle_id,
            members.len(),
            verified
        )
    }

    pub async fn save(&self, path: &str) -> std::io::Result<()> {
        let snapshot = MembershipSnapshot {
            circle_id: self.circle_id.clone(),
            members: self.members.read().await.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&snapshot)?;
        let path = PathBuf::from(path);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let tmp = path.with_extension("tmp");
        tokio::fs::write(&tmp, bytes).await?;
        tokio::fs::rename(tmp, path).await
    }

    pub async fn load(path: &str) -> std::io::Result<Self> {
        let data = tokio::fs::read(path).await?;
        let snapshot: MembershipSnapshot = serde_json::from_slice(&data)?;
        Ok(Self {
            circle_id: snapshot.circle_id,
            members: Arc::new(RwLock::new(snapshot.members)),
        })
    }

    async fn persist_default(&self) {
        if let Err(err) = self.save(&default_members_path().to_string_lossy()).await {
            eprintln!("⚠️ Failed to persist circle membership: {}", err);
        }
    }

    fn persist_default_background(&self) {
        let circle_id = self.circle_id.clone();
        let members = self.members.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let snapshot = MembershipSnapshot {
                    circle_id,
                    members: members.read().await.clone(),
                };
                if let Ok(bytes) = serde_json::to_vec_pretty(&snapshot) {
                    let path = default_members_path();
                    if let Some(parent) = path.parent() {
                        let _ = tokio::fs::create_dir_all(parent).await;
                    }
                    let tmp = path.with_extension("tmp");
                    let _ = tokio::fs::write(&tmp, bytes).await;
                    let _ = tokio::fs::rename(tmp, path).await;
                }
            });
        }
    }
}

fn default_members_path() -> PathBuf {
    std::env::var(MEMBERS_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(MEMBERS_PATH))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_key() -> Vec<u8> {
        vec![0x04; 65]
    }

    #[tokio::test]
    async fn test_create_circle_with_owner() {
        let circle = CircleMembership::new("c1".into(), "owner".into(), dummy_key());
        assert_eq!(circle.member_count().await, 1);
        assert!(circle.is_member("owner").await);
    }

    #[tokio::test]
    async fn test_add_member() {
        let circle = CircleMembership::new("c1".into(), "owner".into(), dummy_key());
        circle.add_member("m1".into(), dummy_key()).await.unwrap();
        assert_eq!(circle.member_count().await, 2);
    }

    #[tokio::test]
    async fn test_duplicate_rejected() {
        let circle = CircleMembership::new("c1".into(), "owner".into(), dummy_key());
        assert!(circle
            .add_member("owner".into(), dummy_key())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_trust_level() {
        let circle = CircleMembership::new("c1".into(), "owner".into(), dummy_key());
        circle
            .set_trust_level("owner", TrustLevel::Verified)
            .await
            .unwrap();
        assert!(circle.is_trusted_member("owner").await);
    }

    #[tokio::test]
    async fn test_endpoint_upsert() {
        let circle = CircleMembership::new("c1".into(), "owner".into(), dummy_key());
        let ep = PeerEndpoint::new(
            "owner".into(),
            TransportType::Ethernet,
            "1.2.3.4:50051".into(),
        );
        circle.update_endpoint("owner", ep).await.unwrap();
        let m = circle.get_member("owner").await.unwrap();
        assert_eq!(m.endpoints.len(), 1);
    }

    #[tokio::test]
    async fn test_remove_member() {
        let circle = CircleMembership::new("c1".into(), "owner".into(), dummy_key());
        circle.add_member("m1".into(), dummy_key()).await.unwrap();
        circle.remove_member("m1").await.unwrap();
        assert!(!circle.is_member("m1").await);
    }
}
