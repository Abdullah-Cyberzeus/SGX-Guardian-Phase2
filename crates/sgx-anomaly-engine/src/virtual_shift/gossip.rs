//! VS15: bounded `VSHIFT_ALERT` propagation behind a reusable transport API.
//!
//! The standalone repository has no board/Nebula gossip implementation yet.
//! `InMemoryGossipTransport` is therefore a deterministic 3-node relay
//! harness, not a new network listener. Production replaces only this
//! transport adapter while retaining the same message, dedup and receipt API.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::VShiftAlert;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipTopology {
    pub schema_version: u32,
    pub circle_id: String,
    pub members: Vec<String>,
    pub links: Vec<[String; 2]>,
}

impl GossipTopology {
    pub fn from_path(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let topology: Self = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        topology.validate()?;
        Ok(topology)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema_version != 1 || self.circle_id.trim().is_empty() {
            anyhow::bail!("Gossip topology needs schema version 1 and a Circle ID");
        }
        let unique: BTreeSet<_> = self.members.iter().collect();
        if unique.len() < 2
            || unique.len() != self.members.len()
            || self.members.iter().any(|id| id.trim().is_empty())
        {
            anyhow::bail!("Gossip topology needs at least two unique non-empty members");
        }
        for [left, right] in &self.links {
            if left == right || !unique.contains(left) || !unique.contains(right) {
                anyhow::bail!("Gossip topology has an invalid member link");
            }
        }
        Ok(())
    }

    fn neighbours(&self, node: &str) -> Vec<String> {
        self.links
            .iter()
            .filter_map(|[left, right]| {
                if left == node {
                    Some(right.clone())
                } else if right == node {
                    Some(left.clone())
                } else {
                    None
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GossipMessageType {
    VshiftAlert,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipDelivery {
    pub node_id: String,
    pub relay_hops: u32,
}

/// Timestamped receipt for one member.  In the standalone transport the
/// measured value is local simulated delivery time; a real Nebula adapter
/// will fill the same fields with actual network receive time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipDeliveryTiming {
    pub node_id: String,
    pub relay_hops: u32,
    pub received_at_ms: u64,
    pub delivery_time_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipBroadcastReceipt {
    pub schema_version: u32,
    pub message_type: GossipMessageType,
    pub alert_id: String,
    pub origin_node: String,
    pub circle_id: String,
    pub broadcast_started_at_ms: u64,
    pub broadcast_completed_at_ms: u64,
    pub delivered: Vec<GossipDelivery>,
    pub delivery_timings: Vec<GossipDeliveryTiming>,
    pub pending_offline_nodes: Vec<String>,
    pub duplicate_suppressed: bool,
    pub status: String,
}

/// Narrow seam for the future board/Nebula implementation.
pub trait GossipTransport {
    fn broadcast_vshift_alert(
        &mut self,
        origin_node: &str,
        alert: &VShiftAlert,
    ) -> anyhow::Result<GossipBroadcastReceipt>;
}

/// Deterministic transport harness: connected members relay once, and an
/// `(member, alert_id)` receipt prevents duplicate delivery.
#[derive(Debug, Clone)]
pub struct InMemoryGossipTransport {
    topology: GossipTopology,
    online: BTreeSet<String>,
    delivered: BTreeSet<(String, String)>,
    pending: BTreeMap<String, BTreeMap<String, VShiftAlert>>,
}

impl InMemoryGossipTransport {
    pub fn new(topology: GossipTopology) -> anyhow::Result<Self> {
        topology.validate()?;
        Ok(Self {
            online: topology.members.iter().cloned().collect(),
            topology,
            delivered: BTreeSet::new(),
            pending: BTreeMap::new(),
        })
    }

    pub fn set_online(&mut self, node_id: &str, online: bool) -> anyhow::Result<()> {
        if !self.topology.members.iter().any(|node| node == node_id) {
            anyhow::bail!("unknown gossip member '{node_id}'");
        }
        if online {
            self.online.insert(node_id.to_owned());
        } else {
            self.online.remove(node_id);
        }
        Ok(())
    }

    /// A returning peer receives each stored alert once. The receiving member
    /// will perform cryptographic authorization in VS16 before any apply.
    pub fn retry_offline_member(&mut self, node_id: &str) -> anyhow::Result<Vec<VShiftAlert>> {
        if !self.online.contains(node_id) {
            anyhow::bail!("offline member '{node_id}' cannot receive pending gossip");
        }
        let pending = self.pending.remove(node_id).unwrap_or_default();
        let mut alerts = Vec::new();
        for (alert_id, alert) in pending {
            if self.delivered.insert((node_id.to_owned(), alert_id)) {
                alerts.push(alert);
            }
        }
        Ok(alerts)
    }
}

impl GossipTransport for InMemoryGossipTransport {
    fn broadcast_vshift_alert(
        &mut self,
        origin_node: &str,
        alert: &VShiftAlert,
    ) -> anyhow::Result<GossipBroadcastReceipt> {
        let broadcast_started_at_ms = now_ms()?;
        alert.validate()?;
        if alert.circle_id != self.topology.circle_id {
            anyhow::bail!("alert Circle does not match gossip topology Circle");
        }
        if !self.topology.members.iter().any(|node| node == origin_node) {
            anyhow::bail!("origin '{origin_node}' is not a gossip member");
        }
        let already_seen = self.delivered.iter().any(|(_, id)| id == &alert.alert_id);
        if already_seen {
            return Ok(GossipBroadcastReceipt {
                schema_version: 1,
                message_type: GossipMessageType::VshiftAlert,
                alert_id: alert.alert_id.clone(),
                origin_node: origin_node.into(),
                circle_id: alert.circle_id.clone(),
                broadcast_started_at_ms,
                broadcast_completed_at_ms: now_ms()?,
                delivered: vec![],
                delivery_timings: vec![],
                pending_offline_nodes: vec![],
                duplicate_suppressed: true,
                status: "duplicate_suppressed".into(),
            });
        }
        let mut delivered = Vec::new();
        let mut delivery_timings = Vec::new();
        let mut offline = BTreeSet::new();
        let mut visited = BTreeSet::from([origin_node.to_owned()]);
        let mut queue = VecDeque::from([(origin_node.to_owned(), 0u32)]);
        while let Some((current, hops)) = queue.pop_front() {
            for neighbour in self.topology.neighbours(&current) {
                if !visited.insert(neighbour.clone()) {
                    continue;
                }
                if !self.online.contains(&neighbour) {
                    self.pending
                        .entry(neighbour.clone())
                        .or_default()
                        .insert(alert.alert_id.clone(), alert.clone());
                    offline.insert(neighbour);
                    continue;
                }
                self.delivered
                    .insert((neighbour.clone(), alert.alert_id.clone()));
                delivered.push(GossipDelivery {
                    node_id: neighbour.clone(),
                    relay_hops: hops + 1,
                });
                let received_at_ms = now_ms()?;
                delivery_timings.push(GossipDeliveryTiming {
                    node_id: neighbour.clone(),
                    relay_hops: hops + 1,
                    received_at_ms,
                    delivery_time_ms: received_at_ms.saturating_sub(alert.issued_at_ms),
                });
                queue.push_back((neighbour, hops + 1));
            }
        }
        delivered.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        delivery_timings.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        Ok(GossipBroadcastReceipt {
            schema_version: 1,
            message_type: GossipMessageType::VshiftAlert,
            alert_id: alert.alert_id.clone(),
            origin_node: origin_node.into(),
            circle_id: alert.circle_id.clone(),
            broadcast_started_at_ms,
            broadcast_completed_at_ms: now_ms()?,
            delivered,
            delivery_timings,
            pending_offline_nodes: offline.into_iter().collect(),
            duplicate_suppressed: false,
            status: "broadcast_simulated_not_applied".into(),
        })
    }
}

fn now_ms() -> anyhow::Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

pub fn write_gossip_receipt(
    root: impl AsRef<Path>,
    receipt: &GossipBroadcastReceipt,
) -> anyhow::Result<PathBuf> {
    if receipt.alert_id.trim().is_empty() || receipt.alert_id.contains(['/', '\\']) {
        anyhow::bail!("gossip alert ID must be file-name-safe");
    }
    let directory = root.as_ref().join(&receipt.alert_id);
    std::fs::create_dir_all(&directory)?;
    let path = directory.join("broadcast_receipt.json");
    std::fs::write(&path, serde_json::to_string_pretty(receipt)?)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtual_shift::{
        canonical_policy_bytes, sha256_hex, GuardianKeyManager, VersionedPolicyCandidate,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQ: AtomicUsize = AtomicUsize::new(0);
    fn topology() -> GossipTopology {
        GossipTopology {
            schema_version: 1,
            circle_id: "circle-test".into(),
            members: vec!["nodeA".into(), "nodeB".into(), "nodeC".into()],
            links: vec![
                ["nodeA".into(), "nodeB".into()],
                ["nodeB".into(), "nodeC".into()],
            ],
        }
    }
    fn alert() -> VShiftAlert {
        let root = std::env::temp_dir().join(format!(
            "vshift_gossip_{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let config = root.join("key.json");
        std::fs::write(
            &config,
            r#"{"schema_version":1,"guardian_id":"guardian-test","algorithm":"ed25519"}"#,
        )
        .unwrap();
        let manager = GuardianKeyManager::from_config(&config, root.join("keys")).unwrap();
        let mut policy = VersionedPolicyCandidate {
            schema_version: 1,
            policy_id: "p-22".into(),
            circle_id: "circle-test".into(),
            parent_policy_version: 21,
            policy_version: 22,
            source_recommendation_id: "rec-1".into(),
            source_anomaly_id: "anom-1".into(),
            actions: vec![],
            rules: vec![],
            applicable_members: vec!["nodeB".into()],
            canonical_sha256: String::new(),
            status: "candidate_not_signed".into(),
        };
        let blob = canonical_policy_bytes(&policy).unwrap();
        policy.canonical_sha256 = sha256_hex(&blob);
        let (signature, public_key) = manager.sign(&blob).unwrap();
        let _ = std::fs::remove_dir_all(root);
        VShiftAlert {
            schema_version: 1,
            alert_id: "alert-1".into(),
            circle_id: "circle-test".into(),
            policy_version: 22,
            policy_blob: blob,
            policy_hash_hex: policy.canonical_sha256.clone(),
            guardian_signature_hex: signature,
            guardian_public_key_hex: public_key,
            signer_id: "guardian-test".into(),
            signature_algorithm: "ed25519".into(),
            anomaly_id: "anom-1".into(),
            recommendation_id: "rec-1".into(),
            anomaly_score: 0.9,
            confidence: 0.9,
            ai_justification: "test".into(),
            issued_at_ms: 1_000,
            expires_at_ms: 61_000,
        }
    }
    #[test]
    fn three_node_relay_delivers_once_to_each_member() {
        let mut transport = InMemoryGossipTransport::new(topology()).unwrap();
        let receipt = transport.broadcast_vshift_alert("nodeA", &alert()).unwrap();
        assert_eq!(
            receipt.delivered,
            vec![
                GossipDelivery {
                    node_id: "nodeB".into(),
                    relay_hops: 1
                },
                GossipDelivery {
                    node_id: "nodeC".into(),
                    relay_hops: 2
                }
            ]
        );
        assert!(!receipt.duplicate_suppressed);
    }
    #[test]
    fn duplicate_alert_is_suppressed() {
        let mut transport = InMemoryGossipTransport::new(topology()).unwrap();
        let alert = alert();
        transport.broadcast_vshift_alert("nodeA", &alert).unwrap();
        let second = transport.broadcast_vshift_alert("nodeA", &alert).unwrap();
        assert!(second.duplicate_suppressed);
        assert!(second.delivered.is_empty());
    }
    #[test]
    fn offline_member_is_queued_then_receives_once_after_return() {
        let mut transport = InMemoryGossipTransport::new(topology()).unwrap();
        transport.set_online("nodeC", false).unwrap();
        let receipt = transport.broadcast_vshift_alert("nodeA", &alert()).unwrap();
        assert_eq!(receipt.pending_offline_nodes, vec!["nodeC"]);
        transport.set_online("nodeC", true).unwrap();
        assert_eq!(transport.retry_offline_member("nodeC").unwrap().len(), 1);
        assert!(transport.retry_offline_member("nodeC").unwrap().is_empty());
    }
}
