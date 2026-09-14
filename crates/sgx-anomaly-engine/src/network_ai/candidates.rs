//! Task 3 Deliverable 2: route candidate inventory.
//!
//! This module only describes possible routes. It does not decide whether a
//! route is safe to apply; `eligibility` performs that trust/policy filtering
//! before any future AI scoring step receives candidates.

use super::telemetry_adapter::{RouteKind, TrafficClass};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteCandidateMetadata {
    pub health_source: String,
    pub trust_authority: String,
    pub trust_state_version_seen: Option<String>,
    pub required_trust_level: String,
    pub health_note: String,
}

impl Default for RouteCandidateMetadata {
    fn default() -> Self {
        Self {
            health_source: "runtime-route-observation".to_string(),
            trust_authority: "Task2 Virtual Shift trust state".to_string(),
            trust_state_version_seen: None,
            required_trust_level: "trusted".to_string(),
            health_note: "candidate carries observed health only; Task2 remains trust authority"
                .to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteCandidate {
    pub route_id: String,
    pub source_node: String,
    pub destination_node: String,
    pub peer_id: String,
    pub kind: RouteKind,
    pub relay_ids: Vec<String>,
    pub hop_count: u8,
    pub traffic_class: TrafficClass,
    pub observed_available: bool,
    pub observed_healthy: bool,
    pub metadata: RouteCandidateMetadata,
}

impl RouteCandidate {
    pub fn direct(
        source_node: impl Into<String>,
        destination_node: impl Into<String>,
        traffic_class: TrafficClass,
    ) -> Self {
        let source_node = source_node.into();
        let destination_node = destination_node.into();
        let route_id = deterministic_route_id(&source_node, &destination_node, &[]);
        Self {
            route_id,
            source_node,
            destination_node: destination_node.clone(),
            peer_id: destination_node,
            kind: RouteKind::DirectP2p,
            relay_ids: Vec::new(),
            hop_count: 0,
            traffic_class,
            observed_available: true,
            observed_healthy: true,
            metadata: RouteCandidateMetadata::default(),
        }
    }

    pub fn relay(
        source_node: impl Into<String>,
        relay_id: impl Into<String>,
        destination_node: impl Into<String>,
        traffic_class: TrafficClass,
    ) -> Self {
        Self::multi_hop(
            source_node,
            vec![relay_id.into()],
            destination_node,
            traffic_class,
        )
    }

    pub fn multi_hop(
        source_node: impl Into<String>,
        relay_ids: Vec<String>,
        destination_node: impl Into<String>,
        traffic_class: TrafficClass,
    ) -> Self {
        let source_node = source_node.into();
        let destination_node = destination_node.into();
        let hop_count = relay_ids.len().min(u8::MAX as usize) as u8;
        let kind = match hop_count {
            0 => RouteKind::DirectP2p,
            1 => RouteKind::Relay,
            _ => RouteKind::MultiHopRelay,
        };
        let route_id = deterministic_route_id(&source_node, &destination_node, &relay_ids);
        Self {
            route_id,
            source_node,
            destination_node: destination_node.clone(),
            peer_id: destination_node,
            kind,
            relay_ids,
            hop_count,
            traffic_class,
            observed_available: true,
            observed_healthy: true,
            metadata: RouteCandidateMetadata::default(),
        }
    }

    pub fn with_health(mut self, available: bool, healthy: bool) -> Self {
        self.observed_available = available;
        self.observed_healthy = healthy;
        self
    }

    pub fn with_trust_state_version(mut self, version: impl Into<String>) -> Self {
        self.metadata.trust_state_version_seen = Some(version.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteCandidateInventory {
    pub source_node: String,
    pub destination_node: String,
    pub traffic_class: TrafficClass,
    pub candidates: Vec<RouteCandidate>,
}

impl RouteCandidateInventory {
    pub fn from_relays(
        source_node: impl Into<String>,
        destination_node: impl Into<String>,
        traffic_class: TrafficClass,
        relay_ids: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let source_node = source_node.into();
        let destination_node = destination_node.into();
        let relay_ids: Vec<String> = relay_ids.into_iter().map(Into::into).collect();

        let mut candidates = vec![RouteCandidate::direct(
            &source_node,
            &destination_node,
            traffic_class,
        )];

        for relay_id in &relay_ids {
            if relay_id != &source_node && relay_id != &destination_node {
                candidates.push(RouteCandidate::relay(
                    &source_node,
                    relay_id,
                    &destination_node,
                    traffic_class,
                ));
            }
        }

        if relay_ids.len() > 1 {
            candidates.push(RouteCandidate::multi_hop(
                &source_node,
                relay_ids,
                &destination_node,
                traffic_class,
            ));
        }

        Self {
            source_node,
            destination_node,
            traffic_class,
            candidates,
        }
    }
}

pub fn deterministic_route_id(
    source_node: &str,
    destination_node: &str,
    relay_ids: &[String],
) -> String {
    let clean = |value: &str| {
        value
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                    ch
                } else {
                    '-'
                }
            })
            .collect::<String>()
    };

    if relay_ids.is_empty() {
        format!("direct-{}-{}", clean(source_node), clean(destination_node))
    } else {
        let relays = relay_ids
            .iter()
            .map(|relay| clean(relay))
            .collect::<Vec<_>>()
            .join("-");
        format!(
            "relay-{}-via-{}-{}",
            clean(source_node),
            relays,
            clean(destination_node)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_direct_single_relay_and_multi_hop_candidates() {
        let inventory = RouteCandidateInventory::from_relays(
            "nodeA",
            "nodeB",
            TrafficClass::Operational,
            ["nodeC", "nodeD"],
        );

        assert_eq!(inventory.candidates.len(), 4);
        assert_eq!(inventory.candidates[0].kind, RouteKind::DirectP2p);
        assert_eq!(inventory.candidates[1].kind, RouteKind::Relay);
        assert_eq!(inventory.candidates[2].kind, RouteKind::Relay);
        assert_eq!(inventory.candidates[3].kind, RouteKind::MultiHopRelay);
        assert_eq!(inventory.candidates[3].hop_count, 2);
    }

    #[test]
    fn route_ids_are_deterministic() {
        let first = RouteCandidate::relay("nodeA", "nodeC", "nodeB", TrafficClass::Operational);
        let second = RouteCandidate::relay("nodeA", "nodeC", "nodeB", TrafficClass::Operational);

        assert_eq!(first.route_id, second.route_id);
        assert_eq!(first.route_id, "relay-nodeA-via-nodeC-nodeB");
    }

    #[test]
    fn candidates_attach_health_and_task2_trust_metadata_without_becoming_authority() {
        let candidate = RouteCandidate::relay("nodeA", "nodeC", "nodeB", TrafficClass::Operational)
            .with_health(true, false)
            .with_trust_state_version("task2-trust-v1");

        assert!(candidate.observed_available);
        assert!(!candidate.observed_healthy);
        assert_eq!(
            candidate.metadata.trust_authority,
            "Task2 Virtual Shift trust state"
        );
        assert_eq!(
            candidate.metadata.trust_state_version_seen.as_deref(),
            Some("task2-trust-v1")
        );
    }
}
