//! Task 3 Deliverable 2: route eligibility filtering.
//!
//! Senior rule: trust filtering happens before AI optimization. The future
//! predictor/RL layers should receive only `eligible` routes from this module.

use super::candidates::RouteCandidate;
use super::telemetry_adapter::TrafficClass;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EligibilityReason {
    Eligible,
    RouteUnavailable,
    RouteUnhealthy,
    StaleTrustState,
    UntrustedPeer,
    QuarantinedPeer,
    ProhibitedRoute,
    SecurityControlRequiresTrustedRoute,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EligibilityDecision {
    pub route_id: String,
    pub eligible: bool,
    pub reason: EligibilityReason,
    pub candidate: RouteCandidate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EligibleRouteSet {
    pub trust_state_version: String,
    pub traffic_class: TrafficClass,
    pub safe_fallback_active: bool,
    pub eligible: Vec<RouteCandidate>,
    pub rejected: Vec<EligibilityDecision>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustStateSnapshot {
    pub version: String,
    pub fresh: bool,
    pub observed_at_ms: Option<u64>,
    pub max_age_ms: Option<u64>,
    pub missing: bool,
    pub trusted_peers: HashSet<String>,
    pub quarantined_peers: HashSet<String>,
    pub prohibited_route_ids: HashSet<String>,
}

impl TrustStateSnapshot {
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            fresh: true,
            observed_at_ms: None,
            max_age_ms: None,
            missing: false,
            trusted_peers: HashSet::new(),
            quarantined_peers: HashSet::new(),
            prohibited_route_ids: HashSet::new(),
        }
    }

    pub fn missing(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            fresh: false,
            observed_at_ms: None,
            max_age_ms: None,
            missing: true,
            trusted_peers: HashSet::new(),
            quarantined_peers: HashSet::new(),
            prohibited_route_ids: HashSet::new(),
        }
    }

    pub fn trust_peer(mut self, peer: impl Into<String>) -> Self {
        self.trusted_peers.insert(peer.into());
        self
    }

    pub fn quarantine_peer(mut self, peer: impl Into<String>) -> Self {
        self.quarantined_peers.insert(peer.into());
        self
    }

    pub fn prohibit_route(mut self, route_id: impl Into<String>) -> Self {
        self.prohibited_route_ids.insert(route_id.into());
        self
    }

    pub fn stale(mut self) -> Self {
        self.fresh = false;
        self
    }

    pub fn observed_at(mut self, observed_at_ms: u64) -> Self {
        self.observed_at_ms = Some(observed_at_ms);
        self
    }

    pub fn max_age(mut self, max_age_ms: u64) -> Self {
        self.max_age_ms = Some(max_age_ms);
        self
    }

    fn is_fresh_for(&self, now_ms: Option<u64>) -> bool {
        if self.missing || !self.fresh {
            return false;
        }
        match (now_ms, self.observed_at_ms, self.max_age_ms) {
            (Some(now), Some(observed), Some(max_age)) => now.saturating_sub(observed) <= max_age,
            _ => true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct EligibilityFilter;

impl EligibilityFilter {
    pub fn filter(
        &self,
        candidates: Vec<RouteCandidate>,
        trust_state: &TrustStateSnapshot,
    ) -> EligibleRouteSet {
        self.filter_with_now(candidates, trust_state, None)
    }

    pub fn filter_at(
        &self,
        candidates: Vec<RouteCandidate>,
        trust_state: &TrustStateSnapshot,
        now_ms: u64,
    ) -> EligibleRouteSet {
        self.filter_with_now(candidates, trust_state, Some(now_ms))
    }

    fn filter_with_now(
        &self,
        candidates: Vec<RouteCandidate>,
        trust_state: &TrustStateSnapshot,
        now_ms: Option<u64>,
    ) -> EligibleRouteSet {
        let traffic_class = candidates
            .first()
            .map(|candidate| candidate.traffic_class)
            .unwrap_or(TrafficClass::Operational);
        let mut eligible = Vec::new();
        let mut rejected = Vec::new();
        let trust_is_fresh = trust_state.is_fresh_for(now_ms);

        for candidate in candidates {
            let reason = evaluate_candidate(&candidate, trust_state, trust_is_fresh);
            if reason == EligibilityReason::Eligible {
                eligible.push(candidate);
            } else {
                rejected.push(EligibilityDecision {
                    route_id: candidate.route_id.clone(),
                    eligible: false,
                    reason,
                    candidate,
                });
            }
        }

        EligibleRouteSet {
            trust_state_version: trust_state.version.clone(),
            traffic_class,
            safe_fallback_active: !trust_is_fresh,
            eligible,
            rejected,
        }
    }
}

fn evaluate_candidate(
    candidate: &RouteCandidate,
    trust_state: &TrustStateSnapshot,
    trust_is_fresh: bool,
) -> EligibilityReason {
    if !candidate.observed_available {
        return EligibilityReason::RouteUnavailable;
    }
    if !candidate.observed_healthy {
        return EligibilityReason::RouteUnhealthy;
    }
    if !trust_is_fresh {
        return EligibilityReason::StaleTrustState;
    }
    if trust_state
        .prohibited_route_ids
        .contains(&candidate.route_id)
    {
        return EligibilityReason::ProhibitedRoute;
    }

    let route_peers = candidate
        .relay_ids
        .iter()
        .chain(std::iter::once(&candidate.destination_node));

    for peer in route_peers {
        if trust_state.quarantined_peers.contains(peer) {
            return EligibilityReason::QuarantinedPeer;
        }
        if !trust_state.trusted_peers.contains(peer) {
            return match candidate.traffic_class {
                TrafficClass::SecurityControl => {
                    EligibilityReason::SecurityControlRequiresTrustedRoute
                }
                TrafficClass::Operational => EligibilityReason::UntrustedPeer,
            };
        }
    }

    EligibilityReason::Eligible
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_ai::candidates::RouteCandidateInventory;

    fn inventory() -> Vec<RouteCandidate> {
        RouteCandidateInventory::from_relays(
            "nodeA",
            "nodeB",
            TrafficClass::SecurityControl,
            ["nodeC", "nodeD"],
        )
        .candidates
    }

    #[test]
    fn filters_after_trust_state_and_returns_only_eligible_routes() {
        let trust_state = TrustStateSnapshot::new("trust-v1")
            .trust_peer("nodeB")
            .trust_peer("nodeC")
            .quarantine_peer("nodeD");

        let result = EligibilityFilter.filter(inventory(), &trust_state);

        assert!(result
            .eligible
            .iter()
            .any(|route| route.route_id == "direct-nodeA-nodeB"));
        assert!(result
            .eligible
            .iter()
            .any(|route| route.route_id == "relay-nodeA-via-nodeC-nodeB"));
        assert!(result
            .rejected
            .iter()
            .any(|decision| decision.reason == EligibilityReason::QuarantinedPeer));
    }

    #[test]
    fn stale_trust_state_rejects_before_ai_can_score() {
        let trust_state = TrustStateSnapshot::new("trust-v1")
            .trust_peer("nodeB")
            .trust_peer("nodeC")
            .trust_peer("nodeD")
            .stale();

        let result = EligibilityFilter.filter(inventory(), &trust_state);

        assert!(result.eligible.is_empty());
        assert!(result.safe_fallback_active);
        assert!(result
            .rejected
            .iter()
            .all(|decision| decision.reason == EligibilityReason::StaleTrustState));
    }

    #[test]
    fn prohibited_route_is_never_eligible_even_when_peer_is_trusted() {
        let prohibited = "relay-nodeA-via-nodeC-nodeB";
        let trust_state = TrustStateSnapshot::new("trust-v1")
            .trust_peer("nodeB")
            .trust_peer("nodeC")
            .trust_peer("nodeD")
            .prohibit_route(prohibited);

        let result = EligibilityFilter.filter(inventory(), &trust_state);

        assert!(result
            .rejected
            .iter()
            .any(|decision| decision.route_id == prohibited
                && decision.reason == EligibilityReason::ProhibitedRoute));
    }

    #[test]
    fn unhealthy_routes_are_excluded() {
        let candidates = vec![
            RouteCandidate::direct("nodeA", "nodeB", TrafficClass::Operational)
                .with_health(true, false),
        ];
        let trust_state = TrustStateSnapshot::new("trust-v1").trust_peer("nodeB");

        let result = EligibilityFilter.filter(candidates, &trust_state);

        assert!(result.eligible.is_empty());
        assert_eq!(result.rejected[0].reason, EligibilityReason::RouteUnhealthy);
    }

    #[test]
    fn missing_task2_trust_state_triggers_safe_fallback() {
        let result = EligibilityFilter.filter(inventory(), &TrustStateSnapshot::missing("missing"));

        assert!(result.safe_fallback_active);
        assert!(result.eligible.is_empty());
        assert!(result
            .rejected
            .iter()
            .all(|decision| decision.reason == EligibilityReason::StaleTrustState));
    }

    #[test]
    fn old_task2_trust_state_is_automatically_stale_by_age() {
        let trust_state = TrustStateSnapshot::new("trust-v1")
            .trust_peer("nodeB")
            .trust_peer("nodeC")
            .trust_peer("nodeD")
            .observed_at(1_000)
            .max_age(500);

        let result = EligibilityFilter.filter_at(inventory(), &trust_state, 2_000);

        assert!(result.safe_fallback_active);
        assert!(result.eligible.is_empty());
    }
}
