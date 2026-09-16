//! Task 3 Deliverable 8: multi-relay load balancing.

use super::candidates::RouteCandidate;
use super::predictor::RoutePredictionSet;
use super::telemetry_adapter::{RouteKind, TrafficClass};
use serde::{Deserialize, Serialize};

pub const NETWORK_AI_RELAY_BALANCER_VERSION: &str = "network-ai-relay-balancer-v2";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayBalanceConfig {
    pub overload_utilization_pct: f64,
    pub minimum_overload_factor: f64,
    pub missing_health_factor: f64,
    pub recovery_ramp_seconds: u64,
    pub high_priority_best_route_floor: f64,
}

impl Default for RelayBalanceConfig {
    fn default() -> Self {
        Self {
            overload_utilization_pct: 80.0,
            minimum_overload_factor: 0.25,
            missing_health_factor: 0.50,
            recovery_ramp_seconds: 120,
            high_priority_best_route_floor: 0.60,
        }
    }
}

/// Runtime health is input evidence only. Task2 continues to decide whether a
/// route is trusted/eligible before this module receives it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayRuntimeHealth {
    pub route_id: String,
    pub available: bool,
    pub healthy: bool,
    /// `None` means utilization telemetry was not supplied; it is never
    /// interpreted as an idle (0%) relay.
    pub utilization_pct: Option<f64>,
    pub recovered_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayWeight {
    pub route_id: String,
    pub rank: usize,
    pub weight: f64,
    pub overload_factor: f64,
    pub recovery_factor: f64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayWeightSet {
    pub schema_version: String,
    pub traffic_class: TrafficClass,
    pub total_relay_routes: usize,
    pub total_weight: f64,
    pub weights: Vec<RelayWeight>,
}

#[derive(Debug, Clone)]
pub struct MultiRelayLoadBalancer {
    pub config: RelayBalanceConfig,
}

impl Default for MultiRelayLoadBalancer {
    fn default() -> Self {
        Self {
            config: RelayBalanceConfig::default(),
        }
    }
}

impl MultiRelayLoadBalancer {
    pub fn calculate(
        &self,
        candidates: &[RouteCandidate],
        predictions: &RoutePredictionSet,
    ) -> RelayWeightSet {
        self.calculate_with_health(candidates, predictions, TrafficClass::Operational, &[], 0)
    }

    pub fn calculate_with_health(
        &self,
        candidates: &[RouteCandidate],
        predictions: &RoutePredictionSet,
        traffic_class: TrafficClass,
        runtime_health: &[RelayRuntimeHealth],
        now_ms: u64,
    ) -> RelayWeightSet {
        let mut relay_scores = predictions
            .predictions
            .iter()
            .filter_map(|prediction| {
                let candidate = candidates
                    .iter()
                    .find(|candidate| candidate.route_id == prediction.route_id)?;
                let is_relay =
                    matches!(candidate.kind, RouteKind::Relay | RouteKind::MultiHopRelay);
                if !is_relay || !candidate.observed_available || !candidate.observed_healthy {
                    return None;
                }
                let health = runtime_health
                    .iter()
                    .find(|health| health.route_id == candidate.route_id);
                if health.is_some_and(|health| !health.available || !health.healthy) {
                    return None;
                }
                let utilization = health.and_then(|health| health.utilization_pct);
                let health_factor = if utilization.is_some() {
                    1.0
                } else {
                    self.config.missing_health_factor.clamp(0.0, 1.0)
                };
                let overload_factor = utilization
                    .map(|value| self.overload_factor(value))
                    .unwrap_or(1.0);
                let recovery_factor = self.recovery_factor(
                    health.and_then(|health| health.recovered_at_ms),
                    now_ms,
                );
                let usable_score = prediction.quality_score.max(0.0)
                    * overload_factor
                    * recovery_factor
                    * health_factor;
                let health_reason = utilization
                    .map(|value| format!("utilization={value:.1}%"))
                    .unwrap_or_else(|| {
                        format!(
                            "runtime_health_missing; utilization=unknown; health_factor={health_factor:.2}"
                        )
                    });
                Some((
                    candidate.route_id.clone(),
                    usable_score,
                    overload_factor,
                    recovery_factor,
                    format!(
                        "{}; {health_reason}, overload_factor={overload_factor:.2}, recovery_factor={recovery_factor:.2}",
                        prediction.reason
                    ),
                ))
            })
            .collect::<Vec<_>>();

        relay_scores.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        let total_score: f64 = relay_scores.iter().map(|(_, score, _, _, _)| *score).sum();
        let mut raw_weights = if total_score > 0.0 {
            relay_scores
                .iter()
                .map(|(_, score, _, _, _)| score / total_score)
                .collect::<Vec<_>>()
        } else if relay_scores.is_empty() {
            Vec::new()
        } else {
            vec![1.0 / relay_scores.len() as f64; relay_scores.len()]
        };

        // Security/control traffic must prefer the strongest route, while all
        // candidates remain pre-filtered by Task2 trust eligibility.
        if traffic_class == TrafficClass::SecurityControl && raw_weights.len() > 1 {
            let floor = self.config.high_priority_best_route_floor.clamp(0.0, 1.0);
            if raw_weights[0] < floor {
                let remaining = (1.0 - floor).max(0.0);
                let other_total: f64 = raw_weights.iter().skip(1).sum();
                let other_count = raw_weights.len() - 1;
                raw_weights[0] = floor;
                for weight in raw_weights.iter_mut().skip(1) {
                    *weight = if other_total > 0.0 {
                        *weight / other_total * remaining
                    } else {
                        remaining / other_count as f64
                    };
                }
            }
        }

        let mut weights = relay_scores
            .into_iter()
            .zip(raw_weights)
            .enumerate()
            .map(
                |(index, ((route_id, _, overload_factor, recovery_factor, reason), weight))| {
                    RelayWeight {
                        route_id,
                        rank: index + 1,
                        weight: round4(weight),
                        overload_factor,
                        recovery_factor,
                        reason: format!("weight from trusted eligible predicted quality; {reason}"),
                    }
                },
            )
            .collect::<Vec<_>>();
        // Display/persisted weights are rounded to four decimals. Correct the
        // rank-1 bucket once so the stable persisted sum remains exactly 1.0.
        let rounded_total: f64 = weights.iter().map(|weight| weight.weight).sum();
        if let Some(first) = weights.first_mut() {
            first.weight = round4((first.weight + (1.0 - rounded_total)).max(0.0));
        }
        let total_weight = weights.iter().map(|weight| weight.weight).sum();

        RelayWeightSet {
            schema_version: NETWORK_AI_RELAY_BALANCER_VERSION.to_string(),
            traffic_class,
            total_relay_routes: weights.len(),
            total_weight,
            weights,
        }
    }

    fn overload_factor(&self, utilization_pct: f64) -> f64 {
        if utilization_pct <= self.config.overload_utilization_pct {
            1.0
        } else {
            let excess_ratio = ((utilization_pct - self.config.overload_utilization_pct)
                / (100.0 - self.config.overload_utilization_pct).max(1.0))
            .clamp(0.0, 1.0);
            (1.0 - excess_ratio * (1.0 - self.config.minimum_overload_factor))
                .max(self.config.minimum_overload_factor)
        }
    }

    fn recovery_factor(&self, recovered_at_ms: Option<u64>, now_ms: u64) -> f64 {
        let Some(recovered_at_ms) = recovered_at_ms else {
            return 1.0;
        };
        if now_ms <= recovered_at_ms {
            return 0.20;
        }
        let elapsed = now_ms.saturating_sub(recovered_at_ms) as f64;
        let ramp =
            (elapsed / (self.config.recovery_ramp_seconds.max(1) * 1000) as f64).clamp(0.0, 1.0);
        0.20 + 0.80 * ramp
    }
}

fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_ai::{
        RouteCandidateInventory, RouteHistoryEntry, RouteHistoryStore, RoutePredictor,
        SimpleRouteQualityPredictor, TrafficClass,
    };

    #[test]
    fn relay_weights_are_normalized() {
        let inventory = RouteCandidateInventory::from_relays(
            "nodeA",
            "nodeB",
            TrafficClass::SecurityControl,
            ["nodeC", "nodeD"],
        );
        let mut history = RouteHistoryStore::new(1.0, 10);
        history.record(RouteHistoryEntry {
            ts_ms: 1000,
            route_id: "relay-nodeA-via-nodeC-nodeB".to_string(),
            rtt_ms: 15.0,
            packet_loss_pct: 0.5,
            throughput_mbps: Some(55.0),
            bandwidth_utilization_pct: Some(40.0),
            route_available: true,
            route_healthy: true,
            switched_route: false,
        });
        history.record(RouteHistoryEntry {
            ts_ms: 1000,
            route_id: "relay-nodeA-via-nodeD-nodeB".to_string(),
            rtt_ms: 30.0,
            packet_loss_pct: 2.0,
            throughput_mbps: Some(30.0),
            bandwidth_utilization_pct: Some(50.0),
            route_available: true,
            route_healthy: true,
            switched_route: false,
        });
        let predictions =
            SimpleRouteQualityPredictor::default().predict(&inventory.candidates, &history);
        let weights =
            MultiRelayLoadBalancer::default().calculate(&inventory.candidates, &predictions);

        let total: f64 = weights.weights.iter().map(|weight| weight.weight).sum();
        assert!((total - 1.0).abs() < 0.0002);
        assert_eq!(weights.total_relay_routes, 3);
    }

    #[test]
    fn unhealthy_relay_gets_removed_from_weights() {
        let mut inventory = RouteCandidateInventory::from_relays(
            "nodeA",
            "nodeB",
            TrafficClass::Operational,
            ["nodeC"],
        );
        for candidate in &mut inventory.candidates {
            if candidate.route_id == "relay-nodeA-via-nodeC-nodeB" {
                candidate.observed_healthy = false;
            }
        }
        let history = RouteHistoryStore::new(1.0, 10);
        let predictions =
            SimpleRouteQualityPredictor::default().predict(&inventory.candidates, &history);
        let weights =
            MultiRelayLoadBalancer::default().calculate(&inventory.candidates, &predictions);

        assert!(weights.weights.is_empty());
    }

    #[test]
    fn overload_failed_and_recovered_relays_get_safe_weight_treatment() {
        let inventory = RouteCandidateInventory::from_relays(
            "nodeA",
            "nodeB",
            TrafficClass::Operational,
            ["nodeC", "nodeD"],
        );
        let mut history = RouteHistoryStore::new(1.0, 10);
        for (route_id, rtt) in [
            ("relay-nodeA-via-nodeC-nodeB", 10.0),
            ("relay-nodeA-via-nodeD-nodeB", 12.0),
        ] {
            history.record(RouteHistoryEntry {
                ts_ms: 1_000,
                route_id: route_id.to_string(),
                rtt_ms: rtt,
                packet_loss_pct: 0.5,
                throughput_mbps: Some(60.0),
                bandwidth_utilization_pct: Some(20.0),
                route_available: true,
                route_healthy: true,
                switched_route: false,
            });
        }
        let predictions =
            SimpleRouteQualityPredictor::default().predict(&inventory.candidates, &history);
        let weights = MultiRelayLoadBalancer::default().calculate_with_health(
            &inventory.candidates,
            &predictions,
            TrafficClass::Operational,
            &[
                RelayRuntimeHealth {
                    route_id: "relay-nodeA-via-nodeC-nodeB".into(),
                    available: true,
                    healthy: true,
                    utilization_pct: Some(98.0),
                    recovered_at_ms: None,
                },
                RelayRuntimeHealth {
                    route_id: "relay-nodeA-via-nodeD-nodeB".into(),
                    available: true,
                    healthy: true,
                    utilization_pct: Some(20.0),
                    recovered_at_ms: Some(59_000),
                },
                RelayRuntimeHealth {
                    route_id: "relay-nodeA-via-nodeC-nodeD-nodeB".into(),
                    available: false,
                    healthy: false,
                    utilization_pct: Some(0.0),
                    recovered_at_ms: None,
                },
            ],
            60_000,
        );
        assert_eq!(weights.total_relay_routes, 2);
        let overloaded = weights
            .weights
            .iter()
            .find(|weight| weight.route_id.contains("nodeC-nodeB"))
            .unwrap();
        let recovered = weights
            .weights
            .iter()
            .find(|weight| weight.route_id.contains("nodeD-nodeB"))
            .unwrap();
        assert!(overloaded.overload_factor < 1.0);
        assert!(recovered.recovery_factor < 1.0 && recovered.recovery_factor > 0.20);
        assert!((weights.total_weight - 1.0).abs() < 0.0002);
    }

    #[test]
    fn security_control_gives_best_trusted_relay_priority_floor() {
        let inventory = RouteCandidateInventory::from_relays(
            "nodeA",
            "nodeB",
            TrafficClass::SecurityControl,
            ["nodeC", "nodeD"],
        );
        let history = RouteHistoryStore::new(1.0, 10);
        let predictions =
            SimpleRouteQualityPredictor::default().predict(&inventory.candidates, &history);
        let weights = MultiRelayLoadBalancer::default().calculate_with_health(
            &inventory.candidates,
            &predictions,
            TrafficClass::SecurityControl,
            &[],
            1_000,
        );
        assert!(weights.weights[0].weight >= 0.60);
        assert_eq!(weights.weights[0].rank, 1);
    }

    #[test]
    fn missing_runtime_health_is_penalized_and_explained() {
        let inventory = RouteCandidateInventory::from_relays(
            "nodeA",
            "nodeB",
            TrafficClass::Operational,
            ["nodeC", "nodeD"],
        );
        let history = RouteHistoryStore::new(1.0, 10);
        let predictions =
            SimpleRouteQualityPredictor::default().predict(&inventory.candidates, &history);
        let weights = MultiRelayLoadBalancer::default().calculate_with_health(
            &inventory.candidates,
            &predictions,
            TrafficClass::Operational,
            &[
                RelayRuntimeHealth {
                    route_id: "relay-nodeA-via-nodeC-nodeB".into(),
                    available: true,
                    healthy: true,
                    utilization_pct: Some(0.0),
                    recovered_at_ms: None,
                },
                RelayRuntimeHealth {
                    route_id: "relay-nodeA-via-nodeD-nodeB".into(),
                    available: true,
                    healthy: true,
                    utilization_pct: None,
                    recovered_at_ms: None,
                },
            ],
            1_000,
        );
        let healthy = weights
            .weights
            .iter()
            .find(|weight| weight.route_id == "relay-nodeA-via-nodeC-nodeB")
            .unwrap();
        let missing = weights
            .weights
            .iter()
            .find(|weight| weight.route_id == "relay-nodeA-via-nodeD-nodeB")
            .unwrap();
        assert!(missing.weight < healthy.weight);
        assert!(missing.reason.contains("runtime_health_missing"));
        assert!(healthy.reason.contains("utilization=0.0%"));
    }
}
