//! Task 3 Deliverable 11: guarded runtime route controller.
//!
//! This is a local runtime adapter, not a network-control-plane authority.
//! It only applies a route which has already passed Task2-backed eligibility
//! filtering and the Task3 safety guard. No owner approval is needed for this
//! non-policy route change.

use super::{
    EligibleRouteSet, ObservedRouteOutcome, RouteApplyResult, RouteHistoryStore,
    RouteSafetyDecision, RouteSafetyGuard, RouteSwitchState, SafetyVerdict,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

pub const NETWORK_AI_ROUTE_CONTROLLER_VERSION: &str = "network-ai-route-controller-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeRouteTransition {
    DirectToRelay,
    RelayToDirect,
    RelayToRelay,
    SameRoute,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeRouteState {
    pub schema_version: String,
    pub active_route_id: String,
    pub active_route_started_ms: u64,
    pub previous_route_id: Option<String>,
    pub last_switch_ms: Option<u64>,
    pub switch_timestamps_ms: Vec<u64>,
}

impl RuntimeRouteState {
    pub fn from_switch_state(state: &RouteSwitchState) -> Self {
        Self {
            schema_version: NETWORK_AI_ROUTE_CONTROLLER_VERSION.to_string(),
            active_route_id: state.current_route_id.clone(),
            active_route_started_ms: state.current_route_started_ms,
            previous_route_id: None,
            last_switch_ms: state.last_switch_ms,
            switch_timestamps_ms: state.switch_timestamps_ms.clone(),
        }
    }

    pub fn as_switch_state(&self) -> RouteSwitchState {
        RouteSwitchState {
            current_route_id: self.active_route_id.clone(),
            current_route_started_ms: self.active_route_started_ms,
            last_switch_ms: self.last_switch_ms,
            switch_timestamps_ms: self.switch_timestamps_ms.clone(),
        }
    }

    pub fn save_json(&self, path: impl AsRef<Path>) -> Result<()> {
        write_json(path.as_ref(), self)
    }

    pub fn load_json(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .with_context(|| format!("reading runtime route state {}", path.display()))?;
        serde_json::from_str(&content).context("parsing runtime route state")
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeRouteApplyRequest {
    pub ts_ms: u64,
    pub requested_route_id: String,
    pub current_score: f64,
    pub candidate_score: f64,
    pub current_route_failed: bool,
    /// Adapter result supplied by the actual transport integration. The demo
    /// keeps this true; false proves that the previous route remains active.
    pub transport_apply_succeeds: bool,
    pub selected_by: String,
    pub observed_rtt_ms: f64,
    pub observed_packet_loss_pct: f64,
    pub observed_throughput_mbps: f64,
    pub observed_bandwidth_utilization_pct: f64,
    pub observed_reward: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteTransitionAuditRecord {
    pub schema_version: String,
    pub ts_ms: u64,
    pub transition: RuntimeRouteTransition,
    pub previous_route_id: String,
    pub requested_route_id: String,
    pub resulting_route_id: String,
    pub requested_route_was_eligible: bool,
    pub owner_approval_required: bool,
    pub safety_decision: RouteSafetyDecision,
    pub apply_result: RouteApplyResult,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeRouteControllerResult {
    pub schema_version: String,
    pub state: RuntimeRouteState,
    pub audit: RouteTransitionAuditRecord,
}

#[derive(Debug, Clone, Default)]
pub struct SafeRuntimeRouteController {
    pub safety_guard: RouteSafetyGuard,
}

impl SafeRuntimeRouteController {
    pub fn apply(
        &self,
        state: &mut RuntimeRouteState,
        eligible_routes: &EligibleRouteSet,
        request: &RuntimeRouteApplyRequest,
    ) -> RuntimeRouteControllerResult {
        let previous_route_id = state.active_route_id.clone();
        let requested_route_was_eligible = eligible_routes
            .eligible
            .iter()
            .any(|route| route.route_id == request.requested_route_id);

        let safety_decision = if requested_route_was_eligible {
            self.safety_guard.evaluate_with_route_health(
                request.ts_ms,
                &state.as_switch_state(),
                Some(&request.requested_route_id),
                request.current_score,
                request.candidate_score,
                request.current_route_failed,
            )
        } else {
            RouteSafetyDecision {
                verdict: SafetyVerdict::BlockNoCandidate,
                allowed: false,
                current_route_id: previous_route_id.clone(),
                candidate_route_id: Some(request.requested_route_id.clone()),
                improvement_pct: 0.0,
                hard_failover: false,
                recent_switches_in_window: 0,
                reason: "not applied: requested route is not in the already Task2-trusted eligible route set".to_string(),
            }
        };

        let apply_result = self
            .safety_guard
            .apply_safe_switch(&safety_decision, request.transport_apply_succeeds);

        if apply_result.applied {
            state.previous_route_id = Some(previous_route_id.clone());
            state.active_route_id = apply_result.active_route_id.clone();
            state.active_route_started_ms = request.ts_ms;
            state.last_switch_ms = Some(request.ts_ms);
            state.switch_timestamps_ms.push(request.ts_ms);
        }

        let audit = RouteTransitionAuditRecord {
            schema_version: NETWORK_AI_ROUTE_CONTROLLER_VERSION.to_string(),
            ts_ms: request.ts_ms,
            transition: classify_transition(&previous_route_id, &request.requested_route_id),
            previous_route_id,
            requested_route_id: request.requested_route_id.clone(),
            resulting_route_id: apply_result.active_route_id.clone(),
            requested_route_was_eligible,
            // Route selection is a guarded runtime operation, not Task2 policy mutation.
            owner_approval_required: false,
            safety_decision,
            apply_result,
        };

        RuntimeRouteControllerResult {
            schema_version: NETWORK_AI_ROUTE_CONTROLLER_VERSION.to_string(),
            state: state.clone(),
            audit,
        }
    }

    pub fn apply_and_persist(
        &self,
        state: &mut RuntimeRouteState,
        eligible_routes: &EligibleRouteSet,
        request: &RuntimeRouteApplyRequest,
        state_path: impl AsRef<Path>,
        apply_result_path: impl AsRef<Path>,
        transition_audit_path: impl AsRef<Path>,
        observed_outcome_path: impl AsRef<Path>,
    ) -> Result<RuntimeRouteControllerResult> {
        let result = self.apply(state, eligible_routes, request);
        result.state.save_json(state_path)?;
        write_json(apply_result_path.as_ref(), &result.audit.apply_result)?;
        append_audit_jsonl(transition_audit_path, &result.audit)?;
        RouteHistoryStore::append_observed_outcome_jsonl(
            observed_outcome_path,
            &ObservedRouteOutcome {
                schema_version: "network-ai-route-outcome-v1".to_string(),
                ts_ms: request.ts_ms,
                route_id: result.audit.resulting_route_id.clone(),
                previous_route_id: Some(result.audit.previous_route_id.clone()),
                selected_by: request.selected_by.clone(),
                applied: result.audit.apply_result.applied,
                switched_route: result.audit.apply_result.applied
                    && result.audit.previous_route_id != result.audit.resulting_route_id,
                route_available: result.audit.apply_result.applied,
                route_healthy: result.audit.apply_result.applied,
                rtt_ms: request.observed_rtt_ms,
                packet_loss_pct: request.observed_packet_loss_pct,
                throughput_mbps: request.observed_throughput_mbps,
                bandwidth_utilization_pct: request.observed_bandwidth_utilization_pct,
                reward: request.observed_reward,
                reason: result.audit.apply_result.reason.clone(),
            },
        )?;
        Ok(result)
    }
}

pub fn classify_transition(
    previous_route_id: &str,
    requested_route_id: &str,
) -> RuntimeRouteTransition {
    if previous_route_id == requested_route_id {
        return RuntimeRouteTransition::SameRoute;
    }
    match (is_direct(previous_route_id), is_direct(requested_route_id)) {
        (true, false) if is_relay(requested_route_id) => RuntimeRouteTransition::DirectToRelay,
        (false, true) if is_relay(previous_route_id) => RuntimeRouteTransition::RelayToDirect,
        (false, false) if is_relay(previous_route_id) && is_relay(requested_route_id) => {
            RuntimeRouteTransition::RelayToRelay
        }
        _ => RuntimeRouteTransition::Unknown,
    }
}

fn is_direct(route_id: &str) -> bool {
    route_id.starts_with("direct-")
}

fn is_relay(route_id: &str) -> bool {
    route_id.starts_with("relay-")
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating runtime route directory {}", parent.display()))?;
    }
    fs::write(
        path,
        serde_json::to_string_pretty(value).context("serializing runtime route JSON")?,
    )
    .with_context(|| format!("writing runtime route JSON {}", path.display()))?;
    Ok(())
}

fn append_audit_jsonl(path: impl AsRef<Path>, audit: &RouteTransitionAuditRecord) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "creating route transition audit directory {}",
                parent.display()
            )
        })?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening route transition audit {}", path.display()))?;
    writeln!(
        file,
        "{}",
        serde_json::to_string(audit).context("serializing route transition audit")?
    )
    .with_context(|| format!("writing route transition audit {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_ai::{
        EligibilityFilter, RouteCandidateInventory, TrafficClass, TrustStateSnapshot,
    };

    fn eligible_routes() -> EligibleRouteSet {
        let inventory = RouteCandidateInventory::from_relays(
            "nodeA",
            "nodeB",
            TrafficClass::Operational,
            ["nodeC", "nodeD"],
        );
        EligibilityFilter.filter(
            inventory.candidates,
            &TrustStateSnapshot::new("task2-trust-v1")
                .trust_peer("nodeB")
                .trust_peer("nodeC")
                .trust_peer("nodeD"),
        )
    }

    fn state(route_id: &str) -> RuntimeRouteState {
        RuntimeRouteState::from_switch_state(&RouteSwitchState {
            current_route_id: route_id.to_string(),
            current_route_started_ms: 0,
            last_switch_ms: Some(10_000),
            switch_timestamps_ms: vec![10_000],
        })
    }

    fn request(route_id: &str) -> RuntimeRouteApplyRequest {
        RuntimeRouteApplyRequest {
            ts_ms: 60_000,
            requested_route_id: route_id.to_string(),
            current_score: 40.0,
            candidate_score: 55.0,
            current_route_failed: false,
            transport_apply_succeeds: true,
            selected_by: "contextual-bandit-exploit".to_string(),
            observed_rtt_ms: 12.0,
            observed_packet_loss_pct: 0.2,
            observed_throughput_mbps: 60.0,
            observed_bandwidth_utilization_pct: 45.0,
            observed_reward: Some(8.0),
        }
    }

    #[test]
    fn applies_direct_to_relay_and_updates_runtime_state() {
        let mut state = state("direct-nodeA-nodeB");
        let result = SafeRuntimeRouteController::default().apply(
            &mut state,
            &eligible_routes(),
            &request("relay-nodeA-via-nodeC-nodeB"),
        );
        assert!(result.audit.apply_result.applied);
        assert_eq!(
            result.audit.transition,
            RuntimeRouteTransition::DirectToRelay
        );
        assert_eq!(state.active_route_id, "relay-nodeA-via-nodeC-nodeB");
        assert_eq!(
            state.previous_route_id.as_deref(),
            Some("direct-nodeA-nodeB")
        );
        assert!(!result.audit.owner_approval_required);
    }

    #[test]
    fn applies_relay_to_direct_and_relay_to_relay() {
        let routes = eligible_routes();
        let controller = SafeRuntimeRouteController::default();
        let mut relay_state = state("relay-nodeA-via-nodeC-nodeB");
        let direct = controller.apply(&mut relay_state, &routes, &request("direct-nodeA-nodeB"));
        assert_eq!(
            direct.audit.transition,
            RuntimeRouteTransition::RelayToDirect
        );

        let mut relay_a_state = state("relay-nodeA-via-nodeC-nodeB");
        let relay_b = controller.apply(
            &mut relay_a_state,
            &routes,
            &request("relay-nodeA-via-nodeD-nodeB"),
        );
        assert_eq!(
            relay_b.audit.transition,
            RuntimeRouteTransition::RelayToRelay
        );
        assert!(relay_b.audit.apply_result.applied);
    }

    #[test]
    fn refuses_route_not_in_already_eligible_set() {
        let mut state = state("direct-nodeA-nodeB");
        let result = SafeRuntimeRouteController::default().apply(
            &mut state,
            &eligible_routes(),
            &request("relay-nodeA-via-untrusted-nodeZ-nodeB"),
        );
        assert!(!result.audit.apply_result.applied);
        assert!(!result.audit.requested_route_was_eligible);
        assert_eq!(
            result.audit.safety_decision.verdict,
            SafetyVerdict::BlockNoCandidate
        );
        assert_eq!(state.active_route_id, "direct-nodeA-nodeB");
    }

    #[test]
    fn persists_apply_audit_state_and_observed_outcome() {
        let tmp = std::env::temp_dir().join(format!(
            "network-ai-route-controller-test-{}",
            std::process::id()
        ));
        let mut state = state("direct-nodeA-nodeB");
        let result = SafeRuntimeRouteController::default()
            .apply_and_persist(
                &mut state,
                &eligible_routes(),
                &request("relay-nodeA-via-nodeC-nodeB"),
                tmp.join("current_route_state.json"),
                tmp.join("runtime_route_apply_result.json"),
                tmp.join("route_transition_audit.jsonl"),
                tmp.join("route_outcomes.jsonl"),
            )
            .unwrap();
        assert!(result.audit.apply_result.applied);
        assert!(tmp.join("current_route_state.json").exists());
        assert!(tmp.join("runtime_route_apply_result.json").exists());
        let audit = fs::read_to_string(tmp.join("route_transition_audit.jsonl")).unwrap();
        let outcome = fs::read_to_string(tmp.join("route_outcomes.jsonl")).unwrap();
        assert!(audit.contains("DirectToRelay"));
        assert!(outcome.contains("\"reward\":8.0"));
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn failed_transport_apply_preserves_previous_route() {
        let mut state = state("direct-nodeA-nodeB");
        let mut failed = request("relay-nodeA-via-nodeC-nodeB");
        failed.transport_apply_succeeds = false;
        let result =
            SafeRuntimeRouteController::default().apply(&mut state, &eligible_routes(), &failed);
        assert!(!result.audit.apply_result.applied);
        assert_eq!(state.active_route_id, "direct-nodeA-nodeB");
        assert_eq!(
            result.audit.apply_result.rollback_route_id.as_deref(),
            Some("direct-nodeA-nodeB")
        );
    }
}
