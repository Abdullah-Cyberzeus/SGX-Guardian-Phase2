//! Task 3 Deliverable 15: explicit safe runtime modes.
//!
//! Modes govern whether the existing D10/D11 controller is invoked. They do
//! not alter Task2 trust data or eligibility; Active still receives only the
//! already Task2-filtered route set.

use super::{
    EligibilityReason, EligibleRouteSet, RuntimeRouteApplyRequest, RuntimeRouteControllerResult,
    RuntimeRouteState, SafeRuntimeRouteController, SensitiveRouteHandoffResult,
    SensitiveRouteHandoffService, SensitiveRouteReason,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const NETWORK_AI_RUNTIME_MODE_VERSION: &str = "network-ai-runtime-mode-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAiRuntimeMode {
    Shadow,
    Advisory,
    Active,
}

impl Default for NetworkAiRuntimeMode {
    fn default() -> Self {
        Self::Shadow
    }
}

impl NetworkAiRuntimeMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "shadow" => Some(Self::Shadow),
            "advisory" => Some(Self::Advisory),
            "active" => Some(Self::Active),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeModeDecision {
    pub schema_version: String,
    pub mode: NetworkAiRuntimeMode,
    pub current_route_id: String,
    pub selected_route_id: String,
    pub applied: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeModeExecution {
    pub decision: RuntimeModeDecision,
    pub route_result: Option<RuntimeRouteControllerResult>,
    pub sensitive_handoff: Option<SensitiveRouteHandoffResult>,
}

/// Paths and context supplied by the real host when D4 rejects a requested
/// Active-mode route for a D12-sensitive reason.
#[derive(Debug, Clone)]
pub struct SensitiveRouteHandoffContext {
    pub task2_review_root: std::path::PathBuf,
    pub task2_role_config: String,
    pub audit_path: std::path::PathBuf,
    pub source_node: String,
    pub destination_node: String,
    pub anomaly_score: f64,
    pub model_confidence: f64,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeModeController {
    pub route_controller: SafeRuntimeRouteController,
}

impl RuntimeModeController {
    pub fn execute(
        &self,
        mode: NetworkAiRuntimeMode,
        state: &mut RuntimeRouteState,
        eligible_routes: &EligibleRouteSet,
        request: &RuntimeRouteApplyRequest,
    ) -> RuntimeModeExecution {
        if mode == NetworkAiRuntimeMode::Active {
            let route_result = self.route_controller.apply(state, eligible_routes, request);
            return RuntimeModeExecution {
                decision: RuntimeModeDecision {
                    schema_version: NETWORK_AI_RUNTIME_MODE_VERSION.to_string(),
                    mode,
                    current_route_id: route_result.audit.previous_route_id.clone(),
                    selected_route_id: request.requested_route_id.clone(),
                    applied: route_result.audit.apply_result.applied,
                    reason: format!(
                        "active mode delegated to D10/D11: {}",
                        route_result.audit.apply_result.reason
                    ),
                },
                route_result: Some(route_result),
                sensitive_handoff: None,
            };
        }

        let reason = match mode {
            NetworkAiRuntimeMode::Shadow => {
                "shadow mode observed and predicted only; route apply is disabled"
            }
            NetworkAiRuntimeMode::Advisory => {
                "advisory mode produced a route recommendation; operator action is required"
            }
            NetworkAiRuntimeMode::Active => unreachable!(),
        };
        RuntimeModeExecution {
            decision: RuntimeModeDecision {
                schema_version: NETWORK_AI_RUNTIME_MODE_VERSION.to_string(),
                mode,
                current_route_id: state.active_route_id.clone(),
                selected_route_id: request.requested_route_id.clone(),
                applied: false,
                reason: reason.to_string(),
            },
            route_result: None,
            sensitive_handoff: None,
        }
    }

    /// D15 Active-mode boundary: D4-rejected sensitive routes are never sent
    /// to D11. They are persisted through the existing D12 Task2 review path.
    pub fn execute_with_sensitive_handoff(
        &self,
        mode: NetworkAiRuntimeMode,
        state: &mut RuntimeRouteState,
        eligible_routes: &EligibleRouteSet,
        request: &RuntimeRouteApplyRequest,
        context: Option<&SensitiveRouteHandoffContext>,
    ) -> Result<RuntimeModeExecution> {
        if mode == NetworkAiRuntimeMode::Active {
            if let Some(rejected) = eligible_routes
                .rejected
                .iter()
                .find(|item| item.route_id == request.requested_route_id)
            {
                if let Some(reason) = sensitive_reason(&rejected.reason) {
                    if let Some(context) = context {
                        let handoff = SensitiveRouteHandoffService::new(
                            &context.task2_review_root,
                            &context.task2_role_config,
                        )
                        .handoff(
                            request.ts_ms,
                            &context.source_node,
                            &context.destination_node,
                            &request.requested_route_id,
                            reason,
                            context.anomaly_score,
                            context.model_confidence,
                            &context.audit_path,
                        )?;
                        return Ok(RuntimeModeExecution {
                            decision: RuntimeModeDecision {
                                schema_version: NETWORK_AI_RUNTIME_MODE_VERSION.to_string(),
                                mode,
                                current_route_id: state.active_route_id.clone(),
                                selected_route_id: request.requested_route_id.clone(),
                                applied: false,
                                reason: format!(
                                    "active mode blocked by D4 and handed to D12: {}",
                                    handoff.audit_record.ai_justification
                                ),
                            },
                            route_result: None,
                            sensitive_handoff: Some(handoff),
                        });
                    }
                }
            }
        }
        Ok(self.execute(mode, state, eligible_routes, request))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute_and_persist(
        &self,
        mode: NetworkAiRuntimeMode,
        state: &mut RuntimeRouteState,
        eligible_routes: &EligibleRouteSet,
        request: &RuntimeRouteApplyRequest,
        state_path: impl AsRef<Path>,
        apply_result_path: impl AsRef<Path>,
        transition_audit_path: impl AsRef<Path>,
        observed_outcome_path: impl AsRef<Path>,
    ) -> Result<RuntimeModeExecution> {
        if mode != NetworkAiRuntimeMode::Active {
            return Ok(self.execute(mode, state, eligible_routes, request));
        }
        let route_result = self.route_controller.apply_and_persist(
            state,
            eligible_routes,
            request,
            state_path,
            apply_result_path,
            transition_audit_path,
            observed_outcome_path,
        )?;
        Ok(RuntimeModeExecution {
            decision: RuntimeModeDecision {
                schema_version: NETWORK_AI_RUNTIME_MODE_VERSION.to_string(),
                mode,
                current_route_id: route_result.audit.previous_route_id.clone(),
                selected_route_id: request.requested_route_id.clone(),
                applied: route_result.audit.apply_result.applied,
                reason: format!(
                    "active mode delegated to D10/D11: {}",
                    route_result.audit.apply_result.reason
                ),
            },
            route_result: Some(route_result),
            sensitive_handoff: None,
        })
    }
}

fn sensitive_reason(reason: &EligibilityReason) -> Option<SensitiveRouteReason> {
    match reason {
        EligibilityReason::UntrustedPeer => Some(SensitiveRouteReason::NewUntrustedRelay),
        EligibilityReason::QuarantinedPeer => Some(SensitiveRouteReason::QuarantinedMemberRecovery),
        EligibilityReason::ProhibitedRoute => Some(SensitiveRouteReason::PolicyRuleChangeNeeded),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_ai::{
        EligibilityFilter, RouteCandidateInventory, RouteSwitchState, TrafficClass,
        TrustStateSnapshot,
    };

    fn routes() -> EligibleRouteSet {
        let candidates = RouteCandidateInventory::from_relays(
            "nodeA",
            "nodeB",
            TrafficClass::Operational,
            ["nodeC"],
        )
        .candidates;
        EligibilityFilter.filter_at(
            candidates,
            &TrustStateSnapshot::new("task2-v1")
                .trust_peer("nodeB")
                .trust_peer("nodeC"),
            100_000,
        )
    }

    fn state() -> RuntimeRouteState {
        RuntimeRouteState::from_switch_state(&RouteSwitchState {
            current_route_id: "direct-nodeA-nodeB".to_string(),
            current_route_started_ms: 0,
            last_switch_ms: None,
            switch_timestamps_ms: vec![],
        })
    }

    fn request() -> RuntimeRouteApplyRequest {
        RuntimeRouteApplyRequest {
            ts_ms: 100_000,
            requested_route_id: "relay-nodeA-via-nodeC-nodeB".to_string(),
            current_score: 10.0,
            candidate_score: 30.0,
            current_route_failed: false,
            transport_apply_succeeds: true,
            selected_by: "test".to_string(),
            observed_rtt_ms: 10.0,
            observed_packet_loss_pct: 0.1,
            observed_throughput_mbps: 50.0,
            observed_bandwidth_utilization_pct: 20.0,
            observed_reward: Some(10.0),
        }
    }

    #[test]
    fn default_mode_is_shadow_and_shadow_or_advisory_never_apply() {
        assert_eq!(
            NetworkAiRuntimeMode::default(),
            NetworkAiRuntimeMode::Shadow
        );
        for mode in [NetworkAiRuntimeMode::Shadow, NetworkAiRuntimeMode::Advisory] {
            let mut runtime_state = state();
            let result = RuntimeModeController::default().execute(
                mode,
                &mut runtime_state,
                &routes(),
                &request(),
            );
            assert!(!result.decision.applied);
            assert!(result.route_result.is_none());
            assert_eq!(runtime_state.active_route_id, "direct-nodeA-nodeB");
        }
    }

    #[test]
    fn active_mode_uses_existing_safe_controller() {
        let mut runtime_state = state();
        let result = RuntimeModeController::default().execute(
            NetworkAiRuntimeMode::Active,
            &mut runtime_state,
            &routes(),
            &request(),
        );
        assert!(result.decision.applied);
        assert_eq!(runtime_state.active_route_id, "relay-nodeA-via-nodeC-nodeB");
        assert!(result.route_result.unwrap().audit.safety_decision.allowed);
    }

    #[test]
    fn parser_rejects_unknown_mode_safely() {
        assert_eq!(
            NetworkAiRuntimeMode::parse("ADVISORY"),
            Some(NetworkAiRuntimeMode::Advisory)
        );
        assert_eq!(NetworkAiRuntimeMode::parse("unsafe"), None);
    }

    #[test]
    fn active_sensitive_untrusted_route_creates_d12_handoff_without_apply() {
        let root =
            std::env::temp_dir().join(format!("network-ai-active-handoff-{}", std::process::id()));
        let roles = root.join("roles.json");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&roles, r#"{"nodeA":"admin"}"#).unwrap();
        let candidates = RouteCandidateInventory::from_relays(
            "nodeA",
            "nodeB",
            TrafficClass::Operational,
            ["nodeZ"],
        )
        .candidates;
        let rejected = EligibilityFilter.filter_at(
            candidates,
            &TrustStateSnapshot::new("task2-v1").trust_peer("nodeB"),
            100_000,
        );
        let mut runtime_state = state();
        let mut sensitive_request = request();
        sensitive_request.requested_route_id = "relay-nodeA-via-nodeZ-nodeB".to_string();
        let context = SensitiveRouteHandoffContext {
            task2_review_root: root.join("reviews"),
            task2_role_config: roles.display().to_string(),
            audit_path: root.join("handoff.json"),
            source_node: "nodeA".into(),
            destination_node: "nodeB".into(),
            anomaly_score: 0.8,
            model_confidence: 0.9,
        };
        let result = RuntimeModeController::default()
            .execute_with_sensitive_handoff(
                NetworkAiRuntimeMode::Active,
                &mut runtime_state,
                &rejected,
                &sensitive_request,
                Some(&context),
            )
            .unwrap();
        assert!(!result.decision.applied);
        assert!(result.sensitive_handoff.is_some());
        assert_eq!(runtime_state.active_route_id, "direct-nodeA-nodeB");
        assert!(context.audit_path.exists());
        let _ = std::fs::remove_dir_all(root);
    }
}
