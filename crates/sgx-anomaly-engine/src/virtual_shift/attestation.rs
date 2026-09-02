//! Board-replaceable attestation connector used after VS18.
//!
//! `MockAttestationConnector` is intentionally deterministic for the
//! standalone demo. A board integration implements `AttestationConnector`
//! using its TPM/SGX/remote-attestation API without changing VS18 identity
//! state or the durable result format.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::{
    AttestationState, IdentityRotationResult, IdentityRotationStatus, VShiftAlert,
    VirtualIdentityState,
};

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationRequest {
    pub member_id: String,
    pub virtual_id: String,
    pub alert_id: String,
    pub policy_version: u64,
    pub requested_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationConnectorResponse {
    pub accepted: bool,
    pub reason: String,
}

/// Adapter boundary for future board code.
pub trait AttestationConnector {
    fn attest(&self, request: &AttestationRequest) -> anyhow::Result<AttestationConnectorResponse>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockAttestationOutcome {
    Pass,
    Fail,
}

#[derive(Debug, Clone)]
pub struct MockAttestationConnector {
    outcome: MockAttestationOutcome,
}
impl MockAttestationConnector {
    pub fn new(outcome: MockAttestationOutcome) -> Self {
        Self { outcome }
    }
}
impl AttestationConnector for MockAttestationConnector {
    fn attest(&self, request: &AttestationRequest) -> anyhow::Result<AttestationConnectorResponse> {
        Ok(match self.outcome {
            MockAttestationOutcome::Pass => AttestationConnectorResponse {
                accepted: true,
                reason: format!(
                    "Mock board accepted fresh attestation proof for {} using {}.",
                    request.member_id, request.virtual_id
                ),
            },
            MockAttestationOutcome::Fail => AttestationConnectorResponse {
                accepted: false,
                reason: format!(
                    "Mock board rejected the attestation proof for {}.",
                    request.member_id
                ),
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReAttestationStatus {
    Trusted,
    Failed,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReAttestationResult {
    pub schema_version: u32,
    pub member_id: String,
    pub alert_id: String,
    pub virtual_id: Option<String>,
    pub policy_version: u64,
    pub connector: String,
    pub status: ReAttestationStatus,
    pub completed_at_ms: u64,
    pub reason: String,
    pub identity_state_path: String,
}

#[derive(Debug, Clone)]
pub struct ReAttestationService {
    identity_root: PathBuf,
}
impl ReAttestationService {
    pub fn new(identity_root: impl Into<PathBuf>) -> Self {
        Self {
            identity_root: identity_root.into(),
        }
    }

    pub fn complete_after_rotation<C: AttestationConnector>(
        &self,
        member: &str,
        alert: &VShiftAlert,
        connector_name: &str,
        connector: &C,
        now_ms: u64,
    ) -> anyhow::Result<ReAttestationResult> {
        if member.trim().is_empty()
            || member.contains(['/', '\\'])
            || connector_name.trim().is_empty()
            || now_ms == 0
        {
            anyhow::bail!("member ID, connector name and time must be valid");
        }
        let state_path = self.state_path(member);
        let result = match self.validate_required(member, alert, &state_path) {
            Ok(mut state) => {
                let request = AttestationRequest {
                    member_id: member.into(),
                    virtual_id: state.current_virtual_id.clone(),
                    alert_id: alert.alert_id.clone(),
                    policy_version: alert.policy_version,
                    requested_at_ms: now_ms,
                };
                match connector.attest(&request) {
                    Ok(response) if response.accepted => {
                        state.attestation_state = AttestationState::Trusted;
                        state.updated_at_ms = now_ms;
                        self.write_state(&state)?;
                        ReAttestationResult {
                            schema_version: SCHEMA_VERSION,
                            member_id: member.into(),
                            alert_id: alert.alert_id.clone(),
                            virtual_id: Some(request.virtual_id),
                            policy_version: alert.policy_version,
                            connector: connector_name.into(),
                            status: ReAttestationStatus::Trusted,
                            completed_at_ms: now_ms,
                            reason: response.reason,
                            identity_state_path: state_path.display().to_string(),
                        }
                    }
                    Ok(response) => {
                        state.attestation_state = AttestationState::Failed;
                        state.updated_at_ms = now_ms;
                        self.write_state(&state)?;
                        ReAttestationResult {
                            schema_version: SCHEMA_VERSION,
                            member_id: member.into(),
                            alert_id: alert.alert_id.clone(),
                            virtual_id: Some(request.virtual_id),
                            policy_version: alert.policy_version,
                            connector: connector_name.into(),
                            status: ReAttestationStatus::Failed,
                            completed_at_ms: now_ms,
                            reason: response.reason,
                            identity_state_path: state_path.display().to_string(),
                        }
                    }
                    Err(error) => ReAttestationResult {
                        schema_version: SCHEMA_VERSION,
                        member_id: member.into(),
                        alert_id: alert.alert_id.clone(),
                        virtual_id: Some(request.virtual_id),
                        policy_version: alert.policy_version,
                        connector: connector_name.into(),
                        status: ReAttestationStatus::Failed,
                        completed_at_ms: now_ms,
                        reason: format!("attestation connector failed: {error}"),
                        identity_state_path: state_path.display().to_string(),
                    },
                }
            }
            Err(reason) => rejected(member, alert, now_ms, connector_name, &state_path, reason),
        };
        self.write_result(&result)?;
        Ok(result)
    }
    fn validate_required(
        &self,
        member: &str,
        alert: &VShiftAlert,
        state_path: &Path,
    ) -> Result<VirtualIdentityState, String> {
        let rotation_path = self
            .identity_root
            .join(member)
            .join(&alert.alert_id)
            .join("rotation_result.json");
        let rotation: IdentityRotationResult =
            serde_json::from_str(&std::fs::read_to_string(&rotation_path).map_err(|_| {
                "rejected: VS18 rotation record is missing; rotate identity first".to_string()
            })?)
            .map_err(|_| "rejected: VS18 rotation record is unreadable".to_string())?;
        if rotation.status != IdentityRotationStatus::RotatedReAttestationRequired
            || rotation.member_id != member
            || rotation.policy_version != alert.policy_version
        {
            return Err("rejected: VS18 did not rotate this exact member/alert/policy".into());
        }
        let state: VirtualIdentityState = serde_json::from_str(
            &std::fs::read_to_string(state_path)
                .map_err(|_| "rejected: current identity state is missing".to_string())?,
        )
        .map_err(|_| "rejected: current identity state is unreadable".to_string())?;
        if state.member_id != member || !state.processed_alert_ids.contains(&alert.alert_id) {
            return Err("rejected: current identity state is not linked to this alert".into());
        }
        if state.attestation_state != AttestationState::ReAttestationRequired {
            return Err(
                "rejected: re-attestation is no longer pending for this member identity".into(),
            );
        }
        Ok(state)
    }
    fn state_path(&self, member: &str) -> PathBuf {
        self.identity_root.join(member).join("identity_state.json")
    }
    fn write_state(&self, state: &VirtualIdentityState) -> anyhow::Result<()> {
        std::fs::write(
            self.state_path(&state.member_id),
            serde_json::to_string_pretty(state)?,
        )?;
        Ok(())
    }
    fn write_result(&self, result: &ReAttestationResult) -> anyhow::Result<()> {
        let dir = self
            .identity_root
            .join(&result.member_id)
            .join(&result.alert_id);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("attestation_result.json"),
            serde_json::to_string_pretty(result)?,
        )?;
        Ok(())
    }
}
fn rejected(
    member: &str,
    alert: &VShiftAlert,
    now: u64,
    connector: &str,
    path: &Path,
    reason: String,
) -> ReAttestationResult {
    ReAttestationResult {
        schema_version: SCHEMA_VERSION,
        member_id: member.into(),
        alert_id: alert.alert_id.clone(),
        virtual_id: None,
        policy_version: alert.policy_version,
        connector: connector.into(),
        status: ReAttestationStatus::Rejected,
        completed_at_ms: now,
        reason,
        identity_state_path: path.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    fn root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "vshift_mock_attest_{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }
    fn fixture(member: &str) -> (PathBuf, ReAttestationService, VShiftAlert) {
        let root = root();
        let identity = root.join("identity");
        let alert = VShiftAlert {
            schema_version: 1,
            alert_id: "alert-1".into(),
            circle_id: "circle-test".into(),
            policy_version: 22,
            policy_blob: vec![],
            policy_hash_hex: String::new(),
            guardian_signature_hex: String::new(),
            guardian_public_key_hex: String::new(),
            signer_id: "g".into(),
            signature_algorithm: "ed25519".into(),
            anomaly_id: "a".into(),
            recommendation_id: "r".into(),
            anomaly_score: 0.9,
            confidence: 0.9,
            ai_justification: "test".into(),
            issued_at_ms: 1,
            expires_at_ms: 2,
        };
        let dir = identity.join(member).join(&alert.alert_id);
        std::fs::create_dir_all(&dir).unwrap();
        let rotation = IdentityRotationResult {
            schema_version: 1,
            member_id: member.into(),
            alert_id: alert.alert_id.clone(),
            policy_version: 22,
            status: IdentityRotationStatus::RotatedReAttestationRequired,
            old_virtual_id: Some("old".into()),
            new_virtual_id: Some("new".into()),
            attestation_state: Some(AttestationState::ReAttestationRequired),
            rotated_at_ms: 10,
            reason: "test".into(),
            identity_state_path: String::new(),
        };
        std::fs::write(
            dir.join("rotation_result.json"),
            serde_json::to_string(&rotation).unwrap(),
        )
        .unwrap();
        let state = VirtualIdentityState {
            schema_version: 1,
            member_id: member.into(),
            current_virtual_id: "new".into(),
            invalidated_virtual_ids: BTreeSet::from(["old".into()]),
            last_policy_version: 22,
            processed_alert_ids: BTreeSet::from([alert.alert_id.clone()]),
            attestation_state: AttestationState::ReAttestationRequired,
            updated_at_ms: 10,
        };
        std::fs::write(
            identity.join(member).join("identity_state.json"),
            serde_json::to_string(&state).unwrap(),
        )
        .unwrap();
        (root.clone(), ReAttestationService::new(identity), alert)
    }
    #[test]
    fn mock_pass_marks_member_trusted_and_second_attempt_is_rejected() {
        let (root, service, alert) = fixture("nodeB");
        assert_eq!(
            service
                .complete_after_rotation(
                    "nodeB",
                    &alert,
                    "mock",
                    &MockAttestationConnector::new(MockAttestationOutcome::Pass),
                    20
                )
                .unwrap()
                .status,
            ReAttestationStatus::Trusted
        );
        assert_eq!(
            service
                .complete_after_rotation(
                    "nodeB",
                    &alert,
                    "mock",
                    &MockAttestationConnector::new(MockAttestationOutcome::Pass),
                    21
                )
                .unwrap()
                .status,
            ReAttestationStatus::Rejected
        );
        let _ = std::fs::remove_dir_all(root);
    }
    #[test]
    fn mock_failure_marks_failed_and_missing_rotation_is_rejected() {
        let (root, service, alert) = fixture("nodeB");
        assert_eq!(
            service
                .complete_after_rotation(
                    "nodeB",
                    &alert,
                    "mock",
                    &MockAttestationConnector::new(MockAttestationOutcome::Fail),
                    20
                )
                .unwrap()
                .status,
            ReAttestationStatus::Failed
        );
        assert_eq!(
            service
                .complete_after_rotation(
                    "nodeC",
                    &alert,
                    "mock",
                    &MockAttestationConnector::new(MockAttestationOutcome::Pass),
                    21
                )
                .unwrap()
                .status,
            ReAttestationStatus::Rejected
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
