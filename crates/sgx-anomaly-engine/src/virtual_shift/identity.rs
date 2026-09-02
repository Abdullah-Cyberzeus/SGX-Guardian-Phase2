//! VS18: rotate a member VirtualID only after a successful VS17 policy apply.
//!
//! The standalone engine persists identity lifecycle state and a mandatory
//! re-attestation request.  It does not claim to rotate a hardware TPM/SGX
//! credential; a board integration can later replace this state store with
//! the existing VirtualID and attestation services while retaining the same
//! validation and audit contract.

use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use super::{sha256_hex, MemberPolicyApplyResult, PolicyApplyStatus, VShiftAlert};

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationState {
    ReAttestationRequired,
    Trusted,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityRotationStatus {
    RotatedReAttestationRequired,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualIdentityState {
    pub schema_version: u32,
    pub member_id: String,
    pub current_virtual_id: String,
    pub invalidated_virtual_ids: BTreeSet<String>,
    pub last_policy_version: u64,
    pub processed_alert_ids: BTreeSet<String>,
    pub attestation_state: AttestationState,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRotationResult {
    pub schema_version: u32,
    pub member_id: String,
    pub alert_id: String,
    pub policy_version: u64,
    pub status: IdentityRotationStatus,
    pub old_virtual_id: Option<String>,
    pub new_virtual_id: Option<String>,
    pub attestation_state: Option<AttestationState>,
    pub rotated_at_ms: u64,
    pub reason: String,
    pub identity_state_path: String,
}

/// Durable VS18 state. The apply root is the only authority allowed to begin
/// a rotation: no recommendation, pending review, or merely verified alert is
/// sufficient.
#[derive(Debug, Clone)]
pub struct MemberIdentityRotator {
    apply_root: PathBuf,
    identity_root: PathBuf,
}

impl MemberIdentityRotator {
    pub fn new(apply_root: impl Into<PathBuf>, identity_root: impl Into<PathBuf>) -> Self {
        Self {
            apply_root: apply_root.into(),
            identity_root: identity_root.into(),
        }
    }

    pub fn rotate_after_applied_policy(
        &self,
        member_id: &str,
        alert: &VShiftAlert,
        now_ms: u64,
    ) -> anyhow::Result<IdentityRotationResult> {
        if member_id.trim().is_empty() || member_id.contains(['/', '\\']) || now_ms == 0 {
            anyhow::bail!("member ID and rotation time must be valid");
        }
        let state_path = self.state_path(member_id);
        let result = match self.validate_applied(member_id, alert) {
            Ok(()) => {
                let mut state = self.read_state(member_id)?;
                if state.processed_alert_ids.contains(&alert.alert_id) {
                    rejected(
                        member_id,
                        alert,
                        now_ms,
                        &state_path,
                        "rejected: this alert has already rotated this member identity".into(),
                    )
                } else if alert.policy_version <= state.last_policy_version {
                    rejected(member_id, alert, now_ms, &state_path, format!("rejected: policy version {} is not newer than last identity policy version {}", alert.policy_version, state.last_policy_version))
                } else {
                    let old = state.current_virtual_id.clone();
                    let new = new_virtual_id(member_id, alert, now_ms);
                    state.invalidated_virtual_ids.insert(old.clone());
                    state.current_virtual_id = new.clone();
                    state.last_policy_version = alert.policy_version;
                    state.processed_alert_ids.insert(alert.alert_id.clone());
                    state.attestation_state = AttestationState::ReAttestationRequired;
                    state.updated_at_ms = now_ms;
                    self.write_state(&state)?;
                    IdentityRotationResult { schema_version: SCHEMA_VERSION, member_id: member_id.into(), alert_id: alert.alert_id.clone(), policy_version: alert.policy_version, status: IdentityRotationStatus::RotatedReAttestationRequired, old_virtual_id: Some(old), new_virtual_id: Some(new), attestation_state: Some(AttestationState::ReAttestationRequired), rotated_at_ms: now_ms, reason: "VS17 policy apply succeeded. Previous VirtualID was invalidated, a new VirtualID was issued, and fresh attestation is now required before this identity should be trusted again.".into(), identity_state_path: state_path.display().to_string() }
                }
            }
            Err(reason) => rejected(member_id, alert, now_ms, &state_path, reason),
        };
        self.write_result(&result)?;
        Ok(result)
    }

    fn validate_applied(&self, member: &str, alert: &VShiftAlert) -> Result<(), String> {
        let path = self
            .apply_root
            .join(member)
            .join("latest_apply_result.json");
        let applied: MemberPolicyApplyResult =
            serde_json::from_str(&std::fs::read_to_string(&path).map_err(|_| {
                "rejected: VS17 apply record is missing; policy must be applied first".to_string()
            })?)
            .map_err(|_| "rejected: VS17 apply record is unreadable".to_string())?;
        if applied.status != PolicyApplyStatus::Applied
            || applied.member_id != member
            || applied.alert_id != alert.alert_id
        {
            return Err(
                "rejected: VS17 did not successfully apply this exact alert for this member".into(),
            );
        }
        if applied.policy_version != alert.policy_version {
            return Err("rejected: VS17 apply policy version does not match the alert".into());
        }
        Ok(())
    }

    fn state_path(&self, member: &str) -> PathBuf {
        self.identity_root.join(member).join("identity_state.json")
    }
    fn read_state(&self, member: &str) -> anyhow::Result<VirtualIdentityState> {
        let path = self.state_path(member);
        if !path.is_file() {
            return Ok(VirtualIdentityState {
                schema_version: SCHEMA_VERSION,
                member_id: member.into(),
                current_virtual_id: format!("vid-{member}-bootstrap"),
                invalidated_virtual_ids: BTreeSet::new(),
                last_policy_version: 0,
                processed_alert_ids: BTreeSet::new(),
                attestation_state: AttestationState::ReAttestationRequired,
                updated_at_ms: 0,
            });
        }
        let state: VirtualIdentityState = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        if state.schema_version != SCHEMA_VERSION
            || state.member_id != member
            || state.current_virtual_id.trim().is_empty()
        {
            anyhow::bail!("member identity state is invalid");
        }
        Ok(state)
    }
    fn write_state(&self, state: &VirtualIdentityState) -> anyhow::Result<()> {
        let path = self.state_path(&state.member_id);
        std::fs::create_dir_all(path.parent().expect("identity parent"))?;
        std::fs::write(path, serde_json::to_string_pretty(state)?)?;
        Ok(())
    }
    fn write_result(&self, result: &IdentityRotationResult) -> anyhow::Result<()> {
        let path = self
            .identity_root
            .join(&result.member_id)
            .join(&result.alert_id);
        std::fs::create_dir_all(&path)?;
        std::fs::write(
            path.join("rotation_result.json"),
            serde_json::to_string_pretty(result)?,
        )?;
        Ok(())
    }
}

fn new_virtual_id(member: &str, alert: &VShiftAlert, now_ms: u64) -> String {
    format!(
        "vid-{member}-{}",
        &sha256_hex(
            format!(
                "{member}|{}|{}|{now_ms}",
                alert.alert_id, alert.policy_version
            )
            .as_bytes()
        )[..20]
    )
}
fn rejected(
    member: &str,
    alert: &VShiftAlert,
    now: u64,
    path: &Path,
    reason: String,
) -> IdentityRotationResult {
    IdentityRotationResult {
        schema_version: SCHEMA_VERSION,
        member_id: member.into(),
        alert_id: alert.alert_id.clone(),
        policy_version: alert.policy_version,
        status: IdentityRotationStatus::Rejected,
        old_virtual_id: None,
        new_virtual_id: None,
        attestation_state: None,
        rotated_at_ms: now,
        reason,
        identity_state_path: path.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    fn root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "vshift_vs18_{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }
    fn fixture(member: &str) -> (PathBuf, MemberIdentityRotator, VShiftAlert) {
        let root = root();
        let alert = VShiftAlert {
            schema_version: 1,
            alert_id: "alert-1".into(),
            circle_id: "circle-test".into(),
            policy_version: 22,
            policy_blob: vec![],
            policy_hash_hex: String::new(),
            guardian_signature_hex: String::new(),
            guardian_public_key_hex: String::new(),
            signer_id: "guardian-test".into(),
            signature_algorithm: "ed25519".into(),
            anomaly_id: "anom-1".into(),
            recommendation_id: "rec-1".into(),
            anomaly_score: 0.9,
            confidence: 0.9,
            ai_justification: "test".into(),
            issued_at_ms: 1,
            expires_at_ms: 2,
        };
        let apply_root = root.join("apply");
        let dir = apply_root.join(member);
        std::fs::create_dir_all(&dir).unwrap();
        let applied = MemberPolicyApplyResult {
            schema_version: 1,
            member_id: member.into(),
            alert_id: alert.alert_id.clone(),
            policy_id: Some("p-22".into()),
            policy_version: 22,
            applied_at_ms: 10,
            status: PolicyApplyStatus::Applied,
            reason: "test".into(),
            backup_path: None,
            active_policy_path: "test".into(),
        };
        std::fs::write(
            dir.join("latest_apply_result.json"),
            serde_json::to_string(&applied).unwrap(),
        )
        .unwrap();
        (
            root.clone(),
            MemberIdentityRotator::new(apply_root, root.join("identities")),
            alert,
        )
    }
    #[test]
    fn successful_vs17_apply_rotates_once_and_requires_reattest() {
        let (root, service, alert) = fixture("nodeB");
        let first = service
            .rotate_after_applied_policy("nodeB", &alert, 100)
            .unwrap();
        assert_eq!(
            first.status,
            IdentityRotationStatus::RotatedReAttestationRequired
        );
        assert_eq!(first.old_virtual_id.as_deref(), Some("vid-nodeB-bootstrap"));
        assert!(first.new_virtual_id.unwrap().starts_with("vid-nodeB-"));
        assert_eq!(
            service
                .rotate_after_applied_policy("nodeB", &alert, 101)
                .unwrap()
                .status,
            IdentityRotationStatus::Rejected
        );
        let _ = std::fs::remove_dir_all(root);
    }
    #[test]
    fn missing_or_failed_vs17_cannot_rotate_identity() {
        let (root, service, alert) = fixture("nodeB");
        assert_eq!(
            service
                .rotate_after_applied_policy("nodeC", &alert, 100)
                .unwrap()
                .status,
            IdentityRotationStatus::Rejected
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
