//! VS20: final standalone lifecycle verification report.
//!
//! It does not mutate a policy. It validates a selected saved member
//! lifecycle and provides the final acceptance evidence for the demo.

use super::{
    AttestationState, AuditService, MemberPolicyApplyResult, PolicyApplyStatus,
    ReAttestationResult, ReAttestationStatus, VShiftAlert, VirtualIdentityState,
    VS17_MEMBER_POLICY_STATE, VS18_MEMBER_IDENTITY_STATE, VS20_FINAL_VERIFICATION,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalVerificationReport {
    pub schema_version: u32,
    pub member_id: String,
    pub alert_id: String,
    pub policy_version: u64,
    pub alert_signature_and_hash_valid: bool,
    pub audit_complete: bool,
    pub policy_applied: bool,
    pub identity_rotated: bool,
    pub re_attestation_trusted: bool,
    pub status: String,
    pub missing_stages: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FinalHardeningVerifier {
    root: PathBuf,
}
impl FinalHardeningVerifier {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
    pub fn verify_and_write(
        &self,
        member: &str,
        alert: &VShiftAlert,
        now_ms: u64,
    ) -> anyhow::Result<FinalVerificationReport> {
        if member.trim().is_empty() || member.contains(['/', '\\']) || now_ms == 0 {
            anyhow::bail!("member ID and verification time must be valid");
        }
        let signature_ok = alert.validate().is_ok();
        let audit = AuditService::new(&self.root).build_and_write(member, alert, now_ms)?;
        let mut missing: Vec<String> = audit
            .steps
            .iter()
            .filter(|step| !step.present)
            .map(|step| step.stage.clone())
            .collect();
        let apply_path = self
            .root
            .join(VS17_MEMBER_POLICY_STATE)
            .join(member)
            .join("latest_apply_result.json");
        let applied = read::<MemberPolicyApplyResult>(&apply_path).is_some_and(|value| {
            value.status == PolicyApplyStatus::Applied
                && value.policy_version == alert.policy_version
        });
        if !applied {
            missing.push("VS17 successful apply".into());
        }
        let identity_path = self
            .root
            .join(VS18_MEMBER_IDENTITY_STATE)
            .join(member)
            .join("identity_state.json");
        let identity = read::<VirtualIdentityState>(&identity_path);
        let rotated = identity.as_ref().is_some_and(|state| {
            state.processed_alert_ids.contains(&alert.alert_id)
                && state.last_policy_version == alert.policy_version
        });
        if !rotated {
            missing.push("VS18 VirtualID rotation".into());
        }
        let attestation_path = self
            .root
            .join(VS18_MEMBER_IDENTITY_STATE)
            .join(member)
            .join(&alert.alert_id)
            .join("attestation_result.json");
        let trusted = read::<ReAttestationResult>(&attestation_path)
            .is_some_and(|value| value.status == ReAttestationStatus::Trusted)
            && identity
                .as_ref()
                .is_some_and(|state| state.attestation_state == AttestationState::Trusted);
        if !trusted {
            missing.push("VS18 trusted re-attestation".into());
        }
        if !signature_ok {
            missing.push("VS14 signed alert validation".into());
        }
        missing.sort();
        missing.dedup();
        let result = FinalVerificationReport {
            schema_version: 1,
            member_id: member.into(),
            alert_id: alert.alert_id.clone(),
            policy_version: alert.policy_version,
            alert_signature_and_hash_valid: signature_ok,
            audit_complete: audit.steps.iter().all(|step| step.present),
            policy_applied: applied,
            identity_rotated: rotated,
            re_attestation_trusted: trusted,
            status: if missing.is_empty() {
                "pass".into()
            } else {
                "incomplete_or_failed".into()
            },
            missing_stages: missing,
        };
        let path = self
            .root
            .join(VS20_FINAL_VERIFICATION)
            .join(member)
            .join(&alert.alert_id)
            .join("vs20_report.json");
        std::fs::create_dir_all(path.parent().expect("report directory"))?;
        std::fs::write(path, serde_json::to_string_pretty(&result)?)?;
        Ok(result)
    }
}
fn read<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|value| serde_json::from_str(&value).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn incomplete_lifecycle_reports_missing_stages_without_mutation() {
        let root = std::env::temp_dir().join(format!("vshift_vs20_{}", std::process::id()));
        let alert = VShiftAlert {
            schema_version: 1,
            alert_id: "alert-1".into(),
            circle_id: "circle".into(),
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
            ai_justification: "x".into(),
            issued_at_ms: 1,
            expires_at_ms: 2,
        };
        let report = FinalHardeningVerifier::new(&root)
            .verify_and_write("nodeB", &alert, 10)
            .unwrap();
        assert_eq!(report.status, "incomplete_or_failed");
        assert!(!report.policy_applied);
        assert!(!report.missing_stages.is_empty());
        assert!(root
            .join(VS20_FINAL_VERIFICATION)
            .join("nodeB/alert-1/vs20_report.json")
            .is_file());
        let _ = std::fs::remove_dir_all(root);
    }
}
