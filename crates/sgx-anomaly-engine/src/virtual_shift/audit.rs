//! VS19: durable, linked audit timeline for one anomaly-to-policy lifecycle.

use super::{
    VShiftAlert, VS01_TO_VS09_PROPOSALS, VS10_VS11_REVIEWS, VS14_ALERTS, VS15_GOSSIP,
    VS16_MEMBER_VERIFICATION, VS17_MEMBER_POLICY_STATE, VS18_MEMBER_IDENTITY_STATE, VS19_AUDIT,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditStep {
    pub stage: String,
    pub evidence_path: String,
    pub present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyAuditTrail {
    pub schema_version: u32,
    pub member_id: String,
    pub alert_id: String,
    pub anomaly_id: String,
    pub recommendation_id: String,
    pub policy_version: u64,
    pub generated_at_ms: u64,
    pub steps: Vec<AuditStep>,
}

#[derive(Debug, Clone)]
pub struct AuditService {
    root: PathBuf,
}

impl AuditService {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
    pub fn build_and_write(
        &self,
        member: &str,
        alert: &VShiftAlert,
        now_ms: u64,
    ) -> anyhow::Result<PolicyAuditTrail> {
        if member.trim().is_empty() || member.contains(['/', '\\']) || now_ms == 0 {
            anyhow::bail!("member ID and audit time must be valid");
        }
        let entries = [
            (
                "VS1-VS10 recommendation",
                self.root
                    .join(VS01_TO_VS09_PROPOSALS)
                    .join(&alert.recommendation_id)
                    .join("virtual_shift_proposal.json"),
            ),
            (
                "VS11 owner decision",
                self.root
                    .join(VS10_VS11_REVIEWS)
                    .join(&alert.recommendation_id)
                    .join("review.json"),
            ),
            (
                "VS14 signed alert",
                self.root
                    .join(VS14_ALERTS)
                    .join(&alert.alert_id)
                    .join("vshift_alert.json"),
            ),
            (
                "VS15 gossip",
                self.root
                    .join(VS15_GOSSIP)
                    .join(&alert.alert_id)
                    .join("broadcast_receipt.json"),
            ),
            (
                "VS16 member verification",
                self.root
                    .join(VS16_MEMBER_VERIFICATION)
                    .join(member)
                    .join(&alert.alert_id)
                    .join("verification.json"),
            ),
            (
                "VS17 apply or rollback",
                self.root
                    .join(VS17_MEMBER_POLICY_STATE)
                    .join(member)
                    .join("latest_apply_result.json"),
            ),
            (
                "VS18 VirtualID rotation",
                self.root
                    .join(VS18_MEMBER_IDENTITY_STATE)
                    .join(member)
                    .join(&alert.alert_id)
                    .join("rotation_result.json"),
            ),
            (
                "VS18 re-attestation result",
                self.root
                    .join(VS18_MEMBER_IDENTITY_STATE)
                    .join(member)
                    .join(&alert.alert_id)
                    .join("attestation_result.json"),
            ),
        ];
        let steps = entries
            .into_iter()
            .map(|(stage, path)| AuditStep {
                stage: stage.into(),
                evidence_path: path.display().to_string(),
                present: path.is_file(),
            })
            .collect();
        let result = PolicyAuditTrail {
            schema_version: SCHEMA_VERSION,
            member_id: member.into(),
            alert_id: alert.alert_id.clone(),
            anomaly_id: alert.anomaly_id.clone(),
            recommendation_id: alert.recommendation_id.clone(),
            policy_version: alert.policy_version,
            generated_at_ms: now_ms,
            steps,
        };
        let path = self
            .root
            .join(VS19_AUDIT)
            .join(member)
            .join(&alert.alert_id)
            .join("audit_trail.json");
        std::fs::create_dir_all(path.parent().expect("audit directory"))?;
        std::fs::write(path, serde_json::to_string_pretty(&result)?)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audit_writes_linked_timeline_and_marks_missing_evidence() {
        let root = std::env::temp_dir().join(format!("vshift_audit_{}", std::process::id()));
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
            anomaly_id: "anom-1".into(),
            recommendation_id: "rec-1".into(),
            anomaly_score: 0.9,
            confidence: 0.9,
            ai_justification: "x".into(),
            issued_at_ms: 1,
            expires_at_ms: 2,
        };
        let path = root.join(VS14_ALERTS).join("alert-1");
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("vshift_alert.json"), "{}").unwrap();
        let audit = AuditService::new(&root)
            .build_and_write("nodeB", &alert, 10)
            .unwrap();
        assert_eq!(audit.steps.len(), 8);
        assert!(audit
            .steps
            .iter()
            .any(|step| step.stage == "VS14 signed alert" && step.present));
        assert!(audit.steps.iter().any(|step| !step.present));
        assert!(root
            .join(VS19_AUDIT)
            .join("nodeB/alert-1/audit_trail.json")
            .is_file());
        let _ = std::fs::remove_dir_all(root);
    }
}
