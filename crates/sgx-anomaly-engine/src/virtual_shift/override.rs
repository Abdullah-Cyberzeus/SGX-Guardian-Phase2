// VS19: owner-authorised false-positive override as a new signed policy.
// The active policy is never edited/deleted. The owner selects the policy
// caused by a false positive; the service creates and signs v(N+1) using the
// VS17 backup as its replacement actions. VS14-VS18 distribute/apply it.

use super::{
    canonical_policy_bytes, sha256_hex, verify_signed_policy, ActiveVirtualShiftPolicy,
    GuardianKeyManager, MemberPolicyApplyResult, PolicyApplyStatus, SignedVirtualShiftPolicy,
    VShiftAlert, VersionedPolicyCandidate,
};
use crate::roles::{NodeRole, RoleRegistry};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualOverrideRecord {
    pub schema_version: u32,
    pub override_id: String,
    pub owner_id: String,
    pub member_id: String,
    pub original_alert_id: String,
    pub original_anomaly_id: String,
    pub original_policy_version: u64,
    pub replacement_policy_version: u64,
    pub reason: String,
    pub created_at_ms: u64,
    pub signed_policy_path: String,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct ManualOverrideService {
    policy_state_root: PathBuf,
    override_root: PathBuf,
    roles: RoleRegistry,
}

impl ManualOverrideService {
    pub fn from_role_config(
        policy_state_root: impl Into<PathBuf>,
        override_root: impl Into<PathBuf>,
        role_config: &str,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            policy_state_root: policy_state_root.into(),
            override_root: override_root.into(),
            roles: RoleRegistry::from_path(role_config)?,
        })
    }

    pub fn create_signed_revert(
        &self,
        owner: &str,
        member: &str,
        alert: &VShiftAlert,
        reason: &str,
        now_ms: u64,
        signer: &GuardianKeyManager,
    ) -> anyhow::Result<ManualOverrideRecord> {
        if self.roles.role_for(owner) != NodeRole::Admin {
            anyhow::bail!("'{owner}' is not an authorised Circle Owner for manual override");
        }
        if member.trim().is_empty()
            || member.contains(['/', '\\'])
            || reason.trim().is_empty()
            || reason.len() > 1024
            || now_ms == 0
        {
            anyhow::bail!("override member, reason and time must be valid");
        }
        let apply_path = self
            .policy_state_root
            .join(member)
            .join(&alert.alert_id)
            .join("apply_result.json");
        let apply: MemberPolicyApplyResult = serde_json::from_str(
            &std::fs::read_to_string(&apply_path)
                .map_err(|_| anyhow::anyhow!("original VS17 apply record is missing"))?,
        )?;
        if apply.status != PolicyApplyStatus::Applied
            || apply.policy_version != alert.policy_version
        {
            anyhow::bail!("only a successfully applied original policy can be overridden");
        }
        let backup_path = apply
            .backup_path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("original apply has no backup policy to restore"))?;
        let prior = ActiveVirtualShiftPolicy::from_path(backup_path)?;
        let canonical_active = self
            .policy_state_root
            .join(member)
            .join("policies")
            .join("active_policy.json");
        let active_path = if canonical_active.is_file() {
            canonical_active
        } else {
            self.policy_state_root
                .join(member)
                .join("active_policy.json")
        };
        let active = ActiveVirtualShiftPolicy::from_path(active_path)?;
        if active.policy_version != alert.policy_version {
            anyhow::bail!("member active policy no longer matches selected original policy; select current lifecycle instead");
        }
        let version = active
            .policy_version
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("policy version overflow"))?;
        let override_id = format!("override-{member}-{}-v{version}", alert.alert_id);
        let mut candidate = VersionedPolicyCandidate {
            schema_version: 1,
            policy_id: override_id.clone(),
            circle_id: active.circle_id,
            parent_policy_version: active.policy_version,
            policy_version: version,
            source_recommendation_id: format!("manual-override:{}", alert.recommendation_id),
            source_anomaly_id: alert.anomaly_id.clone(),
            actions: prior.actions,
            rules: active.rules.clone(),
            applicable_members: active.applicable_members.clone(),
            canonical_sha256: String::new(),
            status: "candidate_not_signed".into(),
        };
        let canonical = canonical_policy_bytes(&candidate)?;
        candidate.canonical_sha256 = sha256_hex(&canonical);
        let (signature_hex, public_key_hex) = signer.sign(&canonical)?;
        let signed = SignedVirtualShiftPolicy {
            schema_version: 1,
            policy: candidate.clone(),
            signer_id: signer.guardian_id().into(),
            algorithm: signer.algorithm().into(),
            signed_at_ms: now_ms,
            canonical_sha256: candidate.canonical_sha256.clone(),
            signature_hex,
            public_key_hex,
            status: "signed_not_broadcast".into(),
        };
        verify_signed_policy(&signed)?;
        let directory = self.override_root.join(&override_id);
        std::fs::create_dir_all(&directory)?;
        let signed_path = directory.join("signed_replacement_policy.json");
        std::fs::write(&signed_path, serde_json::to_string_pretty(&signed)?)?;
        let record = ManualOverrideRecord {
            schema_version: SCHEMA_VERSION,
            override_id,
            owner_id: owner.into(),
            member_id: member.into(),
            original_alert_id: alert.alert_id.clone(),
            original_anomaly_id: alert.anomaly_id.clone(),
            original_policy_version: alert.policy_version,
            replacement_policy_version: version,
            reason: reason.into(),
            created_at_ms: now_ms,
            signed_policy_path: signed_path.display().to_string(),
            status: "signed_replacement_not_broadcast".into(),
        };
        std::fs::write(
            directory.join("override_record.json"),
            serde_json::to_string_pretty(&record)?,
        )?;
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    fn root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "vshift_override_{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }
    fn fixture() -> (
        PathBuf,
        ManualOverrideService,
        GuardianKeyManager,
        VShiftAlert,
    ) {
        let root = root();
        let state = root.join("state");
        let member = "nodeA";
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
            anomaly_id: "anom-1".into(),
            recommendation_id: "rec-1".into(),
            anomaly_score: 0.9,
            confidence: 0.9,
            ai_justification: "test".into(),
            issued_at_ms: 1,
            expires_at_ms: 2,
        };
        let original = ActiveVirtualShiftPolicy {
            schema_version: 1,
            policy_id: "policy-active-v21".into(),
            circle_id: "circle-test".into(),
            policy_version: 21,
            actions: vec![],
            rules: vec![],
            applicable_members: vec![member.into()],
        };
        let current = ActiveVirtualShiftPolicy {
            policy_version: 22,
            ..original.clone()
        };
        let backup = state.join(member).join("backups").join("old.json");
        std::fs::create_dir_all(backup.parent().unwrap()).unwrap();
        std::fs::write(&backup, serde_json::to_string(&original).unwrap()).unwrap();
        std::fs::write(
            state.join(member).join("active_policy.json"),
            serde_json::to_string(&current).unwrap(),
        )
        .unwrap();
        let apply_dir = state.join(member).join(&alert.alert_id);
        std::fs::create_dir_all(&apply_dir).unwrap();
        let apply = MemberPolicyApplyResult {
            schema_version: 1,
            member_id: member.into(),
            alert_id: alert.alert_id.clone(),
            policy_id: Some("p22".into()),
            policy_version: 22,
            applied_at_ms: 1,
            status: PolicyApplyStatus::Applied,
            reason: "test".into(),
            backup_path: Some(backup.display().to_string()),
            active_policy_path: String::new(),
        };
        std::fs::write(
            apply_dir.join("apply_result.json"),
            serde_json::to_string(&apply).unwrap(),
        )
        .unwrap();
        let roles = root.join("roles.json");
        std::fs::write(&roles, r#"{"nodeA":"admin","nodeB":"member"}"#).unwrap();
        let signer_config = root.join("guardian.json");
        std::fs::write(
            &signer_config,
            r#"{"schema_version":1,"guardian_id":"guardian-test","algorithm":"ed25519"}"#,
        )
        .unwrap();
        let signer = GuardianKeyManager::from_config(signer_config, root.join("keys")).unwrap();
        (
            root.clone(),
            ManualOverrideService::from_role_config(
                state,
                root.join("overrides"),
                roles.to_str().unwrap(),
            )
            .unwrap(),
            signer,
            alert,
        )
    }
    #[test]
    fn admin_creates_signed_new_version_linked_to_original_alert() {
        let (root, service, signer, alert) = fixture();
        let r = service
            .create_signed_revert("nodeA", "nodeA", &alert, "false positive", 10, &signer)
            .unwrap();
        assert_eq!(r.replacement_policy_version, 23);
        assert!(std::path::Path::new(&r.signed_policy_path).is_file());
        let _ = std::fs::remove_dir_all(root);
    }
    #[test]
    fn member_cannot_create_override() {
        let (root, service, signer, alert) = fixture();
        assert!(service
            .create_signed_revert("nodeB", "nodeA", &alert, "false positive", 10, &signer)
            .is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}
