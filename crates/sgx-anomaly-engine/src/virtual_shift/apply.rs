//! VS17: safely activate a VS16-verified policy on one receiving member.
//!
//! This standalone implementation changes only the member's local policy
//! state JSON.  It never executes firewall, quarantine, or OS commands.
//! A durable backup is written before the new state becomes active; if the
//! activation transaction fails, the backup is restored.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{
    canonical_policy_bytes, sha256_hex, ActiveVirtualShiftPolicy, MemberVerificationResult,
    VShiftAlert, VerificationStatus, VersionedPolicyCandidate,
};

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyApplyStatus {
    Applied,
    Rejected,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberPolicyApplyResult {
    pub schema_version: u32,
    pub member_id: String,
    pub alert_id: String,
    pub policy_id: Option<String>,
    pub policy_version: u64,
    pub applied_at_ms: u64,
    pub status: PolicyApplyStatus,
    pub reason: String,
    pub backup_path: Option<String>,
    pub active_policy_path: String,
}

/// One easy-to-read view of a member's policy state.  This is an index only;
/// the policy bytes themselves remain in `active_policy.json` and
/// `backup_history/v<N>.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberPolicyStateSummary {
    pub schema_version: u32,
    pub member_id: String,
    pub active_policy_version: Option<u64>,
    pub active_policy_id: Option<String>,
    pub active_action_count: usize,
    pub active_rule_count: usize,
    pub active_policy_path: String,
    pub backup_history: Vec<PolicyBackupSummary>,
    pub latest_change: MemberPolicyApplyResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBackupSummary {
    pub policy_version: u64,
    pub path: String,
}

/// VS17 file-backed activation service.  `configured_active_policy` is only
/// the initial seed; every member gets its own active-policy state thereafter.
#[derive(Debug, Clone)]
pub struct MemberPolicyApplier {
    configured_active_policy: PathBuf,
    verification_root: PathBuf,
    state_root: PathBuf,
    simulate_activation_failure: bool,
}

impl MemberPolicyApplier {
    pub fn new(
        configured_active_policy: impl Into<PathBuf>,
        verification_root: impl Into<PathBuf>,
        state_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            configured_active_policy: configured_active_policy.into(),
            verification_root: verification_root.into(),
            state_root: state_root.into(),
            simulate_activation_failure: false,
        }
    }

    /// Demo/test-only switch. It fails after the previous local policy has
    /// been moved aside, so the normal recovery path must restore it.
    pub fn with_simulated_activation_failure(mut self) -> Self {
        self.simulate_activation_failure = true;
        self
    }

    pub fn apply_verified_alert(
        &self,
        member_id: &str,
        alert: &VShiftAlert,
        now_ms: u64,
    ) -> anyhow::Result<MemberPolicyApplyResult> {
        if member_id.trim().is_empty() || member_id.contains(['/', '\\']) || now_ms == 0 {
            anyhow::bail!("member ID and apply time must be valid");
        }
        let active_path = self.policy_dir(member_id).join("active_policy.json");
        self.ensure_policy_layout(member_id, &active_path)?;
        let result = match self.validate_input(member_id, alert, now_ms, &active_path) {
            Ok(candidate) => self.activate(member_id, alert, candidate, now_ms, &active_path),
            Err(reason) => MemberPolicyApplyResult {
                schema_version: SCHEMA_VERSION,
                member_id: member_id.into(),
                alert_id: alert.alert_id.clone(),
                policy_id: None,
                policy_version: alert.policy_version,
                applied_at_ms: now_ms,
                status: PolicyApplyStatus::Rejected,
                reason,
                backup_path: None,
                active_policy_path: active_path.display().to_string(),
            },
        };
        self.write_result(&result)?;
        self.write_policy_state_summary(&result)?;
        Ok(result)
    }

    fn validate_input(
        &self,
        member: &str,
        alert: &VShiftAlert,
        now_ms: u64,
        active_path: &Path,
    ) -> Result<VersionedPolicyCandidate, String> {
        if now_ms >= alert.expires_at_ms {
            return Err(
                "rejected: alert expired after VS16 verification; request a fresh signed alert"
                    .into(),
            );
        }
        let verification_path = self
            .verification_root
            .join(member)
            .join(&alert.alert_id)
            .join("verification.json");
        let verification: MemberVerificationResult =
            serde_json::from_str(&std::fs::read_to_string(&verification_path).map_err(|_| {
                "rejected: VS16 verification record is missing; run VS16 first".to_string()
            })?)
            .map_err(|_| "rejected: VS16 verification record is unreadable".to_string())?;
        if verification.status != VerificationStatus::VerifiedNotApplied
            || verification.alert_id != alert.alert_id
            || verification.member_id != member
        {
            return Err("rejected: VS16 did not accept this exact alert for this member".into());
        }
        let candidate = candidate_from_alert(alert)
            .map_err(|error| format!("rejected: signed policy blob is invalid: {error}"))?;
        if candidate.circle_id != alert.circle_id
            || candidate.policy_version != alert.policy_version
        {
            return Err("rejected: policy blob does not match alert Circle or version".into());
        }
        if !candidate.applicable_members.is_empty()
            && !candidate
                .applicable_members
                .iter()
                .any(|target| target == member)
        {
            return Err(format!(
                "rejected: policy is not applicable to member {member}; targeted members are [{}]",
                candidate.applicable_members.join(", ")
            ));
        }
        let active = self
            .read_active(active_path)
            .map_err(|error| format!("rejected: active policy state is invalid: {error}"))?;
        if candidate.policy_version <= active.policy_version {
            return Err(format!(
                "rejected: policy version {} is not newer than member active version {}",
                candidate.policy_version, active.policy_version
            ));
        }
        if candidate.parent_policy_version != active.policy_version {
            return Err(format!(
                "rejected: candidate parent version {} does not match member active version {}",
                candidate.parent_policy_version, active.policy_version
            ));
        }
        Ok(candidate)
    }

    fn activate(
        &self,
        member: &str,
        alert: &VShiftAlert,
        candidate: VersionedPolicyCandidate,
        now_ms: u64,
        active_path: &Path,
    ) -> MemberPolicyApplyResult {
        let prior = match self.read_active(active_path) {
            Ok(value) => value,
            Err(error) => {
                return rejected(
                    member,
                    alert,
                    now_ms,
                    active_path,
                    format!("rejected: cannot read active policy before backup: {error}"),
                )
            }
        };
        let policy_dir = self.policy_dir(member);
        // Keep one simple policy view per member: the current active policy
        // and one immutable copy of every policy that was previously active.
        let backup_path = policy_dir
            .join("backup_history")
            .join(format!("v{}.json", prior.policy_version));
        if let Err(error) = std::fs::create_dir_all(backup_path.parent().expect("backup parent"))
            .and_then(|_| {
                std::fs::write(&backup_path, serde_json::to_string_pretty(&prior).unwrap())
            })
        {
            return rejected(
                member,
                alert,
                now_ms,
                active_path,
                format!("rejected: could not write backup: {error}"),
            );
        }
        let next = ActiveVirtualShiftPolicy {
            schema_version: 1,
            policy_id: candidate.policy_id.clone(),
            circle_id: candidate.circle_id.clone(),
            policy_version: candidate.policy_version,
            actions: candidate.actions.clone(),
            rules: candidate.rules.clone(),
            applicable_members: candidate.applicable_members.clone(),
        };
        let temporary = active_path.with_extension("json.pending");
        let write = (|| -> anyhow::Result<()> {
            std::fs::create_dir_all(&policy_dir)?;
            std::fs::write(&temporary, serde_json::to_string_pretty(&next)?)?;
            let previous = active_path.with_extension("json.previous");
            if active_path.exists() {
                let _ = std::fs::remove_file(&previous);
                std::fs::rename(active_path, &previous)?;
            }
            if self.simulate_activation_failure {
                if previous.exists() {
                    let _ = std::fs::rename(&previous, active_path);
                }
                anyhow::bail!("simulated VS17 activation failure for rollback demonstration");
            }
            if let Err(error) = std::fs::rename(&temporary, active_path) {
                if previous.exists() {
                    let _ = std::fs::rename(&previous, active_path);
                }
                return Err(error.into());
            }
            let _ = std::fs::remove_file(previous);
            Ok(())
        })();
        match write {
            Ok(()) => MemberPolicyApplyResult { schema_version: SCHEMA_VERSION, member_id: member.into(), alert_id: alert.alert_id.clone(), policy_id: Some(candidate.policy_id), policy_version: candidate.policy_version, applied_at_ms: now_ms, status: PolicyApplyStatus::Applied, reason: "VS16 verification was accepted; backup saved and signed policy activated in this member's local policy state. External enforcement remains an integration step.".into(), backup_path: Some(backup_path.display().to_string()), active_policy_path: active_path.display().to_string() },
            Err(error) => MemberPolicyApplyResult { schema_version: SCHEMA_VERSION, member_id: member.into(), alert_id: alert.alert_id.clone(), policy_id: Some(candidate.policy_id), policy_version: candidate.policy_version, applied_at_ms: now_ms, status: PolicyApplyStatus::RolledBack, reason: format!("activation failed and prior policy was restored: {error}"), backup_path: Some(backup_path.display().to_string()), active_policy_path: active_path.display().to_string() },
        }
    }

    fn member_dir(&self, member: &str) -> PathBuf {
        self.state_root.join(member)
    }
    fn policy_dir(&self, member: &str) -> PathBuf {
        self.member_dir(member)
    }
    fn ensure_policy_layout(&self, member: &str, canonical_active: &Path) -> anyhow::Result<()> {
        if canonical_active.is_file() {
            return Ok(());
        }
        std::fs::create_dir_all(canonical_active.parent().expect("policy parent"))?;
        let legacy_active = self.member_dir(member).join("active_policy.json");
        let seed = if legacy_active.is_file() {
            std::fs::read(&legacy_active)?
        } else {
            std::fs::read(&self.configured_active_policy)?
        };
        std::fs::write(canonical_active, seed)?;
        Ok(())
    }
    fn read_active(&self, member_path: &Path) -> anyhow::Result<ActiveVirtualShiftPolicy> {
        if member_path.is_file() {
            ActiveVirtualShiftPolicy::from_path(member_path)
        } else {
            ActiveVirtualShiftPolicy::from_path(&self.configured_active_policy)
        }
    }
    fn write_result(&self, result: &MemberPolicyApplyResult) -> anyhow::Result<()> {
        // The policy-state folder stays easy to inspect: one active policy,
        // backup history, and the latest apply outcome. Complete per-policy
        // Evidence remains available in the numbered lifecycle folders and audit trails.
        let dir = self.member_dir(&result.member_id);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("latest_apply_result.json"),
            serde_json::to_string_pretty(result)?,
        )?;
        Ok(())
    }

    fn write_policy_state_summary(&self, result: &MemberPolicyApplyResult) -> anyhow::Result<()> {
        let member_dir = self.member_dir(&result.member_id);
        let active_path = member_dir.join("active_policy.json");
        let active_policy = ActiveVirtualShiftPolicy::from_path(&active_path).ok();
        let active_policy_version = active_policy.as_ref().map(|policy| policy.policy_version);
        let active_policy_id = active_policy
            .as_ref()
            .map(|policy| policy.policy_id.clone());
        let active_action_count = active_policy
            .as_ref()
            .map_or(0, |policy| policy.actions.len());
        let active_rule_count = active_policy
            .as_ref()
            .map_or(0, |policy| policy.rules.len());
        let backup_dir = member_dir.join("backup_history");
        let mut backup_history = Vec::new();
        if backup_dir.is_dir() {
            for entry in std::fs::read_dir(&backup_dir)? {
                let path = entry?.path();
                if !path.is_file() {
                    continue;
                }
                if let Ok(policy) = ActiveVirtualShiftPolicy::from_path(&path) {
                    backup_history.push(PolicyBackupSummary {
                        policy_version: policy.policy_version,
                        path: path.display().to_string(),
                    });
                }
            }
        }
        backup_history.sort_by_key(|backup| backup.policy_version);
        let summary = MemberPolicyStateSummary {
            schema_version: SCHEMA_VERSION,
            member_id: result.member_id.clone(),
            active_policy_version,
            active_policy_id,
            active_action_count,
            active_rule_count,
            active_policy_path: active_path.display().to_string(),
            backup_history,
            latest_change: result.clone(),
        };
        std::fs::write(
            member_dir.join("policy_state_summary.json"),
            serde_json::to_string_pretty(&summary)?,
        )?;
        Ok(())
    }
}

fn candidate_from_alert(alert: &VShiftAlert) -> anyhow::Result<VersionedPolicyCandidate> {
    let mut value: serde_json::Value = serde_json::from_slice(&alert.policy_blob)?;
    value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("policy blob is not an object"))?
        .insert(
            "canonical_sha256".into(),
            serde_json::Value::String(alert.policy_hash_hex.clone()),
        );
    let candidate: VersionedPolicyCandidate = serde_json::from_value(value)?;
    if sha256_hex(&canonical_policy_bytes(&candidate)?) != alert.policy_hash_hex {
        anyhow::bail!("canonical SHA-256 does not match alert");
    }
    Ok(candidate)
}

fn rejected(
    member: &str,
    alert: &VShiftAlert,
    now: u64,
    path: &Path,
    reason: String,
) -> MemberPolicyApplyResult {
    MemberPolicyApplyResult {
        schema_version: SCHEMA_VERSION,
        member_id: member.into(),
        alert_id: alert.alert_id.clone(),
        policy_id: None,
        policy_version: alert.policy_version,
        applied_at_ms: now,
        status: PolicyApplyStatus::Rejected,
        reason,
        backup_path: None,
        active_policy_path: path.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQ: AtomicUsize = AtomicUsize::new(0);
    fn root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "vshift_vs17_{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }
    fn fixture(member: &str) -> (PathBuf, MemberPolicyApplier, VShiftAlert) {
        let root = root();
        std::fs::create_dir_all(&root).unwrap();
        let active = root.join("active.json");
        std::fs::write(
            &active,
            r#"{"schema_version":1,"circle_id":"circle-test","policy_version":21,"actions":[]}"#,
        )
        .unwrap();
        let candidate = VersionedPolicyCandidate {
            schema_version: 1,
            policy_id: "policy-v22".into(),
            circle_id: "circle-test".into(),
            parent_policy_version: 21,
            policy_version: 22,
            source_recommendation_id: "rec-1".into(),
            source_anomaly_id: "anom-1".into(),
            actions: vec![],
            rules: vec![],
            applicable_members: vec!["nodeB".into()],
            canonical_sha256: String::new(),
            status: "candidate_not_signed".into(),
        };
        let bytes = canonical_policy_bytes(&candidate).unwrap();
        let hash = sha256_hex(&bytes);
        let alert = VShiftAlert {
            schema_version: 1,
            alert_id: "alert-1".into(),
            circle_id: "circle-test".into(),
            policy_version: 22,
            policy_blob: bytes,
            policy_hash_hex: hash,
            guardian_signature_hex: "00".repeat(64),
            guardian_public_key_hex: "00".repeat(32),
            signer_id: "guardian-test".into(),
            signature_algorithm: "ed25519".into(),
            anomaly_id: "anom-1".into(),
            recommendation_id: "rec-1".into(),
            anomaly_score: 0.9,
            confidence: 0.9,
            ai_justification: "test".into(),
            issued_at_ms: 1_000,
            expires_at_ms: 61_000,
        };
        let verification = MemberVerificationResult {
            schema_version: 1,
            member_id: member.into(),
            alert_id: alert.alert_id.clone(),
            circle_id: alert.circle_id.clone(),
            policy_version: 22,
            signer_id: "guardian-test".into(),
            verified_at_ms: 2_000,
            status: VerificationStatus::VerifiedNotApplied,
            reason: "test".into(),
        };
        let verification_root = root.join("verification");
        let evidence = verification_root.join(member).join(&alert.alert_id);
        std::fs::create_dir_all(&evidence).unwrap();
        std::fs::write(
            evidence.join("verification.json"),
            serde_json::to_string(&verification).unwrap(),
        )
        .unwrap();
        let applier = MemberPolicyApplier::new(&active, verification_root, root.join("state"));
        (root, applier, alert)
    }
    #[test]
    fn verified_alert_is_applied_with_backup_and_second_apply_is_rejected() {
        let (root, applier, alert) = fixture("nodeB");
        let first = applier
            .apply_verified_alert("nodeB", &alert, 2_001)
            .unwrap();
        assert_eq!(first.status, PolicyApplyStatus::Applied);
        assert!(Path::new(first.backup_path.as_deref().unwrap()).is_file());
        let active: ActiveVirtualShiftPolicy = serde_json::from_str(
            &std::fs::read_to_string(root.join("state/nodeB/active_policy.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(active.policy_version, 22);
        assert_eq!(
            applier
                .apply_verified_alert("nodeB", &alert, 2_002)
                .unwrap()
                .status,
            PolicyApplyStatus::Rejected
        );
        let _ = std::fs::remove_dir_all(root);
    }
    #[test]
    fn missing_vs16_proof_and_expired_alert_are_rejected() {
        let (root, applier, alert) = fixture("nodeB");
        assert_eq!(
            applier
                .apply_verified_alert("nodeC", &alert, 2_001)
                .unwrap()
                .status,
            PolicyApplyStatus::Rejected
        );
        assert_eq!(
            applier
                .apply_verified_alert("nodeB", &alert, 61_000)
                .unwrap()
                .status,
            PolicyApplyStatus::Rejected
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn verified_but_non_target_member_cannot_activate_policy() {
        let (root, applier, alert) = fixture("nodeC");
        let result = applier
            .apply_verified_alert("nodeC", &alert, 2_001)
            .unwrap();
        assert_eq!(result.status, PolicyApplyStatus::Rejected);
        assert!(result.reason.contains("not applicable to member nodeC"));
        let _ = std::fs::remove_dir_all(root);
    }
    #[test]
    fn simulated_activation_failure_restores_prior_member_policy() {
        let (root, applier, alert) = fixture("nodeB");
        let member_state = root.join("state/nodeB");
        std::fs::create_dir_all(&member_state).unwrap();
        std::fs::write(
            member_state.join("active_policy.json"),
            r#"{"schema_version":1,"circle_id":"circle-test","policy_version":21,"actions":[]}"#,
        )
        .unwrap();
        let result = applier
            .with_simulated_activation_failure()
            .apply_verified_alert("nodeB", &alert, 2_001)
            .unwrap();
        assert_eq!(result.status, PolicyApplyStatus::RolledBack);
        let restored =
            ActiveVirtualShiftPolicy::from_path(member_state.join("active_policy.json")).unwrap();
        assert_eq!(restored.policy_version, 21);
        assert!(Path::new(result.backup_path.as_deref().unwrap()).is_file());
        let _ = std::fs::remove_dir_all(root);
    }
}
