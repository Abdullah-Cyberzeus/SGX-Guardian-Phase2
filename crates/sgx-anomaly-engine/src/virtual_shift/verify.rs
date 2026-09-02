//! VS16: receiving Circle-member verification.
//!
//! A member verifies every VSHIFT_ALERT before any VS17 enforcement path can
//! see it. The embedded public key is not trusted by itself: it must match a
//! configured Guardian trust anchor. Accepted alert IDs and policy versions
//! are persisted per receiving member to reject replays and stale versions.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use super::{ActiveVirtualShiftPolicy, VShiftAlert};

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianTrustAnchor {
    pub guardian_id: String,
    pub public_key_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircleGuardianAuthorization {
    pub schema_version: u32,
    pub circle_id: String,
    pub active_policy_path: String,
    pub authorized_guardians: Vec<GuardianTrustAnchor>,
}

impl CircleGuardianAuthorization {
    pub fn from_path(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let config: Self = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema_version != SCHEMA_VERSION || self.circle_id.trim().is_empty() {
            anyhow::bail!("Guardian authorization needs schema version 1 and Circle ID");
        }
        if self.active_policy_path.trim().is_empty() || self.authorized_guardians.is_empty() {
            anyhow::bail!("Guardian authorization needs active policy and at least one Guardian");
        }
        let mut ids = BTreeSet::new();
        for guardian in &self.authorized_guardians {
            if guardian.guardian_id.trim().is_empty()
                || guardian.public_key_path.trim().is_empty()
                || guardian.guardian_id.contains(['/', '\\'])
                || !ids.insert(guardian.guardian_id.clone())
            {
                anyhow::bail!("Guardian authorization contains an unsafe or duplicate Guardian ID");
            }
        }
        Ok(())
    }

    fn trusted_public_key(&self, guardian_id: &str) -> anyhow::Result<String> {
        let guardian = self
            .authorized_guardians
            .iter()
            .find(|entry| entry.guardian_id == guardian_id)
            .ok_or_else(|| {
                anyhow::anyhow!("Guardian '{guardian_id}' is not authorized for this Circle")
            })?;
        let value = std::fs::read_to_string(&guardian.public_key_path)?
            .trim()
            .to_ascii_lowercase();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            anyhow::bail!("trusted Guardian public key is not a valid Ed25519 hex key");
        }
        Ok(value)
    }

    fn active_policy_version(&self) -> anyhow::Result<u64> {
        Ok(ActiveVirtualShiftPolicy::from_path(&self.active_policy_path)?.policy_version)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberVerificationState {
    pub schema_version: u32,
    pub member_id: String,
    pub latest_verified_policy_version: u64,
    pub accepted_alert_ids: BTreeSet<String>,
}

impl MemberVerificationState {
    fn new(member_id: &str, active_policy_version: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            member_id: member_id.into(),
            latest_verified_policy_version: active_policy_version,
            accepted_alert_ids: BTreeSet::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    VerifiedNotApplied,
    /// The identical alert was accepted earlier. This is not a second
    /// verification or a second apply permission; the original accepted proof
    /// is retained and the duplicate attempt is recorded separately.
    AlreadyVerified,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberVerificationResult {
    pub schema_version: u32,
    pub member_id: String,
    pub alert_id: String,
    pub circle_id: String,
    pub policy_version: u64,
    pub signer_id: String,
    pub verified_at_ms: u64,
    pub status: VerificationStatus,
    pub reason: String,
}

impl MemberVerificationResult {
    fn accepted(member: &str, alert: &VShiftAlert, now_ms: u64) -> Self {
        Self { schema_version: SCHEMA_VERSION, member_id: member.into(), alert_id: alert.alert_id.clone(), circle_id: alert.circle_id.clone(), policy_version: alert.policy_version, signer_id: alert.signer_id.clone(), verified_at_ms: now_ms, status: VerificationStatus::VerifiedNotApplied, reason: "Circle, Guardian authorization, Ed25519 signature, policy hash, version, freshness and replay checks passed. VS17 has not applied the policy.".into() }
    }
    fn rejected(member: &str, alert: &VShiftAlert, now_ms: u64, reason: String) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            member_id: member.into(),
            alert_id: alert.alert_id.clone(),
            circle_id: alert.circle_id.clone(),
            policy_version: alert.policy_version,
            signer_id: alert.signer_id.clone(),
            verified_at_ms: now_ms,
            status: VerificationStatus::Rejected,
            reason,
        }
    }

    fn already_verified(member: &str, alert: &VShiftAlert, now_ms: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            member_id: member.into(),
            alert_id: alert.alert_id.clone(),
            circle_id: alert.circle_id.clone(),
            policy_version: alert.policy_version,
            signer_id: alert.signer_id.clone(),
            verified_at_ms: now_ms,
            status: VerificationStatus::AlreadyVerified,
            reason: "same alert was already accepted by this member; replay was ignored and the original VS16 proof remains available for VS17.".into(),
        }
    }
}

/// Durable VS16 verifier. State is member-scoped; NodeB and NodeC independently
/// reject a replay even if they received it through different gossip hops.
#[derive(Debug, Clone)]
pub struct MemberAlertVerifier {
    authorization: CircleGuardianAuthorization,
    state_root: PathBuf,
}

impl MemberAlertVerifier {
    pub fn from_config(
        config_path: impl AsRef<Path>,
        state_root: impl Into<PathBuf>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            authorization: CircleGuardianAuthorization::from_path(config_path)?,
            state_root: state_root.into(),
        })
    }

    pub fn verify_and_record(
        &self,
        member_id: &str,
        alert: &VShiftAlert,
        now_ms: u64,
    ) -> anyhow::Result<MemberVerificationResult> {
        if member_id.trim().is_empty() || member_id.contains(['/', '\\']) || now_ms == 0 {
            anyhow::bail!("member ID and verification time must be valid");
        }
        let active_version = self.authorization.active_policy_version()?;
        let mut state = self.read_state(member_id, active_version)?;
        if state.accepted_alert_ids.contains(&alert.alert_id) {
            // Older standalone runs wrote a later rejected replay over the
            // accepted proof. Restore the authoritative accepted proof from
            // durable state, then store this duplicate attempt separately.
            self.restore_accepted_proof_if_needed(member_id, alert, now_ms)?;
            let result = MemberVerificationResult::already_verified(member_id, alert, now_ms);
            self.write_result(&result)?;
            return Ok(result);
        }
        let result = match self.check(&state, alert, now_ms, active_version) {
            Ok(()) => {
                state.accepted_alert_ids.insert(alert.alert_id.clone());
                state.latest_verified_policy_version = alert.policy_version;
                self.write_state(&state)?;
                MemberVerificationResult::accepted(member_id, alert, now_ms)
            }
            Err(reason) => MemberVerificationResult::rejected(member_id, alert, now_ms, reason),
        };
        self.write_result(&result)?;
        Ok(result)
    }

    fn check(
        &self,
        state: &MemberVerificationState,
        alert: &VShiftAlert,
        now_ms: u64,
        active_version: u64,
    ) -> Result<(), String> {
        if alert.circle_id != self.authorization.circle_id {
            return Err("rejected: alert Circle ID does not match this member's Circle".into());
        }
        if alert.issued_at_ms > now_ms {
            return Err("rejected: alert issue time is in the future".into());
        }
        if now_ms >= alert.expires_at_ms {
            return Err("rejected: alert has expired".into());
        }
        let trusted_key = self
            .authorization
            .trusted_public_key(&alert.signer_id)
            .map_err(|error| format!("rejected: {error}"))?;
        if trusted_key != alert.guardian_public_key_hex.to_ascii_lowercase() {
            return Err(
                "rejected: alert Guardian public key does not match configured trust anchor".into(),
            );
        }
        alert.validate().map_err(|error| {
            format!(
                "rejected: alert signature, policy blob or policy hash validation failed: {error}"
            )
        })?;
        if state.accepted_alert_ids.contains(&alert.alert_id) {
            return Err("rejected: replayed alert ID was already accepted by this member".into());
        }
        let minimum = state.latest_verified_policy_version.max(active_version);
        if alert.policy_version <= minimum {
            return Err(format!("rejected: stale policy version {}; member requires a version greater than {minimum}", alert.policy_version));
        }
        Ok(())
    }

    fn member_dir(&self, member: &str) -> PathBuf {
        self.state_root.join(member)
    }
    fn state_path(&self, member: &str) -> PathBuf {
        self.member_dir(member).join("verification_state.json")
    }
    fn read_state(
        &self,
        member: &str,
        active_version: u64,
    ) -> anyhow::Result<MemberVerificationState> {
        let path = self.state_path(member);
        if !path.is_file() {
            return Ok(MemberVerificationState::new(member, active_version));
        }
        let state: MemberVerificationState = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        if state.schema_version != SCHEMA_VERSION || state.member_id != member {
            anyhow::bail!("member verification state is invalid");
        }
        Ok(state)
    }
    fn write_state(&self, state: &MemberVerificationState) -> anyhow::Result<()> {
        let directory = self.member_dir(&state.member_id);
        std::fs::create_dir_all(&directory)?;
        std::fs::write(
            directory.join("verification_state.json"),
            serde_json::to_string_pretty(state)?,
        )?;
        Ok(())
    }
    fn write_result(&self, result: &MemberVerificationResult) -> anyhow::Result<()> {
        let directory = self.member_dir(&result.member_id).join(&result.alert_id);
        std::fs::create_dir_all(&directory)?;
        let proof_path = directory.join("verification.json");
        if result.status == VerificationStatus::AlreadyVerified
            || (result.status == VerificationStatus::Rejected
                && proof_path.is_file()
                && serde_json::from_str::<MemberVerificationResult>(&std::fs::read_to_string(
                    &proof_path,
                )?)
                .is_ok_and(|existing| existing.status == VerificationStatus::VerifiedNotApplied))
        {
            std::fs::write(
                directory.join(format!(
                    "replay_or_rejected_attempt_{}.json",
                    result.verified_at_ms
                )),
                serde_json::to_string_pretty(result)?,
            )?;
            return Ok(());
        }
        std::fs::write(proof_path, serde_json::to_string_pretty(result)?)?;
        Ok(())
    }

    fn restore_accepted_proof_if_needed(
        &self,
        member: &str,
        alert: &VShiftAlert,
        now_ms: u64,
    ) -> anyhow::Result<()> {
        let directory = self.member_dir(member).join(&alert.alert_id);
        let proof_path = directory.join("verification.json");
        let already_accepted = std::fs::read_to_string(&proof_path)
            .ok()
            .and_then(|text| serde_json::from_str::<MemberVerificationResult>(&text).ok())
            .is_some_and(|result| result.status == VerificationStatus::VerifiedNotApplied);
        if !already_accepted {
            std::fs::create_dir_all(&directory)?;
            std::fs::write(
                proof_path,
                serde_json::to_string_pretty(&MemberVerificationResult::accepted(
                    member, alert, now_ms,
                ))?,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtual_shift::{
        canonical_policy_bytes, sha256_hex, GuardianKeyManager, VersionedPolicyCandidate,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQ: AtomicUsize = AtomicUsize::new(0);
    fn root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "vshift_vs16_{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }
    fn fixture() -> (PathBuf, MemberAlertVerifier, VShiftAlert) {
        let root = root();
        std::fs::create_dir_all(&root).unwrap();
        let key_config = root.join("guardian.json");
        std::fs::write(
            &key_config,
            r#"{"schema_version":1,"guardian_id":"guardian-test","algorithm":"ed25519"}"#,
        )
        .unwrap();
        let keys = root.join("keys");
        let manager = GuardianKeyManager::from_config(&key_config, &keys).unwrap();
        let mut policy = VersionedPolicyCandidate {
            schema_version: 1,
            policy_id: "p-22".into(),
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
        let blob = canonical_policy_bytes(&policy).unwrap();
        policy.canonical_sha256 = sha256_hex(&blob);
        let (signature, public_key) = manager.sign(&blob).unwrap();
        let active = root.join("active.json");
        std::fs::write(
            &active,
            r#"{"schema_version":1,"circle_id":"circle-test","policy_version":21,"actions":[]}"#,
        )
        .unwrap();
        let authorization = root.join("authorization.json");
        let public = keys
            .join("guardian-test.ed25519.public")
            .to_string_lossy()
            .replace('\\', "\\\\");
        std::fs::write(&authorization, format!(r#"{{"schema_version":1,"circle_id":"circle-test","active_policy_path":"{}","authorized_guardians":[{{"guardian_id":"guardian-test","public_key_path":"{}"}}]}}"#, active.display().to_string().replace('\\', "\\\\"), public)).unwrap();
        let verifier =
            MemberAlertVerifier::from_config(&authorization, root.join("state")).unwrap();
        let alert = VShiftAlert {
            schema_version: 1,
            alert_id: "alert-1".into(),
            circle_id: "circle-test".into(),
            policy_version: 22,
            policy_blob: blob,
            policy_hash_hex: policy.canonical_sha256,
            guardian_signature_hex: signature,
            guardian_public_key_hex: public_key,
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
        (root, verifier, alert)
    }
    #[test]
    fn valid_alert_is_verified_not_applied_then_replay_is_rejected() {
        let (root, verifier, alert) = fixture();
        assert_eq!(
            verifier
                .verify_and_record("nodeB", &alert, 2_000)
                .unwrap()
                .status,
            VerificationStatus::VerifiedNotApplied
        );
        assert_eq!(
            verifier
                .verify_and_record("nodeB", &alert, 2_001)
                .unwrap()
                .status,
            VerificationStatus::AlreadyVerified
        );
        let proof: MemberVerificationResult = serde_json::from_str(
            &std::fs::read_to_string(root.join("state/nodeB/alert-1/verification.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(proof.status, VerificationStatus::VerifiedNotApplied);
        let _ = std::fs::remove_dir_all(root);
    }
    #[test]
    fn wrong_circle_bad_key_stale_version_and_expiry_are_rejected() {
        let (root, verifier, alert) = fixture();
        let mut wrong = alert.clone();
        wrong.circle_id = "wrong".into();
        assert_eq!(
            verifier
                .verify_and_record("nodeB", &wrong, 2_000)
                .unwrap()
                .status,
            VerificationStatus::Rejected
        );
        let mut key = alert.clone();
        key.guardian_public_key_hex.replace_range(0..2, "00");
        assert_eq!(
            verifier
                .verify_and_record("nodeB", &key, 2_000)
                .unwrap()
                .status,
            VerificationStatus::Rejected
        );
        let mut stale = alert.clone();
        stale.policy_version = 21;
        assert_eq!(
            verifier
                .verify_and_record("nodeB", &stale, 2_000)
                .unwrap()
                .status,
            VerificationStatus::Rejected
        );
        assert_eq!(
            verifier
                .verify_and_record("nodeB", &alert, 61_000)
                .unwrap()
                .status,
            VerificationStatus::Rejected
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
