//! VS13: Guardian signing for an approved, immutable VS12 policy candidate.
//!
//! The signing boundary uses Ed25519.  The standalone key manager keeps its
//! software private key under `data/virtual_shift/guardian_keys`; production
//! can replace this manager with TPM/HSM-backed key retrieval without changing
//! candidate, review, or signature record formats.

use std::path::{Path, PathBuf};

use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519},
};
use serde::{Deserialize, Serialize};

use super::{
    canonical_policy_bytes, sha256_hex, ApprovalService, BuiltPolicyCandidate, ReviewRecord,
    VersionedPolicyCandidate,
};

const SIGNATURE_SCHEMA_VERSION: u32 = 1;

/// Non-secret Guardian configuration.  The key itself is never stored in this
/// config file or committed to source control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianSignerConfig {
    pub schema_version: u32,
    pub guardian_id: String,
    pub algorithm: String,
}

impl GuardianSignerConfig {
    pub fn from_path(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let config: Self = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema_version != 1 {
            anyhow::bail!("unsupported Guardian signer schema {}", self.schema_version);
        }
        if self.guardian_id.trim().is_empty()
            || self.guardian_id.contains(['/', '\\'])
            || self.guardian_id == "."
            || self.guardian_id == ".."
        {
            anyhow::bail!("Guardian ID must be a non-empty file-name-safe identifier");
        }
        if self.algorithm != "ed25519" {
            anyhow::bail!("only ed25519 Guardian signing is supported");
        }
        Ok(())
    }
}

/// Software-backed standalone key manager.  It has one Guardian identity and
/// exposes signing and public verification, never the private key bytes.
#[derive(Debug, Clone)]
pub struct GuardianKeyManager {
    config: GuardianSignerConfig,
    key_root: PathBuf,
}

impl GuardianKeyManager {
    pub fn from_config(
        config_path: impl AsRef<Path>,
        key_root: impl Into<PathBuf>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            config: GuardianSignerConfig::from_path(config_path)?,
            key_root: key_root.into(),
        })
    }

    pub fn guardian_id(&self) -> &str {
        &self.config.guardian_id
    }

    pub fn algorithm(&self) -> &str {
        &self.config.algorithm
    }

    pub fn sign(&self, canonical_policy_bytes: &[u8]) -> anyhow::Result<(String, String)> {
        if canonical_policy_bytes.is_empty() {
            anyhow::bail!("refusing to sign empty canonical policy bytes");
        }
        let key_pair = self.load_or_create_key_pair()?;
        let signature = key_pair.sign(canonical_policy_bytes);
        Ok((
            hex_encode(signature.as_ref()),
            hex_encode(key_pair.public_key().as_ref()),
        ))
    }

    pub fn verify(
        &self,
        canonical_policy_bytes: &[u8],
        public_key_hex: &str,
        signature_hex: &str,
    ) -> anyhow::Result<()> {
        let public_key = hex_decode(public_key_hex, "public key")?;
        let signature = hex_decode(signature_hex, "signature")?;
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(canonical_policy_bytes, &signature)
            .map_err(|_| anyhow::anyhow!("Guardian signature verification failed"))
    }

    fn key_path(&self) -> PathBuf {
        self.key_root
            .join(format!("{}.ed25519.pkcs8", self.config.guardian_id))
    }

    /// Public half of the Guardian key. This is safe to distribute to Circle
    /// members and is the trust-anchor value compared by VS16. The private
    /// PKCS#8 key remains separate and is never read by a receiving member.
    fn public_key_path(&self) -> PathBuf {
        self.key_root
            .join(format!("{}.ed25519.public", self.config.guardian_id))
    }

    fn load_or_create_key_pair(&self) -> anyhow::Result<Ed25519KeyPair> {
        let key_path = self.key_path();
        let key_bytes = if key_path.is_file() {
            std::fs::read(&key_path)?
        } else {
            std::fs::create_dir_all(&self.key_root)?;
            let generated = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .map_err(|_| anyhow::anyhow!("failed to generate Guardian Ed25519 key"))?;
            // `create_new` prevents silently replacing a concurrently-created
            // Guardian key, which would make prior signatures unverifiable.
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&key_path)
            {
                Ok(mut file) => {
                    use std::io::Write;
                    file.write_all(generated.as_ref())?;
                    generated.as_ref().to_vec()
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    std::fs::read(&key_path)?
                }
                Err(error) => return Err(error.into()),
            }
        };
        let pair = Ed25519KeyPair::from_pkcs8(&key_bytes).map_err(|_| {
            anyhow::anyhow!("stored Guardian key is not a valid Ed25519 PKCS#8 key")
        })?;
        let public_path = self.public_key_path();
        let public_hex = hex_encode(pair.public_key().as_ref());
        if public_path.is_file() {
            let stored = std::fs::read_to_string(&public_path)?.trim().to_owned();
            if stored != public_hex {
                anyhow::bail!("stored Guardian public key does not match its private key");
            }
        } else {
            std::fs::write(public_path, public_hex)?;
        }
        Ok(pair)
    }
}

/// Durable VS13 result.  This is not yet a network message (that is VS14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedVirtualShiftPolicy {
    pub schema_version: u32,
    pub policy: VersionedPolicyCandidate,
    pub signer_id: String,
    pub algorithm: String,
    pub signed_at_ms: u64,
    pub canonical_sha256: String,
    pub signature_hex: String,
    pub public_key_hex: String,
    pub status: String,
}

/// Sign the exact VS12 canonical bytes, only after the owner approval record
/// and all candidate/review linkages have been checked.
pub fn sign_approved_policy(
    manager: &GuardianKeyManager,
    review: &ReviewRecord,
    built: &BuiltPolicyCandidate,
    signed_at_ms: u64,
) -> anyhow::Result<SignedVirtualShiftPolicy> {
    ApprovalService::require_approved(review)?;
    if signed_at_ms == 0 {
        anyhow::bail!("signed policy needs a non-zero signing timestamp");
    }
    if built.candidate.status != "candidate_not_signed" {
        anyhow::bail!("only an unsigned VS12 candidate may enter VS13 signing");
    }
    if built.candidate.source_recommendation_id != review.recommendation_id
        || built.candidate.source_anomaly_id != review.anomaly_id
    {
        anyhow::bail!("candidate does not link to the approved recommendation/anomaly");
    }
    let recomputed = canonical_policy_bytes(&built.candidate)?;
    if recomputed != built.canonical_bytes {
        anyhow::bail!("candidate canonical bytes do not match its structured policy content");
    }
    let digest = sha256_hex(&built.canonical_bytes);
    if digest != built.candidate.canonical_sha256 {
        anyhow::bail!("candidate canonical SHA-256 does not match its exact bytes");
    }
    let (signature_hex, public_key_hex) = manager.sign(&built.canonical_bytes)?;
    let signed = SignedVirtualShiftPolicy {
        schema_version: SIGNATURE_SCHEMA_VERSION,
        policy: built.candidate.clone(),
        signer_id: manager.guardian_id().to_owned(),
        algorithm: manager.algorithm().to_owned(),
        signed_at_ms,
        canonical_sha256: digest,
        signature_hex,
        public_key_hex,
        status: "signed_not_broadcast".into(),
    };
    verify_signed_policy(&signed)?;
    Ok(signed)
}

/// Local verification used before a later VS14 message is created.  Any byte
/// change in the policy invalidates either the hash check or the Ed25519 check.
pub fn verify_signed_policy(signed: &SignedVirtualShiftPolicy) -> anyhow::Result<()> {
    if signed.schema_version != SIGNATURE_SCHEMA_VERSION
        || signed.signer_id.trim().is_empty()
        || signed.algorithm != "ed25519"
        || signed.signed_at_ms == 0
        || signed.status != "signed_not_broadcast"
    {
        anyhow::bail!("signed Guardian policy metadata is invalid");
    }
    let canonical = canonical_policy_bytes(&signed.policy)?;
    let digest = sha256_hex(&canonical);
    if digest != signed.canonical_sha256 || digest != signed.policy.canonical_sha256 {
        anyhow::bail!("signed Guardian policy hash does not match exact canonical bytes");
    }
    let public_key = hex_decode(&signed.public_key_hex, "public key")?;
    let signature = hex_decode(&signed.signature_hex, "signature")?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&canonical, &signature)
        .map_err(|_| anyhow::anyhow!("Guardian signature verification failed"))
}

pub fn write_signed_policy(
    root: impl AsRef<Path>,
    signed: &SignedVirtualShiftPolicy,
) -> anyhow::Result<PathBuf> {
    verify_signed_policy(signed)?;
    if signed.policy.policy_id.trim().is_empty() || signed.policy.policy_id.contains(['/', '\\']) {
        anyhow::bail!("signed policy ID must be file-name-safe");
    }
    let directory = root.as_ref().join(&signed.policy.policy_id);
    std::fs::create_dir_all(&directory)?;
    let path = directory.join("signed_policy.json");
    std::fs::write(&path, serde_json::to_string_pretty(signed)?)?;
    Ok(path)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(value: &str, description: &str) -> anyhow::Result<Vec<u8>> {
    if value.is_empty() || value.len() % 2 != 0 {
        anyhow::bail!("{description} must be non-empty, even-length hexadecimal");
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| anyhow::anyhow!("{description} is not valid hexadecimal"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::alert::Severity;
    use crate::virtual_shift::{
        build_candidate_from_approved_review, recommendation_from_event, AnomalyEvent,
        AnomalyEvidence, AnomalyType, OwnerDecision, ReviewStatus,
    };

    use super::*;

    fn key_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("virtual_shift_vs13_{label}_{}", std::process::id()))
    }

    fn manager(root: &Path) -> GuardianKeyManager {
        let config_path = root.join("guardian.json");
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(
            &config_path,
            r#"{ "schema_version": 1, "guardian_id": "guardian-nodeA", "algorithm": "ed25519" }"#,
        )
        .unwrap();
        GuardianKeyManager::from_config(config_path, root.join("keys")).unwrap()
    }

    fn approved_review() -> ReviewRecord {
        let recommendation = recommendation_from_event(
            "vsr-sign-001",
            &AnomalyEvent {
                anomaly_id: "anom-sign-001".into(),
                source_node: "nodeA".into(),
                anomaly_type: AnomalyType::ConnectionScan,
                score: 0.95,
                confidence: 0.93,
                severity: Severity::High,
                affected_peers: vec![],
                observed_at_ms: 1_000,
                evidence: vec![AnomalyEvidence {
                    feature: "conn_rate".into(),
                }],
                reason: "test".into(),
                recommendation: "test".into(),
                proposed_action: None,
            },
        );
        // Build an actual VS8 aggregate through the public recommendation
        // path, then reuse it inside a realistic approved review record.
        let aggregate = crate::virtual_shift::aggregate_recommendations(
            &recommendation,
            vec![],
            vec![crate::virtual_shift::AttestationRecommendation {
                policy_action: crate::policy::PolicyAction::IncreaseAttestationFrequency,
                target_node: "nodeA".into(),
                interval_seconds: 120,
                immediate_reattest: true,
                advisory_only: true,
                reason: "test".into(),
            }],
            vec![],
            vec![],
        );
        ReviewRecord {
            schema_version: 1,
            recommendation_id: "vsr-sign-001".into(),
            anomaly_id: "anom-sign-001".into(),
            source_node: "nodeA".into(),
            status: ReviewStatus::Approved,
            owner_decision: Some(OwnerDecision {
                reviewer_id: "nodeA".into(),
                decision: ReviewStatus::Approved,
                reason: Some("approved".into()),
                decided_at_ms: 2_000,
            }),
            created_at_ms: 1_000,
            source_proposal_path: "test.json".into(),
            proposal: serde_json::json!({
                "vs8": aggregate,
                "vs9": { "human_summary": "test" }
            }),
        }
    }

    fn built() -> BuiltPolicyCandidate {
        let active = super::super::policy_builder::ActiveVirtualShiftPolicy {
            schema_version: 1,
            policy_id: "policy-active-v21".into(),
            circle_id: "circle-main".into(),
            policy_version: 21,
            actions: vec![],
            rules: vec![],
            applicable_members: vec!["nodeA".into()],
        };
        build_candidate_from_approved_review(&active, &approved_review()).unwrap()
    }

    #[test]
    fn approved_exact_candidate_is_signed_and_verified() {
        let root = key_root("valid");
        let signed =
            sign_approved_policy(&manager(&root), &approved_review(), &built(), 3_000).unwrap();
        assert_eq!(signed.policy.policy_version, 22);
        assert_eq!(signed.status, "signed_not_broadcast");
        assert!(verify_signed_policy(&signed).is_ok());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn altered_policy_byte_fails_local_verification() {
        let root = key_root("tamper");
        let mut signed =
            sign_approved_policy(&manager(&root), &approved_review(), &built(), 3_000).unwrap();
        signed.policy.policy_version = 23;
        assert!(verify_signed_policy(&signed).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn signing_without_approval_or_with_wrong_bytes_is_refused() {
        let root = key_root("gate");
        let mut pending = approved_review();
        pending.status = ReviewStatus::PendingReview;
        pending.owner_decision = None;
        assert!(sign_approved_policy(&manager(&root), &pending, &built(), 3_000).is_err());
        let mut changed = built();
        changed.canonical_bytes.push(b'x');
        assert!(
            sign_approved_policy(&manager(&root), &approved_review(), &changed, 3_000).is_err()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn signed_policy_persists_and_reloads_verifiably() {
        let root = key_root("persist");
        let signed =
            sign_approved_policy(&manager(&root), &approved_review(), &built(), 3_000).unwrap();
        let path = write_signed_policy(root.join("policies"), &signed).unwrap();
        let reloaded: SignedVirtualShiftPolicy =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert!(verify_signed_policy(&reloaded).is_ok());
        let _ = std::fs::remove_dir_all(root);
    }
}
