//! VS12: build a versioned candidate policy from an approved review record.
//!
//! The builder reads an active policy and returns a separate candidate copy.
//! It never changes the active policy, signs a policy or applies enforcement.

use std::path::{Path, PathBuf};

use super::{AggregatedAction, AggregatedRecommendation, ApprovalService, ReviewRecord};
use serde::{Deserialize, Serialize};

/// A precise Layer-3/4 rule defined by the Circle Owner.  The anomaly model
/// never invents these values: policy building only carries forward rules
/// that an administrator has explicitly approved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NetworkRuleAction {
    Allow,
    Deny,
}

/// Portable policy rule format.  It deliberately mirrors the admin policy
/// document: source, destination, protocol and port are all explicit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicyRule {
    pub id: String,
    pub action: NetworkRuleAction,
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub port: u16,
    pub reason: String,
}

/// Owner-maintained source of allowed network-rule templates.  It is read as
/// JSON today; the same fields can later be supplied by a policy service or
/// YAML loader without changing candidate/signing code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminNetworkRuleTemplates {
    pub schema_version: u32,
    pub purpose: String,
    pub rules: Vec<NetworkPolicyRule>,
    /// Owner-defined matching metadata. It limits which existing admin rules
    /// the system may suggest for an anomaly family.
    #[serde(default)]
    pub matches: Vec<AdminRuleMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminRuleMatch {
    pub rule_id: String,
    pub anomaly_types: Vec<String>,
}

impl AdminNetworkRuleTemplates {
    pub fn from_path(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let templates: Self = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        templates.validate()?;
        Ok(templates)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema_version != 1 {
            anyhow::bail!(
                "unsupported network rule template schema {}",
                self.schema_version
            );
        }
        for rule in &self.rules {
            if rule.id.trim().is_empty()
                || rule.src.trim().is_empty()
                || rule.dst.trim().is_empty()
                || rule.protocol.trim().is_empty()
                || rule.reason.trim().is_empty()
            {
                anyhow::bail!("each network rule needs id, src, dst, protocol and reason");
            }
            if rule.port == 0 {
                anyhow::bail!(
                    "network rule '{}' needs an explicit port from 1 to 65535",
                    rule.id
                );
            }
            if !matches!(rule.protocol.to_ascii_uppercase().as_str(), "TCP" | "UDP") {
                anyhow::bail!("network rule '{}' protocol must be TCP or UDP", rule.id);
            }
        }
        for rule_match in &self.matches {
            if !self.rules.iter().any(|rule| rule.id == rule_match.rule_id) {
                anyhow::bail!(
                    "rule match references unknown rule '{}'",
                    rule_match.rule_id
                );
            }
            if rule_match.anomaly_types.is_empty() {
                anyhow::bail!(
                    "rule match '{}' needs at least one anomaly type",
                    rule_match.rule_id
                );
            }
        }
        Ok(())
    }

    pub fn suggested_rule_ids(&self, anomaly_type: &str) -> Vec<String> {
        self.matches
            .iter()
            .filter(|rule_match| {
                rule_match
                    .anomaly_types
                    .iter()
                    .any(|value| value == anomaly_type)
            })
            .map(|rule_match| rule_match.rule_id.clone())
            .collect()
    }
}

/// Read-only current policy. In production this will be supplied by the
/// existing active-policy store; the standalone demo reads the configured JSON
/// fixture instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveVirtualShiftPolicy {
    pub schema_version: u32,
    /// Stable identifier of the policy currently active on this member.
    /// Old fixtures without it retain a readable `legacy-active-policy` ID.
    #[serde(default = "default_active_policy_id")]
    pub policy_id: String,
    pub circle_id: String,
    pub policy_version: u64,
    pub actions: Vec<AggregatedAction>,
    /// Administrator-owned ALLOW/DENY rules currently in force.  When a new
    /// candidate is applied, its predecessor is kept unchanged in backup
    /// history, including these rules.
    #[serde(default)]
    pub rules: Vec<NetworkPolicyRule>,
    /// Members to which this policy version applies. An empty legacy value
    /// means no explicit scope was recorded; all newly built policies carry
    /// an explicit member list.
    #[serde(default)]
    pub applicable_members: Vec<String>,
}

fn default_active_policy_id() -> String {
    "legacy-active-policy".into()
}

impl ActiveVirtualShiftPolicy {
    pub fn from_path(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let policy: Self = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema_version != 1 {
            anyhow::bail!("unsupported active policy schema {}", self.schema_version);
        }
        if self.circle_id.trim().is_empty() || self.policy_version == 0 {
            anyhow::bail!("active policy needs a Circle ID and non-zero version");
        }
        if self.policy_id.trim().is_empty() {
            anyhow::bail!("active policy needs a policy ID");
        }
        Ok(())
    }
}

/// Immutable candidate generated by VS12 and consumed by VS13 signing later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedPolicyCandidate {
    pub schema_version: u32,
    pub policy_id: String,
    pub circle_id: String,
    pub parent_policy_version: u64,
    pub policy_version: u64,
    pub source_recommendation_id: String,
    pub source_anomaly_id: String,
    pub actions: Vec<AggregatedAction>,
    /// Exact network rules copied from the approved active policy.  A later
    /// admin-approved rule change can add/remove an entry before signing;
    /// Task-1 telemetry alone is never allowed to guess IPs or ports.
    #[serde(default)]
    pub rules: Vec<NetworkPolicyRule>,
    /// Explicit policy scope. Circle members may receive an alert for audit,
    /// but only these members may activate the policy.
    #[serde(default)]
    pub applicable_members: Vec<String>,
    pub canonical_sha256: String,
    pub status: String,
}

/// Candidate plus exact canonical policy bytes. Bytes are kept out of the
/// JSON candidate to avoid accidental re-serialization before VS13 signs them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltPolicyCandidate {
    pub candidate: VersionedPolicyCandidate,
    pub canonical_bytes: Vec<u8>,
}

/// Read active policy, copy in the approved VS8 actions, increment the
/// version and hash canonical bytes. The active policy is borrowed only.
pub fn build_candidate_from_approved_review(
    active: &ActiveVirtualShiftPolicy,
    review: &ReviewRecord,
) -> anyhow::Result<BuiltPolicyCandidate> {
    active.validate()?;
    ApprovalService::require_approved(review)?;
    let aggregate: AggregatedRecommendation = serde_json::from_value(
        review
            .proposal
            .get("vs8")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("approved review is missing VS8 aggregate"))?,
    )?;
    if aggregate.recommendation_id != review.recommendation_id
        || aggregate.anomaly_id != review.anomaly_id
        || aggregate.source_node != review.source_node
    {
        anyhow::bail!("VS8 aggregate does not match approved review identity");
    }
    if aggregate.actions.is_empty() {
        anyhow::bail!("approved recommendation has no final VS8 actions to build into a policy");
    }
    let policy_version = active
        .policy_version
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("policy version overflow"))?;
    // The version remains the next version of the read-only active policy.
    // The recommendation suffix prevents two concurrently reviewed proposals
    // for that same next version from overwriting each other's candidate files
    // before VS17 decides which one becomes active.
    let policy_id = format!(
        "vshift-{}-v{}-{}",
        active.circle_id,
        policy_version,
        file_safe_id(&review.recommendation_id)?
    );
    let mut candidate = VersionedPolicyCandidate {
        schema_version: 1,
        policy_id,
        circle_id: active.circle_id.clone(),
        parent_policy_version: active.policy_version,
        policy_version,
        source_recommendation_id: review.recommendation_id.clone(),
        source_anomaly_id: review.anomaly_id.clone(),
        actions: aggregate.actions,
        rules: active.rules.clone(),
        applicable_members: vec![review.source_node.clone()],
        canonical_sha256: String::new(),
        status: "candidate_not_signed".into(),
    };
    let canonical_bytes = canonical_policy_bytes(&candidate)?;
    candidate.canonical_sha256 = sha256_hex(&canonical_bytes);
    Ok(BuiltPolicyCandidate {
        candidate,
        canonical_bytes,
    })
}

/// Set the explicit member scope for a new candidate before it is signed.
/// This is an owner-controlled deployment choice, not a model prediction.
pub fn set_policy_targets(
    built: &mut BuiltPolicyCandidate,
    members: &[String],
) -> anyhow::Result<()> {
    if members.is_empty() {
        anyhow::bail!("a policy needs at least one applicable member");
    }
    let mut targets = members.to_vec();
    targets.sort();
    targets.dedup();
    if targets
        .iter()
        .any(|member| member.trim().is_empty() || member.contains(['/', '\\']))
    {
        anyhow::bail!("policy target members must be non-empty safe node IDs");
    }
    built.candidate.applicable_members = targets;
    let canonical = canonical_policy_bytes(&built.candidate)?;
    built.candidate.canonical_sha256 = sha256_hex(&canonical);
    built.canonical_bytes = canonical;
    Ok(())
}

/// Build a candidate which carries both the currently active rules and a
/// specific, owner-selected subset of validated rule templates.  This is the
/// safe integration point for the future manual Trigger button: the model may
/// recommend an action, but only the owner-selected template IDs enter the
/// signed policy.
pub fn add_owner_selected_rules(
    built: &mut BuiltPolicyCandidate,
    templates: &AdminNetworkRuleTemplates,
    selected_rule_ids: &[String],
) -> anyhow::Result<()> {
    templates.validate()?;
    for id in selected_rule_ids {
        let rule = templates
            .rules
            .iter()
            .find(|rule| &rule.id == id)
            .ok_or_else(|| {
                anyhow::anyhow!("owner-selected rule '{id}' is not in the approved template file")
            })?;
        if let Some(existing) = built
            .candidate
            .rules
            .iter_mut()
            .find(|existing| existing.id == rule.id)
        {
            // A selected template is the owner's latest approved definition.
            // Refresh it only in the new candidate; VS17 keeps the prior
            // policy unchanged in backup history for rollback.
            *existing = rule.clone();
        } else {
            built.candidate.rules.push(rule.clone());
        }
    }
    built
        .candidate
        .rules
        .sort_by(|left, right| left.id.cmp(&right.id));
    let canonical = canonical_policy_bytes(&built.candidate)?;
    built.candidate.canonical_sha256 = sha256_hex(&canonical);
    built.canonical_bytes = canonical;
    Ok(())
}

fn file_safe_id(value: &str) -> anyhow::Result<&str> {
    if value.trim().is_empty() || value.contains(['/', '\\']) || matches!(value, "." | "..") {
        anyhow::bail!("recommendation ID must be file-name-safe for policy building");
    }
    Ok(value)
}

/// Persist only the candidate copy and its exact canonical bytes. The active
/// policy remains at its original path until VS17 atomic apply is implemented.
pub fn write_built_candidate(
    root: impl AsRef<Path>,
    built: &BuiltPolicyCandidate,
) -> anyhow::Result<PathBuf> {
    if built.candidate.policy_id.trim().is_empty()
        || built.candidate.policy_id.contains(['/', '\\'])
    {
        anyhow::bail!("candidate policy ID must be file-name-safe");
    }
    let directory = root.as_ref().join(&built.candidate.policy_id);
    std::fs::create_dir_all(&directory)?;
    let candidate_path = directory.join("candidate_policy.json");
    let canonical_path = directory.join("canonical_policy.json");
    std::fs::write(
        &candidate_path,
        serde_json::to_string_pretty(&built.candidate)?,
    )?;
    std::fs::write(&canonical_path, &built.canonical_bytes)?;
    Ok(candidate_path)
}

/// Serialize a candidate without its own hash field. Object keys are sorted
/// recursively so the exact same candidate always produces the same bytes.
pub fn canonical_policy_bytes(candidate: &VersionedPolicyCandidate) -> anyhow::Result<Vec<u8>> {
    let mut value = serde_json::to_value(candidate)?;
    value
        .as_object_mut()
        .expect("serialized policy candidate is an object")
        .remove("canonical_sha256");
    let mut output = String::new();
    write_canonical_json(&value, &mut output)?;
    Ok(output.into_bytes())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    sha256(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Small dependency-free SHA-256 implementation. VS13 will sign the exact
/// canonical bytes and this digest; keeping it local lets the standalone
/// engine build offline while still producing a standard SHA-256 hash.
fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut message = input.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = INITIAL;
    for chunk in message.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes(
                chunk[index * 4..index * 4 + 4]
                    .try_into()
                    .expect("4-byte word"),
            );
        }
        for index in 16..64 {
            let small0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let small1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(small0)
                .wrapping_add(words[index - 7])
                .wrapping_add(small1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let big1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(big1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let big0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = big0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
    let mut digest = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn write_canonical_json(value: &serde_json::Value, output: &mut String) -> anyhow::Result<()> {
    match value {
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => output.push_str(&serde_json::to_string(value)?),
        serde_json::Value::Array(values) => {
            output.push('[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical_json(item, output)?;
            }
            output.push(']');
        }
        serde_json::Value::Object(values) => {
            output.push('{');
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(key)?);
                output.push(':');
                write_canonical_json(&values[key], output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::alert::Severity;
    use crate::policy::{LoggingLevel, PolicyAction};
    use crate::virtual_shift::{
        recommendation_from_event, AggregatedAction, AnomalyEvent, AnomalyEvidence,
        LoggingRecommendation, OwnerDecision, ReviewStatus,
    };

    use super::*;

    fn active() -> ActiveVirtualShiftPolicy {
        ActiveVirtualShiftPolicy {
            schema_version: 1,
            policy_id: "policy-active-v21".into(),
            circle_id: "circle-main".into(),
            policy_version: 21,
            actions: vec![],
            rules: vec![],
            applicable_members: vec!["nodeA".into()],
        }
    }

    fn review(status: ReviewStatus) -> ReviewRecord {
        let recommendation = recommendation_from_event(
            "vsr-policy-001",
            &AnomalyEvent {
                anomaly_id: "anom-policy-001".into(),
                source_node: "nodeA".into(),
                anomaly_type: crate::virtual_shift::AnomalyType::ConnectionScan,
                score: 0.94,
                confidence: 0.92,
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
        let action = AggregatedAction::Logging(LoggingRecommendation {
            policy_action: PolicyAction::EnableAdditionalLogging,
            target_node: "nodeA".into(),
            logging_level: LoggingLevel::Detailed,
            scopes: vec![],
            duration_seconds: 900,
            starts_at_ms: 1_000,
            expires_at_ms: 901_000,
            advisory_only: true,
            reason: "test".into(),
        });
        ReviewRecord {
            schema_version: 1,
            recommendation_id: recommendation.recommendation_id.clone(),
            anomaly_id: recommendation.anomaly_id.clone(),
            source_node: recommendation.source_node.clone(),
            status,
            owner_decision: (status != ReviewStatus::PendingReview).then(|| OwnerDecision {
                reviewer_id: "nodeA".into(),
                decision: status,
                reason: None,
                decided_at_ms: 2_000,
            }),
            created_at_ms: 1_000,
            source_proposal_path: "test.json".into(),
            proposal: serde_json::json!({
                "vs8": {
                    "recommendation_id": recommendation.recommendation_id,
                    "anomaly_id": recommendation.anomaly_id,
                    "source_node": recommendation.source_node,
                    "actions": [action],
                    "advisory_only": true,
                    "conflict_resolution": []
                },
                "vs9": { "human_summary": "test" }
            }),
        }
    }

    #[test]
    fn approved_review_builds_v_next_without_mutating_active_policy() {
        let active = active();
        let built =
            build_candidate_from_approved_review(&active, &review(ReviewStatus::Approved)).unwrap();
        assert_eq!(built.candidate.parent_policy_version, 21);
        assert_eq!(built.candidate.policy_version, 22);
        assert_eq!(built.candidate.actions.len(), 1);
        assert_eq!(active.policy_version, 21);
        assert_eq!(built.candidate.canonical_sha256.len(), 64);
    }

    #[test]
    fn pending_or_rejected_review_cannot_build_candidate_policy() {
        assert!(build_candidate_from_approved_review(
            &active(),
            &review(ReviewStatus::PendingReview)
        )
        .is_err());
        assert!(
            build_candidate_from_approved_review(&active(), &review(ReviewStatus::Rejected))
                .is_err()
        );
    }

    #[test]
    fn canonical_bytes_and_hash_are_stable() {
        let first =
            build_candidate_from_approved_review(&active(), &review(ReviewStatus::Approved))
                .unwrap();
        let second =
            build_candidate_from_approved_review(&active(), &review(ReviewStatus::Approved))
                .unwrap();
        assert_eq!(first.canonical_bytes, second.canonical_bytes);
        assert_eq!(
            first.candidate.canonical_sha256,
            second.candidate.canonical_sha256
        );
    }

    #[test]
    fn sha256_matches_standard_abc_test_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn candidate_persistence_does_not_touch_active_policy_file() {
        let root =
            std::env::temp_dir().join(format!("virtual_shift_policy_{}", std::process::id()));
        let active_path = root.join("active.json");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            &active_path,
            serde_json::to_string_pretty(&active()).unwrap(),
        )
        .unwrap();
        let before = std::fs::read(&active_path).unwrap();
        let built =
            build_candidate_from_approved_review(&active(), &review(ReviewStatus::Approved))
                .unwrap();
        let candidate = write_built_candidate(root.join("candidates"), &built).unwrap();
        assert!(candidate.is_file());
        assert_eq!(std::fs::read(&active_path).unwrap(), before);
        let _ = std::fs::remove_dir_all(root);
    }
}
