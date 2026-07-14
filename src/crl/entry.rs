//! CRL entry — one revocation record.
//!
//! Each entry is cryptographically signed (DataIntegrityProof + ecdsa-2019)
//! by the issuer (Circle owner or member reporting compromise) using their
//! DKP. The proof verifies against the issuer's DID Document resolved via
//! the local DID resolver.
//!
//! Gossip propagation, emergency broadcast, and offline sync build on this
//! structure, so the schema pre-allocates the bookkeeping fields they need
//! (`peers_notified`, `propagated`).

use crate::did::document::Proof;
use serde::{Deserialize, Serialize};

pub const CRL_CONTEXT_CORE: &str = "https://www.w3.org/2018/credentials/v1";
pub const CRL_CONTEXT_SGX: &str = "https://schemas.cyberzeus.io/sgx/v1/crl";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    Compromised,
    Lost,
    Stolen,
    PolicyViolation,
    /// Owner-initiated administrative removal (not a security event).
    /// Not in the original spec but operationally required — flagged
    /// here so we don't conflate it with `PolicyViolation`.
    AdministrativeRemoval,
    /// Member voluntarily leaving the Circle (also operational).
    VoluntaryDeparture,
}

impl RevocationReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compromised => "compromised",
            Self::Lost => "lost",
            Self::Stolen => "stolen",
            Self::PolicyViolation => "policy_violation",
            Self::AdministrativeRemoval => "administrative_removal",
            Self::VoluntaryDeparture => "voluntary_departure",
        }
    }

    /// Whether this reason is security-critical (i.e. should propagate via
    /// emergency broadcast and terminate sessions instantly). Used to select
    /// the fast-path notification channel.
    pub fn is_security_critical(self) -> bool {
        matches!(
            self,
            Self::Compromised | Self::Lost | Self::Stolen | Self::PolicyViolation
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokerRole {
    /// Circle owner. Has authority to revoke any DID for any reason.
    Owner,
    /// A member reporting another peer's compromise. Restricted to
    /// security-critical reasons; severity must be Critical or High.
    Member,
}

/// Optional context attached to the revocation. Free-form to support
/// member reports including attestation failures, audit-log refs, etc.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RevocationEvidence {
    /// Human-readable description.
    pub note: Option<String>,
    /// Reference to an audit-log entry id, if any.
    pub audit_ref: Option<String>,
    /// Reference to a failed attestation evidence id, if any.
    pub attestation_ref: Option<String>,
    /// SHA-256 of any external evidence blob the issuer asserts.
    pub evidence_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlEntry {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// `urn:uuid:<v4>` — unique per entry; used for gossip dedup.
    pub id: String,
    #[serde(rename = "type")]
    pub r#type: Vec<String>, // ["VerifiableCredential", "RevocationCredential"]

    // ── Spec-required identity fields ──────────────────────────────────
    /// The DID being revoked.
    pub revoked_did: String,
    /// Optional device fingerprint (SE050 UID hash or peer DKP fingerprint).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Optional user binding (Phase 2 has user_id only if your tenancy
    /// model populates it; left optional so it doesn't block on absence).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// The Circle this revocation applies to.
    pub circle_id: String,

    // ── Spec-required revocation facts ─────────────────────────────────
    pub reason: RevocationReason,
    pub severity: Severity,
    pub timestamp: String, // RFC3339
    pub revoker_did: String,
    pub revoker_role: RevokerRole,

    // ── Optional context ───────────────────────────────────────────────
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<RevocationEvidence>,

    // ── Cryptographic proof (spec: "cryptographic signature") ──────────
    pub proof: Proof,

    // ── Gossip / anti-entropy fields ───────────────────────────────────
    /// Peers (by DID) that have ack'd receipt of this entry.
    #[serde(default)]
    pub peers_notified: Vec<String>,
    /// Set true once peers_notified reaches the propagation threshold
    /// (default 80% of Circle). Updated by the gossip task, NOT by issue.
    #[serde(default)]
    pub propagated: bool,
}

impl CrlEntry {
    /// Stable identifier for dedup and Merkle-root computation.
    /// Hash the entry MINUS the gossip fields (peers_notified, propagated)
    /// and MINUS the proof, so a re-signed entry from a different node
    /// produces the same fingerprint.
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut cloned = self.clone();
        cloned.peers_notified.clear();
        cloned.propagated = false;
        cloned.proof = Proof::default();
        let v = serde_json::to_value(&cloned).expect("crl entry to value");
        let bytes = canonical_bytes(&v);
        let h = Sha256::digest(&bytes);
        hex::encode(h)
    }

    /// Bytes to sign — entry without its own proof, with sorted keys.
    pub fn canonical_bytes_for_sign(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut cloned = self.clone();
        cloned.proof = Proof::default();
        // Gossip fields are NOT part of the signed surface — they mutate
        // post-issuance as peers ack. Signing must skip them.
        cloned.peers_notified.clear();
        cloned.propagated = false;
        let v: serde_json::Value = serde_json::to_value(&cloned)?;
        Ok(canonical_bytes(&v))
    }
}

fn canonical_bytes(v: &serde_json::Value) -> Vec<u8> {
    let sorted = sort_json_keys(v);
    serde_json::to_vec(&sorted).expect("canonical to vec")
}

fn sort_json_keys(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(m) => {
            let mut bt = std::collections::BTreeMap::new();
            for (k, vv) in m {
                bt.insert(k.clone(), sort_json_keys(vv));
            }
            serde_json::Value::Object(bt.into_iter().collect())
        }
        serde_json::Value::Array(a) => {
            serde_json::Value::Array(a.iter().map(sort_json_keys).collect())
        }
        _ => v.clone(),
    }
}
