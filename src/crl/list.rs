//! The CertificateRevocationList container. Holds all known revocations
//! and a Merkle root for O(log n) anti-entropy comparisons.

use crate::crl::entry::CrlEntry;
use crate::crl::errors::CrlError;
use crate::did::document::Proof;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const CRL_TYPE: &str = "CertificateRevocationList";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRevocationList {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String, // `did:guardian:<owner>/crl`
    #[serde(rename = "type")]
    pub r#type: Vec<String>, // ["VerifiableCredential", "CertificateRevocationList"]
    pub issuer: String, // local snapshotting node's DID
    pub circle_id: String,
    pub generated_at: String, // RFC3339
    /// Monotonically increasing per Circle. Anti-entropy uses this when
    /// Merkle roots differ to decide which side is newer.
    pub sequence: u64,
    /// Merkle root over the sorted list of entry fingerprints.
    pub merkle_root: String,
    pub entries: Vec<CrlEntry>,
    pub proof: Proof,
}

impl CertificateRevocationList {
    pub fn new(issuer_did: &str, circle_id: &str) -> Self {
        Self {
            context: vec![
                crate::crl::entry::CRL_CONTEXT_CORE.into(),
                crate::crl::entry::CRL_CONTEXT_SGX.into(),
            ],
            id: format!("{}/crl", issuer_did),
            r#type: vec!["VerifiableCredential".into(), CRL_TYPE.into()],
            issuer: issuer_did.into(),
            circle_id: circle_id.into(),
            generated_at: Utc::now().to_rfc3339(),
            sequence: 0,
            merkle_root: String::new(),
            entries: vec![],
            proof: Proof::default(),
        }
    }

    /// Fast lookup. We keep entries sorted by `revoked_did` so binary search
    /// is correct. `contains` is the public O(log n) gate.
    pub fn contains(&self, did: &str) -> bool {
        self.entries
            .binary_search_by(|e| e.revoked_did.as_str().cmp(did))
            .is_ok()
    }

    /// Idempotent insert. Returns Ok(true) if added, Ok(false) if already
    /// present (by entry.id OR by revoked_did — both must be unique).
    pub fn upsert(&mut self, e: CrlEntry) -> Result<bool, CrlError> {
        if self.entries.iter().any(|x| x.id == e.id) {
            return Ok(false);
        }
        if self.entries.iter().any(|x| x.revoked_did == e.revoked_did) {
            return Err(CrlError::AlreadyRevoked(e.revoked_did));
        }
        self.entries.push(e);
        self.entries
            .sort_by(|a, b| a.revoked_did.cmp(&b.revoked_did));
        Ok(true)
    }

    /// Recompute the Merkle root over sorted entry fingerprints.
    /// Single SHA-256 over the concatenation is sufficient for Phase 2
    /// (no proof-of-inclusion required yet — that's a Sprint 6 forensics
    /// task). Function name kept "merkle" to preserve nomenclature.
    pub fn recompute_root(&mut self) {
        use sha2::{Digest, Sha256};
        let fps: BTreeSet<String> = self.entries.iter().map(|e| e.fingerprint()).collect();
        let mut h = Sha256::new();
        for fp in fps {
            h.update(fp.as_bytes());
            h.update(b"\0");
        }
        self.merkle_root = hex::encode(h.finalize());
    }

    /// Bytes for signing — everything but `proof`, with sorted keys.
    pub fn canonical_bytes_for_sign(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut cloned = self.clone();
        cloned.proof = Proof::default();
        let v: serde_json::Value = serde_json::to_value(&cloned)?;
        let sorted = sort_json_keys(&v);
        Ok(serde_json::to_vec(&sorted)?)
    }
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
