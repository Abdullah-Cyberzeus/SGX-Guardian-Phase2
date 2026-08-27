//! The CertificateRevocationList container. Holds all known revocations
//! and a Merkle root for O(log n) anti-entropy comparisons.

use crate::crl::entry::{CrlEntry, UnrevokeTombstone};
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
    /// Merkle root over the sorted list of active revoke/tombstone fingerprints.
    pub merkle_root: String,
    pub entries: Vec<CrlEntry>,
    #[serde(default)]
    pub tombstones: Vec<UnrevokeTombstone>,
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
            tombstones: vec![],
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
        if let Ok(idx) = self
            .tombstones
            .binary_search_by(|t| t.revoked_did.as_str().cmp(&e.revoked_did))
        {
            self.tombstones.remove(idx);
        }
        self.entries.push(e);
        self.entries
            .sort_by(|a, b| a.revoked_did.cmp(&b.revoked_did));
        Ok(true)
    }

    /// Upsert the active tombstone for `revoked_did`, removing any now-stale
    /// active revocation for that DID. A duplicate `id` is treated as a no-op.
    pub fn upsert_tombstone(&mut self, tombstone: UnrevokeTombstone) -> bool {
        if self.tombstones.iter().any(|x| x.id == tombstone.id) {
            return false;
        }
        if let Ok(idx) = self
            .entries
            .binary_search_by(|e| e.revoked_did.as_str().cmp(&tombstone.revoked_did))
        {
            self.entries.remove(idx);
        }
        match self
            .tombstones
            .binary_search_by(|t| t.revoked_did.as_str().cmp(&tombstone.revoked_did))
        {
            Ok(idx) => self.tombstones[idx] = tombstone,
            Err(idx) => self.tombstones.insert(idx, tombstone),
        }
        true
    }

    /// Admin-only reversal of a mistaken revocation. Removes the entry for
    /// `did` from the live container (the original per-entry file under
    /// `entries/<id>.json` is left untouched as append-only history).
    /// Returns the removed entry, or `NotRevoked` if `did` isn't present.
    pub fn remove(&mut self, did: &str) -> Result<CrlEntry, CrlError> {
        let idx = self
            .entries
            .binary_search_by(|e| e.revoked_did.as_str().cmp(did))
            .map_err(|_| CrlError::NotRevoked(did.to_string()))?;
        Ok(self.entries.remove(idx))
    }

    pub fn tombstone(&self, did: &str) -> Option<&UnrevokeTombstone> {
        self.tombstones
            .binary_search_by(|t| t.revoked_did.as_str().cmp(did))
            .ok()
            .map(|idx| &self.tombstones[idx])
    }

    pub fn remove_tombstone(&mut self, did: &str) -> Option<UnrevokeTombstone> {
        self.tombstones
            .binary_search_by(|t| t.revoked_did.as_str().cmp(did))
            .ok()
            .map(|idx| self.tombstones.remove(idx))
    }

    /// Recompute the Merkle root over sorted entry fingerprints.
    /// Single SHA-256 over the concatenation is sufficient for Phase 2
    /// (no proof-of-inclusion required yet - future forensics work can add
    /// that later). Function name kept "merkle" to preserve nomenclature.
    pub fn recompute_root(&mut self) {
        use sha2::{Digest, Sha256};
        let fps: BTreeSet<String> = self
            .entries
            .iter()
            .map(CrlEntry::state_fingerprint)
            .chain(
                self.tombstones
                    .iter()
                    .map(UnrevokeTombstone::state_fingerprint),
            )
            .collect();
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
        serde_json::to_vec(&sorted)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crl::entry::{
        RevocationReason, RevokerRole, Severity, CRL_CONTEXT_CORE, CRL_CONTEXT_SGX,
        CRL_UNREVOKE_TOMBSTONE_TYPE,
    };

    fn sample_crl_entry(id: &str, did: &str) -> CrlEntry {
        CrlEntry {
            context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
            id: format!("urn:uuid:{}", id),
            r#type: vec!["VerifiableCredential".into(), "RevocationCredential".into()],
            revoked_did: did.into(),
            device_id: None,
            user_id: None,
            circle_id: "c1".into(),
            reason: RevocationReason::Compromised,
            severity: Severity::Critical,
            timestamp: "2026-01-01T00:00:00Z".into(),
            revoker_did: "did:guardian:owner".into(),
            revoker_role: RevokerRole::Owner,
            evidence: None,
            proof: Proof::default(),
            peers_notified: vec![],
            propagated: false,
        }
    }

    fn sample_tombstone(id: &str, did: &str) -> UnrevokeTombstone {
        UnrevokeTombstone {
            context: vec![CRL_CONTEXT_CORE.into()],
            id: format!("urn:uuid:{}", id),
            r#type: vec!["VerifiableCredential".into(), CRL_UNREVOKE_TOMBSTONE_TYPE.into()],
            revoked_did: did.into(),
            original_entry_id: "urn:uuid:orig-1".into(),
            owner_did: "did:guardian:owner".into(),
            sequence: 1,
            timestamp: "2026-01-01T00:00:00Z".into(),
            proof: Proof::default(),
            peers_notified: vec![],
            propagated: false,
        }
    }

    #[test]
    fn test_crl_new_and_empty() {
        let crl = CertificateRevocationList::new("did:guardian:issuer", "circle-1");
        assert_eq!(crl.issuer, "did:guardian:issuer");
        assert_eq!(crl.circle_id, "circle-1");
        assert_eq!(crl.entries.len(), 0);
        assert_eq!(crl.tombstones.len(), 0);
        assert!(!crl.contains("did:guardian:target"));
    }

    #[test]
    fn test_crl_upsert_and_contains() {
        let mut crl = CertificateRevocationList::new("did:guardian:issuer", "circle-1");

        let entry1 = sample_crl_entry("1111", "did:guardian:target-b");
        let entry2 = sample_crl_entry("2222", "did:guardian:target-a");

        assert!(crl.upsert(entry1.clone()).unwrap());
        assert!(crl.contains("did:guardian:target-b"));
        assert!(!crl.contains("did:guardian:target-a"));

        assert!(crl.upsert(entry2).unwrap());
        assert!(crl.contains("did:guardian:target-a"));
        assert!(crl.contains("did:guardian:target-b"));

        // Entries must be kept sorted by revoked_did
        assert_eq!(crl.entries[0].revoked_did, "did:guardian:target-a");
        assert_eq!(crl.entries[1].revoked_did, "did:guardian:target-b");

        // Duplicate ID returns Ok(false)
        assert!(!crl.upsert(entry1).unwrap());

        // Duplicate revoked_did with new ID returns AlreadyRevoked
        let duplicate_did_entry = sample_crl_entry("3333", "did:guardian:target-a");
        assert!(matches!(
            crl.upsert(duplicate_did_entry),
            Err(CrlError::AlreadyRevoked(_))
        ));
    }

    #[test]
    fn test_crl_remove_and_tombstone_lifecycle() {
        let mut crl = CertificateRevocationList::new("did:guardian:issuer", "circle-1");
        let entry = sample_crl_entry("1111", "did:guardian:alice");
        crl.upsert(entry).unwrap();

        assert!(crl.contains("did:guardian:alice"));
        let removed = crl.remove("did:guardian:alice").unwrap();
        assert_eq!(removed.revoked_did, "did:guardian:alice");
        assert!(!crl.contains("did:guardian:alice"));

        // Removing non-existent returns NotRevoked
        assert!(matches!(
            crl.remove("did:guardian:alice"),
            Err(CrlError::NotRevoked(_))
        ));

        // Upsert tombstone
        let tombstone = sample_tombstone("t1", "did:guardian:alice");
        assert!(crl.upsert_tombstone(tombstone));
        assert!(crl.tombstone("did:guardian:alice").is_some());

        // Revoking again removes the tombstone
        let new_entry = sample_crl_entry("4444", "did:guardian:alice");
        assert!(crl.upsert(new_entry).unwrap());
        assert!(crl.contains("did:guardian:alice"));
        assert!(crl.tombstone("did:guardian:alice").is_none());
    }

    #[test]
    fn test_crl_recompute_root_and_canonical_bytes() {
        let mut crl = CertificateRevocationList::new("did:guardian:issuer", "circle-1");
        crl.recompute_root();
        let root1 = crl.merkle_root.clone();
        assert!(!root1.is_empty());

        let entry = sample_crl_entry("1111", "did:guardian:alice");
        crl.upsert(entry).unwrap();
        crl.recompute_root();
        let root2 = crl.merkle_root.clone();
        assert_ne!(root1, root2);

        let bytes = crl.canonical_bytes_for_sign().unwrap();
        assert!(!bytes.is_empty());
    }
}

