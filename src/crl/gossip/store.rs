//! Serialized read-modify-write operations on the local CRL for gossip.
//!
//! All mutations from the listener task, the periodic round task, and the
//! REST trigger handler go through `CRL_WRITE_LOCK`, preventing lost
//! updates between concurrent exchanges inside this process.
//!
//! Known cross-process window: `POST /api/v1/crl/revoke` shells out to
//! `sgx-pa-cli`, which writes `crl.json` from a separate process. Both
//! writers use atomic tmp+rename (no torn files) and this module reloads
//! from disk at the start of every mutation, shrinking the lost-update
//! window to milliseconds. A cross-process advisory lock is a listed
//! follow-up hardening item.

use crate::crl::entry::{CrlEntry, UnrevokeTombstone};
use crate::crl::errors::CrlError;
use crate::crl::list::CertificateRevocationList;
use crate::crl::persistence;
use crate::did::DidRecord;
use crate::key_manager::KeyManager;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use std::collections::HashSet;
use tokio::sync::Mutex;

/// Serializes every CRL read-modify-write in this process.
pub static CRL_WRITE_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[derive(Debug, Default)]
pub struct MergeOutcome {
    pub added: usize,
    pub replaced: usize,
    pub skipped: usize,
    /// Clones of the entries actually added or replaced (for audit).
    pub merged_entries: Vec<CrlEntry>,
    /// Clones of the tombstones actually added or replaced (for audit).
    pub merged_tombstones: Vec<UnrevokeTombstone>,
    pub newly_propagated: Vec<String>,
    pub merkle_root: String,
    pub sequence: u64,
}

/// Deterministic conflict rule when two independently-issued, verified
/// records affect the SAME DID: LATER `timestamp` wins (an attacker who
/// backdates a revocation must not be able to pin a stale entry over a
/// genuinely more recent one); ties break on the lexicographically lower
/// fingerprint. Every node applies the same rule, so record sets (and
/// therefore Merkle roots) converge.
pub fn incoming_record_wins(
    existing_timestamp: &str,
    existing_fingerprint: &str,
    incoming_timestamp: &str,
    incoming_fingerprint: &str,
) -> bool {
    let existing_ts = DateTime::parse_from_rfc3339(existing_timestamp).ok();
    let incoming_ts = DateTime::parse_from_rfc3339(incoming_timestamp).ok();
    match (incoming_ts, existing_ts) {
        (Some(incoming), Some(existing)) if incoming != existing => incoming > existing,
        _ => incoming_fingerprint < existing_fingerprint,
    }
}

pub fn incoming_wins(existing: &CrlEntry, incoming: &CrlEntry) -> bool {
    let existing_fp = existing.fingerprint();
    let incoming_fp = incoming.fingerprint();
    incoming_record_wins(
        &existing.timestamp,
        &existing_fp,
        &incoming.timestamp,
        &incoming_fp,
    )
}

/// Gossip-mutable fields are LOCAL bookkeeping. A remote copy's
/// `peers_notified` / `propagated` must never be inherited (a peer could
/// otherwise fake propagation progress) - reset them on ingest. The
/// fingerprint (dedup key) is unaffected because `fingerprint()` already
/// excludes these fields.
pub fn normalized(entry: &CrlEntry) -> CrlEntry {
    let mut cleaned = entry.clone();
    cleaned.peers_notified.clear();
    cleaned.propagated = false;
    cleaned
}

pub fn normalized_tombstone(tombstone: &UnrevokeTombstone) -> UnrevokeTombstone {
    let mut cleaned = tombstone.clone();
    cleaned.peers_notified.clear();
    cleaned.propagated = false;
    cleaned
}

fn load_or_new(self_did: &str, circle_id: &str) -> Result<CertificateRevocationList, CrlError> {
    Ok(persistence::load_crl()?
        .unwrap_or_else(|| CertificateRevocationList::new(self_did, circle_id)))
}

fn resign_and_save(
    crl: &mut CertificateRevocationList,
    record: &DidRecord,
    km: &KeyManager,
) -> Result<(), CrlError> {
    crl.sequence += 1;
    crl.generated_at = Utc::now().to_rfc3339();
    crl.recompute_root();
    let canonical = crl.canonical_bytes_for_sign()?;
    let vm_ref = format!("{}#dkp-v{}", record.did, record.current_dkp_version.max(1));
    crate::did::doc_sign::sign_in_place_generic(&mut crl.proof, &canonical, km, &vm_ref)?;
    persistence::save_crl(crl)?;
    Ok(())
}

/// Merge records that the CALLER HAS ALREADY VERIFIED
/// (`crl::verify::verify_entry` / `crl::verify::verify_tombstone`) into the
/// local CRL state.
pub fn merge_verified_records(
    record: &DidRecord,
    km: &KeyManager,
    circle_id: &str,
    incoming_entries: &[CrlEntry],
    incoming_tombstones: &[UnrevokeTombstone],
) -> Result<MergeOutcome, CrlError> {
    let mut crl = load_or_new(&record.did, circle_id)?;
    let mut outcome = MergeOutcome::default();
    let mut remaining = super::protocol::MAX_ENTRIES_PER_MESSAGE;

    for entry in incoming_entries.iter().take(remaining) {
        let fingerprint = entry.fingerprint();
        if crl
            .entries
            .iter()
            .any(|existing| existing.state_fingerprint() == entry.state_fingerprint())
        {
            outcome.skipped += 1;
            remaining = remaining.saturating_sub(1);
            continue;
        }
        if let Some(existing_tombstone) = crl.tombstone(&entry.revoked_did).cloned() {
            let existing_fp = existing_tombstone.fingerprint();
            if incoming_record_wins(
                &existing_tombstone.timestamp,
                &existing_fp,
                &entry.timestamp,
                &fingerprint,
            ) {
                let normalized = normalized(entry);
                crl.upsert(normalized.clone())?;
                persistence::save_entry(&normalized)?;
                outcome.merged_entries.push(entry.clone());
                outcome.replaced += 1;
            } else {
                outcome.skipped += 1;
            }
            remaining = remaining.saturating_sub(1);
            continue;
        }
        if let Some(position) = crl
            .entries
            .iter()
            .position(|e| e.revoked_did == entry.revoked_did)
        {
            if incoming_wins(&crl.entries[position], entry) {
                let normalized = normalized(entry);
                crl.entries[position] = normalized.clone();
                persistence::save_entry(&normalized)?;
                outcome.merged_entries.push(entry.clone());
                outcome.replaced += 1;
            } else {
                outcome.skipped += 1;
            }
            remaining = remaining.saturating_sub(1);
            continue;
        }
        let normalized = normalized(entry);
        crl.entries.push(normalized.clone());
        persistence::save_entry(&normalized)?;
        outcome.merged_entries.push(entry.clone());
        outcome.added += 1;
        remaining = remaining.saturating_sub(1);
    }

    for tombstone in incoming_tombstones.iter().take(remaining) {
        let fingerprint = tombstone.fingerprint();
        if crl
            .tombstones
            .iter()
            .any(|existing| existing.state_fingerprint() == tombstone.state_fingerprint())
        {
            outcome.skipped += 1;
            continue;
        }
        if let Some(position) = crl
            .entries
            .iter()
            .position(|entry| entry.revoked_did == tombstone.revoked_did)
        {
            let existing_fp = crl.entries[position].fingerprint();
            if incoming_record_wins(
                &crl.entries[position].timestamp,
                &existing_fp,
                &tombstone.timestamp,
                &fingerprint,
            ) {
                let normalized = normalized_tombstone(tombstone);
                crl.upsert_tombstone(normalized.clone());
                persistence::save_tombstone(&normalized)?;
                outcome.merged_tombstones.push(tombstone.clone());
                outcome.replaced += 1;
            } else {
                outcome.skipped += 1;
            }
            continue;
        }
        if let Some(existing_tombstone) = crl.tombstone(&tombstone.revoked_did).cloned() {
            let existing_fp = existing_tombstone.fingerprint();
            if incoming_record_wins(
                &existing_tombstone.timestamp,
                &existing_fp,
                &tombstone.timestamp,
                &fingerprint,
            ) {
                let normalized = normalized_tombstone(tombstone);
                crl.upsert_tombstone(normalized.clone());
                persistence::save_tombstone(&normalized)?;
                outcome.merged_tombstones.push(tombstone.clone());
                outcome.replaced += 1;
            } else {
                outcome.skipped += 1;
            }
            continue;
        }
        let normalized = normalized_tombstone(tombstone);
        crl.upsert_tombstone(normalized.clone());
        persistence::save_tombstone(&normalized)?;
        outcome.merged_tombstones.push(tombstone.clone());
        outcome.added += 1;
    }

    if outcome.added + outcome.replaced == 0 {
        outcome.merkle_root = crl.merkle_root.clone();
        outcome.sequence = crl.sequence;
        return Ok(outcome);
    }

    crl.entries
        .sort_by(|a, b| a.revoked_did.cmp(&b.revoked_did));
    crl.tombstones
        .sort_by(|a, b| a.revoked_did.cmp(&b.revoked_did));
    resign_and_save(&mut crl, record, km)?;
    outcome.merkle_root = crl.merkle_root.clone();
    outcome.sequence = crl.sequence;
    Ok(outcome)
}

/// After a successful exchange with `peer_did`, record the ack on every
/// entry and flip `propagated` where `peers_notified` reaches
/// `threshold_count`. The revoked DID itself never counts as a recipient.
/// No-op writes are skipped, so steady state costs zero disk churn.
pub fn mark_peer_notified(
    record: &DidRecord,
    km: &KeyManager,
    circle_id: &str,
    peer_did: &str,
    threshold_count: usize,
) -> Result<MergeOutcome, CrlError> {
    let mut crl = load_or_new(&record.did, circle_id)?;
    let mut changed = false;
    let mut outcome = MergeOutcome::default();

    for entry in crl.entries.iter_mut() {
        if entry.revoked_did == peer_did {
            continue;
        }
        if !entry.peers_notified.iter().any(|did| did == peer_did) {
            entry.peers_notified.push(peer_did.to_string());
            changed = true;
        }
        if !entry.propagated && entry.peers_notified.len() >= threshold_count {
            entry.propagated = true;
            outcome.newly_propagated.push(entry.id.clone());
            changed = true;
        }
    }
    for tombstone in crl.tombstones.iter_mut() {
        if tombstone.revoked_did == peer_did {
            continue;
        }
        if !tombstone.peers_notified.iter().any(|did| did == peer_did) {
            tombstone.peers_notified.push(peer_did.to_string());
            changed = true;
        }
        if !tombstone.propagated && tombstone.peers_notified.len() >= threshold_count {
            tombstone.propagated = true;
            outcome.newly_propagated.push(tombstone.id.clone());
            changed = true;
        }
    }

    if changed {
        resign_and_save(&mut crl, record, km)?;
    }
    outcome.merkle_root = crl.merkle_root.clone();
    outcome.sequence = crl.sequence;
    Ok(outcome)
}

/// (sequence, merkle_root, fingerprints) of the local CRL.
pub fn snapshot() -> Result<(u64, String, Vec<String>), CrlError> {
    Ok(match persistence::load_crl()? {
        Some(crl) => (
            crl.sequence,
            crl.merkle_root.clone(),
            crl.entries
                .iter()
                .map(CrlEntry::state_fingerprint)
                .chain(
                    crl.tombstones
                        .iter()
                        .map(UnrevokeTombstone::state_fingerprint),
                )
                .collect(),
        ),
        None => (0, String::new(), Vec::new()),
    })
}

/// Local records whose fingerprints are NOT in `known` (what the peer lacks).
pub fn entries_not_in(
    known: &HashSet<String>,
) -> Result<(Vec<CrlEntry>, Vec<UnrevokeTombstone>), CrlError> {
    Ok(match persistence::load_crl()? {
        Some(crl) => {
            let mut entries = Vec::new();
            let mut tombstones = Vec::new();
            let mut remaining = super::protocol::MAX_ENTRIES_PER_MESSAGE;

            for entry in &crl.entries {
                if remaining == 0 {
                    break;
                }
                if !known.contains(&entry.state_fingerprint()) {
                    entries.push(entry.clone());
                    remaining -= 1;
                }
            }
            for tombstone in &crl.tombstones {
                if remaining == 0 {
                    break;
                }
                if !known.contains(&tombstone.state_fingerprint()) {
                    tombstones.push(tombstone.clone());
                    remaining -= 1;
                }
            }

            (entries, tombstones)
        }
        None => (Vec::new(), Vec::new()),
    })
}

/// Local records whose fingerprints ARE in `want` (what the peer asked for).
pub fn entries_matching(
    want: &HashSet<String>,
) -> Result<(Vec<CrlEntry>, Vec<UnrevokeTombstone>), CrlError> {
    Ok(match persistence::load_crl()? {
        Some(crl) => {
            let mut entries = Vec::new();
            let mut tombstones = Vec::new();
            let mut remaining = super::protocol::MAX_ENTRIES_PER_MESSAGE;

            for entry in &crl.entries {
                if remaining == 0 {
                    break;
                }
                if want.contains(&entry.state_fingerprint()) {
                    entries.push(entry.clone());
                    remaining -= 1;
                }
            }
            for tombstone in &crl.tombstones {
                if remaining == 0 {
                    break;
                }
                if want.contains(&tombstone.state_fingerprint()) {
                    tombstones.push(tombstone.clone());
                    remaining -= 1;
                }
            }

            (entries, tombstones)
        }
        None => (Vec::new(), Vec::new()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crl::entry::{
        RevocationReason, RevokerRole, Severity, CRL_CONTEXT_CORE, CRL_CONTEXT_SGX,
        CRL_UNREVOKE_TOMBSTONE_TYPE,
    };
    use crate::did::document::Proof;
    use crate::did::persistence::DerivationProof;
    use tempfile::TempDir;

    /// Serializes `SGX_GUARDIAN_CRL_BASE` mutation across tests in this
    /// module, restoring whatever value (if any) preceded the test.
    struct CrlBaseGuard(Option<std::ffi::OsString>);

    impl CrlBaseGuard {
        fn set(path: &std::path::Path) -> Self {
            let previous = std::env::var_os(persistence::CRL_BASE_ENV);
            std::env::set_var(persistence::CRL_BASE_ENV, path);
            Self(previous)
        }
    }

    impl Drop for CrlBaseGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.0.take() {
                std::env::set_var(persistence::CRL_BASE_ENV, previous);
            } else {
                std::env::remove_var(persistence::CRL_BASE_ENV);
            }
        }
    }

    fn make_key_manager(dir: &std::path::Path) -> KeyManager {
        let path = dir.join("device.key");
        KeyManager::load_or_generate(path.to_str().expect("utf8 key path")).expect("key manager")
    }

    fn make_did_record(did: &str) -> DidRecord {
        DidRecord {
            did: did.to_string(),
            method: "guardian".to_string(),
            method_version: "1.0".to_string(),
            did_id_b58: format!("b58-{}", did.replace(':', "_")),
            did_id_hex: hex::encode(did.as_bytes()),
            created_at: Utc::now().to_rfc3339(),
            deactivated_at: None,
            derivation: DerivationProof {
                se050_uid: "se050-test-uid".to_string(),
                se050_uid_source: "test".to_string(),
                dkp_v1_pubkey_sha256_b16: "00".repeat(32),
                dkp_v1_pubkey_path: "device.key".to_string(),
                dkp_v1_pubkey_der_b64: None,
                dik_pubkey_sha256_b16: "11".repeat(32),
                dik_pubkey_der_b64: None,
            },
            current_dkp_version: 1,
            deriv_signature_b64: "signature".to_string(),
        }
    }

    fn sample_tombstone(
        id: &str,
        revoked_did: &str,
        original_entry_id: &str,
        timestamp: &str,
    ) -> UnrevokeTombstone {
        UnrevokeTombstone {
            context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
            id: id.to_string(),
            r#type: vec![
                "VerifiableCredential".into(),
                CRL_UNREVOKE_TOMBSTONE_TYPE.into(),
            ],
            revoked_did: revoked_did.to_string(),
            original_entry_id: original_entry_id.to_string(),
            owner_did: "did:guardian:owner".to_string(),
            sequence: 0,
            timestamp: timestamp.to_string(),
            proof: Proof::default(),
            peers_notified: vec![],
            propagated: false,
        }
    }

    fn sample_entry(id: &str, revoked_did: &str, timestamp: &str) -> CrlEntry {
        CrlEntry {
            context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
            id: id.to_string(),
            r#type: vec!["VerifiableCredential".into(), "RevocationCredential".into()],
            revoked_did: revoked_did.to_string(),
            device_id: None,
            user_id: None,
            circle_id: "circle-1".to_string(),
            reason: RevocationReason::Compromised,
            severity: Severity::High,
            timestamp: timestamp.to_string(),
            revoker_did: "did:guardian:owner".to_string(),
            revoker_role: RevokerRole::Owner,
            evidence: None,
            proof: Proof::default(),
            peers_notified: vec!["did:guardian:peerA".to_string()],
            propagated: true,
        }
    }

    #[test]
    fn incoming_wins_prefers_later_timestamp() {
        let existing = sample_entry("urn:uuid:1", "did:guardian:x", "2026-01-01T00:00:00Z");
        let newer = sample_entry("urn:uuid:2", "did:guardian:x", "2026-06-01T00:00:00Z");
        assert!(incoming_wins(&existing, &newer));
        assert!(!incoming_wins(&newer, &existing));
    }

    #[test]
    fn incoming_wins_ties_break_on_lower_fingerprint() {
        // Same timestamp: whichever fingerprint sorts lower should win,
        // and the relation must be consistent both directions.
        let a = sample_entry("urn:uuid:a", "did:guardian:x", "2026-01-01T00:00:00Z");
        let b = sample_entry("urn:uuid:b", "did:guardian:x", "2026-01-01T00:00:00Z");

        let a_wins_over_b = incoming_wins(&b, &a);
        let b_wins_over_a = incoming_wins(&a, &b);
        // Exactly one direction should win (fingerprints differ since ids differ).
        assert_ne!(a_wins_over_b, b_wins_over_a);
    }

    #[test]
    fn incoming_wins_handles_unparseable_timestamps_via_fingerprint_fallback() {
        let existing = sample_entry("urn:uuid:1", "did:guardian:x", "not-a-timestamp");
        let incoming = sample_entry("urn:uuid:2", "did:guardian:x", "not-a-timestamp");
        // Must not panic and must be a well-defined, antisymmetric relation.
        let first = incoming_wins(&existing, &incoming);
        let second = incoming_wins(&incoming, &existing);
        assert_ne!(first, second);
    }

    #[test]
    fn normalized_clears_gossip_bookkeeping_fields() {
        let entry = sample_entry("urn:uuid:1", "did:guardian:x", "2026-01-01T00:00:00Z");
        assert!(!entry.peers_notified.is_empty());
        assert!(entry.propagated);

        let cleaned = normalized(&entry);
        assert!(cleaned.peers_notified.is_empty());
        assert!(!cleaned.propagated);
        // Everything else is preserved.
        assert_eq!(cleaned.id, entry.id);
        assert_eq!(cleaned.revoked_did, entry.revoked_did);
        assert_eq!(cleaned.fingerprint(), entry.fingerprint());
    }

    #[test]
    fn normalized_tombstone_clears_gossip_bookkeeping_fields() {
        let mut tombstone = sample_tombstone(
            "urn:uuid:t1",
            "did:guardian:x",
            "urn:uuid:orig",
            "2026-01-01T00:00:00Z",
        );
        tombstone.peers_notified.push("did:guardian:peerA".into());
        tombstone.propagated = true;

        let cleaned = normalized_tombstone(&tombstone);
        assert!(cleaned.peers_notified.is_empty());
        assert!(!cleaned.propagated);
        assert_eq!(cleaned.id, tombstone.id);
        assert_eq!(cleaned.revoked_did, tombstone.revoked_did);
        assert_eq!(cleaned.fingerprint(), tombstone.fingerprint());
    }

    #[test]
    fn merge_new_entry_is_added_normalized_and_persisted() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        let record = make_did_record("did:guardian:owner");
        let km = make_key_manager(temp.path());

        let entry = sample_entry("urn:uuid:e1", "did:guardian:target", "2026-01-01T00:00:00Z");
        assert!(!entry.peers_notified.is_empty());
        assert!(entry.propagated);

        let outcome =
            merge_verified_records(&record, &km, "circle-1", std::slice::from_ref(&entry), &[])
                .expect("merge new entry");
        assert_eq!(outcome.added, 1);
        assert_eq!(outcome.replaced, 0);
        assert_eq!(outcome.skipped, 0);
        assert_eq!(outcome.sequence, 1);
        assert!(!outcome.merkle_root.is_empty());

        let crl = persistence::load_crl()
            .expect("load crl")
            .expect("crl exists");
        assert!(crl.contains("did:guardian:target"));
        let stored = crl
            .entries
            .iter()
            .find(|e| e.revoked_did == "did:guardian:target")
            .expect("stored entry");
        // Gossip bookkeeping must be reset on ingest, never inherited.
        assert!(stored.peers_notified.is_empty());
        assert!(!stored.propagated);

        let persisted_files = persistence::list_entries().expect("list entries");
        assert_eq!(persisted_files.len(), 1);
    }

    #[test]
    fn merge_duplicate_entry_by_fingerprint_is_skipped() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        let record = make_did_record("did:guardian:owner");
        let km = make_key_manager(temp.path());

        let entry = sample_entry("urn:uuid:e1", "did:guardian:target", "2026-01-01T00:00:00Z");
        let first =
            merge_verified_records(&record, &km, "circle-1", std::slice::from_ref(&entry), &[])
                .expect("first merge");
        assert_eq!(first.added, 1);

        let second =
            merge_verified_records(&record, &km, "circle-1", std::slice::from_ref(&entry), &[])
                .expect("second merge");
        assert_eq!(second.added, 0);
        assert_eq!(second.replaced, 0);
        assert_eq!(second.skipped, 1);

        let crl = persistence::load_crl()
            .expect("load crl")
            .expect("crl exists");
        assert_eq!(crl.entries.len(), 1);
    }

    #[test]
    fn merge_conflicting_entry_incoming_wins_replaces_stale_record() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        let record = make_did_record("did:guardian:owner");
        let km = make_key_manager(temp.path());

        let stale = sample_entry("urn:uuid:old", "did:guardian:x", "2026-01-01T00:00:00Z");
        merge_verified_records(&record, &km, "circle-1", std::slice::from_ref(&stale), &[])
            .expect("merge stale");

        let fresh = sample_entry("urn:uuid:new", "did:guardian:x", "2026-06-01T00:00:00Z");
        let outcome =
            merge_verified_records(&record, &km, "circle-1", std::slice::from_ref(&fresh), &[])
                .expect("merge fresh");
        assert_eq!(outcome.added, 0);
        assert_eq!(outcome.replaced, 1);
        assert_eq!(outcome.skipped, 0);

        let crl = persistence::load_crl()
            .expect("load crl")
            .expect("crl exists");
        assert_eq!(crl.entries.len(), 1);
        assert_eq!(crl.entries[0].id, fresh.id);
    }

    #[test]
    fn merge_conflicting_entry_incoming_loses_is_skipped() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        let record = make_did_record("did:guardian:owner");
        let km = make_key_manager(temp.path());

        let fresh = sample_entry("urn:uuid:new", "did:guardian:x", "2026-06-01T00:00:00Z");
        merge_verified_records(&record, &km, "circle-1", std::slice::from_ref(&fresh), &[])
            .expect("merge fresh");

        let stale = sample_entry("urn:uuid:old", "did:guardian:x", "2026-01-01T00:00:00Z");
        let outcome =
            merge_verified_records(&record, &km, "circle-1", std::slice::from_ref(&stale), &[])
                .expect("merge stale");
        assert_eq!(outcome.added, 0);
        assert_eq!(outcome.replaced, 0);
        assert_eq!(outcome.skipped, 1);

        let crl = persistence::load_crl()
            .expect("load crl")
            .expect("crl exists");
        assert_eq!(crl.entries.len(), 1);
        assert_eq!(crl.entries[0].id, fresh.id);
    }

    #[test]
    fn merge_entry_replaces_existing_tombstone_when_incoming_newer() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        let record = make_did_record("did:guardian:owner");
        let km = make_key_manager(temp.path());

        let tombstone = sample_tombstone(
            "urn:uuid:t1",
            "did:guardian:x",
            "urn:uuid:orig",
            "2026-01-01T00:00:00Z",
        );
        let outcome1 = merge_verified_records(
            &record,
            &km,
            "circle-1",
            &[],
            std::slice::from_ref(&tombstone),
        )
        .expect("merge tombstone");
        assert_eq!(outcome1.added, 1);

        let entry = sample_entry("urn:uuid:e1", "did:guardian:x", "2026-06-01T00:00:00Z");
        let outcome2 =
            merge_verified_records(&record, &km, "circle-1", std::slice::from_ref(&entry), &[])
                .expect("merge entry");
        assert_eq!(outcome2.replaced, 1);
        assert_eq!(outcome2.skipped, 0);

        let crl = persistence::load_crl()
            .expect("load crl")
            .expect("crl exists");
        assert!(crl.contains("did:guardian:x"));
        assert!(crl.tombstone("did:guardian:x").is_none());
    }

    #[test]
    fn merge_entry_skipped_when_existing_tombstone_is_newer() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        let record = make_did_record("did:guardian:owner");
        let km = make_key_manager(temp.path());

        let tombstone = sample_tombstone(
            "urn:uuid:t1",
            "did:guardian:x",
            "urn:uuid:orig",
            "2026-06-01T00:00:00Z",
        );
        merge_verified_records(
            &record,
            &km,
            "circle-1",
            &[],
            std::slice::from_ref(&tombstone),
        )
        .expect("merge tombstone");

        let entry = sample_entry("urn:uuid:e1", "did:guardian:x", "2026-01-01T00:00:00Z");
        let outcome =
            merge_verified_records(&record, &km, "circle-1", std::slice::from_ref(&entry), &[])
                .expect("merge entry");
        assert_eq!(outcome.added, 0);
        assert_eq!(outcome.replaced, 0);
        assert_eq!(outcome.skipped, 1);

        let crl = persistence::load_crl()
            .expect("load crl")
            .expect("crl exists");
        assert!(!crl.contains("did:guardian:x"));
        assert!(crl.tombstone("did:guardian:x").is_some());
    }

    #[test]
    fn merge_tombstone_replaces_active_entry_when_incoming_newer() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        let record = make_did_record("did:guardian:owner");
        let km = make_key_manager(temp.path());

        let entry = sample_entry("urn:uuid:e1", "did:guardian:y", "2026-01-01T00:00:00Z");
        merge_verified_records(&record, &km, "circle-1", std::slice::from_ref(&entry), &[])
            .expect("merge entry");

        let tombstone = sample_tombstone(
            "urn:uuid:t1",
            "did:guardian:y",
            &entry.id,
            "2026-06-01T00:00:00Z",
        );
        let outcome = merge_verified_records(
            &record,
            &km,
            "circle-1",
            &[],
            std::slice::from_ref(&tombstone),
        )
        .expect("merge tombstone");
        assert_eq!(outcome.replaced, 1);
        assert_eq!(outcome.skipped, 0);

        let crl = persistence::load_crl()
            .expect("load crl")
            .expect("crl exists");
        assert!(!crl.contains("did:guardian:y"));
        assert!(crl.tombstone("did:guardian:y").is_some());
    }

    #[test]
    fn merge_tombstone_skipped_when_active_entry_is_newer() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        let record = make_did_record("did:guardian:owner");
        let km = make_key_manager(temp.path());

        let entry = sample_entry("urn:uuid:e1", "did:guardian:y", "2026-06-01T00:00:00Z");
        merge_verified_records(&record, &km, "circle-1", std::slice::from_ref(&entry), &[])
            .expect("merge entry");

        let tombstone = sample_tombstone(
            "urn:uuid:t1",
            "did:guardian:y",
            &entry.id,
            "2026-01-01T00:00:00Z",
        );
        let outcome = merge_verified_records(
            &record,
            &km,
            "circle-1",
            &[],
            std::slice::from_ref(&tombstone),
        )
        .expect("merge tombstone");
        assert_eq!(outcome.added, 0);
        assert_eq!(outcome.replaced, 0);
        assert_eq!(outcome.skipped, 1);

        let crl = persistence::load_crl()
            .expect("load crl")
            .expect("crl exists");
        assert!(crl.contains("did:guardian:y"));
        assert!(crl.tombstone("did:guardian:y").is_none());
    }

    #[test]
    fn merge_duplicate_tombstone_by_fingerprint_is_skipped() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        let record = make_did_record("did:guardian:owner");
        let km = make_key_manager(temp.path());

        let tombstone = sample_tombstone(
            "urn:uuid:t1",
            "did:guardian:z",
            "urn:uuid:orig",
            "2026-01-01T00:00:00Z",
        );
        let first = merge_verified_records(
            &record,
            &km,
            "circle-1",
            &[],
            std::slice::from_ref(&tombstone),
        )
        .expect("first merge");
        assert_eq!(first.added, 1);

        let second = merge_verified_records(
            &record,
            &km,
            "circle-1",
            &[],
            std::slice::from_ref(&tombstone),
        )
        .expect("second merge");
        assert_eq!(second.added, 0);
        assert_eq!(second.skipped, 1);

        let crl = persistence::load_crl()
            .expect("load crl")
            .expect("crl exists");
        assert_eq!(crl.tombstones.len(), 1);
    }

    #[test]
    fn merge_tombstone_replaces_existing_tombstone_when_incoming_newer() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        let record = make_did_record("did:guardian:owner");
        let km = make_key_manager(temp.path());

        let tombstone1 = sample_tombstone(
            "urn:uuid:t1",
            "did:guardian:w",
            "urn:uuid:orig",
            "2026-01-01T00:00:00Z",
        );
        merge_verified_records(
            &record,
            &km,
            "circle-1",
            &[],
            std::slice::from_ref(&tombstone1),
        )
        .expect("merge first tombstone");

        let tombstone2 = sample_tombstone(
            "urn:uuid:t2",
            "did:guardian:w",
            "urn:uuid:orig",
            "2026-06-01T00:00:00Z",
        );
        let outcome = merge_verified_records(
            &record,
            &km,
            "circle-1",
            &[],
            std::slice::from_ref(&tombstone2),
        )
        .expect("merge second tombstone");
        assert_eq!(outcome.replaced, 1);
        assert_eq!(outcome.skipped, 0);

        let crl = persistence::load_crl()
            .expect("load crl")
            .expect("crl exists");
        assert_eq!(crl.tombstones.len(), 1);
        assert_eq!(crl.tombstones[0].id, tombstone2.id);
    }

    #[test]
    fn merge_with_nothing_added_or_replaced_leaves_sequence_and_root_untouched() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        let record = make_did_record("did:guardian:owner");
        let km = make_key_manager(temp.path());

        let entry = sample_entry("urn:uuid:e1", "did:guardian:x", "2026-01-01T00:00:00Z");
        let first =
            merge_verified_records(&record, &km, "circle-1", std::slice::from_ref(&entry), &[])
                .expect("first merge");
        assert_eq!(first.sequence, 1);

        // A duplicate-only merge should not resign / bump sequence.
        let second =
            merge_verified_records(&record, &km, "circle-1", std::slice::from_ref(&entry), &[])
                .expect("second merge");
        assert_eq!(second.sequence, first.sequence);
        assert_eq!(second.merkle_root, first.merkle_root);
    }

    #[test]
    fn mark_peer_notified_flips_propagated_at_threshold() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        let record = make_did_record("did:guardian:owner");
        let km = make_key_manager(temp.path());

        let entry = sample_entry("urn:uuid:e1", "did:guardian:a", "2026-01-01T00:00:00Z");
        merge_verified_records(&record, &km, "circle-1", std::slice::from_ref(&entry), &[])
            .expect("merge entry");

        let outcome = mark_peer_notified(&record, &km, "circle-1", "did:guardian:peerX", 1)
            .expect("mark peer notified");
        assert_eq!(outcome.newly_propagated, vec![entry.id.clone()]);

        let crl = persistence::load_crl()
            .expect("load crl")
            .expect("crl exists");
        let stored = &crl.entries[0];
        assert!(stored
            .peers_notified
            .iter()
            .any(|d| d == "did:guardian:peerX"));
        assert!(stored.propagated);
    }

    #[test]
    fn mark_peer_notified_excludes_the_revoked_did_itself() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        let record = make_did_record("did:guardian:owner");
        let km = make_key_manager(temp.path());

        let entry = sample_entry(
            "urn:uuid:e1",
            "did:guardian:selfpeer",
            "2026-01-01T00:00:00Z",
        );
        merge_verified_records(&record, &km, "circle-1", std::slice::from_ref(&entry), &[])
            .expect("merge entry");

        let outcome = mark_peer_notified(&record, &km, "circle-1", "did:guardian:selfpeer", 1)
            .expect("mark peer notified");
        assert!(outcome.newly_propagated.is_empty());

        let crl = persistence::load_crl()
            .expect("load crl")
            .expect("crl exists");
        assert!(crl.entries[0].peers_notified.is_empty());
        assert!(!crl.entries[0].propagated);
    }

    #[test]
    fn mark_peer_notified_is_idempotent_and_skips_resave_when_unchanged() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        let record = make_did_record("did:guardian:owner");
        let km = make_key_manager(temp.path());

        let entry = sample_entry("urn:uuid:e1", "did:guardian:b", "2026-01-01T00:00:00Z");
        merge_verified_records(&record, &km, "circle-1", std::slice::from_ref(&entry), &[])
            .expect("merge entry");

        // Threshold of 5 is never reached by a single ack, so the entry
        // never propagates but the first ack still records an unseen peer.
        let first = mark_peer_notified(&record, &km, "circle-1", "did:guardian:peerY", 5)
            .expect("first ack");
        // Repeating the same ack must be a true no-op: no new peer recorded,
        // no resign, no sequence bump.
        let second = mark_peer_notified(&record, &km, "circle-1", "did:guardian:peerY", 5)
            .expect("second ack");
        assert_eq!(second.sequence, first.sequence);
        assert_eq!(second.merkle_root, first.merkle_root);

        let crl = persistence::load_crl()
            .expect("load crl")
            .expect("crl exists");
        let notified_count = crl.entries[0]
            .peers_notified
            .iter()
            .filter(|d| d.as_str() == "did:guardian:peerY")
            .count();
        assert_eq!(notified_count, 1);
    }

    #[test]
    fn snapshot_returns_zero_defaults_when_no_crl_persisted() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());

        let (sequence, root, fingerprints) = snapshot().expect("snapshot");
        assert_eq!(sequence, 0);
        assert!(root.is_empty());
        assert!(fingerprints.is_empty());
    }

    #[test]
    fn snapshot_reports_local_sequence_root_and_fingerprints() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        let record = make_did_record("did:guardian:owner");
        let km = make_key_manager(temp.path());

        let entry = sample_entry("urn:uuid:e1", "did:guardian:a", "2026-01-01T00:00:00Z");
        let tombstone = sample_tombstone(
            "urn:uuid:t1",
            "did:guardian:b",
            "urn:uuid:orig",
            "2026-01-01T00:00:00Z",
        );
        merge_verified_records(
            &record,
            &km,
            "circle-1",
            std::slice::from_ref(&entry),
            std::slice::from_ref(&tombstone),
        )
        .expect("merge entry and tombstone");

        let (sequence, root, fingerprints) = snapshot().expect("snapshot");
        assert_eq!(sequence, 1);
        assert!(!root.is_empty());
        assert_eq!(fingerprints.len(), 2);
        assert!(fingerprints.iter().any(|f| f.starts_with("revoke:")));
        assert!(fingerprints.iter().any(|f| f.starts_with("tombstone:")));
    }

    #[test]
    fn entries_not_in_and_entries_matching_partition_by_known_fingerprints() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        let record = make_did_record("did:guardian:owner");
        let km = make_key_manager(temp.path());

        let entry_a = sample_entry("urn:uuid:a", "did:guardian:a", "2026-01-01T00:00:00Z");
        let entry_b = sample_entry("urn:uuid:b", "did:guardian:b", "2026-01-01T00:00:00Z");
        let tombstone_c = sample_tombstone(
            "urn:uuid:c",
            "did:guardian:c",
            "urn:uuid:orig",
            "2026-01-01T00:00:00Z",
        );
        merge_verified_records(
            &record,
            &km,
            "circle-1",
            &[entry_a.clone(), entry_b.clone()],
            std::slice::from_ref(&tombstone_c),
        )
        .expect("merge entries and tombstone");

        let mut known = HashSet::new();
        known.insert(entry_a.state_fingerprint());

        let (not_in_entries, not_in_tombstones) = entries_not_in(&known).expect("entries not in");
        assert_eq!(not_in_entries.len(), 1);
        assert_eq!(not_in_entries[0].revoked_did, "did:guardian:b");
        assert_eq!(not_in_tombstones.len(), 1);
        assert_eq!(not_in_tombstones[0].revoked_did, "did:guardian:c");

        let (matching_entries, matching_tombstones) =
            entries_matching(&known).expect("entries matching");
        assert_eq!(matching_entries.len(), 1);
        assert_eq!(matching_entries[0].revoked_did, "did:guardian:a");
        assert!(matching_tombstones.is_empty());
    }

    #[test]
    fn entries_not_in_and_entries_matching_return_empty_when_no_crl_persisted() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());

        let known = HashSet::new();
        let (entries, tombstones) = entries_not_in(&known).expect("entries not in");
        assert!(entries.is_empty());
        assert!(tombstones.is_empty());

        let (entries, tombstones) = entries_matching(&known).expect("entries matching");
        assert!(entries.is_empty());
        assert!(tombstones.is_empty());
    }

    #[test]
    fn corrupted_crl_file_surfaces_as_error_instead_of_panicking() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        std::fs::write(persistence::crl_path(), b"not-json-at-all").expect("write malformed crl");

        assert!(snapshot().is_err());
        assert!(entries_not_in(&HashSet::new()).is_err());
        assert!(entries_matching(&HashSet::new()).is_err());

        let record = make_did_record("did:guardian:owner");
        let km = make_key_manager(temp.path());
        let entry = sample_entry("urn:uuid:e1", "did:guardian:a", "2026-01-01T00:00:00Z");
        assert!(merge_verified_records(
            &record,
            &km,
            "circle-1",
            std::slice::from_ref(&entry),
            &[]
        )
        .is_err());
        assert!(mark_peer_notified(&record, &km, "circle-1", "did:guardian:peer", 1).is_err());
    }
}
