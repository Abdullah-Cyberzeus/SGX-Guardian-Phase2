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
mod unit_tests {
    use super::*;
    use crate::crl::entry::{
        RevocationReason, RevokerRole, Severity, CRL_CONTEXT_CORE, CRL_CONTEXT_SGX,
    };
    use crate::did::document::Proof;

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
}
