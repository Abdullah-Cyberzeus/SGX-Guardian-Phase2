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

use crate::crl::entry::CrlEntry;
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
    pub newly_propagated: Vec<String>,
    pub merkle_root: String,
    pub sequence: u64,
}

/// Deterministic conflict rule when two independently-issued, verified
/// entries revoke the SAME DID: LATER `timestamp` wins (an attacker who
/// backdates a revocation must not be able to pin a stale entry over a
/// genuinely more recent one); ties break on the lexicographically lower
/// fingerprint. Every node applies the same rule, so entry sets (and
/// therefore Merkle roots) converge.
pub fn incoming_wins(existing: &CrlEntry, incoming: &CrlEntry) -> bool {
    let existing_ts = DateTime::parse_from_rfc3339(&existing.timestamp).ok();
    let incoming_ts = DateTime::parse_from_rfc3339(&incoming.timestamp).ok();
    match (incoming_ts, existing_ts) {
        (Some(incoming), Some(existing)) if incoming != existing => incoming > existing,
        _ => incoming.fingerprint() < existing.fingerprint(),
    }
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

/// Merge entries that the CALLER HAS ALREADY VERIFIED
/// (`crl::verify::verify_entry`) into the local CRL.
pub fn merge_verified_entries(
    record: &DidRecord,
    km: &KeyManager,
    circle_id: &str,
    incoming: &[CrlEntry],
) -> Result<MergeOutcome, CrlError> {
    let mut crl = load_or_new(&record.did, circle_id)?;
    let mut outcome = MergeOutcome::default();

    for entry in incoming
        .iter()
        .take(super::protocol::MAX_ENTRIES_PER_MESSAGE)
    {
        let fingerprint = entry.fingerprint();
        if crl.entries.iter().any(|e| e.fingerprint() == fingerprint) {
            outcome.skipped += 1;
            continue;
        }
        if let Some(position) = crl
            .entries
            .iter()
            .position(|e| e.revoked_did == entry.revoked_did)
        {
            if incoming_wins(&crl.entries[position], entry) {
                crl.entries[position] = normalized(entry);
                persistence::save_entry(entry)?;
                outcome.merged_entries.push(entry.clone());
                outcome.replaced += 1;
            } else {
                outcome.skipped += 1;
            }
            continue;
        }
        crl.entries.push(normalized(entry));
        persistence::save_entry(entry)?;
        outcome.merged_entries.push(entry.clone());
        outcome.added += 1;
    }

    if outcome.added + outcome.replaced == 0 {
        outcome.merkle_root = crl.merkle_root.clone();
        outcome.sequence = crl.sequence;
        return Ok(outcome);
    }

    crl.entries
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
            crl.entries.iter().map(|e| e.fingerprint()).collect(),
        ),
        None => (0, String::new(), Vec::new()),
    })
}

/// Local entries whose fingerprints are NOT in `known` (what the peer lacks).
pub fn entries_not_in(known: &HashSet<String>) -> Result<Vec<CrlEntry>, CrlError> {
    Ok(match persistence::load_crl()? {
        Some(crl) => crl
            .entries
            .iter()
            .filter(|e| !known.contains(&e.fingerprint()))
            .take(super::protocol::MAX_ENTRIES_PER_MESSAGE)
            .cloned()
            .collect(),
        None => Vec::new(),
    })
}

/// Local entries whose fingerprints ARE in `want` (what the peer asked for).
pub fn entries_matching(want: &HashSet<String>) -> Result<Vec<CrlEntry>, CrlError> {
    Ok(match persistence::load_crl()? {
        Some(crl) => crl
            .entries
            .iter()
            .filter(|e| want.contains(&e.fingerprint()))
            .take(super::protocol::MAX_ENTRIES_PER_MESSAGE)
            .cloned()
            .collect(),
        None => Vec::new(),
    })
}
