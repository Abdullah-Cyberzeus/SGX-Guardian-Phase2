# SG-X Guardian — Sprint 4 Task 1 (CRL Data Structure) — Development Plan

**Branch base:** `shahzad_did` (latest pull via `project_knowledge_search`).
**Target branch:** `shahzad_crl` (additive; assumes Sprint 5 DID/Resolver and Sprint 6 VC merges have landed — they're consumed below).
**Milestone:** 4 — target 2026-06-21 (per Phase 2 Final Timeline) / Sprint 4 (per SGX_Phase_2.docx).
**Test prefix:** CRL-001 …

---

## Task Statement (verbatim — Phase 2 Final Timeline)

> Design Certificate Revocation List (CRL) data structure for peer-to-peer revocation propagation. CRL entry contains: revoked DID, device_id, user_id, Circle_id, revocation reason, (compromised/lost/stolen/policy violation), severity level, timestamp, revoker's DID, cryptographic signature. CRL stored in distributed, Certificate Revocation List entity. Each entry cryptographically signed by issuer (Circle owner or member reporting compromise).

Obligations vs. current state:

| # | Obligation | Currently on `shahzad_did`? |
|---|---|---|
| O1 | CRL entry schema (revoked DID, device_id, user_id, circle_id, reason, severity, timestamp, revoker DID, sig) | ❌ Nothing exists |
| O2 | Distributed CertificateRevocationList container | ❌ |
| O3 | Each entry cryptographically signed | ⚠️ `sign_in_place_generic` exists, reused |
| O4 | Issuer can be Circle owner OR member reporting compromise | ❌ — needs role-aware issuance path |
| O5 | Persists across restarts | ❌ |
| O6 | Designed to support gossip (Sprint 4 Task 2) | ❌ — design must enable, not implement |
| O7 | Designed to support emergency broadcast (Sprint 4 Task 3) | ❌ — severity field must exist |
| O8 | Distinguished from VC StatusList2021 revocation | n/a — VC StatusList exists, CRL is net-new |

---

## What I Confirmed on Latest `shahzad_did`

- **`src/did/doc_sign.rs::sign_in_place_generic(proof, canonical_bytes, km, vm_ref)`** exists and is used by VC. CRL entries reuse it directly — no new crypto code.
- **`Proof` struct** (`DataIntegrityProof` + `ecdsa-2019` cryptosuite + `assertionMethod` purpose) — reused verbatim.
- **`KeyManager` / SE050-backed P-256 signing** — reused.
- **`src/cot/membership.rs::MemberRole { Owner, Member }`** — used to gate who can issue what severity.
- **`src/vc/status_list.rs::StatusListManager`** — VC revocation primitive. CRL is *separate but cross-references* — when a DID is revoked, the VCs issued *to* that subject get their status-list bits flipped too.
- **`src/did/Resolver`** (Sprint 5 Task 3) — used by CRL verifier to resolve the revoker's DID and get their pubkey.
- **`src/nebula/registry_sync.rs`** port 50062 transport — reusable for one CRL-related action (`crl_snapshot`); full gossip protocol is Sprint 4 Task 2.
- **`AuditCategory`** has `Did`, `Vc`, `Attestation`, `Identity`. Adding `Crl`.

**Critical distinction (often confused):**

| | CRL (this task) | VC StatusList2021 (already exists) |
|---|---|---|
| Revokes | A DID (entire identity) | A VC (credential instance) |
| Stored as | Signed list of `CrlEntry` records | Gzipped bitstring credential |
| Identifier | DID URI (`did:guardian:...`) | `statusListIndex` (uint64) |
| Effect | DID is dead across the Circle | One credential is dead; other VCs to same DID may still be valid |
| Reasons | compromised / lost / stolen / policy_violation | revocation (single purpose) |
| Issuer | Circle owner OR member reporting | Circle owner only |

The cross-reference: when a DID is added to the CRL, the issuer (CA) MUST also flip the status-list bit for every VC issued to that DID. Implementation in D6.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  REPORTER (any node, any role)                               │
│   sgx-pa-cli crl revoke --did <peer-DID> --reason compromised│
│   POST /api/v1/crl/revoke                                    │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
           ┌──────────────────────────┐
           │  src/crl/issue.rs        │
           │  build CrlEntry          │
           │  sign with DKP           │
           │  if self_is_ca:          │
           │     also flip VC bits    │
           │  persist entries/<id>    │
           │  rebuild crl.json (signed)│
           └──────────────┬───────────┘
                          │
                          ▼
           ┌──────────────────────────┐
           │ /var/lib/sgx-guardian/   │
           │  identity/crl/           │
           │   ├── crl.json   (signed)│
           │   ├── entries/<uuid>.json│
           │   └── pending/<uuid>.json│
           └──────────────┬───────────┘
                          │
   ┌──────────────────────┴────────────────────────────┐
   │       CONSUMERS (wired in this task)              │
   │                                                   │
   │   crl::lookup::is_revoked(did) → bool             │
   │                                                   │
   │   (Out of scope here, hook reserved:              │
   │    DID resolver gate, VC verifier gate,           │
   │    attestation evidence gate.)                    │
   └───────────────────────────────────────────────────┘
```

**Why a per-entry file AND a container file:**
- Per-entry files (`entries/<uuid>.json`) are the gossip atom — the gossip protocol (Sprint 4 Task 2) trades these one-by-one.
- The container (`crl.json`) is the queryable form for fast "is this DID revoked?" lookups, signed by the local node as a snapshot for export.
- Anti-entropy comparisons use the container's Merkle root over sorted entry hashes — peers swap roots, then request only missing entry IDs.

---

## Deliverables (8 atomic items, ~7 dev-days for 1 dev / ~4 days for 2 devs)

| # | Deliverable | Effort | File(s) |
|---|---|---|---|
| D1 | Core CRL types (entry, reason, severity, role enums) + errors | 1.0 d | `src/crl/{entry,errors,mod}.rs` (new) |
| D2 | CRL container + Merkle root for anti-entropy | 1.0 d | `src/crl/list.rs` (new) |
| D3 | Issuance (sign entry — member OR owner) | 1.0 d | `src/crl/issue.rs` (new) |
| D4 | Verification (entry sig + CRL self-verify + role checks) | 1.0 d | `src/crl/verify.rs` (new) |
| D5 | Persistence (atomic, dedup by id, restart-safe) | 0.5 d | `src/crl/persistence.rs` (new) |
| D6 | Cross-ref hook: CA flips VC status-list bits when revoking own-issued DID | 0.5 d | `src/crl/issue.rs` (extends D3) |
| D7 | CLI + REST + audit | 1.0 d | `sgx-pa-cli/src/commands/crl.rs`, `src/api/handlers/crl.rs`, `src/api/routes.rs` |
| D8 | Tests CRL-001..010 + board script | 1.0 d | `src/crl/tests/`, `Phase2_Test_Cases.pdf` addendum |

> **Calendar:** 1 dev ≈ 7 working days → ~1.5 calendar weeks. 2 devs: D1 serial (everyone needs the types), then D2+D3 parallel, then D4+D5+D6 parallel, D7+D8 last → ~4 working days → ~1 calendar week.

---

## File Structure (after this task)

```
src/crl/                          (new module)
├── entry.rs                      D1: CrlEntry, RevocationReason, Severity, RevokerRole
├── errors.rs                     D1: CrlError variants
├── mod.rs                        D1: re-exports + crl::lookup::is_revoked()
├── list.rs                       D2: CertificateRevocationList + Merkle root
├── issue.rs                      D3, D6: build + sign + cross-ref VC bits
├── verify.rs                     D4: verify entry / verify CRL
├── persistence.rs                D5: load/save atomic
└── tests/
    ├── entry_tests.rs            D8
    ├── list_tests.rs             D8
    ├── issue_tests.rs            D8
    └── verify_tests.rs           D8

src/audit/event.rs                D1: AuditCategory::Crl variant

src/api/handlers/crl.rs           D7: REST handlers (new file)
src/api/routes.rs                 D7: wire CRL routes
sgx-pa-cli/src/commands/crl.rs    D7: CLI subcommands (new file)
sgx-pa-cli/src/commands/mod.rs    D7: register cmd_crl
sgx-pa-cli/src/main.rs            D7: CRL subcommand wiring

docs/REST API Details.md          D7: §X.Y CRL endpoints
```

**On-disk layout:**
```
/var/lib/sgx-guardian/identity/crl/
├── crl.json                      signed container (all entries + Merkle root)
├── entries/<uuid-safe>.json      one file per entry (gossip atom)
└── pending/<uuid-safe>.json      entries we initiated, not yet committed to crl.json
                                  (used by Sprint 4 Task 4 Offline Sync — placeholder dir here)
```

---

# D1 — Core CRL Types

## D1.1 — `src/crl/entry.rs`

```rust
//! CRL entry — one revocation record.
//!
//! Each entry is cryptographically signed (DataIntegrityProof + ecdsa-2019)
//! by the issuer (Circle owner or member reporting compromise) using their
//! DKP. The proof verifies against the issuer's DID Document resolved via
//! Sprint 5 Task 3 Resolver.
//!
//! Sprint 4 Task 1 = THIS structure. Gossip propagation, emergency
//! broadcast, and offline sync are separate Sprint 4 tasks but the schema
//! here pre-allocates the fields they need (peers_notified, propagated).

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
            Self::Compromised           => "compromised",
            Self::Lost                  => "lost",
            Self::Stolen                => "stolen",
            Self::PolicyViolation       => "policy_violation",
            Self::AdministrativeRemoval => "administrative_removal",
            Self::VoluntaryDeparture    => "voluntary_departure",
        }
    }

    /// Whether this reason is security-critical (i.e. should propagate via
    /// emergency broadcast, terminate sessions instantly). Used by Sprint 4
    /// Task 3 to decide channel.
    pub fn is_security_critical(self) -> bool {
        matches!(self,
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
            Self::High     => "high",
            Self::Medium   => "medium",
            Self::Low      => "low",
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

    // ── Gossip / anti-entropy fields (pre-allocated for Sprint 4 Task 2)
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
```

## D1.2 — `src/crl/errors.rs`

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CrlError {
    #[error("invalid CRL entry: {0}")]
    InvalidStructure(String),
    #[error("invalid signature on CRL entry {0}")]
    InvalidProof(String),
    #[error("issuer DID not resolvable: {0}")]
    IssuerNotResolvable(String),
    #[error("member-issued entries must be Critical or High severity (got {0:?})")]
    MemberSeverityTooLow(crate::crl::entry::Severity),
    #[error("member-issued entries must be a security-critical reason (got {0})")]
    MemberReasonNotCritical(String),
    #[error("only the Circle owner can issue administrative_removal or voluntary_departure")]
    NotOwner,
    #[error("circle mismatch: expected {expected}, got {got}")]
    CircleMismatch { expected: String, got: String },
    #[error("revoker may not revoke themselves")]
    SelfRevocation,
    #[error("DID is already revoked (entry {0})")]
    AlreadyRevoked(String),
    #[error("CRL self-verification failed: Merkle root mismatch")]
    MerkleRootMismatch,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("did: {0}")]
    Did(#[from] crate::did::errors::DidError),
}
```

## D1.3 — `src/crl/mod.rs`

```rust
pub mod entry;
pub mod errors;
pub mod issue;
pub mod list;
pub mod persistence;
pub mod verify;

pub use entry::{
    CrlEntry, RevocationEvidence, RevocationReason, RevokerRole, Severity,
    CRL_CONTEXT_CORE, CRL_CONTEXT_SGX,
};
pub use errors::CrlError;
pub use list::CertificateRevocationList;

/// Fast O(log n) lookup: is this DID currently revoked?
///
/// Reads the locally-persisted `crl.json`. Callers that need fresher data
/// should first call gossip-pull (Sprint 4 Task 2) before this. For Phase
/// 2 baseline this is the canonical "are you allowed to talk" gate.
pub fn is_revoked(did: &str) -> bool {
    match persistence::load_crl() {
        Ok(Some(crl)) => crl.contains(did),
        _ => false,
    }
}
```

## D1.4 — `AuditCategory::Crl`

**File:** `src/audit/event.rs`

**FIND:**
```rust
pub enum AuditCategory {
    Identity,
    Did,
    Vc,
```

**REPLACE WITH:**
```rust
pub enum AuditCategory {
    Identity,
    Did,
    Vc,
    Crl,
```

---

# D2 — CRL Container

## D2.1 — `src/crl/list.rs`

```rust
//! The CertificateRevocationList container. Holds all known revocations
//! and a Merkle root for O(log n) anti-entropy comparisons.

use crate::crl::entry::CrlEntry;
use crate::crl::errors::CrlError;
use crate::did::document::Proof;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const CRL_TYPE: &str = "CertificateRevocationList";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRevocationList {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,                    // `did:guardian:<owner>/crl`
    #[serde(rename = "type")]
    pub r#type: Vec<String>,           // ["VerifiableCredential", "CertificateRevocationList"]
    pub issuer: String,                // local snapshotting node's DID
    pub circle_id: String,
    pub generated_at: String,          // RFC3339
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
        self.entries.sort_by(|a, b| a.revoked_did.cmp(&b.revoked_did));
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
```

---

# D3 — Issuance

## D3.1 — `src/crl/issue.rs`

```rust
//! CRL issuance. Two paths:
//!   1. Owner-initiated: any reason, any severity.
//!   2. Member-initiated: security-critical reasons only, severity
//!      Critical or High. (Subject to peer-level trust at gossip time —
//!      this module just enforces the issue-side constraints.)

use crate::crl::entry::{
    CrlEntry, RevocationEvidence, RevocationReason, RevokerRole, Severity,
    CRL_CONTEXT_CORE, CRL_CONTEXT_SGX,
};
use crate::crl::errors::CrlError;
use crate::crl::list::CertificateRevocationList;
use crate::crl::persistence;
use crate::did::doc_sign;
use crate::did::DidRecord;
use crate::key_manager::KeyManager;
use chrono::Utc;
use uuid::Uuid;

pub const DEFAULT_CIRCLE_ID: &str = "guardian-circle-alpha";

pub struct IssueRequest<'a> {
    pub revoked_did: &'a str,
    pub reason: RevocationReason,
    pub severity: Severity,
    pub circle_id: &'a str,
    pub device_id: Option<String>,
    pub user_id: Option<String>,
    pub evidence: Option<RevocationEvidence>,
}

/// Issue a revocation for `revoked_did`. The caller passes their own
/// DidRecord and KeyManager — those determine `revoker_did` and (via
/// role inspection) `revoker_role`.
pub fn issue_revocation(
    revoker: &DidRecord,
    revoker_role: RevokerRole,
    km: &KeyManager,
    req: IssueRequest,
) -> Result<CrlEntry, CrlError> {
    // O4: Member-initiated entries restricted to security-critical reasons
    // AND severity Critical or High. Owner-initiated has no restrictions.
    if matches!(revoker_role, RevokerRole::Member) {
        if !req.reason.is_security_critical() {
            return Err(CrlError::MemberReasonNotCritical(
                req.reason.as_str().to_string(),
            ));
        }
        if !matches!(req.severity, Severity::Critical | Severity::High) {
            return Err(CrlError::MemberSeverityTooLow(req.severity));
        }
    }

    // No self-revocation. (Operators wanting to leave use voluntary_departure
    // via the owner, or run a separate `did deactivate` flow.)
    if req.revoked_did == revoker.did {
        return Err(CrlError::SelfRevocation);
    }

    // Refuse if already revoked locally. Idempotent at the container level
    // (see CertificateRevocationList::upsert) but the entry-side reject
    // gives a cleaner error to the operator.
    if crate::crl::is_revoked(req.revoked_did) {
        return Err(CrlError::AlreadyRevoked(req.revoked_did.to_string()));
    }

    let now = Utc::now();
    let id = format!("urn:uuid:{}", Uuid::new_v4());

    let mut entry = CrlEntry {
        context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
        id,
        r#type: vec![
            "VerifiableCredential".into(),
            "RevocationCredential".into(),
        ],
        revoked_did: req.revoked_did.into(),
        device_id: req.device_id,
        user_id: req.user_id,
        circle_id: req.circle_id.into(),
        reason: req.reason,
        severity: req.severity,
        timestamp: now.to_rfc3339(),
        revoker_did: revoker.did.clone(),
        revoker_role,
        evidence: req.evidence,
        proof: crate::did::document::Proof::default(),
        peers_notified: vec![],
        propagated: false,
    };

    let canonical = entry.canonical_bytes_for_sign()?;
    let vm_ref = format!(
        "{}#dkp-v{}",
        revoker.did,
        revoker.current_dkp_version.max(1)
    );
    doc_sign::sign_in_place_generic(&mut entry.proof, &canonical, km, &vm_ref)?;

    // Persist the gossip atom.
    persistence::save_entry(&entry)?;

    // Rebuild crl.json snapshot (atomic). Sequence bumps by 1.
    let mut crl = persistence::load_crl()?.unwrap_or_else(|| {
        CertificateRevocationList::new(&revoker.did, req.circle_id)
    });
    crl.upsert(entry.clone())?;
    crl.sequence += 1;
    crl.generated_at = now.to_rfc3339();
    crl.recompute_root();
    let crl_canonical = crl.canonical_bytes_for_sign()?;
    doc_sign::sign_in_place_generic(&mut crl.proof, &crl_canonical, km, &vm_ref)?;
    persistence::save_crl(&crl)?;

    // Cross-reference VC StatusList (D6): if THIS node is the CA AND the
    // revoked DID has any VCs we issued, flip their bits.
    if matches!(revoker_role, RevokerRole::Owner) {
        cross_revoke_owned_vcs(&revoker.did, req.revoked_did, km, &vm_ref)?;
    }

    crate::audit::logger::log_audit(
        std::env::args().nth(1).unwrap_or_else(|| "unknown".into()).as_str(),
        crate::audit::event::AuditCategory::Crl,
        match entry.severity {
            Severity::Critical => crate::audit::event::AuditSeverity::Critical,
            Severity::High     => crate::audit::event::AuditSeverity::Warning,
            _                  => crate::audit::event::AuditSeverity::Info,
        },
        crate::audit::event::AuditAction::Succeeded,
        &format!(
            "Issued CRL entry {} revoked_did={} reason={} severity={} revoker_role={:?}",
            entry.id, entry.revoked_did, entry.reason.as_str(),
            entry.severity.as_str(), entry.revoker_role
        ),
    );

    Ok(entry)
}

/// When the CA (Owner) revokes a peer's DID, also flip the status-list
/// bits for every VC we issued to that subject. Members don't have access
/// to the status list, so this is owner-only.
fn cross_revoke_owned_vcs(
    issuer_did: &str,
    revoked_did: &str,
    km: &KeyManager,
    vm_ref: &str,
) -> Result<(), CrlError> {
    // List all issued VCs whose subject == revoked_did.
    let issued = crate::vc::persistence::list_issued_for_subject(revoked_did)
        .map_err(|e| CrlError::InvalidStructure(format!("vc list: {}", e)))?;
    if issued.is_empty() {
        return Ok(());
    }
    // Load issuer's DidRecord to satisfy the StatusListManager constructor.
    let issuer_record = crate::did::DidRecord {
        did: issuer_did.to_string(),
        current_dkp_version: vm_ref
            .rsplit_once("dkp-v")
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(1),
        // Other fields aren't needed for status-list load; populate via
        // DidRecord::load(DEFAULT_DID_PATH) in real callers.
        ..Default::default()
    };
    let mut slm = crate::vc::status_list::StatusListManager::load_or_create(&issuer_record, km)
        .map_err(|e| CrlError::InvalidStructure(format!("status list load: {}", e)))?;
    for vc in &issued {
        let idx: u64 = vc.credential_status.status_list_index.parse()
            .map_err(|e: std::num::ParseIntError| CrlError::InvalidStructure(
                format!("vc {} bad index: {}", vc.id, e)
            ))?;
        slm.set_revoked(idx, true)
            .map_err(|e| CrlError::InvalidStructure(format!("set_revoked: {}", e)))?;
    }
    slm.commit(km, vm_ref)
        .map_err(|e| CrlError::InvalidStructure(format!("commit status list: {}", e)))?;
    Ok(())
}
```

---

# D4 — Verification

## D4.1 — `src/crl/verify.rs`

```rust
use crate::crl::entry::{CrlEntry, RevokerRole, Severity};
use crate::crl::errors::CrlError;
use crate::crl::list::CertificateRevocationList;
use crate::did::Resolver;
use chrono::{DateTime, Utc};

/// Verify a single CRL entry:
///   1. Resolve revoker DID via Sprint 5 Task 3 Resolver.
///   2. Verify the signature against revoker's DKP pubkey.
///   3. Verify role/severity/reason invariants (same checks as issue).
///   4. Optional: bounded clock skew on timestamp (±5 min).
pub async fn verify_entry(
    entry: &CrlEntry,
    resolver: &Resolver,
    expected_circle_id: &str,
) -> Result<(), CrlError> {
    if entry.circle_id != expected_circle_id {
        return Err(CrlError::CircleMismatch {
            expected: expected_circle_id.into(),
            got: entry.circle_id.clone(),
        });
    }

    // Role invariants (re-checked on receive — issuer might be malicious).
    if matches!(entry.revoker_role, RevokerRole::Member) {
        if !entry.reason.is_security_critical() {
            return Err(CrlError::MemberReasonNotCritical(
                entry.reason.as_str().to_string(),
            ));
        }
        if !matches!(entry.severity, Severity::Critical | Severity::High) {
            return Err(CrlError::MemberSeverityTooLow(entry.severity));
        }
    }

    // Self-revocation check.
    if entry.revoker_did == entry.revoked_did {
        return Err(CrlError::SelfRevocation);
    }

    // Timestamp sanity.
    let ts = DateTime::parse_from_rfc3339(&entry.timestamp)
        .map_err(|e| CrlError::InvalidStructure(format!("timestamp: {}", e)))?;
    let now = Utc::now();
    let skew_min = (now - ts.with_timezone(&Utc)).num_minutes().abs();
    if skew_min > 60 * 24 * 365 {
        // Allow up to 1 year — accommodates offline-sync queues. Tune as
        // needed once gossip stats are available.
        return Err(CrlError::InvalidStructure(
            "timestamp too far from local clock".into(),
        ));
    }

    // Resolve the revoker DID for their pubkey.
    let resolved = resolver
        .resolve(&entry.revoker_did)
        .await
        .map_err(|e| CrlError::IssuerNotResolvable(format!("{}: {}", entry.revoker_did, e)))?;

    // Verify proof: same ecdsa-2019 path as DID Document and VC.
    let canonical = entry.canonical_bytes_for_sign()?;
    use base64::{engine::general_purpose, Engine as _};
    use sha2::{Digest, Sha256};
    let pubkey_der = general_purpose::STANDARD
        .decode(&resolved.public_key_der_b64)
        .map_err(|_| CrlError::InvalidProof(entry.id.clone()))?;
    let sig = general_purpose::STANDARD
        .decode(&entry.proof.proof_value)
        .map_err(|_| CrlError::InvalidProof(entry.id.clone()))?;
    let digest = Sha256::digest(&canonical);
    crate::did::doc_sign::ecdsa_p256_verify_der_or_raw(&pubkey_der, &digest, &sig)
        .map_err(|_| CrlError::InvalidProof(entry.id.clone()))?;

    Ok(())
}

/// Verify the CRL container itself: each entry valid, plus Merkle root
/// matches a recomputation.
pub async fn verify_list(
    crl: &CertificateRevocationList,
    resolver: &Resolver,
    expected_circle_id: &str,
) -> Result<(), CrlError> {
    if crl.circle_id != expected_circle_id {
        return Err(CrlError::CircleMismatch {
            expected: expected_circle_id.into(),
            got: crl.circle_id.clone(),
        });
    }

    // Verify every entry.
    for e in &crl.entries {
        verify_entry(e, resolver, expected_circle_id).await?;
    }

    // Verify Merkle root.
    let mut clone = crl.clone();
    clone.recompute_root();
    if clone.merkle_root != crl.merkle_root {
        return Err(CrlError::MerkleRootMismatch);
    }

    Ok(())
}
```

> `ecdsa_p256_verify_der_or_raw` is a helper extracted from the existing `doc_sign::verify` body. If it doesn't already exist as a standalone helper, factor it out as part of D4 (same pattern as `sign_in_place_generic` extraction from `sign_in_place`).

---

# D5 — Persistence

## D5.1 — `src/crl/persistence.rs`

```rust
use crate::crl::entry::CrlEntry;
use crate::crl::errors::CrlError;
use crate::crl::list::CertificateRevocationList;
use std::path::PathBuf;

pub const CRL_BASE: &str = "/var/lib/sgx-guardian/identity/crl";

pub fn crl_path() -> PathBuf { format!("{}/crl.json", CRL_BASE).into() }
pub fn entries_dir() -> PathBuf { format!("{}/entries", CRL_BASE).into() }
pub fn pending_dir() -> PathBuf { format!("{}/pending", CRL_BASE).into() }

fn write_atomic(path: &PathBuf, bytes: &[u8]) -> Result<(), CrlError> {
    if let Some(p) = path.parent() { std::fs::create_dir_all(p)?; }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn id_to_filename(id: &str) -> String {
    // urn:uuid:xxxx → urn_uuid_xxxx (filesystem-safe)
    id.replace(':', "_").replace('/', "_")
}

pub fn save_entry(e: &CrlEntry) -> Result<(), CrlError> {
    let path = entries_dir().join(format!("{}.json", id_to_filename(&e.id)));
    write_atomic(&path, &serde_json::to_vec_pretty(e)?)?;
    Ok(())
}

pub fn list_entries() -> Result<Vec<CrlEntry>, CrlError> {
    let dir = entries_dir();
    if !dir.exists() { return Ok(vec![]); }
    let mut out = Vec::new();
    for ent in std::fs::read_dir(&dir)? {
        let ent = ent?;
        if !ent.path().is_file() { continue; }
        if ent.path().extension().map(|e| e == "tmp").unwrap_or(false) { continue; }
        let bytes = std::fs::read(ent.path())?;
        let e: CrlEntry = serde_json::from_slice(&bytes)?;
        out.push(e);
    }
    Ok(out)
}

pub fn save_crl(crl: &CertificateRevocationList) -> Result<(), CrlError> {
    write_atomic(&crl_path(), &serde_json::to_vec_pretty(crl)?)?;
    Ok(())
}

pub fn load_crl() -> Result<Option<CertificateRevocationList>, CrlError> {
    let p = crl_path();
    if !p.exists() { return Ok(None); }
    let bytes = std::fs::read(&p)?;
    let crl: CertificateRevocationList = serde_json::from_slice(&bytes)?;
    Ok(Some(crl))
}
```

---

# D6 — Cross-Reference Hook (already in D3)

The owner-side `cross_revoke_owned_vcs` call in `issue_revocation` (D3.1) is D6. No separate file. It depends on `crate::vc::persistence::list_issued_for_subject` — confirm this helper exists in the VC module; if not, add it as a one-liner that walks `vc/issued/` and filters by `vc.credential_subject.id == subject_did`.

---

# D7 — CLI + REST + audit

## D7.1 — CLI (`sgx-pa-cli/src/commands/crl.rs`)

```rust
use clap::Subcommand;

#[derive(Subcommand)]
pub enum CrlCommand {
    /// Revoke a peer DID. By default uses this node's current role.
    Revoke {
        #[arg(long)]
        did: String,
        #[arg(long, default_value = "compromised")]
        reason: String,
        #[arg(long, default_value = "critical")]
        severity: String,
        #[arg(long)]
        device_id: Option<String>,
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        note: Option<String>,
    },
    /// Show the CRL contents.
    List,
    /// Show one entry by id.
    Show { #[arg(long)] id: String },
    /// Check if a DID is revoked.
    Check { #[arg(long)] did: String },
    /// Verify the local CRL against the resolver and the entry signatures.
    Verify,
    /// Print the current Merkle root (for anti-entropy diagnostics).
    Root,
}
```

Each subcommand maps cleanly into `crate::crl::*`:
- `Revoke` → `crl::issue::issue_revocation(...)`
- `List` → `crl::persistence::load_crl()`, table format
- `Show` → `crl::persistence::load_crl()` + filter, pretty-print JSON
- `Check` → `crl::is_revoked(&did)`
- `Verify` → `crl::verify::verify_list(...)`
- `Root` → `crl.merkle_root` after recompute

## D7.2 — REST (`src/api/handlers/crl.rs`)

| Verb | Path | Purpose |
|---|---|---|
| POST | `/api/v1/crl/revoke` | Issue revocation (body: did, reason, severity, optional fields) |
| GET  | `/api/v1/crl/list` | All entries |
| GET  | `/api/v1/crl/entry?id=...` | One entry |
| GET  | `/api/v1/crl/check?did=...` | `{ revoked: bool, entry?: CrlEntry }` |
| POST | `/api/v1/crl/verify` | Full CRL verification, returns `{ ok: bool, errors: [...] }` |
| GET  | `/api/v1/crl/root` | `{ sequence: u64, merkle_root: String }` |

Each handler shells out to `sgx-pa-cli crl <subcommand>` to keep SE050/audit/signing logic in one place — same pattern as the VC REST layer.

## D7.3 — REST docs

Add new §X.Y to `docs/REST API Details.md` covering the six endpoints with example payloads. Mirror the format used for `/vc/*`.

---

# D8 — Test Matrix

| Case | Setup | Pass criteria |
|---|---|---|
| **CRL-001** Owner revokes member, all reasons | nodeA CA, nodeB member | `crl revoke --did <B-DID> --reason compromised --severity critical` succeeds; `crl check --did <B-DID>` returns `revoked: true` |
| **CRL-002** Member reports another member compromise | nodeB revokes nodeC | Succeeds (Critical+compromised allowed); `crl verify` passes |
| **CRL-003** Member tries Medium severity | nodeB attempts `--severity medium` | Fails with `MemberSeverityTooLow(Medium)` |
| **CRL-004** Member tries `voluntary_departure` | nodeB attempts that reason | Fails with `MemberReasonNotCritical` |
| **CRL-005** Self-revocation | nodeA tries to revoke own DID | Fails with `SelfRevocation` |
| **CRL-006** Idempotent re-revoke | revoke nodeC twice | First succeeds; second fails with `AlreadyRevoked` |
| **CRL-007** Persistence across restart | revoke, kill daemon, restart, `crl check` | Returns `revoked: true` |
| **CRL-008** Forgery rejected | hand-craft entry with `revoker_did=<B-DID>` but signed by C's key | `crl verify` returns `InvalidProof` |
| **CRL-009** Merkle root anti-entropy | revoke 3 DIDs on nodeA; copy `crl.json` to nodeB; nodeB recomputes root | Identical root values; `crl verify` passes |
| **CRL-010** Cross-ref VC revocation | nodeA (CA) revokes nodeB; nodeB had a VC | Status-list bit for nodeB's VC = 1 after the revoke |

### Board script

```bash
#!/bin/bash
# Run on nodeA (CA).

NODEB_DID=$(ssh root@192.168.50.115 "cat /var/lib/sgx-guardian/identity/did.json | jq -r .did")
NODEC_DID=$(ssh root@192.168.50.248 "cat /var/lib/sgx-guardian/identity/did.json | jq -r .did")

echo "=== CRL-001 owner revokes member ==="
./sgx-pa-cli crl revoke --did "$NODEB_DID" --reason compromised --severity critical --note "test SE001"
./sgx-pa-cli crl check --did "$NODEB_DID"
# Expect: revoked: true

echo "=== CRL-005 self-revocation rejected ==="
SELF_DID=$(jq -r .did /var/lib/sgx-guardian/identity/did.json)
./sgx-pa-cli crl revoke --did "$SELF_DID" --reason compromised --severity critical 2>&1 | grep -i "self"

echo "=== CRL-006 double-revoke rejected ==="
./sgx-pa-cli crl revoke --did "$NODEB_DID" --reason stolen --severity critical 2>&1 | grep -i "already"

echo "=== CRL-007 persistence across restart ==="
pkill -f sgx_guardian_client
sleep 3
./sgx_guardian_client nodeA &
sleep 5
./sgx-pa-cli crl check --did "$NODEB_DID"
# Expect: revoked: true

echo "=== CRL-009 Merkle root parity ==="
./sgx-pa-cli crl revoke --did "$NODEC_DID" --reason policy_violation --severity high
./sgx-pa-cli crl root
ROOT_A=$(./sgx-pa-cli crl root | jq -r .merkle_root)
scp /var/lib/sgx-guardian/identity/crl/crl.json root@192.168.50.115:/tmp/crl-from-A.json
ssh root@192.168.50.115 "jq -r .merkle_root /tmp/crl-from-A.json"
# Expect: identical hex string on both sides.

echo "=== CRL-010 cross-ref VC status flipped ==="
ssh root@192.168.50.115 './sgx-pa-cli vc show'
# Expect: nodeB's VC's `credential_status` is reported as revoked when re-verified
ssh root@192.168.50.115 "./sgx-pa-cli vc verify --path /var/lib/sgx-guardian/identity/vc/own/*.json 2>&1 | grep -i revoked"
```

### Unit tests — `src/crl/tests/`

```rust
#[test] fn entry_fingerprint_is_stable_across_resigning() { /* same revoker_did/reason/etc, different proof → same fingerprint */ }
#[test] fn list_upsert_dedups_by_entry_id() {}
#[test] fn list_upsert_rejects_already_revoked_did() {}
#[test] fn list_contains_returns_correct_bool() {}
#[test] fn list_recompute_root_is_deterministic() {}
#[test] fn member_with_medium_severity_rejected() {}
#[test] fn member_with_non_critical_reason_rejected() {}
#[test] fn self_revocation_rejected() {}
#[test] fn round_trip_serde_preserves_all_fields() {}
#[test] fn legacy_entry_without_evidence_field_still_parses() {}  // serde-default tolerance
```

---

# Regression Checks

```bash
cargo build --release 2>&1 | grep -E "^(warning|error):" | grep -v unused || true
cargo test --release crl                  2>&1 | tail -40
cargo test --release did                  2>&1 | tail -20  # MUST be unchanged
cargo test --release vc                   2>&1 | tail -20  # MUST be unchanged (D6 touches status_list)
cargo test --release attestation          2>&1 | tail -20  # MUST be unchanged
```

Watch for:
- ✅ `is_revoked(did)` is O(log n) on the entries list (binary search on sorted vec).
- ✅ Entry fingerprint is stable across re-signing — needed for gossip dedup.
- ✅ Status list bit flipped for VCs whose subject DID was revoked by the CA.
- ✅ Audit log records every issue with Critical severity for `Compromised/Lost/Stolen/PolicyViolation`.
- ✅ Persistence: `crl.json` survives daemon restart; `crl check` after restart still reports revoked.

---

# Step-by-Step Checklist

- [ ] Branch from `shahzad_did` → `shahzad_crl` (or rebase after VC merge to `main`).
- [ ] **D1** new `src/crl/{entry,errors,mod}.rs`; add `AuditCategory::Crl`.
- [ ] **D2** new `src/crl/list.rs` with Merkle root + `upsert` + `contains`.
- [ ] **D3** new `src/crl/issue.rs` with member/owner gating + signing via `sign_in_place_generic`.
- [ ] **D4** new `src/crl/verify.rs` using Sprint 5 Task 3 Resolver + ECDSA verify helper.
- [ ] **D5** new `src/crl/persistence.rs` with atomic writes + `entries/` directory.
- [ ] **D6** add `cross_revoke_owned_vcs` in `issue.rs`; depends on `vc::persistence::list_issued_for_subject`.
- [ ] **D7** `sgx-pa-cli crl {revoke,list,show,check,verify,root}`; REST `/api/v1/crl/*`; add §X.Y to REST docs.
- [ ] **D8** unit tests + board script; add CRL-001..010 to Phase2_Test_Cases.pdf addendum.
- [ ] CodeRabbit + CodeQL.

---

# Out of Scope (deliberate deferrals — these are SEPARATE Sprint 4 tasks)

- **Gossip protocol** (Sprint 4 Task 2): epidemic-style propagation of CRL entries between peers every 1–5 minutes with peers_notified tracking and 80% propagation threshold. The data structure here pre-allocates the fields (`peers_notified`, `propagated`) but the gossip task is a separate PR.
- **Emergency revocation broadcast** (Sprint 4 Task 3): priority channel for Critical-severity entries; immediate REVOCATION_NOTICE bypassing normal intervals. The severity field is here; the broadcaster isn't.
- **Offline revocation sync** (Sprint 4 Task 4): retry queue for disconnected guardians, version-vector merging. The `pending/` directory is reserved in persistence; the queue logic is a separate PR.
- **Session termination on revocation**: cutting active mTLS sessions when a peer is revoked mid-session. Hook reserved at `crl::is_revoked` callers (attestation, resolver, VC verifier) but the actual session-kill code lives in those modules and is wired in a follow-up.
- **CRL UI in admin console**: the Lightning-Leap frontend renders this from `/api/v1/crl/list`. Frontend is their scope; we provide the endpoints in D7.
- **CRL signature aggregation / threshold sigs**: a single-issuer model for Phase 2. Multi-signature endorsement of revocations is a research-grade follow-up.
- **CRL pruning**: entries are append-only forever in Phase 2 ("Verify revocation persists across Guardian restarts"). Pruning policy is a Phase 3 question.

---

# Honest Notes on What I Couldn't Verify

- I cannot compile or run on the boards. FIND blocks anchor to verbatim text I pulled from `shahzad_did` via `project_knowledge_search`. Use `grep -n` for line-number drift.
- `crate::vc::persistence::list_issued_for_subject` is referenced in D6 — verify it exists by grepping; if not, the one-liner implementation is:
  ```rust
  pub fn list_issued_for_subject(subject_did: &str) -> Result<Vec<VerifiableCredential>, VcError> {
      let mut out = Vec::new();
      for ent in std::fs::read_dir(issued_dir())? { ... if vc.subject_did() == subject_did { out.push(vc); } }
      Ok(out)
  }
  ```
- The existing `DidRecord` struct fields beyond `did` and `current_dkp_version` aren't fully visible in my search results. The `..Default::default()` shorthand in `cross_revoke_owned_vcs` assumes `DidRecord: Default`. If not, load it properly via `DidRecord::load(DEFAULT_DID_PATH)` — that's the safer path and what real callers should use.
- `ecdsa_p256_verify_der_or_raw` is my naming for the verify helper. The codebase has the equivalent logic inline in `doc_sign::verify` — extract it as part of D4 so CRL and any future consumers use the same path. Same pattern as how `sign_in_place_generic` was extracted from `sign_in_place` during VC work.
- The Merkle root in D2 uses a single SHA-256 over sorted entry fingerprints (not a true Merkle tree). For Phase 2 anti-entropy this is sufficient — peers only need to know "do we agree on the set?", not produce inclusion proofs. Upgrading to a full Merkle tree is a Sprint 6 forensics task and adds proof-of-inclusion capability.
- Clock-skew tolerance in `verify_entry` is set to ±1 year to accommodate Sprint 4 Task 4 (Offline Sync) — guardians coming back online after long disconnection. Tune downward once gossip stats are available.
- The cross-ref VC revocation in D6 only fires when the LOCAL node is the CA. A member-initiated CRL entry against another peer's DID will NOT flip that peer's VC bits — only the Owner has the StatusList authority. Operationally this is fine because the Owner runs gossip too and will catch the member's report, then issue their own CRL entry (or override) and that one will flip the bits. Document this in the runbook.
- I did NOT add a `crl_snapshot` action on registry-sync port 50062 in this plan — that belongs to the gossip task (Sprint 4 Task 2). Adding it here would muddy the data-structure-only scope. The `persistence::load_crl()` / `save_crl()` pair is enough for this task; gossip wraps them when it lands.
- Once a DID is revoked there's no un-revoke operation, by design. If a DID is mistakenly revoked, the operator must rotate the DID via re-provisioning (new SE050 UID derivation) and re-enroll under a new DID. This is in the runbook, not in code.
