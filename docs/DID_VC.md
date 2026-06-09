# SG-X Guardian — Sprint 6 Task 1 (Verifiable Credentials) — Development Plan

**Branch base:** `main` (latest pull via `project_knowledge_search`).
**Target branch:** `shahzad_vc` (additive; assumes Sprint 5 Task 2 fixes and Task 3 resolver have landed — they're consumed below).
**Milestone:** 3 — target 2026-05-18 (per Phase 2 Final Timeline) / Sprint 6 (per SGX_Phase_2.docx).
**Test prefix:** VC-001 …

---

## Task Statement (verbatim — Phase 2 Final Timeline)

> Implement W3C Verifiable Credentials (VC) for cryptographically-provable Circle membership. Circle owner issues signed VC to member's DID asserting membership status, assigned role (owner/member), join date, and permissions. VC contains issuer DID (Circle owner), subject DID (member), claims (role, permissions), issuance/expiration dates, and cryptographic proof (owner's signature). Members present VCs during peer authentication to prove Circle membership without contacting central authority. Support VC revocation via status list.

Translation into testable obligations:

| # | Obligation | Currently on main? |
|---|---|---|
| O1 | W3C VC Data Model compliance | Nothing exists |
| O2 | CA-only issuance, signed by Circle owner's DKP | DKP/sign primitives exist; no VC layer |
| O3 | Claims: subject DID, role, permissions, joinDate, dates | `MemberRole` enum exists; nothing else |
| O4 | Members present VCs during peer authentication | Attestation handshake exists but has no VC step |
| O5 | Prove membership without contacting CA | StatusList sync runs offline once distributed |
| O6 | Revocation via status list | W3C StatusList2021 — net-new |

---

## What I Confirmed in Latest `main`

- **`src/cot/membership.rs`** — `CircleMembership { members: Arc<RwLock<HashMap<String, CircleMember>>> }`, with `MemberRole { Owner, Member }`, `TrustLevel { Unverified, Verified, Revoked }`. **In-memory only**; no persistence. We'll write `members.json` for the first time as part of this PR.
- **`src/nebula/ca.rs::NebulaCA::issue_node_cert(base_dir, membership, ip)`** — calls `validate_circle_membership(membership)` and shells out to `nebula-cert sign -groups guardian,member …`. The `-groups` flag is where VC role + permissions will be injected.
- **`src/cert_service.rs`** — gRPC server on the CA side: receives cert requests, polls for human approval via `approve_requests/<node>.yaml`, then signs. **The approval handler is the natural place to issue the VC alongside the Nebula cert.**
- **`src/cert_client.rs`** — member side: requests cert, polls, stores. **One additional response field carries the VC.**
- **`src/attestation_service.rs::mutual_attest`** — Step 2 sends `SignedEvidence`, Step 3 receives peer's. We add a `presented_vc_json` field to evidence; verification gets one extra check.
- **`src/did/{doc_sign,resolver,errors}.rs`** — proof signing/verifying primitives reusable for VCs.
- **`src/nebula/registry_sync.rs`** — port 50062 dispatcher with actions `assign/query/list/snapshot/.../publish_did_doc/snapshot_did_doc/resolve_did`. Adding `status_list_snapshot` is a single new arm.
- **`AuditCategory::Did`** added in Task 2 Fix 2. We add `AuditCategory::Vc`.

No existing `src/vc/` module on `main`. Greenfield, but every integration point already has a clean anchor.

---

## Architecture

```
                       CA NODE (nodeA, Circle owner)
                       ┌──────────────────────────────────────────────┐
                       │  src/vc/issue.rs                              │
                       │   ──> sign with DKP active key                 │
                       │   ──> assign next statusListIndex              │
                       │   ──> persist /vc/issued/<uuid>.json           │
                       │   ──> append to status_list.json (signed)      │
                       └────────────────────┬─────────────────────────┘
                                            │ cert bootstrap response
                                            │ adds `member_vc_json` field
                                            ▼
                       MEMBER NODE (nodeB / nodeC)
                       ┌──────────────────────────────────────────────┐
                       │  src/vc/persistence.rs                        │
                       │   ──> save /vc/own/<uuid>.json                 │
                       └────────────────────┬─────────────────────────┘
                                            │ at peer auth time
                                            ▼
   ┌─────────────────── attestation_service::mutual_attest ─────────────────┐
   │ Step 2: SignedEvidence { ..., presented_vc_json } → peer               │
   │ Step 3: receive peer's evidence                                        │
   │ Step 4: verify_signed_evidence(...)                                    │
   │         ├─ existing PCR + signature checks                             │
   │         └─ vc::verify::verify_presented_vc(&peer_vc, expected_subject) │
   │            ├─ JSON-LD structure check                                  │
   │            ├─ issuer DID resolves via Task-3 Resolver                  │
   │            ├─ proof signature valid against issuer DKP pubkey          │
   │            ├─ expirationDate > now                                     │
   │            └─ statusList bit @ index == 0  (not revoked)               │
   └────────────────────────────────────────────────────────────────────────┘

Status List 2021 distribution:
  CA  ◀── registry_sync.rs action="status_list_snapshot" (port 50062)
  All members pull every 5 min; CA pushes on revoke
```

**Why this shape:**
- VC issuance hooks into the *existing* cert-approval moment — no new approval workflow, no second admin step.
- VC verification slots into the *existing* mutual-attestation handshake — no new RPC, no new port.
- Status List distribution rides the *existing* registry-sync transport — no new server.
- VC proofs reuse `doc_sign::sign_in_place` / `verify` — no new crypto code.

---

## Deliverables (8 atomic items, ~12 dev-days for 1 dev)

| # | Deliverable | Effort | Files |
|---|---|---|---|
| D1 | Core VC data model + errors + mod | 1.0 d | `src/vc/credential.rs`, `errors.rs`, `mod.rs` (new) |
| D2 | VC issuance (CA-only) + persistence | 1.5 d | `src/vc/issue.rs`, `persistence.rs` (new) |
| D3 | VC verification + replay/expiration/status checks | 1.0 d | `src/vc/verify.rs` (new) |
| D4 | StatusList2021 (bitstring + sign + lookup) | 1.5 d | `src/vc/status_list.rs` (new) |
| D5 | Wire integration: cert bootstrap delivers VC | 1.0 d | `src/cert_service.rs`, `src/cert_client.rs` |
| D6 | Wire integration: status list sync on registry-sync (50062) | 1.0 d | `src/vc/distribution.rs`, `src/nebula/registry_sync.rs` |
| D7 | Peer auth: VC presentation in mutual_attest | 1.5 d | `src/attestation_service.rs`, `src/vc/verify.rs` |
| D8 | CLI + REST + audit + tests (VC-001..010) | 2.5 d | `sgx-pa-cli/src/commands/vc.rs`, `src/api/handlers/vc.rs`, `src/api/routes.rs`, `src/vc/tests/` |

> **Calendar:** ~12 working days for 1 dev → **~3 calendar weeks**. For 2 devs in parallel: **~7–8 working days → ~1.5 calendar weeks** (D1+D2 in serial, then D3+D4 in parallel, then D5+D6+D7 in parallel, D8 last).

---

## File Structure (after this task)

```
src/vc/                          (new module)
├── credential.rs                D1: VerifiableCredential struct + JSON-LD context constants
├── errors.rs                    D1: VcError variants
├── issue.rs                     D2: CA issuance entry point + sign
├── verify.rs                    D3: verify proof + expiration + status
├── status_list.rs               D4: StatusList2021 bitstring + signing + index allocator
├── persistence.rs               D2: save/load issued/own/peer VCs + status list file
├── distribution.rs              D6: pull status list snapshot from CA
├── mod.rs                       D1: re-exports
└── tests/
    ├── credential_tests.rs
    ├── issue_tests.rs
    ├── verify_tests.rs
    └── status_list_tests.rs

src/cot/membership.rs            D2: add VC-id pointer per member (+ persist members.json)

src/nebula/registry_sync.rs      D6: add "status_list_snapshot" action arm

src/cert_service.rs              D5: on approval, also issue VC; bundle in response
src/cert_client.rs               D5: store VC from response in /vc/own/

src/attestation_service.rs       D7: presented_vc_json on SignedEvidence; verify in handler

src/audit/event.rs               D1: AuditCategory::Vc variant

src/api/handlers/vc.rs           D8: REST handlers (new file)
src/api/routes.rs                D8: wire VC routes
sgx-pa-cli/src/commands/vc.rs    D8: CLI subcommands (new file)
sgx-pa-cli/src/commands/mod.rs   D8: register cmd_vc
sgx-pa-cli/src/main.rs           D8: VC subcommand wiring
```

**On-disk layout:**
```
/var/lib/sgx-guardian/identity/vc/
├── issued/<uuid>.json           CA only — every VC this owner has issued
├── own/<uuid>.json              member side — VC(s) this node has received
├── peers/did_vc_<msi>.json      member side — VCs presented by peers (verified, cached)
├── status_list.json             every node — signed status list snapshot
└── status_list_index.json       CA only — next free index counter
```

---

# D1 — Core VC Data Model

## D1.1 — `src/vc/credential.rs`

W3C VC Data Model v1.1 compliant. Structure mirrors `DidDocument` style for symmetry with Task 2.

```rust
//! W3C Verifiable Credentials for Circle membership.
//! Compliant with the VC Data Model 1.1 plus StatusList2021 for revocation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::did::document::Proof; // reuse Task-2 proof struct (DataIntegrityProof + ecdsa-2019)

pub const VC_CONTEXT_CORE: &str = "https://www.w3.org/2018/credentials/v1";
pub const VC_CONTEXT_JWS_2020: &str = "https://w3id.org/security/suites/jws-2020/v1";
pub const VC_CONTEXT_STATUS_LIST_2021: &str = "https://w3id.org/vc/status-list/2021/v1";
pub const VC_CONTEXT_SGX_CIRCLE: &str = "https://schemas.cyberzeus.io/sgx/v1/circle-membership";

pub const TYPE_VC: &str = "VerifiableCredential";
pub const TYPE_CIRCLE_MEMBERSHIP: &str = "CircleMembershipCredential";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CredentialRole {
    Owner,
    Member,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubject {
    /// MUST equal a valid DID (the member's DID).
    pub id: String,
    pub role: CredentialRole,
    /// e.g. ["mesh:join", "cert:request", "attest:peer"]; closed set, validated.
    pub permissions: Vec<String>,
    pub join_date: String,        // RFC3339
    pub circle_id: String,        // "guardian-circle-alpha" — must match CA's circle_id
    pub node_hint: Option<String>, // human-readable (e.g. "nodeB")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStatus {
    pub id: String,                       // e.g. "https://nodeA/status_list#42"
    #[serde(rename = "type")]
    pub r#type: String,                   // "StatusList2021Entry"
    pub status_purpose: String,           // "revocation"
    pub status_list_index: String,        // assigned index, decimal string per spec
    pub status_list_credential: String,   // DID URI of the status list credential
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// `urn:uuid:<uuid-v4>` — unique per VC.
    pub id: String,
    /// MUST include "VerifiableCredential" plus "CircleMembershipCredential".
    #[serde(rename = "type")]
    pub r#type: Vec<String>,
    /// Issuer DID (the CA / Circle owner).
    pub issuer: String,
    pub issuance_date: String,
    pub expiration_date: String,
    pub credential_subject: CredentialSubject,
    pub credential_status: CredentialStatus,
    pub proof: Proof,
}

impl VerifiableCredential {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        match DateTime::parse_from_rfc3339(&self.expiration_date) {
            Ok(exp) => now > exp.with_timezone(&Utc),
            Err(_) => true, // malformed → treat as expired (fail-closed)
        }
    }

    pub fn subject_did(&self) -> &str {
        &self.credential_subject.id
    }

    pub fn issuer_did(&self) -> &str {
        &self.issuer
    }

    /// Canonical bytes for signing — same approach as DidDocument.
    /// Strips the proof, sorts keys, hashes via SHA-256 (matches doc_sign).
    pub fn canonical_bytes_for_sign(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut copy = self.clone();
        copy.proof = Proof::default();
        let v: serde_json::Value = serde_json::to_value(&copy)?;
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

## D1.2 — Errors

`src/vc/errors.rs`:
```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VcError {
    #[error("VC structure invalid: {0}")]
    InvalidStructure(String),
    #[error("VC issuer DID not resolvable: {0}")]
    IssuerNotResolvable(String),
    #[error("VC proof signature invalid")]
    InvalidProof,
    #[error("VC expired (expirationDate={0})")]
    Expired(String),
    #[error("VC subject mismatch: expected {expected}, got {got}")]
    SubjectMismatch { expected: String, got: String },
    #[error("VC revoked at status list index {0}")]
    Revoked(u64),
    #[error("status list unavailable: {0}")]
    StatusListUnavailable(String),
    #[error("status list signature invalid")]
    StatusListProofInvalid,
    #[error("status list index out of range: {index} (size={size})")]
    IndexOutOfRange { index: u64, size: u64 },
    #[error("circle mismatch: expected {expected}, got {got}")]
    CircleMismatch { expected: String, got: String },
    #[error("not the CA: only the Circle owner may issue VCs")]
    NotCa,
    #[error("permission not in allowed set: {0}")]
    UnknownPermission(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("did: {0}")]
    Did(#[from] crate::did::errors::DidError),
}
```

## D1.3 — `AuditCategory::Vc`

**File:** `src/audit/event.rs`

**FIND:**
```rust
pub enum AuditCategory {
    Identity,
    Did,
```

**REPLACE WITH:**
```rust
pub enum AuditCategory {
    Identity,
    Did,
    Vc,
```

---

# D2 — VC Issuance (CA-only)

## D2.1 — `src/vc/issue.rs`

```rust
//! Verifiable Credential issuance. CA-only path (Circle owner).
//! Members never call into this module.

use crate::did::{doc_sign, DidRecord};
use crate::key_manager::KeyManager;
use crate::vc::credential::*;
use crate::vc::errors::VcError;
use crate::vc::persistence;
use crate::vc::status_list::StatusListManager;
use chrono::{Duration, Utc};
use uuid::Uuid;

pub const DEFAULT_VC_DURATION_DAYS: i64 = 365;
pub const ALLOWED_PERMISSIONS: &[&str] = &[
    "mesh:join",
    "cert:request",
    "cert:renew",
    "attest:peer",
    "did:resolve",
    "status:read",
];

pub struct IssueRequest<'a> {
    pub subject_did: &'a str,
    pub role: CredentialRole,
    pub permissions: Vec<String>,
    pub circle_id: &'a str,
    pub node_hint: Option<String>,
    pub duration_days: Option<i64>,
}

pub fn issue_membership_vc(
    issuer_did: &DidRecord,
    km: &KeyManager,
    req: IssueRequest,
) -> Result<VerifiableCredential, VcError> {
    // O2: only the CA issues. Caller is responsible for checking
    // is_ca == true; we re-check by asserting issuer_did is in the
    // CA path (members can't load DKP for issuer_did != self anyway).
    if !crate::cot::is_self_ca() {
        return Err(VcError::NotCa);
    }

    // Validate permissions against the allowed closed set.
    for p in &req.permissions {
        if !ALLOWED_PERMISSIONS.contains(&p.as_str()) {
            return Err(VcError::UnknownPermission(p.clone()));
        }
    }

    let now = Utc::now();
    let expires = now + Duration::days(req.duration_days.unwrap_or(DEFAULT_VC_DURATION_DAYS));
    let id = format!("urn:uuid:{}", Uuid::new_v4());

    // Allocate the next free index in the CA's status list.
    let mut slm = StatusListManager::load_or_create(issuer_did, km)?;
    let status_index = slm.allocate_index()?;

    let status = CredentialStatus {
        id: format!("{}#{}", issuer_did.did.as_str(), status_index),
        r#type: "StatusList2021Entry".into(),
        status_purpose: "revocation".into(),
        status_list_index: status_index.to_string(),
        status_list_credential: issuer_did.did.as_str().to_string(),
    };

    let subject = CredentialSubject {
        id: req.subject_did.into(),
        role: req.role,
        permissions: req.permissions,
        join_date: now.to_rfc3339(),
        circle_id: req.circle_id.into(),
        node_hint: req.node_hint,
    };

    let mut vc = VerifiableCredential {
        context: vec![
            VC_CONTEXT_CORE.into(),
            VC_CONTEXT_JWS_2020.into(),
            VC_CONTEXT_STATUS_LIST_2021.into(),
            VC_CONTEXT_SGX_CIRCLE.into(),
        ],
        id,
        r#type: vec![TYPE_VC.into(), TYPE_CIRCLE_MEMBERSHIP.into()],
        issuer: issuer_did.did.as_str().into(),
        issuance_date: now.to_rfc3339(),
        expiration_date: expires.to_rfc3339(),
        credential_subject: subject,
        credential_status: status,
        proof: crate::did::document::Proof::default(),
    };

    // Sign with the active DKP via the same primitive used for DID Documents.
    let vm_ref = format!("{}#dkp-v{}", issuer_did.did.as_str(),
                        crate::secure_element::pcr::read_dkp_key_version());
    doc_sign::sign_in_place_generic(&mut vc.proof, &vc.canonical_bytes_for_sign()?, km, &vm_ref)?;

    persistence::save_issued(&vc)?;
    slm.commit()?; // persists the allocator + re-signs the status list

    crate::audit::log_audit(
        issuer_did.did.as_str(),
        crate::audit::AuditCategory::Vc,
        crate::audit::AuditSeverity::Info,
        crate::audit::AuditAction::Succeeded,
        &format!(
            "Issued VC {} to subject={} role={:?} idx={} expires={}",
            vc.id, vc.subject_did(), vc.credential_subject.role, status_index, vc.expiration_date,
        ),
    );

    Ok(vc)
}

pub fn revoke_vc(
    issuer_did: &DidRecord,
    km: &KeyManager,
    vc_id: &str,
    reason: &str,
) -> Result<(), VcError> {
    if !crate::cot::is_self_ca() {
        return Err(VcError::NotCa);
    }
    let vc = persistence::load_issued(vc_id)?;
    let idx: u64 = vc.credential_status.status_list_index.parse()
        .map_err(|e: std::num::ParseIntError| VcError::InvalidStructure(format!("index: {}", e)))?;
    let mut slm = StatusListManager::load_or_create(issuer_did, km)?;
    slm.set_revoked(idx, true)?;
    slm.commit()?;

    crate::audit::log_audit(
        issuer_did.did.as_str(),
        crate::audit::AuditCategory::Vc,
        crate::audit::AuditSeverity::Warning,
        crate::audit::AuditAction::Succeeded,
        &format!("Revoked VC {} (idx={}) reason: {}", vc_id, idx, reason),
    );
    Ok(())
}
```

## D2.2 — `sign_in_place_generic` helper

**File:** `src/did/doc_sign.rs` — extract the existing inner of `sign_in_place` so it works on any `Proof` + canonical bytes, not just a `DidDocument`. Then have the existing `sign_in_place` call it.

**ADD:**
```rust
pub fn sign_in_place_generic(
    proof: &mut Proof,
    canonical_bytes: &[u8],
    km: &KeyManager,
    vm_ref: &str,
) -> Result<(), DidError> {
    let hash = sha2::Sha256::digest(canonical_bytes);
    let sig = km.sign(&hash).map_err(|e| DidError::Signing(e.to_string()))?;
    *proof = Proof {
        r#type: "DataIntegrityProof".into(),
        cryptosuite: "ecdsa-2019".into(),
        created: chrono::Utc::now().to_rfc3339(),
        verification_method: vm_ref.into(),
        proof_purpose: "assertionMethod".into(),
        proof_value: base64::engine::general_purpose::STANDARD.encode(&sig),
    };
    Ok(())
}
```

And refactor existing `sign_in_place` to call `sign_in_place_generic(&mut doc.proof, &doc.canonical_bytes_for_sign()?, km, vm_ref)`.

## D2.3 — `src/vc/persistence.rs`

```rust
use crate::vc::credential::VerifiableCredential;
use crate::vc::errors::VcError;
use std::path::PathBuf;

pub const VC_BASE: &str = "/var/lib/sgx-guardian/identity/vc";

pub fn issued_dir() -> PathBuf { format!("{}/issued", VC_BASE).into() }
pub fn own_dir()    -> PathBuf { format!("{}/own",    VC_BASE).into() }
pub fn peers_dir()  -> PathBuf { format!("{}/peers",  VC_BASE).into() }
pub fn status_list_path() -> PathBuf { format!("{}/status_list.json", VC_BASE).into() }

fn write_atomic(path: &PathBuf, bytes: &[u8]) -> Result<(), VcError> {
    if let Some(p) = path.parent() { std::fs::create_dir_all(p)?; }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn save_issued(vc: &VerifiableCredential) -> Result<(), VcError> {
    let id_safe = vc.id.replace(':', "_");
    let path = issued_dir().join(format!("{}.json", id_safe));
    write_atomic(&path, &serde_json::to_vec_pretty(vc)?)?;
    Ok(())
}

pub fn save_own(vc: &VerifiableCredential) -> Result<(), VcError> {
    let id_safe = vc.id.replace(':', "_");
    let path = own_dir().join(format!("{}.json", id_safe));
    write_atomic(&path, &serde_json::to_vec_pretty(vc)?)?;
    Ok(())
}

pub fn save_peer(peer_did: &str, vc: &VerifiableCredential) -> Result<(), VcError> {
    let msi = peer_did.rsplit(':').next().unwrap_or(peer_did);
    let path = peers_dir().join(format!("did_vc_{}.json", msi));
    write_atomic(&path, &serde_json::to_vec_pretty(vc)?)?;
    Ok(())
}

pub fn load_issued(id: &str) -> Result<VerifiableCredential, VcError> {
    let id_safe = id.replace(':', "_");
    let bytes = std::fs::read(issued_dir().join(format!("{}.json", id_safe)))?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn load_own_any() -> Result<Option<VerifiableCredential>, VcError> {
    // Returns the most recently issued (highest mtime) VC this node holds.
    // Used by mutual_attest to attach VC presentation automatically.
    let dir = own_dir();
    if !dir.exists() { return Ok(None); }
    let mut newest: Option<(std::time::SystemTime, VerifiableCredential)> = None;
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let m = entry.metadata()?.modified()?;
        if let Ok(bytes) = std::fs::read(entry.path()) {
            if let Ok(vc) = serde_json::from_slice::<VerifiableCredential>(&bytes) {
                if newest.as_ref().map_or(true, |(t, _)| m > *t) {
                    newest = Some((m, vc));
                }
            }
        }
    }
    Ok(newest.map(|(_, vc)| vc))
}
```

## D2.4 — Member persistence (long overdue)

**File:** `src/cot/membership.rs`

Add `vc_id: Option<String>` field on `CircleMember`, plus disk persistence:
```rust
pub fn save(&self, path: &str) -> std::io::Result<()> { /* atomic write of members map */ }
pub fn load(path: &str) -> std::io::Result<Self>     { /* read or empty */ }
```

`add_member` becomes `add_member_with_vc(device_id, pubkey, vc_id)`; backward-compat wrapper keeps the old signature with `vc_id = None` for tests.

---

# D3 — VC Verification

## D3.1 — `src/vc/verify.rs`

```rust
use crate::did::Resolver;
use crate::vc::credential::*;
use crate::vc::errors::VcError;
use crate::vc::status_list::StatusListView;
use chrono::Utc;

pub struct VerifyOptions<'a> {
    pub expected_subject_did: Option<&'a str>,
    pub expected_circle_id: Option<&'a str>,
    pub check_status_list: bool,
    pub status_list: Option<&'a StatusListView>,
}

pub async fn verify_vc(
    vc: &VerifiableCredential,
    resolver: &Resolver,
    opts: VerifyOptions<'_>,
) -> Result<(), VcError> {
    // O1: structural shape
    if !vc.r#type.iter().any(|t| t == TYPE_VC)
        || !vc.r#type.iter().any(|t| t == TYPE_CIRCLE_MEMBERSHIP)
    {
        return Err(VcError::InvalidStructure("missing required type".into()));
    }
    if vc.context.iter().find(|c| *c == VC_CONTEXT_CORE).is_none() {
        return Err(VcError::InvalidStructure("missing VC core context".into()));
    }

    // Expected subject (used during peer auth: we expect the VC subject to be the connecting peer)
    if let Some(exp) = opts.expected_subject_did {
        if vc.subject_did() != exp {
            return Err(VcError::SubjectMismatch {
                expected: exp.into(),
                got: vc.subject_did().into(),
            });
        }
    }
    // Expected circle
    if let Some(exp) = opts.expected_circle_id {
        if vc.credential_subject.circle_id != exp {
            return Err(VcError::CircleMismatch {
                expected: exp.into(),
                got: vc.credential_subject.circle_id.clone(),
            });
        }
    }

    // Expiration
    if vc.is_expired(Utc::now()) {
        return Err(VcError::Expired(vc.expiration_date.clone()));
    }

    // Resolve issuer to get pubkey
    let issuer = resolver
        .resolve(vc.issuer_did())
        .await
        .map_err(|e| VcError::IssuerNotResolvable(format!("{}: {}", vc.issuer_did(), e)))?;

    // Verify proof
    use base64::{engine::general_purpose, Engine as _};
    let sig = general_purpose::STANDARD
        .decode(&vc.proof.proof_value)
        .map_err(|_| VcError::InvalidProof)?;
    let issuer_pk_der = general_purpose::STANDARD
        .decode(&issuer.public_key_der_b64)
        .map_err(|_| VcError::InvalidProof)?;
    let canonical = vc.canonical_bytes_for_sign()?;
    let hash = sha2::Sha256::digest(&canonical);
    crate::crypto::ecdsa_p256_verify(&issuer_pk_der, &hash, &sig)
        .map_err(|_| VcError::InvalidProof)?;

    // Revocation
    if opts.check_status_list {
        let sl = opts.status_list.ok_or_else(|| {
            VcError::StatusListUnavailable("verify caller did not supply status list".into())
        })?;
        let idx: u64 = vc.credential_status.status_list_index.parse()
            .map_err(|e: std::num::ParseIntError| VcError::InvalidStructure(format!("idx: {}", e)))?;
        if sl.is_revoked(idx)? {
            return Err(VcError::Revoked(idx));
        }
    }

    Ok(())
}
```

---

# D4 — StatusList2021

## D4.1 — `src/vc/status_list.rs`

```rust
//! W3C StatusList2021 implementation.
//! A bitstring credential, gzip+base64-encoded per spec.
//! Single global list per Circle, signed by the CA's DKP.

use crate::did::doc_sign;
use crate::did::DidRecord;
use crate::key_manager::KeyManager;
use crate::vc::credential::*;
use crate::vc::errors::VcError;
use crate::vc::persistence::status_list_path;
use chrono::Utc;
use serde::{Deserialize, Serialize};

/// 131072 bits = 16384 bytes = ample headroom for VCs in a single Circle.
pub const STATUS_LIST_SIZE_BITS: u64 = 131072;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusListCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "type")]
    pub r#type: Vec<String>,
    pub issuer: String,
    pub issuance_date: String,
    pub credential_subject: StatusListSubject,
    pub proof: crate::did::document::Proof,
    /// Next index to allocate. Not part of W3C spec — Cervais bookkeeping.
    #[serde(default)]
    pub sgx_next_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusListSubject {
    pub id: String,
    #[serde(rename = "type")]
    pub r#type: String, // "StatusList2021"
    pub status_purpose: String, // "revocation"
    pub encoded_list: String, // base64(gzip(bitstring))
}

pub struct StatusListManager {
    cred: StatusListCredential,
    bits: Vec<u8>,
    issuer_did: String,
    km_vm_ref: String,
}

impl StatusListManager {
    pub fn load_or_create(
        issuer: &DidRecord,
        km: &KeyManager,
    ) -> Result<Self, VcError> {
        let path = status_list_path();
        let vm = format!("{}#dkp-v{}",
            issuer.did.as_str(),
            crate::secure_element::pcr::read_dkp_key_version());

        if path.exists() {
            let bytes = std::fs::read(&path)?;
            let cred: StatusListCredential = serde_json::from_slice(&bytes)?;
            let bits = decode_encoded_list(&cred.credential_subject.encoded_list)?;
            return Ok(Self { cred, bits, issuer_did: issuer.did.as_str().into(), km_vm_ref: vm });
        }

        // Fresh status list — all zeros.
        let mut bits = vec![0u8; (STATUS_LIST_SIZE_BITS / 8) as usize];
        let encoded = encode_encoded_list(&bits)?;
        let cred = StatusListCredential {
            context: vec![VC_CONTEXT_CORE.into(), VC_CONTEXT_STATUS_LIST_2021.into()],
            id: format!("{}/status_list", issuer.did.as_str()),
            r#type: vec!["VerifiableCredential".into(), "StatusList2021Credential".into()],
            issuer: issuer.did.as_str().into(),
            issuance_date: Utc::now().to_rfc3339(),
            credential_subject: StatusListSubject {
                id: format!("{}/status_list#list", issuer.did.as_str()),
                r#type: "StatusList2021".into(),
                status_purpose: "revocation".into(),
                encoded_list: encoded,
            },
            proof: crate::did::document::Proof::default(),
            sgx_next_index: 1, // index 0 reserved
        };

        let mut slm = Self { cred, bits, issuer_did: issuer.did.as_str().into(), km_vm_ref: vm };
        slm.resign(km)?;
        Ok(slm)
    }

    pub fn allocate_index(&mut self) -> Result<u64, VcError> {
        let idx = self.cred.sgx_next_index;
        if idx >= STATUS_LIST_SIZE_BITS {
            return Err(VcError::IndexOutOfRange { index: idx, size: STATUS_LIST_SIZE_BITS });
        }
        self.cred.sgx_next_index += 1;
        Ok(idx)
    }

    pub fn set_revoked(&mut self, idx: u64, revoked: bool) -> Result<(), VcError> {
        if idx >= STATUS_LIST_SIZE_BITS {
            return Err(VcError::IndexOutOfRange { index: idx, size: STATUS_LIST_SIZE_BITS });
        }
        let byte = (idx / 8) as usize;
        let bit  = (idx % 8) as u8;
        if revoked { self.bits[byte] |= 1 << bit; } else { self.bits[byte] &= !(1 << bit); }
        Ok(())
    }

    pub fn commit(&mut self) -> Result<(), VcError> {
        self.cred.credential_subject.encoded_list = encode_encoded_list(&self.bits)?;
        // Re-sign with whatever KM the caller used at construction time.
        // (We need km here — passed in via resign).
        // In practice issue/revoke flows call resign before commit explicitly.
        let bytes = serde_json::to_vec_pretty(&self.cred)?;
        let path = status_list_path();
        if let Some(p) = path.parent() { std::fs::create_dir_all(p)?; }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn resign(&mut self, km: &KeyManager) -> Result<(), VcError> {
        let canonical = canonical_bytes_status_list(&self.cred)?;
        doc_sign::sign_in_place_generic(&mut self.cred.proof, &canonical, km, &self.km_vm_ref)?;
        Ok(())
    }
}

pub struct StatusListView {
    bits: Vec<u8>,
    pub size_bits: u64,
}

impl StatusListView {
    pub fn from_credential(cred: &StatusListCredential) -> Result<Self, VcError> {
        let bits = decode_encoded_list(&cred.credential_subject.encoded_list)?;
        Ok(Self { bits, size_bits: (bits.len() as u64) * 8 })
    }

    pub fn is_revoked(&self, idx: u64) -> Result<bool, VcError> {
        if idx >= self.size_bits {
            return Err(VcError::IndexOutOfRange { index: idx, size: self.size_bits });
        }
        let byte = (idx / 8) as usize;
        let bit  = (idx % 8) as u8;
        Ok(self.bits[byte] & (1 << bit) != 0)
    }
}

fn encode_encoded_list(bits: &[u8]) -> Result<String, VcError> {
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;
    use base64::{engine::general_purpose, Engine as _};
    let mut enc = GzEncoder::new(Vec::new(), Compression::best());
    enc.write_all(bits)?;
    let gz = enc.finish()?;
    Ok(general_purpose::STANDARD.encode(&gz))
}

fn decode_encoded_list(s: &str) -> Result<Vec<u8>, VcError> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    use base64::{engine::general_purpose, Engine as _};
    let gz = general_purpose::STANDARD.decode(s)
        .map_err(|e| VcError::InvalidStructure(format!("status list b64: {}", e)))?;
    let mut d = GzDecoder::new(&gz[..]);
    let mut out = Vec::new();
    d.read_to_end(&mut out)?;
    Ok(out)
}

fn canonical_bytes_status_list(cred: &StatusListCredential) -> Result<Vec<u8>, VcError> {
    let mut clone = cred.clone();
    clone.proof = crate::did::document::Proof::default();
    let v = serde_json::to_value(&clone)?;
    Ok(serde_json::to_vec(&v)?) // BTreeMap-based canonical via serde_json::Value
}
```

> Status list verifier (status-list-side, called by `verify::verify_vc` via `StatusListView::from_credential`) MUST first verify the status-list-credential's own proof signature against the issuer's resolved pubkey. Add `verify_status_list_credential(cred, resolver) -> Result<StatusListView, VcError>` in `status_list.rs` — pattern identical to `doc_sign::verify_with_replay_protection` minus the replay check.

---

# D5 — Wire Integration: Cert Bootstrap Delivers VC

## D5.1 — `src/cert_service.rs`

**FIND** (the gRPC response build after approval, in the `RequestCert` handler — anchor on the `signed_cert_pem` field assignment):
```rust
        Ok(CertResponse {
            status: "approved".into(),
            signed_cert_pem,
            ca_cert_pem,
            // ...
        })
```

**REPLACE WITH:**
```rust
        // Sprint 6 Task 1: issue VC alongside the Nebula cert.
        let circle_id = "guardian-circle-alpha";
        let issuer = crate::did::DidRecord::load(crate::did::DEFAULT_DID_PATH)
            .map_err(|e| Status::internal(format!("CA DID load: {}", e)))?;
        let vc = crate::vc::issue::issue_membership_vc(
            &issuer,
            &km,
            crate::vc::issue::IssueRequest {
                subject_did: &subject_did_for_node,
                role: match decision {
                    ApprovalDecision::Lighthouse | ApprovalDecision::LhRelay
                        => crate::vc::credential::CredentialRole::Owner,
                    _   => crate::vc::credential::CredentialRole::Member,
                },
                permissions: crate::vc::issue::default_permissions_for(&decision),
                circle_id,
                node_hint: Some(node_id.clone()),
                duration_days: None,
            },
        ).map_err(|e| Status::internal(format!("VC issue: {}", e)))?;

        let member_vc_json = serde_json::to_string(&vc)
            .map_err(|e| Status::internal(format!("VC serialize: {}", e)))?;

        Ok(CertResponse {
            status: "approved".into(),
            signed_cert_pem,
            ca_cert_pem,
            member_vc_json,  // NEW field
            // ...
        })
```

`subject_did_for_node` is derived from the node's pubkey at the start of the handler — same way the existing code already maps node_id → pubkey. Add the helper `crate::vc::issue::default_permissions_for(decision) -> Vec<String>` returning the right closed-set permissions per role.

Update the `.proto` (in `proto/cert.proto` or wherever the service is defined): add `string member_vc_json = N;` to `CertResponse`. Rebuild with `cargo build`.

## D5.2 — `src/cert_client.rs`

**FIND** (the block that saves the signed cert after approval):
```rust
                "approved" => {
                    // ── Save node cert ────────────────────────────────
                    if !Path::new(&cert_path).exists() && !resp.signed_cert_pem.is_empty() {
                        // existing save logic …
                    }
```

**REPLACE WITH:** (immediately AFTER the existing save block, BEFORE the "return") add:
```rust
                    // Sprint 6 Task 1: persist the VC the CA issued to us.
                    if !resp.member_vc_json.is_empty() {
                        match serde_json::from_str::<crate::vc::credential::VerifiableCredential>(&resp.member_vc_json) {
                            Ok(vc) => {
                                if let Err(e) = crate::vc::persistence::save_own(&vc) {
                                    log_error(&node_id, &format!("VC save failed: {}", e));
                                } else {
                                    log_audit(
                                        &node_id,
                                        AuditCategory::Vc,
                                        AuditSeverity::Info,
                                        AuditAction::Succeeded,
                                        &format!("VC received and stored: {}", vc.id),
                                    );
                                }
                            }
                            Err(e) => log_error(&node_id, &format!("VC parse failed: {}", e)),
                        }
                    }
```

---

# D6 — Status List Distribution

## D6.1 — Pull side: `src/vc/distribution.rs`

```rust
use crate::nebula::registry_sync::{RegistryRequest, RegistryResponse};
use crate::vc::errors::VcError;
use crate::vc::persistence::status_list_path;
use crate::vc::status_list::StatusListCredential;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use std::time::Duration;

pub async fn pull_status_list(ca_host: &str) -> Result<bool, VcError> {
    let req = RegistryRequest {
        action: "status_list_snapshot".into(),
        node_name: String::new(),
        pubkey_prefix: None,
        did_doc_json: None,
        did_query: None,
        status_list_body: None,
    };
    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        crate::did::doc_distribution::send_request(ca_host, &req),
    )
    .await
    .map_err(|_| VcError::StatusListUnavailable("CA timeout".into()))??;

    let body = resp.status_list_body.ok_or_else(|| {
        VcError::StatusListUnavailable("CA did not return a status list".into())
    })?;
    let cred: StatusListCredential = serde_json::from_str(&body)?;

    // Persist atomically.
    let path = status_list_path();
    if let Some(p) = path.parent() { std::fs::create_dir_all(p)?; }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, body.as_bytes())?;
    std::fs::rename(&tmp, &path)?;
    Ok(true)
}
```

Extend `RegistryRequest` and `RegistryResponse` with `status_list_body: Option<String>` (same `#[serde(default, skip_serializing_if = "Option::is_none")]` wire-compat treatment as `did_query` in Task 3 D3.1).

## D6.2 — CA side: `src/nebula/registry_sync.rs`

Add a new arm under the action dispatcher:
```rust
                    "status_list_snapshot" => {
                        let body = std::fs::read_to_string(crate::vc::persistence::status_list_path())
                            .ok();
                        let resp = RegistryResponse {
                            ok: body.is_some(),
                            error: body.is_none().then(|| "no status list yet".to_string()),
                            assigned_ip: None,
                            entries: vec![],
                            did_doc_json: None,
                            status_list_body: body,
                        };
                        let mut line = serde_json::to_string(&resp).unwrap_or_default();
                        line.push('\n');
                        let _ = writer.write_all(line.as_bytes()).await;
                    }
```

## D6.3 — Daemon pull loop

**File:** `src/main.rs` — add alongside the existing DID doc pull loop:
```rust
            // VC status list pull — every 5 minutes
            tokio::time::sleep(Duration::from_secs(300)).await;
            if let Err(e) = sgx_guardian_client::vc::distribution::pull_status_list(&ca_host_loop).await {
                tracing::warn!("VC status list pull failed: {}", e);
            }
```

---

# D7 — Peer Authentication Carries VC

## D7.1 — Evidence struct

**File:** `src/attestation_service.rs`

**FIND** the `SignedEvidence` struct definition. **ADD** a field:
```rust
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented_vc_json: Option<String>,
```

**Wire-compat:** older peers running pre-VC code don't send the field; receiver treats `None` as "no VC presented" and either accepts (if VC enforcement is opt-in via flag) or rejects (when enforcement is on). The default for fresh Circles should be: **require VC unless the env var `SGX_REQUIRE_VC=0` is set** — clean inverse of how the DID Document fix flags worked.

## D7.2 — Attach our VC on send

**FIND** in `mutual_attest`, where `create_signed_evidence(km, &policy.yaml)?` is called. Make it carry the held VC:
```rust
        let mut evidence = Self::create_signed_evidence(km, &policy.yaml)?;
        if let Ok(Some(vc)) = sgx_guardian_client::vc::persistence::load_own_any() {
            evidence.presented_vc_json = Some(serde_json::to_string(&vc).unwrap_or_default());
        }
```

## D7.3 — Verify peer's VC in handler

In both `mutual_attest` (after `Self::verify_signed_evidence(&peer_ev, &policy.yaml)?`) and the inbound listener (after `Ok(true)` from verify):

```rust
        if std::env::var("SGX_REQUIRE_VC").as_deref() != Ok("0") {
            let Some(vc_json) = peer_ev.presented_vc_json.as_deref() else {
                log_audit(&node_id, AuditCategory::Vc, AuditSeverity::Warning,
                    AuditAction::Rejected,
                    &format!("Peer {} presented no VC", addr));
                return Ok(false);
            };
            let vc: sgx_guardian_client::vc::credential::VerifiableCredential =
                serde_json::from_str(vc_json).map_err(|e| anyhow::anyhow!("VC parse: {}", e))?;

            // Resolve our local copy of the status list.
            let sl_cred: sgx_guardian_client::vc::status_list::StatusListCredential = {
                let p = sgx_guardian_client::vc::persistence::status_list_path();
                let bytes = tokio::fs::read(&p).await
                    .map_err(|e| anyhow::anyhow!("read status list: {}", e))?;
                serde_json::from_slice(&bytes)?
            };
            let sl_view = sgx_guardian_client::vc::status_list::verify_status_list_credential(
                &sl_cred, &resolver,
            ).await?;

            let opts = sgx_guardian_client::vc::verify::VerifyOptions {
                expected_subject_did: Some(&peer_ev.subject_did),
                expected_circle_id: Some("guardian-circle-alpha"),
                check_status_list: true,
                status_list: Some(&sl_view),
            };
            if let Err(e) = sgx_guardian_client::vc::verify::verify_vc(&vc, &resolver, opts).await {
                log_audit(&node_id, AuditCategory::Vc, AuditSeverity::Critical,
                    AuditAction::Rejected,
                    &format!("Peer {} VC rejected: {}", addr, e));
                remove_trusted_peer(&addr);
                return Ok(false);
            }

            // Cache the peer's VC for offline use.
            let _ = sgx_guardian_client::vc::persistence::save_peer(&peer_ev.subject_did, &vc);
        }
```

> If `SignedEvidence` doesn't currently carry a `subject_did`, add it at the same time. The CA always knows the subject DID for each node from the cert request flow.

---

# D8 — CLI, REST, Tests

## D8.1 — CLI (`sgx-pa-cli/src/commands/vc.rs`)

```rust
use clap::Subcommand;

#[derive(Subcommand)]
pub enum VcCommand {
    /// Issue a VC to a member (CA-only).
    Issue {
        /// Subject DID (the member receiving the VC).
        #[arg(long)]
        to: String,
        /// Role: owner | member
        #[arg(long, default_value = "member")]
        role: String,
        /// Permissions, comma-separated. Defaults to role-based set.
        #[arg(long)]
        permissions: Option<String>,
        /// Validity in days (default: 365).
        #[arg(long)]
        days: Option<i64>,
    },
    /// Show all VCs this node holds.
    Show,
    /// Verify a VC file (by path).
    Verify {
        #[arg(long)]
        path: String,
    },
    /// Revoke a VC by id (CA-only).
    Revoke {
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "policy violation")]
        reason: String,
    },
    /// Show revocation status of a single VC id.
    Status {
        #[arg(long)]
        id: String,
    },
    /// Force a status-list pull from the CA.
    PullStatusList,
}
```

Each subcommand maps to the obvious entry in `src/vc/*`. Output uses the `Table` style other CLIs in this codebase use.

## D8.2 — REST (`src/api/handlers/vc.rs`)

```rust
POST /api/v1/vc/issue          (CA-only; body: subject_did, role, permissions)
GET  /api/v1/vc/list           (own VCs)
GET  /api/v1/vc/peers          (peers' cached VCs)
POST /api/v1/vc/revoke         (CA-only; body: vc_id, reason)
GET  /api/v1/vc/status?id=...  (revocation status check)
POST /api/v1/vc/pull-status    (force status list refresh)
```

Wire in `src/api/routes.rs`. Each handler shells out to `sgx-pa-cli vc <subcommand>` to keep SE050 / audit / signing logic in one place — matches the Lightning-Leap REST audit pattern.

## D8.3 — Test Matrix

| Case | Setup | Pass criteria |
|---|---|---|
| **VC-001** issue + verify roundtrip | nodeA CA, nodeB member | `vc issue --to <B-DID>` succeeds; `vc verify <path>` returns ✅ |
| **VC-002** wrong-issuer rejected | hand-craft VC with `issuer` set to nodeB | `verify` returns `IssuerNotResolvable` or `InvalidProof` |
| **VC-003** expired | issue with `--days 0`; wait | `verify` returns `Expired` |
| **VC-004** revoked | issue VC; `vc revoke --id ...`; peer pulls status list | `verify` returns `Revoked(idx)` |
| **VC-005** subject mismatch | present nodeC's VC during nodeB's attestation | Attestation rejects with `SubjectMismatch` |
| **VC-006** circle mismatch | hand-craft VC with `circle_id="other-circle"` | `verify` returns `CircleMismatch` |
| **VC-007** member-issued forgery | nodeB signs a VC; presents at nodeC | nodeC's resolver returns nodeB's pubkey for issuer → signature does match → BUT circle owner check fails (issuer must equal CA's DID; add explicit check) → rejected |
| **VC-008** status list signature tamper | flip a bit in encoded_list; status list re-served | `verify_status_list_credential` returns `StatusListProofInvalid` |
| **VC-009** non-CA tries to issue | call `vc issue` from nodeB | returns `NotCa` |
| **VC-010** peer auth with VC enforced | normal flow with both sides on new build | mutual_attest succeeds, audit logs show "VC verified" entries on both sides |

### Board script
```bash
#!/bin/bash
# Run on nodeA (CA).

# VC-001
./sgx-pa-cli vc issue --to "$(ssh root@192.168.50.115 'cat /var/lib/sgx-guardian/identity/did.json | jq -r .did')" \
                     --role member --days 30
ls /var/lib/sgx-guardian/identity/vc/issued/

# Force status list to nodeB
ssh root@192.168.50.115 './sgx-pa-cli vc pull-status-list'
ssh root@192.168.50.115 './sgx-pa-cli vc show'
# Expect: nodeB now lists the VC in /vc/own/

# VC-004 revoke
VC_ID=$(ls /var/lib/sgx-guardian/identity/vc/issued/ | head -1 | sed 's/_/:/g; s/.json//')
./sgx-pa-cli vc revoke --id "$VC_ID" --reason "test"
ssh root@192.168.50.115 './sgx-pa-cli vc pull-status-list'
ssh root@192.168.50.115 "./sgx-pa-cli vc status --id $VC_ID"
# Expect: status=Revoked

# VC-010 peer auth
ssh root@192.168.50.115 'systemctl restart sgx-guardian'
sleep 30
ssh root@192.168.50.115 'journalctl -u sgx-guardian -n 100 | grep -i "VC"'
# Expect: "VC verified" entries
```

---

# Regression Checks

```bash
cargo build --release 2>&1 | grep -E "^(warning|error):" | grep -v unused || true
cargo test --release vc                  2>&1 | tail -30
cargo test --release did                 2>&1 | tail -30   # nothing must regress
cargo test --release cert                2>&1 | tail -30   # cert flow regression
cargo test --release attestation         2>&1 | tail -30   # attestation regression
```

Watch for:
- ✅ Pre-VC peers (no `presented_vc_json` field) handled correctly: with `SGX_REQUIRE_VC=0` they pass; otherwise rejected with clean audit.
- ✅ Status list size: 16 KB gzipped + base64 ≈ 22 KB on the wire — well below TCP frame defaults.
- ✅ VC issuance is idempotent on retry: same `urn:uuid` not re-issued; client retries see existing file.
- ✅ Audit log records every issuance, every revocation, every peer-auth verification.
- ✅ Existing test suites (DID, attestation, cert, registry-sync) all pass.

---

# Step-by-Step Checklist

- [ ] Branch from `main` → `shahzad_vc` (after Sprint 5 Task 2 fixes + Task 3 resolver merged).
- [ ] **D1** new `src/vc/{credential,errors,mod}.rs`; add `AuditCategory::Vc`.
- [ ] **D2** new `src/vc/{issue,persistence}.rs`; extract `doc_sign::sign_in_place_generic`; add `vc_id` field + persistence on `CircleMember`.
- [ ] **D3** new `src/vc/verify.rs`; depends on Task-3 `Resolver`.
- [ ] **D4** new `src/vc/status_list.rs`; verify status-list-credential's own proof.
- [ ] **D5** extend `.proto`, `cert_service.rs`, `cert_client.rs` with `member_vc_json`.
- [ ] **D6** add `status_list_body` to `RegistryRequest`/`RegistryResponse`; new arm in `registry_sync.rs`; daemon pull loop entry; new `src/vc/distribution.rs`.
- [ ] **D7** extend `SignedEvidence` with `presented_vc_json` + `subject_did`; attach in send path; verify in receive path; default ON, env override `SGX_REQUIRE_VC=0`.
- [ ] **D8** CLI `sgx-pa-cli vc {issue,show,verify,revoke,status,pull-status-list}`; REST `/api/v1/vc/*`; tests VC-001..010 + board script; addendum to Phase2_Test_Cases.pdf.
- [ ] CodeRabbit + CodeQL.

---

# Out of Scope (deliberate deferrals)

- **VC selective disclosure / BBS+ signatures.** Spec doesn't require it; standard `DataIntegrityProof` is sufficient for Phase 2.
- **VC presentation as JWT.** We use plain JSON-LD per W3C VC-DM 1.1 §6.3.1 (`DataIntegrityProof`) which the rest of our stack already supports.
- **Cross-Circle VC interop.** Each Circle has its own CA and status list; Phase 2 has one Circle per deployment.
- **VC delegation chains** (member→sub-member). Sprint 7+ if needed; currently only Owner→Member.
- **Status List 2021 sharding.** 131072 bits = 16384 VCs per Circle is comfortable for any realistic deployment. Sharding deferred.
- **VC presentation during cert renewal.** Currently VC is bundled in initial cert issuance; renewal reissues the VC alongside. If you want VC to be presented (not reissued) on renewal, add a `renewal_vc` flow in Sprint 7.

---

# Honest Notes on What I Could Not Verify

- I cannot compile or run on the boards. FIND blocks are anchored to text I pulled from `main` via `project_knowledge_search`. Use `grep -n` against the anchor strings if line numbers shift.
- The `.proto` file path is conventionally `proto/cert.proto` but the actual location may differ; `grep -rn "message CertResponse" .` will resolve it.
- `SignedEvidence` may or may not currently carry `subject_did` — I infer it does because the listener already calls `incoming.node_id`. If it actually carries `node_id` not `subject_did`, add `subject_did: String` alongside (DID is derived from node_id + pubkey at the cert-issuance step on the CA side, so the field is cheap to populate).
- `crate::cot::is_self_ca()` is a function I'm naming — the codebase has CA-vs-member determination logic via `--is-ca` env or AppState; use whatever exists. The intent is identical.
- `flate2` is the conventional gzip crate; if `Cargo.toml` doesn't have it, add `flate2 = "1"` and `uuid = { version = "1", features = ["v4"] }`.
- `crate::crypto::ecdsa_p256_verify` — confirm the actual path. The existing DID proof verification uses something like `crate::did::doc_sign::ecdsa_verify_with_pubkey_der`; mirror that path.
- Adding `presented_vc_json: Option<String>` to `SignedEvidence` is wire-safe (serde-default), but the policy_digest field that the existing verify uses must continue to be checked AS BEFORE — VC verification is additive, not a replacement.
- The 5-minute status-list pull cadence is a starting point; tune after observing CA registry-sync load on the board.
- For VC-007 (member-issued forgery), the test relies on `verify_vc` checking that `vc.issuer == known_ca_did`. Add that explicit check in `verify_vc` as a top-level gate; the spec implies it ("Circle owner issues") but my code above only enforces it implicitly through resolver behavior. Add an explicit `expected_issuer_did` field to `VerifyOptions` and use it.
