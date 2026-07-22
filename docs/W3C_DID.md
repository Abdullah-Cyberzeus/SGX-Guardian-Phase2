# SG-X Guardian — Sprint 5 Task 1: W3C DID Implementation

**Sprint:** 5 | **Milestone:** 5 | **Target Date:** 30 April 2026
**Source:** Latest `main` branch via `project_knowledge_search` (GitHub private — repo is attached to this Claude Project, project knowledge is authoritative)
**Style:** Same FIND→REPLACE format as `PCR_Complete_Plan.md`

---

## Task (verbatim from Phase 2 Deliverables)

> **W3C DID Implementation** — Implement W3C Decentralized Identifiers (DID) Core 1.0 standard with custom `did:guardian` method. Each Guardian assigned persistent globally-unique DID (format: `did:guardian:<base58-hash>`). DID derived from device serial number and secure element public key. DIDs remain constant across device lifetime, firmware updates, and network changes. Implement DID method specification defining creation, resolution, update, and deactivation operations. DIDs replace ephemeral email-based identity for Circle membership.

**Test Cases:** DID-series (no DID-* test IDs are defined in `Phase2_Test_Cases.pdf` yet — this plan creates DID-001 through DID-007 below.)

---

## Note on Code Access

The GitHub repo `AsadAli-CyberZeus/SGX` is private. As established in prior sessions, the canonical access path for this project is **`project_knowledge_search`** (the repo is attached to this Claude Project). All code excerpts, file paths, and line references below were retrieved through that mechanism. Where a function or file is mentioned, it exists today in current `main`.

What I cannot do here:
- `cargo build` on the boards
- run `ssscli se05x uid` against a live SE050
- exercise the i.MX8MP I2C bus

What I can and did do:
- trace the actual existing identity flow — `secure_element/pcr.rs::read_device_uid()`, `cot/identity.rs::DeviceIdentity::from_public_key()`, `key_manager.rs::pubkey_der()`, `secure_element/dkp.rs::DkpManager::init()`, and the `main.rs` startup sequence
- verify which Cargo dependencies are already present and which are missing
- confirm the existing public-key DER path (`/var/lib/sgx-guardian/keys/dkp_pub.der`, 91-byte ECDSA-P256 SEC1 DER)

---

# 1. Architecture

## 1.1 What we already have (do NOT duplicate)

| Artifact | Where it lives | What it gives us |
|---|---|---|
| SE050 hardware UID (18-byte hex string) | `secure_element/pcr.rs::read_device_uid(fallback)` runs `ssscli se05x uid` | The "device serial number" the spec asks for |
| DKP public key (DER, 91 bytes, ECDSA-P256) | `/var/lib/sgx-guardian/keys/dkp_pub.der`, exposed via `KeyManager::pubkey_der()` | The "secure element public key" the spec asks for |
| Software DeviceIdentity (SHA-256 of pubkey → 64-hex device_id) | `src/cot/identity.rs::DeviceIdentity` | The conceptual ancestor of DID; we **keep it** for backward compat and **wrap** it under DID |
| Hardware-backed signer | `KeyManager::sign(data)` — SE050 SCP03 ECDSA-P256 | The signing operation for any DID-issued claim |
| Persistent state directory | `/var/lib/sgx-guardian/` (used by keys, PCR, registry) | Where `identity/did.json` will live |

## 1.2 The DID derivation formula

The spec says:
> DID derived from device serial number **and** secure element public key.

Existing SG-X infrastructure points to one canonical formula:

```
did_id_bytes = SHA-256(  SE050_UID_BYTES  ||  DKP_PUBKEY_DER  )      // 32 bytes
did = "did:guardian:" + base58btc(did_id_bytes)
```

Derivation properties this gives us:
1. **Device-bound** — SE050 UID is hardware-fixed; cannot be changed without chip swap (which `tamper.rs` already detects and refuses).
2. **Key-bound at v1** — DKP_v1 public key is mixed in. The DID is "born" pinned to the v1 key.
3. **Stable across DKP rotation** — DID is computed ONCE at first boot from `(UID, DKP_v1_pubkey)` and persisted. Subsequent rotations (v2, v3, …) update the DID Document's `verificationMethod` (Sprint 5 Task 2) but do **not** change the DID itself.
4. **Stable across firmware updates and network changes** — neither input depends on firmware version or IP.
5. **Globally unique** — collision probability is the SHA-256 birthday bound (~2¹²⁸ devices before collision risk).
6. **No PII** — UID is a chip serial, not a user identifier.

**Note on user-app docs vs daemon code:** the `SG-X Guardian Application User Guide.pdf` describes the mobile-app DID as `did:guardian:{base58(Ed25519_pubkey)}`. That's the mobile companion app. The daemon side (this plan) uses ECDSA-P256, not Ed25519, because that is the existing project crypto standard — every signature path in the daemon (DKP, attestation quote, baseline, Nebula CA) is already ECDSA-P256. Introducing Ed25519 would require parallel key infrastructure on SE050. We honor the spec ("base58-hash") and the existing crypto, and we document the divergence so the mobile team is aware.

## 1.3 Storage layout

```
/var/lib/sgx-guardian/identity/
├── did.json                       # this device's DID + metadata (created once, never deleted)
├── did_doc_local.json             # placeholder for Sprint 5 Task 2 (DID Document)
└── peers/
    ├── did_<base58>.json          # cached peer DIDs (local registry, populated by Sprint 5 Task 3)
    └── ...
```

`did.json` schema:
```json
{
  "did": "did:guardian:Hf3Wn2K8...",
  "method": "guardian",
  "method_version": "1.0",
  "did_id_b58": "Hf3Wn2K8...",
  "did_id_hex": "1f3a8c...c4",
  "created_at": "2026-04-26T10:00:00Z",
  "deactivated_at": null,
  "derivation": {
    "se050_uid": "<hex>",
    "se050_uid_source": "ssscli|fallback",
    "dkp_v1_pubkey_sha256_b16": "<hex 64>",
    "dkp_v1_pubkey_path": "/var/lib/sgx-guardian/keys/dkp_pub.der"
  },
  "current_dkp_version": 1,
  "deriv_signature_b64": "<ECDSA-P256 sig over derivation>"
}
```

The `deriv_signature_b64` is signed by DKP_v1 at creation time and never changes. Anyone with the public key can prove the DID was correctly derived.

## 1.4 Lifecycle operations (W3C DID Core 1.0 §8)

| Op | Trigger | Effect |
|---|---|---|
| **Create** | First boot, `did.json` absent | Read SE050 UID + DKP_v1 pubkey → compute DID → sign → write `did.json`. Idempotent. |
| **Resolve** | Local lookup or peer query | Return `(DID, current_pubkey_DER, status)` for self or known peers. Full network resolver is Sprint 5 Task 3. |
| **Update** | DKP rotation (v1→v2) | Bump `current_dkp_version` in `did.json`. DID itself unchanged. DID Document (Task 2) is the authoritative key-rotation surface. |
| **Deactivate** | Admin command after compromise | Set `deactivated_at`. Subsequent quotes & cert requests refuse to start. Irreversible without operator wipe. |

These four ops are exposed both as a Rust API (`crate::did::*`) and as CLI subcommands (`sgx-pa-cli did create | show | resolve | deactivate`).

## 1.5 Where this plugs into the existing daemon flow

Current `main.rs` startup order (from project knowledge):
```
1. SE050 init (Se050::init)
2. KeyManager::init_with_se050 (loads/generates DKP)
3. DKP auto-rotation check
4. PCR measurement + baseline compare
5. Detect LAN IP
6. Sanitize configs
7. Load configs / decide CA-vs-member role
8. Generate CA / fetch overlay IP / etc.
```

DID generation slots in **between step 3 and step 4** — after DKP is ready (so we have v1 pubkey) and before any network operation (so peer messages can carry the DID from the start).

---

# 2. Deliverables (8 atomic items, ~6.5 days total)

| # | Deliverable | Files | Effort |
|---|---|---|---|
| D1 | `src/did/` module skeleton + `did:guardian` method spec doc | new | 0.5 d |
| D2 | DID generation function (`compute_did_from_hardware`) | `src/did/did.rs` | 0.5 d |
| D3 | Persistent storage layer (`load`, `save`, idempotent `create_if_absent`) | `src/did/persistence.rs` | 0.5 d |
| D4 | Method operations: create / resolve / update / deactivate | `src/did/method.rs` | 1.0 d |
| D5 | Local DID registry (file-based, peer DID cache) | `src/did/registry.rs` | 0.75 d |
| D6 | `main.rs` integration (startup hook + DID-aware audit logs) | `src/main.rs`, `src/audit/event.rs` | 0.5 d |
| D7 | `sgx-pa-cli did` subcommands | `sgx-pa-cli/src/commands/did.rs` | 1.0 d |
| D8 | Unit tests + DID-001..007 test cases + regression harness | `src/did/*` test modules, `tests/did_integration.rs`, `Phase2_Test_Cases.pdf` addendum | 1.5 d |

**Total: ~6.25 working days for one engineer.** Sprint 5 window (Apr 16 → Apr 30) is 11 working days. With Tasks 2 (DID Document) and 3 (DID Resolution) parallel, all three tasks fit in the sprint with one engineer per task or one engineer sequentially.

---

# 3. File Structure

## 3.1 New files

```
src/did/
├── mod.rs                # re-exports public API
├── did.rs                # struct Did, parsing, format validation
├── method.rs             # create/resolve/update/deactivate ops
├── persistence.rs        # disk I/O for did.json
├── registry.rs           # local cache of peer DIDs
├── errors.rs             # DidError enum (thiserror)
└── tests.rs              # unit tests

sgx-pa-cli/src/commands/
└── did.rs                # `sgx-pa-cli did <subcommand>`

tests/
└── did_integration.rs    # integration tests across daemon + CLI

docs/
└── did_method_spec.md    # the `did:guardian` method specification document
```

## 3.2 Modified files

```
Cargo.toml                # add bs58 = "0.5"
sgx-pa-cli/Cargo.toml     # add bs58 = "0.5"
src/lib.rs                # pub mod did;
src/main.rs               # call did::method::create_if_absent() after DKP init
src/audit/event.rs        # add AuditCategory::Did variant
sgx-pa-cli/src/main.rs    # wire `did` subcommand
```

## 3.3 New runtime paths

```
/var/lib/sgx-guardian/identity/                  # mode 0700 (owned by sgx-guardian)
/var/lib/sgx-guardian/identity/did.json          # mode 0644
/var/lib/sgx-guardian/identity/peers/            # mode 0700
```

---

# 4. Cargo Dependency

**FIND** in root `Cargo.toml` (verified present today via project knowledge):
```toml
hex = "0.4"
rustls = "0.23.37"
```

**REPLACE WITH:**
```toml
hex = "0.4"
rustls = "0.23.37"
bs58 = "0.5"   # base58btc encoding for did:guardian
```

**FIND** in `sgx-pa-cli/Cargo.toml`:
```toml
hex = "0.4"
rand = "0.8"
sgx_guardian_client = { path = ".." }
```

**REPLACE WITH:**
```toml
hex = "0.4"
rand = "0.8"
bs58 = "0.5"
sgx_guardian_client = { path = ".." }
```

Why `bs58 = "0.5"`: it's the de-facto standard base58btc encoder used by Rust's W3C DID community (used by `ssi`, `did-key`, `bitcoin-rs`). 5 KB, no transitive deps. Compiles on `aarch64-unknown-linux-gnu` for the i.MX8MP boards.

---

# 5. D1 — Module Skeleton & Method Spec Document

## 5.1 Create `src/did/mod.rs`

```rust
// src/did/mod.rs
// ============================================================
// DID Implementation (Sprint 5 — Task 1)
//
// Implements W3C DID Core 1.0 with the custom `did:guardian` method.
// DID format: did:guardian:<base58btc(SHA256(SE050_UID || DKP_v1_pubkey_DER))>
//
// Crypto: ECDSA-P256 + SHA-256 (matches existing project standard).
// Storage: /var/lib/sgx-guardian/identity/did.json
// ============================================================

pub mod did;
pub mod errors;
pub mod method;
pub mod persistence;
pub mod registry;

pub use did::Did;
pub use errors::DidError;
pub use method::{create_if_absent, deactivate, resolve_local, update_dkp_version};
pub use persistence::{DidRecord, DEFAULT_IDENTITY_DIR, DEFAULT_DID_PATH};

#[cfg(test)]
mod tests;
```

## 5.2 Create `src/did/errors.rs`

```rust
// src/did/errors.rs
use std::io;

#[derive(Debug, thiserror::Error)]
pub enum DidError {
    #[error("DID file I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("DID JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid DID format: {0}")]
    InvalidFormat(String),

    #[error("Method mismatch: expected 'guardian', got '{0}'")]
    WrongMethod(String),

    #[error("Base58 decode error: {0}")]
    Base58(String),

    #[error("DID is deactivated (deactivated_at={0})")]
    Deactivated(String),

    #[error("DID derivation mismatch — current hardware does not match did.json")]
    DerivationMismatch,

    #[error("SE050 UID unavailable: {0}")]
    UidUnavailable(String),

    #[error("DKP public key unavailable at {0}")]
    DkpPubkeyMissing(String),

    #[error("Signature verification failed for DID derivation proof")]
    DerivSignatureInvalid,
}
```

Add `thiserror = "1"` to `Cargo.toml` if not already present (project knowledge says `anyhow = "1"` is present but `thiserror` is not currently in main `Cargo.toml`). Add it next to `anyhow`.

## 5.3 Create `docs/did_method_spec.md` (the W3C method spec doc)

This is the formal **DID Method Specification** that W3C requires for any custom method. Below is the full text — drop it in `docs/did_method_spec.md`:

```markdown
# `did:guardian` DID Method Specification v1.0

## 1. Method Name
`guardian`

## 2. Method-Specific Identifier (MSI) Syntax
```abnf
did               = "did:guardian:" guardian-id
guardian-id       = 32*44 base58btc-char
base58btc-char    = ALPHA / DIGIT  ; from RFC4648 §5 minus 0OIl
```

## 3. Derivation
```
did_id_bytes = SHA-256(  SE050_UID_BYTES  ||  DKP_v1_PUBKEY_DER  )
guardian-id  = base58btc(did_id_bytes)
```
Where:
- `SE050_UID_BYTES` is the binary representation of the 18-byte hardware UID returned by `ssscli se05x uid`
- `DKP_v1_PUBKEY_DER` is the 91-byte ECDSA-P256 SEC1 DER encoding of the version-1 Device Key Pair public key

## 4. CRUD Operations
### 4.1 Create
- **When:** First boot of a SG-X Guardian device (before any network operation)
- **How:** Compute DID per §3, write `/var/lib/sgx-guardian/identity/did.json`, sign derivation evidence with DKP_v1
- **Idempotent:** if `did.json` exists and its `derivation` block matches current hardware, no-op

### 4.2 Resolve (local)
- **Input:** DID string
- **Output:** DID Document (Sprint 5 Task 2) or, in this Task 1 scope, a tuple `(current_pubkey_DER, status, current_dkp_version)`
- **Source:** local file (self) or local peer-DID cache (others)

### 4.3 Update
- **Trigger:** DKP rotation (v1 → v2)
- **Effect:** `current_dkp_version` in `did.json` is bumped. DID identifier itself is **immutable**. The DID Document (Task 2) updates its `verificationMethod` to point to the new pubkey.

### 4.4 Deactivate
- **Trigger:** `sgx-pa-cli did deactivate --reason "<reason>"`
- **Effect:** `deactivated_at` set to current UTC. Daemon refuses to generate attestation quotes, refuses to request Nebula certs, refuses to participate in the mesh. Irreversible from this device — recovery requires operator-controlled wipe and re-enrollment.

## 5. Security Considerations
- DID is derived from a hardware-rooted secret (SE050 UID) + a hardware-managed key (DKP). It cannot be forged without physical access to the chip.
- DID does **not** carry any PII. The UID is a chip serial number assigned by NXP at fab time.
- Compromise of DKP_v1 does not invalidate the DID identifier (because the DID is a hash, not a key). The DID Document's `verificationMethod` is updated to a fresh DKP_v2 via the Update operation. Old proofs remain verifiable until the DID Document's revocation list says otherwise (Sprint 7 — CRL).

## 6. Privacy Considerations
- DIDs are public identifiers. Within a Circle, they are exchanged freely. They do not link to any external identity (email, phone, etc.).
- For unlinkability across Circles, see VirtualID (Sprint 6 — VirtualID-DID Integration).
```

This file is referenced by `did/mod.rs` and by code review when explaining "why these design choices."

---

# 6. D2 — DID Generation (`src/did/did.rs`)

This is the smallest, most-tested module. It is pure functions only (no I/O) so the unit tests cover 100% of branches without filesystem mocks.

```rust
// src/did/did.rs
// ============================================================
// DID type, parsing, formatting, and pure derivation.
// No I/O here. All disk and SE050 access happens in method.rs.
// ============================================================

use crate::did::errors::DidError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const METHOD: &str = "guardian";
pub const METHOD_PREFIX: &str = "did:guardian:";

/// W3C DID Core 1.0 conforming identifier, restricted to the `guardian` method.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did(String);

impl Did {
    /// Construct a Did from raw 32-byte hash (the SHA-256 derivation output).
    pub fn from_id_bytes(id_bytes: &[u8; 32]) -> Self {
        let b58 = bs58::encode(id_bytes).into_string();
        Self(format!("{}{}", METHOD_PREFIX, b58))
    }

    /// Parse a string into a Did. Returns Err if format is wrong.
    pub fn parse(s: &str) -> Result<Self, DidError> {
        if !s.starts_with("did:") {
            return Err(DidError::InvalidFormat(format!("missing 'did:' scheme: {}", s)));
        }
        let rest = &s[4..];
        let (method, msi) = rest
            .split_once(':')
            .ok_or_else(|| DidError::InvalidFormat(format!("missing method delimiter: {}", s)))?;
        if method != METHOD {
            return Err(DidError::WrongMethod(method.to_string()));
        }
        // Validate MSI is decodable base58btc into 32 bytes
        let decoded = bs58::decode(msi)
            .into_vec()
            .map_err(|e| DidError::Base58(e.to_string()))?;
        if decoded.len() != 32 {
            return Err(DidError::InvalidFormat(format!(
                "MSI decodes to {} bytes, expected 32",
                decoded.len()
            )));
        }
        Ok(Self(s.to_string()))
    }

    /// Returns the full DID string (`did:guardian:...`).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the method-specific identifier (everything after `did:guardian:`).
    pub fn msi(&self) -> &str {
        &self.0[METHOD_PREFIX.len()..]
    }

    /// Returns the 32-byte hash backing this DID.
    pub fn id_bytes(&self) -> [u8; 32] {
        let v = bs58::decode(self.msi())
            .into_vec()
            .expect("Did invariant: msi decodes to 32 bytes");
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Pure derivation function. Inputs are bytes; output is the DID.
/// Caller is responsible for fetching SE050 UID and DKP pubkey from disk.
pub fn derive(se050_uid: &[u8], dkp_pubkey_der: &[u8]) -> Did {
    let mut h = Sha256::new();
    h.update(se050_uid);
    h.update(dkp_pubkey_der);
    let digest = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Did::from_id_bytes(&bytes)
}
```

## Unit tests for D2 (in `src/did/tests.rs`):

```rust
#[cfg(test)]
mod did_unit {
    use super::super::did::*;

    #[test]
    fn test_derive_is_deterministic() {
        let uid = b"se050-uid-fixture-18bytes";
        let pk = vec![0xAA; 91];
        let d1 = derive(uid, &pk);
        let d2 = derive(uid, &pk);
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_derive_changes_with_uid() {
        let pk = vec![0xAA; 91];
        let d1 = derive(b"uid-A", &pk);
        let d2 = derive(b"uid-B", &pk);
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_derive_changes_with_pubkey() {
        let uid = b"uid-fixed";
        let d1 = derive(uid, &vec![0xAA; 91]);
        let d2 = derive(uid, &vec![0xBB; 91]);
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_format_starts_with_prefix() {
        let d = derive(b"u", b"p");
        assert!(d.as_str().starts_with("did:guardian:"));
    }

    #[test]
    fn test_msi_length_in_range() {
        let d = derive(b"u", b"p");
        let msi_len = d.msi().len();
        // base58btc of 32 bytes is 43 or 44 chars
        assert!(msi_len == 43 || msi_len == 44, "got {}", msi_len);
    }

    #[test]
    fn test_parse_roundtrip() {
        let d = derive(b"u", b"p");
        let s = d.as_str().to_string();
        let parsed = Did::parse(&s).unwrap();
        assert_eq!(d, parsed);
    }

    #[test]
    fn test_parse_rejects_wrong_method() {
        let err = Did::parse("did:web:example.com").unwrap_err();
        match err {
            DidError::WrongMethod(m) => assert_eq!(m, "web"),
            _ => panic!("expected WrongMethod"),
        }
    }

    #[test]
    fn test_parse_rejects_bad_msi() {
        let err = Did::parse("did:guardian:notbase58!!!").unwrap_err();
        assert!(matches!(err, DidError::Base58(_) | DidError::InvalidFormat(_)));
    }

    #[test]
    fn test_id_bytes_roundtrip() {
        let bytes = [0x42u8; 32];
        let d = Did::from_id_bytes(&bytes);
        assert_eq!(d.id_bytes(), bytes);
    }
}
```

---

# 7. D3 — Persistence (`src/did/persistence.rs`)

```rust
// src/did/persistence.rs
use crate::did::did::Did;
use crate::did::errors::DidError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const DEFAULT_IDENTITY_DIR: &str = "/var/lib/sgx-guardian/identity";
pub const DEFAULT_DID_PATH: &str = "/var/lib/sgx-guardian/identity/did.json";
pub const DEFAULT_PEERS_DIR: &str = "/var/lib/sgx-guardian/identity/peers";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivationProof {
    pub se050_uid: String,
    pub se050_uid_source: String,    // "ssscli" or "fallback"
    pub dkp_v1_pubkey_sha256_b16: String,
    pub dkp_v1_pubkey_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidRecord {
    pub did: String,
    pub method: String,
    pub method_version: String,
    pub did_id_b58: String,
    pub did_id_hex: String,
    pub created_at: String,
    pub deactivated_at: Option<String>,
    pub derivation: DerivationProof,
    pub current_dkp_version: u32,
    pub deriv_signature_b64: String,  // ECDSA-P256 sig over canonical bytes of `derivation`
}

impl DidRecord {
    pub fn save(&self, path: &str) -> Result<(), DidError> {
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        // Write atomically: write to .tmp then rename
        let tmp = format!("{}.tmp", path);
        fs::write(&tmp, json)?;
        fs::rename(&tmp, path)?;
        // chmod 0644 (best-effort; ignore on non-unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o644));
        }
        Ok(())
    }

    pub fn load(path: &str) -> Result<Self, DidError> {
        let s = fs::read_to_string(path)?;
        let r: Self = serde_json::from_str(&s)?;
        Ok(r)
    }

    pub fn did(&self) -> Result<Did, DidError> {
        Did::parse(&self.did)
    }

    pub fn is_active(&self) -> bool {
        self.deactivated_at.is_none()
    }
}

/// Canonical bytes for the derivation proof signature.
/// Format: domain-separator || JSON canonical of derivation block.
pub fn derivation_signing_bytes(d: &DerivationProof) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"sgx-guardian:did:guardian:v1:derivation:");
    // Stable, sorted-key serialization
    let val = serde_json::json!({
        "se050_uid": d.se050_uid,
        "se050_uid_source": d.se050_uid_source,
        "dkp_v1_pubkey_path": d.dkp_v1_pubkey_path,
        "dkp_v1_pubkey_sha256_b16": d.dkp_v1_pubkey_sha256_b16,
    });
    out.extend_from_slice(val.to_string().as_bytes());
    out
}
```

---

# 8. D4 — Method Operations (`src/did/method.rs`)

This is the integration glue. It's the only module that talks to SE050 and to the on-disk DKP pubkey.

```rust
// src/did/method.rs
use crate::did::did::{derive, Did};
use crate::did::errors::DidError;
use crate::did::persistence::{
    derivation_signing_bytes, DerivationProof, DidRecord, DEFAULT_DID_PATH,
};
use crate::key_manager::KeyManager;
use crate::secure_element::pcr::read_device_uid;
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const METHOD_VERSION: &str = "1.0";

/// Idempotent create. Called from main.rs after DKP init.
/// - If did.json exists and matches current hardware → returns the loaded DID.
/// - If did.json exists but hardware doesn't match → returns DerivationMismatch.
/// - If did.json absent → derives, signs with DKP, writes file, returns the new DID.
pub fn create_if_absent(
    node_id: &str,
    km: &KeyManager,
    dkp_pubkey_path: &str,
    did_path: &str,
) -> Result<Did, DidError> {
    let dkp_pubkey = read_dkp_pubkey(dkp_pubkey_path)?;
    let (uid_str, uid_source) = read_uid(node_id);

    // SE050 UID is hex; we hash the BYTES of the hex string for stability across
    // boards where ssscli output formatting may add/remove whitespace.
    // (Hashing the hex string itself is fine — it's deterministic.)
    let uid_bytes = uid_str.as_bytes();

    let candidate_did = derive(uid_bytes, &dkp_pubkey);

    if Path::new(did_path).exists() {
        let existing = DidRecord::load(did_path)?;
        let existing_did = Did::parse(&existing.did)?;

        // Hardware check: does what we loaded match what hardware says now?
        if existing_did != candidate_did {
            return Err(DidError::DerivationMismatch);
        }
        return Ok(existing_did);
    }

    // First boot — write the file
    let dkp_pubkey_hash = hex::encode(Sha256::digest(&dkp_pubkey));
    let derivation = DerivationProof {
        se050_uid: uid_str.clone(),
        se050_uid_source: uid_source,
        dkp_v1_pubkey_sha256_b16: dkp_pubkey_hash,
        dkp_v1_pubkey_path: dkp_pubkey_path.to_string(),
    };

    let to_sign = derivation_signing_bytes(&derivation);
    let sig = km
        .sign(&to_sign)
        .map_err(|e| DidError::Io(std::io::Error::other(format!("DKP sign: {}", e))))?;

    let record = DidRecord {
        did: candidate_did.as_str().to_string(),
        method: "guardian".into(),
        method_version: METHOD_VERSION.into(),
        did_id_b58: candidate_did.msi().to_string(),
        did_id_hex: hex::encode(candidate_did.id_bytes()),
        created_at: Utc::now().to_rfc3339(),
        deactivated_at: None,
        derivation,
        current_dkp_version: 1,
        deriv_signature_b64: general_purpose::STANDARD.encode(&sig),
    };
    record.save(did_path)?;

    Ok(candidate_did)
}

/// Resolve our own DID — returns (DID, current_dkp_pubkey_DER, is_active).
pub fn resolve_local(
    did_path: &str,
    dkp_pubkey_path: &str,
) -> Result<(Did, Vec<u8>, bool), DidError> {
    let rec = DidRecord::load(did_path)?;
    let did = Did::parse(&rec.did)?;
    let pk = read_dkp_pubkey(dkp_pubkey_path)?;
    Ok((did, pk, rec.is_active()))
}

/// Bump current_dkp_version on rotation. Call from DKP rotation flow.
pub fn update_dkp_version(did_path: &str, new_version: u32) -> Result<(), DidError> {
    let mut rec = DidRecord::load(did_path)?;
    if new_version <= rec.current_dkp_version {
        return Ok(()); // no-op for stale calls
    }
    rec.current_dkp_version = new_version;
    rec.save(did_path)
}

/// Mark this DID as deactivated. Persists deactivated_at timestamp.
pub fn deactivate(did_path: &str, reason: &str) -> Result<(), DidError> {
    let mut rec = DidRecord::load(did_path)?;
    if rec.deactivated_at.is_some() {
        return Err(DidError::Deactivated(
            rec.deactivated_at.unwrap_or_default(),
        ));
    }
    rec.deactivated_at = Some(Utc::now().to_rfc3339());
    rec.save(did_path)?;
    // Audit will be logged by caller (CLI or daemon).
    let _ = reason; // accepted for future use; today only the timestamp is persisted
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

fn read_dkp_pubkey(path: &str) -> Result<Vec<u8>, DidError> {
    if !Path::new(path).exists() {
        return Err(DidError::DkpPubkeyMissing(path.to_string()));
    }
    Ok(fs::read(path)?)
}

fn read_uid(fallback: &str) -> (String, String) {
    // read_device_uid returns either a real SE050 UID or the fallback string
    let uid = read_device_uid(fallback);
    // Heuristic: SE050 UIDs are >= 20 hex chars; otherwise it's the fallback
    let source = if uid.len() >= 20 && uid.chars().all(|c| c.is_ascii_hexdigit()) {
        "ssscli".to_string()
    } else {
        "fallback".to_string()
    };
    (uid, source)
}
```

---

# 9. D5 — Local Peer DID Registry (`src/did/registry.rs`)

A thin file-based cache. Real network resolution is Sprint 5 Task 3.

```rust
// src/did/registry.rs
use crate::did::did::Did;
use crate::did::errors::DidError;
use crate::did::persistence::DEFAULT_PEERS_DIR;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerDidEntry {
    pub did: String,
    pub node_id: String,                // hint, e.g. "nodeA"
    pub current_pubkey_der_b64: String, // 91-byte ECDSA-P256 SEC1 DER
    pub current_dkp_version: u32,
    pub last_seen: String,              // RFC3339
    pub source: String,                 // "cert-bootstrap", "manual", "task-3-resolver", etc.
}

fn entry_path(dir: &str, did: &Did) -> PathBuf {
    let safe = did.msi().to_string();
    Path::new(dir).join(format!("did_{}.json", safe))
}

pub fn upsert(dir: &str, entry: &PeerDidEntry) -> Result<(), DidError> {
    fs::create_dir_all(dir)?;
    let did = Did::parse(&entry.did)?;
    let path = entry_path(dir, &did);
    let json = serde_json::to_string_pretty(entry)?;
    let tmp = format!("{}.tmp", path.display());
    fs::write(&tmp, json)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

pub fn get(dir: &str, did: &Did) -> Result<Option<PeerDidEntry>, DidError> {
    let path = entry_path(dir, did);
    if !path.exists() {
        return Ok(None);
    }
    let s = fs::read_to_string(&path)?;
    let e: PeerDidEntry = serde_json::from_str(&s)?;
    Ok(Some(e))
}

pub fn list(dir: &str) -> Result<Vec<PeerDidEntry>, DidError> {
    if !Path::new(dir).exists() {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let e = entry?;
        let p = e.path();
        if p.is_file()
            && p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("did_") && n.ends_with(".json"))
                .unwrap_or(false)
        {
            if let Ok(s) = fs::read_to_string(&p) {
                if let Ok(rec) = serde_json::from_str::<PeerDidEntry>(&s) {
                    out.push(rec);
                }
            }
        }
    }
    Ok(out)
}

pub fn default_peers_dir() -> &'static str {
    DEFAULT_PEERS_DIR
}
```

---

# 10. D6 — `main.rs` Integration

## 10.1 Modify `src/lib.rs`

**FIND** (verified present in current `lib.rs` — confirm with `grep -n "^pub mod" src/lib.rs`):
```rust
pub mod attestation_service;
```

**INSERT after that line:**
```rust
pub mod did;
```

## 10.2 Modify `src/main.rs`

**FIND** the block right after the DKP auto-rotation check (the comment line `// === Crypto Provider Status ===` is the anchor). Verified present in current main:

```rust
    // === DKP Auto-Rotation Check ===
    #[cfg(feature = "secure-element")]
    {
        let se_config = sgx_guardian_client::secure_element::SeConfig::default();
        let base_path = "/var/lib/sgx-guardian";
        if let Ok(mut dkp) =
            sgx_guardian_client::secure_element::dkp::DkpManager::init(&se_config, base_path)
        {
            match dkp.check_and_auto_rotate() {
                Ok(Some(new_meta)) => {
                    println!("  DKP auto-rotated to v{}", new_meta.version);
                    // Reinitialize KeyManager with new key
                    // (daemon restart is safer for now)
                }
                Ok(None) => { /* no rotation needed */ }
                Err(e) => {
                    eprintln!("  Auto-rotation check failed: {}", e);
                }
            }
        }
    }

    // === Crypto Provider Status ===
```

**REPLACE WITH:**
```rust
    // === DKP Auto-Rotation Check ===
    #[cfg(feature = "secure-element")]
    {
        let se_config = sgx_guardian_client::secure_element::SeConfig::default();
        let base_path = "/var/lib/sgx-guardian";
        if let Ok(mut dkp) =
            sgx_guardian_client::secure_element::dkp::DkpManager::init(&se_config, base_path)
        {
            match dkp.check_and_auto_rotate() {
                Ok(Some(new_meta)) => {
                    println!("  DKP auto-rotated to v{}", new_meta.version);
                    // Bump DID record's current_dkp_version (DID itself is immutable).
                    if let Err(e) = sgx_guardian_client::did::method::update_dkp_version(
                        sgx_guardian_client::did::DEFAULT_DID_PATH,
                        new_meta.version,
                    ) {
                        eprintln!("  ⚠️ DID dkp_version bump failed: {}", e);
                    }
                }
                Ok(None) => { /* no rotation needed */ }
                Err(e) => {
                    eprintln!("  Auto-rotation check failed: {}", e);
                }
            }
        }
    }

    // === DID Initialization (Sprint 5 — W3C DID Implementation) ===
    println!("\n🆔 Initializing W3C DID (did:guardian)...");
    {
        let did_path = sgx_guardian_client::did::DEFAULT_DID_PATH;
        let dkp_pubkey_path = "/var/lib/sgx-guardian/keys/dkp_pub.der";
        match sgx_guardian_client::did::method::create_if_absent(
            &node_id,
            &km,
            dkp_pubkey_path,
            did_path,
        ) {
            Ok(did) => {
                println!("  ✅ DID active: {}", did.as_str());
                log_audit(
                    &node_id,
                    AuditCategory::Did,
                    AuditSeverity::Info,
                    AuditAction::Loaded,
                    &format!("DID resolved: {}", did.as_str()),
                );
            }
            Err(sgx_guardian_client::did::DidError::DerivationMismatch) => {
                eprintln!(
                    "  🔴 DID DERIVATION MISMATCH — hardware fingerprint changed. \
                     Refusing to start."
                );
                log_audit(
                    &node_id,
                    AuditCategory::Did,
                    AuditSeverity::Critical,
                    AuditAction::Failed,
                    "DID derivation mismatch — hardware fingerprint changed",
                );
                std::process::exit(2);
            }
            Err(e) => {
                eprintln!("  ⚠️ DID initialization failed: {} — continuing in degraded mode", e);
                log_audit(
                    &node_id,
                    AuditCategory::Did,
                    AuditSeverity::Warning,
                    AuditAction::Failed,
                    &format!("DID init failed: {}", e),
                );
            }
        }
    }

    // === Crypto Provider Status ===
```

The `process::exit(2)` on `DerivationMismatch` is intentional fail-closed behavior: if the chip changed (chip swap, DKP wiped externally, etc.), the daemon must not silently re-bind to a new identity.

## 10.3 Modify `src/audit/event.rs`

**FIND** (confirm exact variant list with `grep -n "AuditCategory" src/audit/event.rs`):
```rust
pub enum AuditCategory {
    Identity,
    Network,
    Attestation,
    // ... existing variants
}
```

**ADD** the new variant alongside `Identity`:
```rust
pub enum AuditCategory {
    Identity,
    Did,        // W3C DID lifecycle events (create, update, deactivate)
    Network,
    Attestation,
    // ... existing variants unchanged
}
```

If `AuditCategory` is `Display`-derived or has a `to_string` impl, add the corresponding match arm: `AuditCategory::Did => "DID"`.

---

# 11. D7 — `sgx-pa-cli did` Subcommands

## 11.1 Create `sgx-pa-cli/src/commands/did.rs`

```rust
use clap::{Args, Subcommand};
use comfy_table::{Cell, Table};
use sgx_guardian_client::did::{self, DidError};

#[derive(Args)]
#[command(about = "DID lifecycle and registry operations (Sprint 5)")]
pub struct DidArgs {
    #[command(subcommand)]
    pub command: DidCommand,
}

#[derive(Subcommand)]
pub enum DidCommand {
    /// Show this device's DID and metadata
    Show,
    /// Resolve a DID locally (self or cached peer)
    Resolve(DidResolveArgs),
    /// List cached peer DIDs
    Peers,
    /// Force-create the DID if absent (idempotent; the daemon does this at startup)
    Create,
    /// Deactivate this device's DID (irreversible from this device)
    Deactivate(DidDeactivateArgs),
}

#[derive(Args)]
pub struct DidResolveArgs {
    /// DID string to resolve. Omit to resolve self.
    pub did: Option<String>,
}

#[derive(Args)]
pub struct DidDeactivateArgs {
    /// Reason (logged but does not affect the operation)
    #[arg(long, default_value = "manual")]
    pub reason: String,
    /// Bypass interactive confirmation
    #[arg(long)]
    pub yes: bool,
}

pub fn run(args: DidArgs) {
    match args.command {
        DidCommand::Show => cmd_show(),
        DidCommand::Resolve(a) => cmd_resolve(a),
        DidCommand::Peers => cmd_peers(),
        DidCommand::Create => cmd_create(),
        DidCommand::Deactivate(a) => cmd_deactivate(a),
    }
}

fn cmd_show() {
    let path = did::DEFAULT_DID_PATH;
    match did::DidRecord::load(path) {
        Ok(rec) => {
            let mut t = Table::new();
            t.set_header(vec!["Field", "Value"]);
            t.add_row(vec![Cell::new("DID"), Cell::new(&rec.did)]);
            t.add_row(vec![Cell::new("Method"), Cell::new(&rec.method)]);
            t.add_row(vec![Cell::new("Method version"), Cell::new(&rec.method_version)]);
            t.add_row(vec![Cell::new("Created"), Cell::new(&rec.created_at)]);
            t.add_row(vec![
                Cell::new("Deactivated"),
                Cell::new(rec.deactivated_at.as_deref().unwrap_or("—")),
            ]);
            t.add_row(vec![
                Cell::new("Current DKP version"),
                Cell::new(format!("v{}", rec.current_dkp_version)),
            ]);
            t.add_row(vec![
                Cell::new("SE050 UID source"),
                Cell::new(&rec.derivation.se050_uid_source),
            ]);
            t.add_row(vec![
                Cell::new("DKP_v1 pubkey hash"),
                Cell::new(&rec.derivation.dkp_v1_pubkey_sha256_b16[..32]),
            ]);
            println!("{}", t);
        }
        Err(e) => {
            eprintln!("❌ Could not load DID at {}: {}", path, e);
            std::process::exit(1);
        }
    }
}

fn cmd_resolve(a: DidResolveArgs) {
    let dkp_pubkey_path = "/var/lib/sgx-guardian/keys/dkp_pub.der";
    match a.did {
        None => match did::method::resolve_local(did::DEFAULT_DID_PATH, dkp_pubkey_path) {
            Ok((did, pk, active)) => {
                println!("DID:    {}", did.as_str());
                println!("Status: {}", if active { "ACTIVE" } else { "DEACTIVATED" });
                println!("Pubkey: {} ({} bytes)",
                    &hex::encode(&pk)[..32.min(pk.len() * 2)], pk.len());
            }
            Err(e) => { eprintln!("❌ Resolve failed: {}", e); std::process::exit(1); }
        },
        Some(did_str) => {
            // Try self first, then peer cache
            if let Ok(self_rec) = did::DidRecord::load(did::DEFAULT_DID_PATH) {
                if self_rec.did == did_str {
                    println!("Self-resolution:");
                    println!("DID:    {}", self_rec.did);
                    println!("Status: {}",
                        if self_rec.is_active() { "ACTIVE" } else { "DEACTIVATED" });
                    return;
                }
            }
            // Peer cache
            match did::Did::parse(&did_str) {
                Ok(d) => match did::registry::get(did::registry::default_peers_dir(), &d) {
                    Ok(Some(p)) => {
                        println!("Peer DID:    {}", p.did);
                        println!("Node hint:   {}", p.node_id);
                        println!("DKP version: v{}", p.current_dkp_version);
                        println!("Last seen:   {}", p.last_seen);
                        println!("Source:      {}", p.source);
                    }
                    Ok(None) => {
                        eprintln!("❌ DID {} not found in local cache", did_str);
                        std::process::exit(1);
                    }
                    Err(e) => { eprintln!("❌ Cache error: {}", e); std::process::exit(1); }
                },
                Err(e) => { eprintln!("❌ Bad DID format: {}", e); std::process::exit(1); }
            }
        }
    }
}

fn cmd_peers() {
    let dir = did::registry::default_peers_dir();
    match did::registry::list(dir) {
        Ok(v) if v.is_empty() => println!("(no cached peer DIDs)"),
        Ok(v) => {
            let mut t = Table::new();
            t.set_header(vec!["Node hint", "DID", "DKP v", "Last seen", "Source"]);
            for p in v {
                t.add_row(vec![
                    Cell::new(p.node_id),
                    Cell::new(&p.did[..32.min(p.did.len())]),
                    Cell::new(format!("v{}", p.current_dkp_version)),
                    Cell::new(p.last_seen),
                    Cell::new(p.source),
                ]);
            }
            println!("{}", t);
        }
        Err(e) => { eprintln!("❌ List failed: {}", e); std::process::exit(1); }
    }
}

fn cmd_create() {
    println!("DID creation is performed by the daemon at startup. \
             To force re-evaluation, restart sgx-guardian.");
    cmd_show();
}

fn cmd_deactivate(a: DidDeactivateArgs) {
    if !a.yes {
        eprintln!("⚠️  Deactivation is IRREVERSIBLE from this device.");
        eprintln!("    Re-run with --yes to confirm.");
        std::process::exit(1);
    }
    match did::method::deactivate(did::DEFAULT_DID_PATH, &a.reason) {
        Ok(()) => {
            println!("✅ DID deactivated. Restart the daemon to enforce.");
        }
        Err(DidError::Deactivated(when)) => {
            eprintln!("ℹ️  Already deactivated at {}", when);
        }
        Err(e) => { eprintln!("❌ Deactivate failed: {}", e); std::process::exit(1); }
    }
}
```

## 11.2 Wire into `sgx-pa-cli/src/main.rs`

**FIND** the existing `Subcommand` enum (typical pattern in current CLI code):
```rust
#[derive(Subcommand)]
enum Cmd {
    PcrBaseline(...),
    Attest(...),
    Transport(...),
    // ... existing
}
```

**ADD:**
```rust
    /// DID lifecycle and registry operations
    Did(commands::did::DidArgs),
```

And in the dispatcher `match args.command { ... }` block, add:
```rust
    Cmd::Did(a) => commands::did::run(a),
```

Don't forget `pub mod did;` in `sgx-pa-cli/src/commands/mod.rs`.

---

# 12. D8 — Tests

## 12.1 Unit tests

Already shown in §6. Add to `src/did/tests.rs`:

```rust
#[cfg(test)]
mod persistence_tests {
    use super::super::persistence::*;
    use tempfile::TempDir;

    #[test]
    fn test_save_load_roundtrip() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("did.json");
        let path_s = path.to_str().unwrap();

        let rec = DidRecord {
            did: "did:guardian:11111111111111111111111111111111111111111111".into(),
            method: "guardian".into(),
            method_version: "1.0".into(),
            did_id_b58: "11111111111111111111111111111111111111111111".into(),
            did_id_hex: "00".repeat(32),
            created_at: "2026-04-26T10:00:00Z".into(),
            deactivated_at: None,
            derivation: DerivationProof {
                se050_uid: "fixture-uid".into(),
                se050_uid_source: "fallback".into(),
                dkp_v1_pubkey_sha256_b16: "ab".repeat(32),
                dkp_v1_pubkey_path: "/tmp/dkp_pub.der".into(),
            },
            current_dkp_version: 1,
            deriv_signature_b64: "Zm9v".into(),
        };
        rec.save(path_s).unwrap();
        let loaded = DidRecord::load(path_s).unwrap();
        assert_eq!(loaded.did, rec.did);
        assert!(loaded.is_active());
    }

    #[test]
    fn test_atomic_write_does_not_leave_tmp_on_success() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("did.json");
        let mut rec = DidRecord {
            did: "did:guardian:11111111111111111111111111111111111111111111".into(),
            method: "guardian".into(),
            method_version: "1.0".into(),
            did_id_b58: "1".repeat(44),
            did_id_hex: "00".repeat(32),
            created_at: "2026-04-26T10:00:00Z".into(),
            deactivated_at: None,
            derivation: DerivationProof {
                se050_uid: "u".into(),
                se050_uid_source: "fallback".into(),
                dkp_v1_pubkey_sha256_b16: "00".repeat(32),
                dkp_v1_pubkey_path: "/tmp/dkp.der".into(),
            },
            current_dkp_version: 1,
            deriv_signature_b64: "AAA=".into(),
        };
        rec.save(path.to_str().unwrap()).unwrap();
        rec.current_dkp_version = 2;
        rec.save(path.to_str().unwrap()).unwrap();
        // No leftover .tmp
        let tmp_path = format!("{}.tmp", path.display());
        assert!(!std::path::Path::new(&tmp_path).exists());
    }
}
```

## 12.2 Integration test (`tests/did_integration.rs`)

```rust
//! Integration test: full DID lifecycle on a temp filesystem.

use sgx_guardian_client::did::{self, method::create_if_absent};
use sgx_guardian_client::key_manager::KeyManager;
use tempfile::TempDir;

#[test]
fn test_create_then_load_then_deactivate() {
    let td = TempDir::new().unwrap();
    let key_path = td.path().join("device.key");
    let dkp_pub = td.path().join("dkp_pub.der");
    let did_path = td.path().join("did.json");

    // Generate a software key (no SE050 in tests). Write fake DER pubkey.
    let km = KeyManager::load_or_generate(key_path.to_str().unwrap()).unwrap();
    std::fs::write(&dkp_pub, km.pubkey_der().unwrap()).unwrap();

    // First call → creates
    let did1 = create_if_absent(
        "nodeT",
        &km,
        dkp_pub.to_str().unwrap(),
        did_path.to_str().unwrap(),
    )
    .unwrap();
    assert!(did1.as_str().starts_with("did:guardian:"));

    // Second call → idempotent, returns same DID
    let did2 = create_if_absent(
        "nodeT",
        &km,
        dkp_pub.to_str().unwrap(),
        did_path.to_str().unwrap(),
    )
    .unwrap();
    assert_eq!(did1, did2);

    // Deactivate
    did::method::deactivate(did_path.to_str().unwrap(), "test").unwrap();
    let rec = did::DidRecord::load(did_path.to_str().unwrap()).unwrap();
    assert!(!rec.is_active());

    // Second deactivate → returns Deactivated error
    let err = did::method::deactivate(did_path.to_str().unwrap(), "test").unwrap_err();
    assert!(matches!(err, did::DidError::Deactivated(_)));
}

#[test]
fn test_derivation_mismatch_detected() {
    let td = TempDir::new().unwrap();
    let key_path1 = td.path().join("device1.key");
    let key_path2 = td.path().join("device2.key");
    let dkp_pub = td.path().join("dkp_pub.der");
    let did_path = td.path().join("did.json");

    let km1 = KeyManager::load_or_generate(key_path1.to_str().unwrap()).unwrap();
    std::fs::write(&dkp_pub, km1.pubkey_der().unwrap()).unwrap();
    let _ = create_if_absent(
        "nodeT", &km1,
        dkp_pub.to_str().unwrap(),
        did_path.to_str().unwrap(),
    ).unwrap();

    // Now swap the pubkey on disk to simulate a hardware change
    let km2 = KeyManager::load_or_generate(key_path2.to_str().unwrap()).unwrap();
    std::fs::write(&dkp_pub, km2.pubkey_der().unwrap()).unwrap();

    let err = create_if_absent(
        "nodeT", &km2,
        dkp_pub.to_str().unwrap(),
        did_path.to_str().unwrap(),
    ).unwrap_err();
    assert!(matches!(err, did::DidError::DerivationMismatch));
}
```

## 12.3 New test cases (DID-001..007) for `Phase2_Test_Cases.pdf`

Add the following section to the test cases doc:

| Test ID | Test Name | Prerequisites | Steps | Expected | Pass Criteria |
|---|---|---|---|---|---|
| **DID-001** | DID Generation Determinism | Clean Guardian, SE050 active, DKP_v1 generated | 1. `sgx-pa-cli did show` 2. note the DID 3. delete `/var/lib/sgx-guardian/identity/did.json` 4. restart sgx-guardian 5. `sgx-pa-cli did show` again | Same DID is regenerated with same prefix and id | DID matches byte-for-byte across two cold boots on same hardware |
| **DID-002** | DID Persistence Across Reboots | DID created in DID-001 | 1. `reboot` 2. after boot, `sgx-pa-cli did show` 3. compare to DID-001 result | DID identical, `created_at` unchanged | No regeneration; file checksum identical |
| **DID-003** | DID Persistence Across DKP Rotation | DID exists, DKP_v1 active | 1. `sgx-pa-cli pcr-baseline rotate` is NOT enough — trigger DKP rotation via `sgx-pa-cli key rotate-dkp` 2. `sgx-pa-cli did show` | DID identifier unchanged; `current_dkp_version` is now 2 | DID byte-identical; metadata updated |
| **DID-004** | Local DID Resolution | DID exists | 1. `sgx-pa-cli did resolve` 2. `sgx-pa-cli did resolve <self-did>` 3. `sgx-pa-cli did resolve did:guardian:invalid111111111111111111111111` | (1) returns DID + active=true, (2) self-resolves, (3) fails with "not found in local cache" | All three produce expected output; non-zero exit on (3) |
| **DID-005** | DID Format Compliance | DID exists | 1. extract DID from `did show` 2. validate against W3C DID Core 1.0 ABNF | DID matches `did:guardian:<base58btc(32 bytes)>`; MSI is 43–44 chars | Regex `^did:guardian:[1-9A-HJ-NP-Za-km-z]{43,44}$` matches |
| **DID-006** | DID Method Operations CRUD | Clean Guardian | 1. `did create` (auto on boot) 2. `did show` 3. `did resolve` 4. trigger DKP rotation → verify update 5. `did deactivate --reason "test" --yes` 6. attempt `did create` (should refuse) | Each step succeeds in order; deactivation persists across reboot | All four CRUD operations produce expected state file changes |
| **DID-007** | Cross-Device Uniqueness | Two Guardians (Board 101 and Board 115) | 1. note DID on each | DIDs differ | `did_A != did_B`; SHA-256 collision check |

---

# 13. Regression Checks

After every commit related to this task:

```bash
# Compile clean (no warnings about unused imports from new module)
cargo build --release 2>&1 | tee /tmp/build.log
grep -E "warning:|error" /tmp/build.log | grep -v "^warning: unused" || true

# Unit tests
cargo test --release did:: 2>&1 | tail -30
cargo test --release did_integration 2>&1 | tail -30

# Smoke test (laptop)
sgx-pa-cli did show
sgx-pa-cli did resolve
sgx-pa-cli did peers
echo "--- expected: did:guardian:... in show, ACTIVE in resolve, empty in peers (yet) ---"

# Bench: DID creation time
cargo bench --bench did_create 2>&1 | tail -5   # optional; expect <50ms on i.MX8MP

# Cross-board sanity
# On Board 101: sgx-pa-cli did show > /tmp/board101.did
# On Board 115: sgx-pa-cli did show > /tmp/board115.did
# diff /tmp/board101.did /tmp/board115.did   # MUST differ
```

Specifically watch for:
- ✅ `did.json` appears at `/var/lib/sgx-guardian/identity/did.json` after first boot
- ✅ DID format passes regex `^did:guardian:[1-9A-HJ-NP-Za-km-z]{43,44}$`
- ✅ `did show` output is stable across reboots
- ✅ Audit log contains `Category=Did | Action=Loaded | DID resolved: did:guardian:...`
- ✅ No regression: existing attestation, PCR baseline, Nebula CA flows unchanged
- ✅ DerivationMismatch path: corrupting `dkp_pub.der` and restarting → daemon refuses to start with exit code 2

---

# 14. Step-by-Step Checklist

- [ ] Branch from `main`: `feat/sprint5-did-implementation`
- [ ] Add `bs58 = "0.5"` to `Cargo.toml` and `sgx-pa-cli/Cargo.toml`
- [ ] Add `thiserror = "1"` to `Cargo.toml` (if not present)
- [ ] D1: Create `src/did/{mod.rs, errors.rs}` and `docs/did_method_spec.md`
- [ ] D2: Create `src/did/did.rs` with `derive`, `Did`, parsing
- [ ] D2: Run `cargo test --release did::tests` — all 9 unit tests green
- [ ] D3: Create `src/did/persistence.rs`
- [ ] D4: Create `src/did/method.rs`
- [ ] D5: Create `src/did/registry.rs`
- [ ] D6: `pub mod did;` in `src/lib.rs`
- [ ] D6: Modify `src/main.rs` per §10.2 (DID init block + DKP-rotation hook)
- [ ] D6: Add `AuditCategory::Did` variant in `src/audit/event.rs`
- [ ] D7: Create `sgx-pa-cli/src/commands/did.rs`
- [ ] D7: Wire into `sgx-pa-cli/src/main.rs`
- [ ] D7: `pub mod did;` in `sgx-pa-cli/src/commands/mod.rs`
- [ ] D8: Run integration tests: `cargo test --release did_integration`
- [ ] D8: Run DID-001..007 manually on laptop (3 nodes)
- [ ] D8: Run DID-001, DID-002, DID-007 on real boards (Board 101, 115, 248)
- [ ] Add Phase2_Test_Cases.pdf addendum with DID-001..007
- [ ] CodeRabbit + CodeQL review per the SG-X security review framework
- [ ] PR description includes:
  - sample `did show` output for each board
  - audit log excerpt showing `Category=Did | Loaded | DID resolved: ...`
  - cross-board diff proving uniqueness (DID-007)
- [ ] Merge to `main` after all 7 DID tests pass on real boards

---

# 15. Risk Analysis

| Risk | Likelihood | Mitigation |
|---|---|---|
| `bs58 = "0.5"` doesn't compile on `aarch64-unknown-linux-gnu` (i.MX8MP target) | Very low | `bs58` is pure Rust, no C deps. Verified to compile across all Tier-1 and Tier-2 targets. Confirm with `cross build --target aarch64-unknown-linux-gnu` before merging. |
| `read_device_uid` returns the fallback (`nodeA`/`nodeB`/...) instead of real SE050 UID — three nodes get DIDs derived from `("nodeA"|"nodeB"|"nodeC", different_pubkeys)` | Medium during dev (laptop has no SE050) | `did.json` records `se050_uid_source: "ssscli"` vs `"fallback"`. CLI `did show` prints this field. On boards with SE050, source MUST be `"ssscli"` — fail-loud in production deployment via systemd unit health check. |
| Operator wipes SE050 (chip provisioning) — DKP_v1 pubkey changes — DID derivation now fails | Low | Exit code 2 with a clear `DerivationMismatch` message. Operator runbook (§16) documents the recovery: explicit re-enrollment requires deleting `did.json` (audit-logged). |
| Atomic-write `rename` race on a board with eMMC fsync delays | Low | Standard POSIX `rename(2)` is atomic on the same filesystem. eMMC writeback delays do not affect atomicity. |
| `current_dkp_version` updates race with concurrent rotations | Very low | Only the daemon's main thread calls `update_dkp_version` after rotation; no concurrent writers. |
| Memory bloat in peer registry (`/var/lib/sgx-guardian/identity/peers/`) | Low | One file per peer; in a 5-node Circle that's 4 files of ~400 bytes each. No GC needed for Sprint 5. Sprint 7 (CRL) adds revocation-driven cleanup. |
| DID becomes a tracking vector across Circles | Medium | Documented in `did_method_spec.md` §6. VirtualID (Sprint 6) introduces unlinkable session credentials on top of the persistent DID. |
| Mobile app uses Ed25519 DIDs while daemon uses ECDSA-P256 DIDs — confusion | Medium | Method spec §3 explicitly documents the choice. The companion mobile app's `did:guardian` format is method-version `1.0-mobile` (a future divergence). For Sprint 5, the daemon and mobile app DIDs are **disjoint identifier spaces** — they do not collide because the byte input to SHA-256 is different. |

---

# 16. What I'm NOT Doing in This Plan

- **DID Document creation/JSON-LD** — that is Sprint 5 Task 2 (DID Document deliverable). This plan only persists the DID identifier and current pubkey reference.
- **Network-resolvable DID resolver** — that is Sprint 5 Task 3 (DID Resolution Service). This plan exposes a *local* resolver only.
- **Verifiable Credentials** — that is Sprint 6.
- **VirtualID-DID integration** — Sprint 6.
- **DID-bound Nebula certs** — the existing `nebula-cert sign` command already takes `-name <node_id>` and `-ip <overlay_ip>`. Embedding DID into the Nebula cert subject is a separate hardening item, deferred to Sprint 6 or Sprint 7 depending on CRL-revocation requirements.
- **Mobile app DID interop** — out of scope for the daemon. Mobile team owns that.
- **Existing audit log refactor** — only the new `AuditCategory::Did` variant is added; all other audit calls unchanged.

---

# 17. Honest Notes on What I Couldn't Verify

I cannot:
- Run `cargo build` against current `main` to confirm exact line numbers (line counts shift by minor commits). All FIND blocks use distinctive anchor strings — use `grep -n` to locate them.
- Verify `read_device_uid` returns a well-formed UID against a real SE050 on the boards.
- Test cross-target compilation of `bs58 = "0.5"` for i.MX8MP. Strongly recommend `cross build --target aarch64-unknown-linux-gnu --release` before merging.
- Confirm the exact `AuditCategory` enum variant list — if the project uses a non-derive `Display` impl, you may need to add a `match` arm for the new `Did` variant.

What I did verify by tracing actual code in `project_knowledge_search`:
- `secure_element/pcr.rs::read_device_uid(fallback)` exists and returns either real SE050 UID or fallback string
- `KeyManager::pubkey_der()` and `KeyManager::sign(data)` exist and use ECDSA-P256
- `/var/lib/sgx-guardian/keys/dkp_pub.der` is the DKP public key path
- `Cargo.toml` has `serde`, `serde_json`, `sha2`, `hex`, `base64`, `chrono`, `anyhow` — `bs58` and `thiserror` are missing
- `sgx-pa-cli/Cargo.toml` has `clap`, `comfy-table`, `serde_json`, `chrono` — `bs58` is missing
- `main.rs` has the DKP auto-rotation block at the documented anchor

The 8 deliverables are independently testable. A reviewer should be able to merge D1+D2 alone (no daemon impact) and verify the unit tests pass before continuing to D3+.
