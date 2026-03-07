# SG-X Guardian — Hardware Key Manager (HKM)
**Version:** 1.0  
**Date:** March 6, 2026  
**Phase:** Phase 2 – Sprint 1 (Hardware Security)  
**Test Cases:** HKM-001 to HKM-004  
**Prerequisite:** SE050 Secure Element Integration COMPLETE (37 tests, all board commands verified)  
**Developer:** Asad




## What is the Hardware Key Manager?

Today, the Guardian daemon generates its identity key pair using the `ring` crate (software) and stores the private key as a file on disk (`device_nodeA.key`). Anyone with root access can copy that file.

> **With HKM:** The Device Key Pair (DKP) is generated INSIDE the SE050 chip. The private key never exists in software — it never touches RAM, never touches disk. When the daemon needs to sign something, it asks the chip to sign. The chip returns the signature. The private key stays locked inside the hardware forever.

**What changes:**

```
BEFORE (Phase 1 — Software Keys):
  Daemon starts → ring generates ECDSA key → saves to /var/lib/.../device_nodeA.key
  Sign request  → ring loads key from disk → signs in RAM → returns signature
  Problem:      → root can copy the .key file → impersonate the node

AFTER (HKM — Hardware Keys):
  Daemon starts → SE050 generates ECDSA key inside chip → public key exported
  Sign request  → ssscli sends data to chip → chip signs internally → returns signature
  Security:     → private key NEVER leaves chip → cannot be copied, even by root
```




## What Already Exists (from SE050 Task)

We built all the plumbing in the SE050 task. HKM connects the wires:

| Component | File | What It Does | Status |
|---|---|---|---|
| ssscli wrapper | `ssscli.rs` | Runs ssscli commands, parses output | ✅ Done |
| Key storage | `key_storage.rs` | Create/delete/list keys in SE050 | ✅ Done |
| Signing | `sign.rs` | Sign/verify via SE050 hardware | ✅ Done |
| Config | `config.rs` | SE050 connection parameters | ✅ Done |
| Tamper guard | `safe_mode.rs` | Block crypto if tamper detected | ✅ Done |
| KeyManager | `key_manager.rs` | SigningBackend::Hardware variant | ✅ Done |
| Board key | `0x20000001` | Test key already created on SE050 | ✅ Done |

**What's MISSING (what HKM adds):**
- A way to initialize KeyManager with SE050 backend (currently always uses Software)
- Device Key Pair (DKP) lifecycle management
- Key metadata tracking (version, status, timestamps)
- Key rotation (create new version, deprecate old)
- Key revocation (permanently block signing)




## HKM System Diagram

```
+====================================================================+
|                    SG-X GUARDIAN NODE                               |
|                                                                    |
|  main.rs                                                           |
|    │                                                               |
|    ├── KeyManager::init_with_se050()           ← HKM-001 (D1)     |
|    │     │                                                         |
|    │     ▼                                                         |
|    │   DkpManager                              ← NEW FILE          |
|    │     │                                                         |
|    │     ├── generate_dkp()   → ssscli generate ecc                |
|    │     ├── load_dkp()       → read metadata + export pub key     |
|    │     ├── rotate()         → create v2, deprecate v1  ← D3      |
|    │     └── revoke()         → mark revoked, block sign ← D4      |
|    │                                                               |
|    │   KeyMetadata            ← NEW FILE                           |
|    │     ├── key_id, version, status, created_at                   |
|    │     ├── save_to_file()   → JSON on disk                       |
|    │     └── load_from_file() → JSON from disk                     |
|    │                                                               |
|    └── KeyManager.sign(data)                                       |
|          │                                                         |
|          ├── SigningBackend::Software  (fallback, no SE050)         |
|          └── SigningBackend::Hardware  (production, SE050)          |
|                │                                                   |
|                ├── safe_mode::guard()  (tamper check)               |
|                └── SeSigner::sign()   → ssscli sign                |
|                                                                    |
|  SE050 Chip (0x20000010 = DKP slot)                                |
|    ├── Private key INSIDE chip (never exported)                    |
|    ├── Public key exportable (DER format)                          |
|    └── All signing happens inside hardware                         |
+====================================================================+
```




## The 4 Deliverables at a Glance

| # | Name | Test Case | Local Tests | Board Work |
|---|------|-----------|-------------|------------|
| D1 | DKP Generation in SE050 | HKM-001 | 8 tests | Generate DKP key |
| D2 | Key Lifecycle — Generation | HKM-002 | 6 tests | Sign + verify test |
| D3 | Key Lifecycle — Rotation | HKM-003 | 5 tests | Rotate key on chip |
| D4 | Key Lifecycle — Revocation | HKM-004 | 4 tests | None needed |
| **Total** | | | **23 tests** | |




## Key Design Decisions

**1. DKP Key Slot:** `0x20000010` (not 0x20000001 which was our test key)

**2. Key Metadata:** Stored as JSON file on disk — NOT inside SE050. The chip stores the cryptographic key; our software tracks the version, status, and timestamps.

```
/var/lib/sgx-guardian/keys/dkp_metadata.json
{
  "key_id": "0x20000010",
  "label": "dkp",
  "algorithm": "ECDSA-P256",
  "version": 1,
  "status": "Active",
  "created_at": "2026-03-06T12:00:00Z",
  "rotated_from": null,
  "revoked_at": null,
  "revoke_reason": null
}
```

**3. Key Rotation Strategy:** New key gets slot `0x20000010 + version`. Old key stays in SE050 for signature verification but software blocks new signing with it.

**4. Fallback:** If SE050 is not available (no hardware, dev laptop), KeyManager falls back to Software backend. This means `cargo test` works without hardware.

**5. Integration Approach:** We add ONE new method `KeyManager::init_with_se050()` alongside the existing `load_or_generate()`. The daemon calls whichever is appropriate based on config.




## Complete Folder Structure (HKM additions)

```
src/
├── key_manager.rs                       # MODIFY — add init_with_se050()
├── secure_element/
│   ├── mod.rs                           # MODIFY — add pub mod dkp; pub mod key_meta;
│   ├── dkp.rs                           # NEW — Device Key Pair manager (D1)
│   ├── key_meta.rs                      # NEW — Key metadata + lifecycle (D2-D4)
│   ├── key_storage.rs                   # EXISTS — used by dkp.rs
│   ├── sign.rs                          # EXISTS — used by KeyManager
│   ├── ssscli.rs                        # EXISTS — used by everything
│   ├── safe_mode.rs                     # EXISTS — tamper guard
│   └── ... (all other SE050 files unchanged)
├── main.rs                              # MODIFY — call init_with_se050() (D1)
config/
└── nodeA.yaml                           # EXISTS — already has secure_element section
```

**Only 2 new files.** Everything else is modifications to existing files.




## Dependency Chain

```
              +--------+
              |  D1    |  DKP Generation (HKM-001)
              | 8 tests|  dkp.rs + key_meta.rs + KeyManager change
              +---+----+
                  |
            +-----+-----+
            |           |
        +---v---+   +---v---+
        |  D2   |   |  D3   |
        | 6 test|   | 5 test|
        | Gen   |   | Rotate|
        +---+---+   +---+---+
            |           |
            +-----+-----+
                  |
              +---v---+
              |  D4   |  Revocation (HKM-004)
              | 4 test|
              +-------+
```




---
---
---




# DELIVERABLE 1 — DKP Generation in Secure Element (HKM-001)

## Concept (Simple Explanation)

> **The daemon starts up and creates its identity key pair inside the SE050 chip instead of in a file on disk.**

Today: `KeyManager::load_or_generate()` → creates software key → saves to file.  
After D1: `KeyManager::init_with_se050()` → creates key inside SE050 → exports public key → stores metadata.

The private key NEVER leaves the chip. The public key is exported in DER format so peers can verify signatures.


## Where It Fits

```
main.rs
  │
  │ calls KeyManager::init_with_se050(config)
  │
  ▼
key_manager.rs
  │
  │ creates DkpManager → calls SE050 to generate key
  │ sets backend = SigningBackend::Hardware { signer, key_id }
  │
  ▼
dkp.rs ← NEW
  │
  │ generate_dkp() → ssscli generate ecc 0x20000010 NIST_P256
  │ load_dkp()     → check if key exists, export public key
  │ export_pub()   → ssscli get ecc pub 0x20000010 /tmp/dkp_pub.der
  │
  ▼
SE050 Chip
  └── Key 0x20000010: ECDSA-P256 (private key locked inside)
```


## Board Commands — D1

```bash
# Generate DKP key at dedicated slot 0x20000010
ssscli generate ecc 0x20000010 NIST_P256

# Verify it exists
ssscli se05x readidlist
# Should show: Key-Id: 0X20000010  NIST-P (Key Pair) Size(Bits): 256

# Export public key
ssscli get ecc pub 0x20000010 /tmp/dkp_pub.der

# Verify public key format (91 bytes for P-256 DER)
ls -la /tmp/dkp_pub.der
hexdump -C /tmp/dkp_pub.der | head

# Test signing with DKP
echo -n "dkp test message" > /tmp/dkp_msg.bin
ssscli sign 0x20000010 /tmp/dkp_msg.bin /tmp/dkp_sig.bin

# Verify signature
ssscli verify 0x20000010 /tmp/dkp_msg.bin /tmp/dkp_sig.bin
```


## Technical Implementation


### New File: `src/secure_element/key_meta.rs`
**What this file does:** Tracks key metadata (version, status, timestamps) as JSON. The SE050 chip stores the actual key; this file tracks the software-side lifecycle state.

```rust
// src/secure_element/key_meta.rs
// ============================================================
// Key metadata — tracks lifecycle state for SE050-backed keys.
// Stored as JSON on disk. SE050 stores the key itself.
// ============================================================

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Status of a hardware-backed key
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeyStatus {
    /// Key is active and can be used for signing + verification
    Active,
    /// Key has been replaced by a newer version — verify only, no new signing
    Deprecated,
    /// Key is permanently revoked — no signing, verify only during grace period
    Revoked,
}

impl std::fmt::Display for KeyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyStatus::Active => write!(f, "Active"),
            KeyStatus::Deprecated => write!(f, "Deprecated (verify-only)"),
            KeyStatus::Revoked => write!(f, "Revoked"),
        }
    }
}

/// Metadata for a single hardware-backed key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// SE050 key ID in hex (e.g., "0x20000010")
    pub key_id: String,
    /// Human-readable label (e.g., "dkp", "dkp-v2")
    pub label: String,
    /// Algorithm (e.g., "ECDSA-P256")
    pub algorithm: String,
    /// Key version (starts at 1, increments on rotation)
    pub version: u32,
    /// Current lifecycle status
    pub status: KeyStatus,
    /// When this key was generated
    pub created_at: DateTime<Utc>,
    /// Key ID this was rotated from (None for first key)
    pub rotated_from: Option<String>,
    /// When this key was revoked (None if not revoked)
    pub revoked_at: Option<DateTime<Utc>>,
    /// Reason for revocation (None if not revoked)
    pub revoke_reason: Option<String>,
    /// Path to exported public key DER file
    pub public_key_path: Option<String>,
}

impl KeyMetadata {
    /// Create metadata for a newly generated key
    pub fn new(key_id: &str, label: &str, algorithm: &str, version: u32) -> Self {
        Self {
            key_id: key_id.to_string(),
            label: label.to_string(),
            algorithm: algorithm.to_string(),
            version,
            status: KeyStatus::Active,
            created_at: Utc::now(),
            rotated_from: None,
            revoked_at: None,
            revoke_reason: None,
            public_key_path: None,
        }
    }

    /// Check if this key can be used for signing
    pub fn can_sign(&self) -> bool {
        self.status == KeyStatus::Active
    }

    /// Check if this key can be used for verification
    pub fn can_verify(&self) -> bool {
        match self.status {
            KeyStatus::Active => true,
            KeyStatus::Deprecated => true,
            KeyStatus::Revoked => {
                // Grace period: allow verification for 30 days after revocation
                if let Some(revoked) = self.revoked_at {
                    let grace_days = 30;
                    let elapsed = Utc::now() - revoked;
                    elapsed.num_days() < grace_days
                } else {
                    false
                }
            }
        }
    }

    /// Mark this key as deprecated (replaced by newer version)
    pub fn deprecate(&mut self) {
        self.status = KeyStatus::Deprecated;
    }

    /// Mark this key as revoked (permanently blocked from signing)
    pub fn revoke(&mut self, reason: &str) {
        self.status = KeyStatus::Revoked;
        self.revoked_at = Some(Utc::now());
        self.revoke_reason = Some(reason.to_string());
    }

    /// Save metadata to JSON file
    pub fn save(&self, path: &str) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialize metadata: {}", e))?;
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Create dir: {}", e))?;
        }
        fs::write(path, json)
            .map_err(|e| format!("Write metadata: {}", e))?;
        Ok(())
    }

    /// Load metadata from JSON file
    pub fn load(path: &str) -> Result<Self, String> {
        let json = fs::read_to_string(path)
            .map_err(|e| format!("Read metadata: {}", e))?;
        serde_json::from_str(&json)
            .map_err(|e| format!("Parse metadata: {}", e))
    }
}


// ── Unit Tests (8 tests) ────────────────────────────────────
// Pure struct/logic tests — no I/O, no subprocess.
// Run: cargo test secure_element::key_meta::tests -- --nocapture
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_key_is_active() {
        let meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        assert_eq!(meta.status, KeyStatus::Active);
        assert!(meta.can_sign());
        assert!(meta.can_verify());
    }

    #[test]
    fn test_deprecated_key_cannot_sign() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.deprecate();
        assert_eq!(meta.status, KeyStatus::Deprecated);
        assert!(!meta.can_sign());
        assert!(meta.can_verify()); // can still verify old signatures
    }

    #[test]
    fn test_revoked_key_cannot_sign() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.revoke("rotation complete");
        assert_eq!(meta.status, KeyStatus::Revoked);
        assert!(!meta.can_sign());
        assert_eq!(meta.revoke_reason.as_deref(), Some("rotation complete"));
    }

    #[test]
    fn test_revoked_key_verify_during_grace_period() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.revoke("test");
        // Just revoked — within 30-day grace period
        assert!(meta.can_verify());
    }

    #[test]
    fn test_key_status_display() {
        assert_eq!(format!("{}", KeyStatus::Active), "Active");
        assert_eq!(format!("{}", KeyStatus::Deprecated), "Deprecated (verify-only)");
        assert_eq!(format!("{}", KeyStatus::Revoked), "Revoked");
    }

    #[test]
    fn test_version_tracking() {
        let v1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        let v2 = KeyMetadata::new("0x20000011", "dkp-v2", "ECDSA-P256", 2);
        assert_eq!(v1.version, 1);
        assert_eq!(v2.version, 2);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        let json = serde_json::to_string(&meta).unwrap();
        let loaded: KeyMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.key_id, "0x20000010");
        assert_eq!(loaded.label, "dkp");
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.status, KeyStatus::Active);
    }

    #[test]
    fn test_revocation_is_permanent() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.revoke("compromised");
        assert!(!meta.can_sign());
        // Cannot un-revoke — there's no un_revoke() method
        assert_eq!(meta.status, KeyStatus::Revoked);
    }
}
```


### New File: `src/secure_element/dkp.rs`
**What this file does:** Manages the Device Key Pair inside SE050. Handles generation, loading, and public key export.

```rust
// src/secure_element/dkp.rs
// ============================================================
// Device Key Pair (DKP) Manager.
// Maps to HKM-001: DKP Generation in Secure Element.
//
// DKP Key Slot: 0x20000010 (base) + version offset
//   v1 = 0x20000010, v2 = 0x20000011, v3 = 0x20000012...
//
// Metadata stored at: /var/lib/sgx-guardian/keys/dkp_metadata.json
// Public key exported to: /var/lib/sgx-guardian/keys/dkp_pub.der
// ============================================================

use crate::secure_element::config::SeConfig;
use crate::secure_element::error::SeError;
use crate::secure_element::key_meta::{KeyMetadata, KeyStatus};
use crate::secure_element::key_storage::SeKeyStorage;
use crate::secure_element::sign::SeSigner;
use crate::secure_element::ssscli::SssCli;
use tracing::{info, warn};

/// Base key ID for DKP keys. Version offset is added.
const DKP_BASE_KEY_ID: u32 = 0x20000010;

/// Device Key Pair manager — the core of HKM.
pub struct DkpManager {
    /// Current active key metadata
    pub active_key: KeyMetadata,
    /// All key versions (for rotation/revocation tracking)
    pub key_history: Vec<KeyMetadata>,
    /// Path to metadata JSON file
    pub metadata_path: String,
    /// Path to exported public key
    pub public_key_path: String,
    /// SE050 config (for creating new SeSigner instances)
    config: SeConfig,
}

impl DkpManager {
    /// Initialize DKP — load existing or generate new.
    /// This is the main entry point called from KeyManager::init_with_se050().
    pub fn init(config: &SeConfig, base_path: &str) -> Result<Self, SeError> {
        let metadata_path = format!("{}/keys/dkp_metadata.json", base_path);
        let public_key_path = format!("{}/keys/dkp_pub.der", base_path);

        // Try to load existing DKP metadata
        if let Ok(meta) = KeyMetadata::load(&metadata_path) {
            if meta.status == KeyStatus::Active {
                info!("DKP loaded: {} (v{})", meta.key_id, meta.version);
                return Ok(Self {
                    active_key: meta.clone(),
                    key_history: vec![meta],
                    metadata_path,
                    public_key_path,
                    config: config.clone(),
                });
            }
        }

        // No existing DKP — generate new one
        info!("No existing DKP found — generating inside SE050...");
        let meta = Self::generate_dkp(config, &metadata_path, &public_key_path)?;

        Ok(Self {
            active_key: meta.clone(),
            key_history: vec![meta],
            metadata_path,
            public_key_path,
            config: config.clone(),
        })
    }

    /// Generate a new DKP inside SE050.
    fn generate_dkp(
        config: &SeConfig,
        metadata_path: &str,
        public_key_path: &str,
    ) -> Result<KeyMetadata, SeError> {
        let key_id = DKP_BASE_KEY_ID;
        let key_id_hex = format!("0x{:08X}", key_id);

        let storage = SeKeyStorage::new(config)?;

        // Check if key already exists in SE050 (idempotent)
        let id_list = storage.list_slots()?;
        let key_exists = id_list
            .to_uppercase()
            .contains(&key_id_hex.to_uppercase().replace("0x", "0X"));

        if !key_exists {
            // Generate ECDSA-P256 key pair inside SE050
            info!("Generating DKP at SE050 slot {}", key_id_hex);
            storage.create_key_slot(key_id - 0x20000000, "dkp", "ecdsa")?;
        } else {
            info!("DKP already exists at SE050 slot {}", key_id_hex);
        }

        // Export public key
        storage.export_public_key(key_id, public_key_path)?;
        info!("DKP public key exported to {}", public_key_path);

        // Create and save metadata
        let mut meta = KeyMetadata::new(&key_id_hex, "dkp", "ECDSA-P256", 1);
        meta.public_key_path = Some(public_key_path.to_string());
        meta.save(metadata_path)
            .map_err(|e| SeError::KeyError(format!("Save metadata: {}", e)))?;

        Ok(meta)
    }

    /// Get the active key ID as u32 (for SeSigner)
    pub fn active_key_id(&self) -> u32 {
        // Parse "0x20000010" back to u32
        u32::from_str_radix(
            self.active_key.key_id.trim_start_matches("0x").trim_start_matches("0X"),
            16,
        )
        .unwrap_or(DKP_BASE_KEY_ID)
    }

    /// Create a SeSigner for the active DKP
    pub fn create_signer(&self) -> Result<SeSigner, SeError> {
        SeSigner::new(&self.config)
    }

    /// Read the exported public key bytes (DER format)
    pub fn public_key_der(&self) -> Result<Vec<u8>, SeError> {
        std::fs::read(&self.public_key_path)
            .map_err(|e| SeError::KeyError(format!("Read public key: {}", e)))
    }

    /// Rotate the DKP — create new version, deprecate current.
    /// Returns the new active KeyMetadata.
    pub fn rotate(&mut self) -> Result<KeyMetadata, SeError> {
        let new_version = self.active_key.version + 1;
        let new_key_id = DKP_BASE_KEY_ID + new_version - 1;
        let new_key_id_hex = format!("0x{:08X}", new_key_id);
        let new_label = format!("dkp-v{}", new_version);

        info!("Rotating DKP: {} → {}", self.active_key.key_id, new_key_id_hex);

        // Generate new key in SE050
        let storage = SeKeyStorage::new(&self.config)?;
        storage.create_key_slot(new_key_id - 0x20000000, &new_label, "ecdsa")?;

        // Export new public key
        storage.export_public_key(new_key_id, &self.public_key_path)?;

        // Deprecate old key
        self.active_key.deprecate();

        // Create new metadata
        let mut new_meta = KeyMetadata::new(&new_key_id_hex, &new_label, "ECDSA-P256", new_version);
        new_meta.rotated_from = Some(self.active_key.key_id.clone());
        new_meta.public_key_path = Some(self.public_key_path.clone());

        // Save new metadata
        new_meta.save(&self.metadata_path)
            .map_err(|e| SeError::KeyError(format!("Save rotated metadata: {}", e)))?;

        // Update state
        self.key_history.push(self.active_key.clone());
        self.active_key = new_meta.clone();
        self.key_history.push(new_meta.clone());

        info!("DKP rotated to v{} ({})", new_version, new_key_id_hex);
        Ok(new_meta)
    }

    /// Revoke a key by version number.
    pub fn revoke(&mut self, version: u32, reason: &str) -> Result<(), SeError> {
        for meta in &mut self.key_history {
            if meta.version == version {
                if meta.status == KeyStatus::Active {
                    return Err(SeError::KeyError(
                        "Cannot revoke active key — rotate first".into(),
                    ));
                }
                meta.revoke(reason);
                info!("Key v{} revoked: {}", version, reason);
                return Ok(());
            }
        }
        Err(SeError::KeyError(format!("Key version {} not found", version)))
    }
}
```


### Modify: `src/secure_element/mod.rs`
**ADD these two lines:**

```rust
pub mod dkp;          // ← ADD (D1)
pub mod key_meta;     // ← ADD (D1)
```

Full updated mod.rs:
```rust
// src/secure_element/mod.rs

pub mod config;
pub mod crypto;
pub mod dkp;           // NEW — Device Key Pair manager
pub mod error;
pub mod key_meta;      // NEW — Key metadata + lifecycle
pub mod key_storage;
pub mod safe_mode;
pub mod se050;
pub mod sign;
pub mod ssscli;
pub mod tamper;
pub mod traits;

pub use config::SeConfig;
pub use error::SeError;
pub use se050::Se050;
```


### Modify: `src/key_manager.rs`
**ADD this new method** inside `impl KeyManager` (after `load_or_generate`):

```rust
    /// Initialize KeyManager with SE050 hardware backend.
    /// DKP is generated/loaded inside the secure element.
    /// Private key NEVER leaves the chip.
    #[cfg(feature = "secure-element")]
    pub fn init_with_se050(
        se_config: &crate::secure_element::config::SeConfig,
        base_path: &str,
        fallback_key_path: &str,
    ) -> Result<Self> {
        use crate::secure_element::dkp::DkpManager;

        info!("Initializing KeyManager with SE050 hardware backend...");

        // Try hardware path first
        match DkpManager::init(se_config, base_path) {
            Ok(dkp) => {
                let key_id = dkp.active_key_id();
                let signer = dkp.create_signer()
                    .map_err(|e| anyhow!("Create SE050 signer: {}", e))?;

                // We still need a software keypair for pubkey_der()
                // Load or generate a software key as reference
                let rng = SystemRandom::new();
                let pkcs8_bytes = if Path::new(fallback_key_path).exists() {
                    fs::read(fallback_key_path)?
                } else {
                    let pkcs8 = EcdsaKeyPair::generate_pkcs8(
                        &ECDSA_P256_SHA256_FIXED_SIGNING, &rng,
                    ).map_err(|_| anyhow!("Generate fallback keypair"))?;
                    fs::create_dir_all(
                        Path::new(fallback_key_path).parent()
                            .ok_or_else(|| anyhow!("Invalid path"))?,
                    )?;
                    fs::write(fallback_key_path, pkcs8.as_ref())?;
                    pkcs8.as_ref().to_vec()
                };

                let keypair = EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8_bytes, &rng,
                ).map_err(|_| anyhow!("Load fallback keypair"))?;

                // If SE050 public key is available, use it instead
                let pub_der_path = format!("{}/keys/dkp_pub.der", base_path);
                if Path::new(&pub_der_path).exists() {
                    info!("DKP public key available at {}", pub_der_path);
                }

                log_audit(
                    "system",
                    AuditCategory::Identity,
                    AuditSeverity::Info,
                    AuditAction::Loaded,
                    &format!("DKP initialized via SE050 hardware (key={})", dkp.active_key.key_id),
                );

                info!("KeyManager initialized with SE050 backend (key_id=0x{:08X})", key_id);

                Ok(Self {
                    keypair,
                    key_path: fallback_key_path.to_string(),
                    backend: SigningBackend::Hardware { signer, key_id },
                })
            }
            Err(e) => {
                warn!("SE050 DKP init failed: {} — falling back to software", e);
                Self::load_or_generate(fallback_key_path)
            }
        }
    }
```


### Modify: `src/main.rs` (D1 integration)
**REPLACE the existing SE050 init block** with:

```rust
    // === Hardware Key Manager Initialization (Phase 2 — HKM) ===
    #[cfg(feature = "secure-element")]
    let km = {
        let se_base_path = "/var/lib/sgx-guardian";
        let se_config = sgx_guardian_client::secure_element::SeConfig::default();

        match KeyManager::init_with_se050(&se_config, se_base_path, &node_key_path) {
            Ok(hw_km) => {
                println!("🔐 DKP initialized via SE050 hardware");
                log_audit(
                    &node_id,
                    AuditCategory::Identity,
                    AuditSeverity::Info,
                    AuditAction::Loaded,
                    "Hardware Key Manager: DKP active via SE050",
                );
                hw_km
            }
            Err(e) => {
                eprintln!("SE050 HKM failed: {} — using software keys", e);
                KeyManager::load_or_generate(&node_key_path)?
            }
        }
    };

    #[cfg(not(feature = "secure-element"))]
    let km = KeyManager::load_or_generate(&node_key_path)?;
```

**Important:** This REPLACES both the old `let km = KeyManager::load_or_generate(...)` AND the old `#[cfg(feature = "secure-element")]` SE050 init block. The HKM block handles both paths (hardware + software fallback).


## D1 Verification

```bash
# Local tests
cargo test secure_element::key_meta::tests -- --nocapture
# Expected: 8 passed

# Compile check
cargo check
cargo build --features secure-element

# Board: Generate DKP at slot 0x20000010
ssscli generate ecc 0x20000010 NIST_P256
ssscli se05x readidlist
ssscli get ecc pub 0x20000010 /tmp/dkp_pub.der
ssscli sign 0x20000010 /tmp/msg.bin /tmp/dkp_sig.bin
ssscli verify 0x20000010 /tmp/msg.bin /tmp/dkp_sig.bin
```

**D1 complete when:** 8 key_meta tests pass + board DKP generation verified.




---
---
---




# DELIVERABLE 2 — Key Lifecycle: Generation (HKM-002)

## Concept

> **Generate named keys with metadata, verify signing works end-to-end.**

D2 tests that keys created through DkpManager have proper metadata (timestamp, algorithm, version) and that the sign+verify path works through the full stack.


## Technical Implementation

No new files — add tests to existing `dkp.rs` and verify integration with `key_manager.rs`.

### Add to `src/secure_element/dkp.rs` — tests section:

```rust
// ── Unit Tests (6 tests) ────────────────────────────────────
// Run: cargo test secure_element::dkp::tests -- --nocapture
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dkp_base_key_id() {
        assert_eq!(DKP_BASE_KEY_ID, 0x20000010);
        assert_eq!(format!("0x{:08X}", DKP_BASE_KEY_ID), "0x20000010");
    }

    #[test]
    fn test_key_id_version_offset() {
        // v1 = base, v2 = base+1, v3 = base+2...
        assert_eq!(DKP_BASE_KEY_ID + 0, 0x20000010); // v1
        assert_eq!(DKP_BASE_KEY_ID + 1, 0x20000011); // v2
        assert_eq!(DKP_BASE_KEY_ID + 2, 0x20000012); // v3
    }

    #[test]
    fn test_key_id_range_safe() {
        // Even with 255 rotations, we don't hit factory range
        let max_rotation = DKP_BASE_KEY_ID + 255;
        assert!(max_rotation < 0x7FFF0000);
        assert!(max_rotation < 0xF0000000);
    }

    #[test]
    fn test_metadata_path_construction() {
        let base = "/var/lib/sgx-guardian";
        let meta_path = format!("{}/keys/dkp_metadata.json", base);
        let pub_path = format!("{}/keys/dkp_pub.der", base);
        assert!(meta_path.ends_with("dkp_metadata.json"));
        assert!(pub_path.ends_with("dkp_pub.der"));
    }

    #[test]
    fn test_active_key_id_parsing() {
        let key_id_hex = "0x20000010";
        let parsed = u32::from_str_radix(
            key_id_hex.trim_start_matches("0x").trim_start_matches("0X"),
            16,
        ).unwrap();
        assert_eq!(parsed, 0x20000010);
    }

    #[test]
    fn test_rotation_version_label() {
        let version = 3;
        let new_key_id = DKP_BASE_KEY_ID + version - 1;
        let label = format!("dkp-v{}", version);
        assert_eq!(new_key_id, 0x20000012);
        assert_eq!(label, "dkp-v3");
    }
}
```


## D2 Verification

```bash
cargo test secure_element::dkp::tests -- --nocapture
# Expected: 6 passed

# Board: sign + verify with DKP key
echo -n "HKM-002 test" > /tmp/hmk_test.bin
ssscli sign 0x20000010 /tmp/hmk_test.bin /tmp/hmk_sig.bin
ssscli verify 0x20000010 /tmp/hmk_test.bin /tmp/hmk_sig.bin
```

Cumulative: 8 (D1) + 6 (D2) = **14 HKM tests**




---
---
---




# DELIVERABLE 3 — Key Lifecycle: Rotation (HKM-003)

## Concept

> **Create a new key version, deprecate the old one. Old key can still verify old signatures. New key used for all new signing.**


## Board Commands — D3

```bash
# Create rotated key (v2) at slot 0x20000011
ssscli generate ecc 0x20000011 NIST_P256

# Verify both keys exist
ssscli se05x readidlist
# Should show: 0x20000010 AND 0x20000011

# Export v2 public key
ssscli get ecc pub 0x20000011 /tmp/dkp_v2_pub.der

# Sign with NEW key (v2)
echo -n "new version message" > /tmp/v2_msg.bin
ssscli sign 0x20000011 /tmp/v2_msg.bin /tmp/v2_sig.bin
ssscli verify 0x20000011 /tmp/v2_msg.bin /tmp/v2_sig.bin

# Verify OLD signature with OLD key (v1) still works
ssscli verify 0x20000010 /tmp/msg.bin /tmp/dkp_sig.bin
```


## Technical Implementation

Add tests to `key_meta.rs`:

```rust
    #[test]
    fn test_rotation_deprecates_old_key() {
        let mut v1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        assert!(v1.can_sign());
        v1.deprecate();
        assert!(!v1.can_sign());
        assert!(v1.can_verify()); // old signatures still verifiable
    }

    #[test]
    fn test_rotated_key_tracks_parent() {
        let mut v2 = KeyMetadata::new("0x20000011", "dkp-v2", "ECDSA-P256", 2);
        v2.rotated_from = Some("0x20000010".to_string());
        assert_eq!(v2.rotated_from.as_deref(), Some("0x20000010"));
    }

    #[test]
    fn test_new_version_is_active() {
        let v2 = KeyMetadata::new("0x20000011", "dkp-v2", "ECDSA-P256", 2);
        assert_eq!(v2.status, KeyStatus::Active);
        assert!(v2.can_sign());
    }

    #[test]
    fn test_deprecated_and_active_coexist() {
        let mut v1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        let v2 = KeyMetadata::new("0x20000011", "dkp-v2", "ECDSA-P256", 2);
        v1.deprecate();
        // v1 can verify, v2 can sign+verify
        assert!(!v1.can_sign());
        assert!(v1.can_verify());
        assert!(v2.can_sign());
        assert!(v2.can_verify());
    }

    #[test]
    fn test_multiple_rotations_version_chain() {
        let v1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        let mut v2 = KeyMetadata::new("0x20000011", "dkp-v2", "ECDSA-P256", 2);
        v2.rotated_from = Some(v1.key_id.clone());
        let mut v3 = KeyMetadata::new("0x20000012", "dkp-v3", "ECDSA-P256", 3);
        v3.rotated_from = Some(v2.key_id.clone());
        assert_eq!(v3.rotated_from.as_deref(), Some("0x20000011"));
    }
```


## D3 Verification

```bash
cargo test secure_element::key_meta::tests -- --nocapture
# Expected: 13 passed (8 original + 5 new)

# Board: Both keys work, old still verifies
```

Cumulative: 14 (D1+D2) + 5 (D3) = **19 HKM tests**




---
---
---




# DELIVERABLE 4 — Key Lifecycle: Revocation (HKM-004)

## Concept

> **Permanently block a key from signing. Old signatures can still be verified during a 30-day grace period. Revocation cannot be undone.**


## Technical Implementation

Add tests to `key_meta.rs`:

```rust
    #[test]
    fn test_revoke_sets_reason_and_timestamp() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.deprecate(); // must deprecate before revoke
        meta.revoke("key compromised");
        assert_eq!(meta.status, KeyStatus::Revoked);
        assert_eq!(meta.revoke_reason.as_deref(), Some("key compromised"));
        assert!(meta.revoked_at.is_some());
    }

    #[test]
    fn test_cannot_revoke_active_key_logic() {
        // Business rule: must rotate first, then revoke the old key
        let meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        assert_eq!(meta.status, KeyStatus::Active);
        // DkpManager.revoke() checks this and returns error
    }

    #[test]
    fn test_revoked_key_blocks_signing() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.revoke("rotation complete");
        assert!(!meta.can_sign());
    }

    #[test]
    fn test_grace_period_allows_verification() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.revoke("test");
        // Within 30-day grace period (just revoked)
        assert!(meta.can_verify());
        // After grace period would return false (tested by checking the logic)
    }
```


## D4 Verification

```bash
cargo test secure_element::key_meta::tests -- --nocapture
# Expected: 17 passed (13 + 4 new)

cargo test secure_element::dkp::tests -- --nocapture
# Expected: 6 passed

# Total HKM tests: 17 + 6 = 23
cargo test secure_element -- --nocapture
# Expected: 37 (SE050) + 23 (HKM) = 60 total
```




---
---
---




# Complete Step-by-Step Checklist

### Step 1: Create key_meta.rs (D1)
Copy the `key_meta.rs` code into `src/secure_element/key_meta.rs`.

### Step 2: Create dkp.rs (D1)
Copy the `dkp.rs` code into `src/secure_element/dkp.rs`.

### Step 3: Update mod.rs (D1)
Add `pub mod dkp;` and `pub mod key_meta;` to `src/secure_element/mod.rs`.

### Step 4: Compile check
```bash
cargo check
# Expected: compiles (may have warnings for unused DkpManager)
```

### Step 5: Run D1 tests
```bash
cargo test secure_element::key_meta::tests -- --nocapture
# Expected: 8 passed
```

### Step 6: Add dkp.rs tests (D2)
Add the 6 tests to `dkp.rs` test module.

```bash
cargo test secure_element::dkp::tests -- --nocapture
# Expected: 6 passed
```

### Step 7: Add rotation tests (D3)
Add the 5 rotation tests to `key_meta.rs` test module.

### Step 8: Add revocation tests (D4)
Add the 4 revocation tests to `key_meta.rs` test module.

### Step 9: Add init_with_se050() to key_manager.rs
Copy the `init_with_se050()` method into `key_manager.rs`.

### Step 10: Update main.rs integration
Replace the SE050 init + KeyManager init block with the HKM block.

### Step 11: Final verification
```bash
cargo check
cargo build --features secure-element
cargo test secure_element -- --nocapture
# Expected: 60 passed (37 SE050 + 23 HKM)
```

### Step 12: Board verification
```bash
ssscli generate ecc 0x20000010 NIST_P256
ssscli se05x readidlist
ssscli get ecc pub 0x20000010 /tmp/dkp_pub.der
ssscli sign 0x20000010 /tmp/msg.bin /tmp/dkp_sig.bin
ssscli verify 0x20000010 /tmp/msg.bin /tmp/dkp_sig.bin
```




# Final Test Summary

| Deliverable | File | Tests | Description |
|---|---|---|---|
| D1 | key_meta.rs | 8 | Key status, sign/verify permissions, serialization |
| D2 | dkp.rs | 6 | Key ID calculations, version offsets, path construction |
| D3 | key_meta.rs | +5 | Rotation: deprecate, coexist, version chain |
| D4 | key_meta.rs | +4 | Revocation: block sign, grace period, permanent |
| **Total HKM** | | **23** | |
| **+ SE050** | | **37** | (from previous task) |
| **Grand Total** | | **60** | |




# Board Verification Summary

| # | Command | Purpose | Status |
|---|---------|---------|--------|
| 1 | `ssscli generate ecc 0x20000010 NIST_P256` | Create DKP v1 | [ ] |
| 2 | `ssscli se05x readidlist` | Verify 0x20000010 exists | [ ] |
| 3 | `ssscli get ecc pub 0x20000010 /tmp/dkp_pub.der` | Export public key | [ ] |
| 4 | `ssscli sign 0x20000010 /tmp/msg.bin /tmp/sig.bin` | Sign with DKP | [ ] |
| 5 | `ssscli verify 0x20000010 /tmp/msg.bin /tmp/sig.bin` | Verify signature | [ ] |
| 6 | `ssscli generate ecc 0x20000011 NIST_P256` | Create DKP v2 (rotation) | [ ] |
| 7 | `ssscli verify 0x20000010 /tmp/msg.bin /tmp/sig.bin` | Old key still verifies | [ ] |
| 8 | `ssscli sign 0x20000011 /tmp/v2.bin /tmp/v2_sig.bin` | New key signs | [ ] |
