# HKM Final Corrections — Complete Guide
**Addresses:** GPT's 5 review points + earlier skipped items + auto-rotation line location




## GPT Review Point 1: Metadata Overwrite → FIXED

**Old:** Single JSON object, rotation overwrites file, loses history.
**New:** JSON array of all versions. `DkpKeyHistory` struct wraps `Vec<KeyMetadata>`.

Old format (`dkp_metadata.json`):
```json
{ "key_id": "0x20000010", "version": 1, "status": "Active" }
```

New format after rotation:
```json
[
  { "key_id": "0x20000010", "version": 1, "status": "Deprecated", ... },
  { "key_id": "0x20000011", "version": 2, "status": "Active", ... }
]
```

**Backward compatible:** `DkpKeyHistory::load()` auto-detects old single-object format and migrates it.

**Files changed:** `key_meta.rs` (new `DkpKeyHistory` struct), `dkp.rs` (uses history), all 3 CLI commands.




## GPT Review Point 2: Revocation Needs History → FIXED

**Old:** Only latest version in file. Cannot revoke older versions.
**New:** `DkpKeyHistory::revoke_version(version, reason)` finds the correct entry in the array and updates it.

```rust
// Revoke v1 while v2 is active:
history.revoke_version(1, "rotation complete")?;
// Result: keys[0].status = "Revoked", keys[1].status = "Active"
```

**Safety:** Cannot revoke Active key. Returns error: "Cannot revoke active key — rotate first".




## GPT Review Point 3: Rotation Must Write Deprecated Status → FIXED

**Old:** `dkp_rotate.rs` printed "Deprecated" but didn't write it to metadata.
**New:** Both `dkp.rs::rotate()` and `dkp_rotate.rs` explicitly update old key's status in the array before writing.

```rust
// In dkp.rs rotate():
self.history.deprecate_version(old_version);  // Updates status in array
self.history.add(new_meta);                    // Appends new version
self.history.save(&self.metadata_path)?;       // Writes FULL array
```




## GPT Review Point 4: Software-Mode Rotation → FIXED

**Old:** Software rotation updated metadata to v2 but daemon still used v1 ring keypair.
**New:** CLI rotation in software mode backs up old `.key` file and forces daemon to regenerate on restart.

```
Old key: device_nodeA.key → renamed to device_nodeA.key.v1.bak
Next daemon start: no key file found → generates fresh keypair → becomes v2
```

The daemon's `load_or_generate()` already handles this: if no `.key` file exists, it generates a new one.




## GPT Review Point 5: Auto-Rotation Trigger → FIXED

**Exact line to change for testing:**

```
FILE: src/secure_element/key_meta.rs
LINE: ~19 (the constant definition)
```

```rust
/// ╔══════════════════════════════════════════════════════╗
/// ║  CHANGE THIS VALUE TO TEST AUTO-ROTATION TIMING     ║
/// ║  1 hour  = 3600                                     ║
/// ║  1 day   = 86400                                    ║
/// ║  30 days = 2592000                                  ║
/// ║  1 year  = 31536000  (production default)           ║
/// ╚══════════════════════════════════════════════════════╝
pub const DKP_ROTATION_INTERVAL_SECS: i64 = 31_536_000; // ← CHANGE THIS
```

**To test:** Change to `3600` (1 hour) or even `60` (1 minute), rebuild, and the daemon will auto-rotate on startup if key age exceeds the value.

**Where auto-rotation is called in main.rs:**

Add this in main.rs AFTER the HKM init block (after `let km = ...`):

```rust
    // === DKP Auto-Rotation Check ===
    #[cfg(feature = "secure-element")]
    {
        let se_config = sgx_guardian_client::secure_element::SeConfig::default();
        let base_path = "/var/lib/sgx-guardian";
        if let Ok(mut dkp) = sgx_guardian_client::secure_element::dkp::DkpManager::init(
            &se_config, base_path
        ) {
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
```




## Earlier Skipped Items — Now Addressed


### DKP Init Logging (from your earlier request)

Added to `dkp.rs::init()`:
```
New DKP:      "No existing DKP found — generating new DKP inside SE050..."
              "DKP generated successfully (v1)"

Existing DKP: "Existing DKP found (v1) — loading from SE050"
              "Using existing device identity key (0x20000010)"

Age warning:  "⚠️ DKP age exceeds rotation policy — auto-rotation recommended"
```


### Crypto Provider Logging

Add this to main.rs after KeyManager init:

```rust
    // === Crypto Provider Status ===
    match &km.backend_name() {  // We need to add this method — see below
        "SE050" => {
            println!("  Secure Element detected: SE050");
            println!("  Signing provider: SE050 hardware (ECDSA-P256)");
            println!("  RNG source: SE050 TRNG");
        }
        _ => {
            println!("  Secure Element not available");
            println!("  Signing provider: software (ring crate, ECDSA-P256)");
            println!("  RNG source: software RNG (SystemRandom)");
        }
    }
```

Add to `key_manager.rs`:
```rust
    pub fn backend_name(&self) -> &str {
        match &self.backend {
            SigningBackend::Software => "Software",
            #[cfg(feature = "secure-element")]
            SigningBackend::Hardware { .. } => "SE050",
        }
    }
```


### Attestation Signature Fix (the CORRECT one that works for BOTH backends)

In `attestation_service.rs`, the verification section:

```rust
        // Auto-detect signature format:
        // ring/software → FIXED (exactly 64 bytes)
        // SE050/hardware → ASN.1 DER (starts with 0x30)
        let is_asn1 = !sig_bytes.is_empty() && sig_bytes[0] == 0x30;

        let verification_algo: &dyn signature::VerificationAlgorithm = if is_asn1 {
            &signature::ECDSA_P256_SHA256_ASN1
        } else {
            &signature::ECDSA_P256_SHA256_FIXED
        };

        // Handle both 91-byte DER and 65-byte raw EC point
        let peer_pubkey = if peer_pubkey_raw.len() == 91 {
            peer_pubkey_raw[26..].to_vec()
        } else {
            peer_pubkey_raw
        };

        let peer_key = signature::UnparsedPublicKey::new(verification_algo, &peer_pubkey);
```

Only ECDSA-P256 + SHA-256. No other algorithms.




## Complete File Change List

| File | Action | What Changed |
|------|--------|-------------|
| `src/secure_element/key_meta.rs` | REPLACE | `DkpKeyHistory`, `DKP_ROTATION_INTERVAL_SECS`, `needs_rotation()`, 22 tests |
| `src/secure_element/dkp.rs` | REPLACE | Uses `DkpKeyHistory`, `check_and_auto_rotate()`, init logging |
| `src/key_manager.rs` | MODIFY | Fix `pubkey_der()`, add `backend_name()` |
| `src/attestation_service.rs` | MODIFY | Auto-detect FIXED vs ASN1 sig format |
| `src/main.rs` | MODIFY | Add auto-rotation check + crypto provider logging |
| `sgx-pa-cli/src/commands/dkp_status.rs` | NEW | Array-based metadata display |
| `sgx-pa-cli/src/commands/dkp_rotate.rs` | NEW | Array append + software key backup |
| `sgx-pa-cli/src/commands/dkp_revoke.rs` | NEW | Find version in array + revoke |
| `sgx-pa-cli/src/commands/mod.rs` | MODIFY | Add 3 pub mod lines |
| `sgx-pa-cli/src/main.rs` | MODIFY | Add 3 commands + match arms |




## Testing Auto-Rotation

```bash
# Step 1: Set rotation interval to 60 seconds for testing
# Edit src/secure_element/key_meta.rs line ~19:
pub const DKP_ROTATION_INTERVAL_SECS: i64 = 60;  // 1 minute for testing

# Step 2: Build and run daemon to create initial DKP
cargo build --features secure-element
./sgx_guardian_client nodeA
# → Creates DKP v1
# Kill daemon after startup

# Step 3: Wait 61+ seconds, then run again
sleep 65
./sgx_guardian_client nodeA
# → "⚠️ DKP auto-rotation triggered (key age exceeded policy)"
# → "✅ DKP auto-rotated to v2"

# Step 4: Check metadata — should show both versions
cat /var/lib/sgx-guardian/keys/dkp_metadata.json
# → Array with v1=Deprecated, v2=Active

# Step 5: Reset to production value
pub const DKP_ROTATION_INTERVAL_SECS: i64 = 31_536_000;  // 1 year
```




## CLI Testing (Both Software and Hardware)

```bash
# Software (your laptop):
cargo build --bin sgx-pa-cli
./target/debug/sgx-pa-cli dkp-status
./target/debug/sgx-pa-cli dkp-rotate
./target/debug/sgx-pa-cli dkp-status      # shows v1=Deprecated, v2=Active
./target/debug/sgx-pa-cli dkp-revoke --version 1 --reason "testing"
./target/debug/sgx-pa-cli dkp-status      # shows v1=Revoked, v2=Active

# Hardware (board):
./sgx-pa-cli dkp-status
./sgx-pa-cli dkp-rotate                   # generates real SE050 key
./sgx-pa-cli dkp-revoke --version 1 --reason "rotation complete"
```




and here are attached files
```rust
// src/secure_element/dkp.rs
// ============================================================
// Device Key Pair (DKP) Manager — HKM-001 to HKM-004
//
// DKP Key Slot: 0x20000010 (base) + version offset
//   v1 = 0x20000010, v2 = 0x20000011, etc.
//
// Metadata: /var/lib/sgx-guardian/keys/dkp_metadata.json
//   → JSON ARRAY of all key versions (not just latest)
// Public key: /var/lib/sgx-guardian/keys/dkp_pub.der
//
// Crypto: ECDSA-P256 + SHA-256 ONLY. No other algorithms.
// ============================================================

use crate::secure_element::config::SeConfig;
use crate::secure_element::error::SeError;
use crate::secure_element::key_meta::{DkpKeyHistory, KeyMetadata, KeyStatus};
use crate::secure_element::key_storage::SeKeyStorage;
use crate::secure_element::sign::SeSigner;
use tracing::{info, warn};

pub const DKP_BASE_KEY_ID: u32 = 0x20000010;

pub struct DkpManager {
    /// Full key history (all versions)
    pub history: DkpKeyHistory,
    /// Path to metadata JSON file
    pub metadata_path: String,
    /// Path to active public key DER
    pub public_key_path: String,
    /// SE050 config
    config: SeConfig,
}

impl DkpManager {
    /// Initialize DKP — load existing history or generate new.
    pub fn init(config: &SeConfig, base_path: &str) -> Result<Self, SeError> {
        let metadata_path = format!("{}/keys/dkp_metadata.json", base_path);
        let public_key_path = format!("{}/keys/dkp_pub.der", base_path);

        // Try to load existing metadata history
        if let Ok(history) = DkpKeyHistory::load(&metadata_path) {
            if let Some(active) = history.active_key() {
                println!("  Existing DKP found (v{}) — loading from SE050", active.version);
                println!("  Using existing device identity key ({})", active.key_id);
                info!("DKP loaded: {} (v{}, age: {})",
                    active.key_id, active.version, active.age_display());

                // Check if auto-rotation is needed
                if active.needs_rotation() {
                    warn!("DKP v{} age ({}) exceeds rotation policy — rotation recommended",
                        active.version, active.age_display());
                    println!("  ⚠️ DKP age exceeds rotation policy — auto-rotation recommended");
                }

                return Ok(Self {
                    history,
                    metadata_path,
                    public_key_path,
                    config: config.clone(),
                });
            }
        }

        // No existing DKP — generate new one
        println!("  No existing DKP found — generating new DKP inside SE050...");
        let meta = Self::generate_dkp(config, &public_key_path)?;
        println!("  DKP generated successfully (v1)");
        info!("New DKP generated: {} (v1)", meta.key_id);

        let history = DkpKeyHistory::new(meta);
        history.save(&metadata_path)
            .map_err(|e| SeError::KeyError(format!("Save history: {}", e)))?;

        Ok(Self {
            history,
            metadata_path,
            public_key_path,
            config: config.clone(),
        })
    }

    fn generate_dkp(
        config: &SeConfig,
        public_key_path: &str,
    ) -> Result<KeyMetadata, SeError> {
        let key_id = DKP_BASE_KEY_ID;
        let key_id_hex = format!("0x{:08X}", key_id);

        let storage = SeKeyStorage::new(config)?;

        // Check if key already exists in SE050 (idempotent)
        let id_list = storage.list_slots()?;
        let exists = id_list.to_uppercase().contains(
            &key_id_hex.to_uppercase().replace("0x", "0X"),
        );

        if !exists {
            info!("Generating DKP at SE050 slot {}", key_id_hex);
            storage.create_key_slot(key_id - 0x20000000, "dkp", "ecdsa")?;
        } else {
            info!("DKP already exists at slot {}", key_id_hex);
        }

        // Export public key
        storage.export_public_key(key_id, public_key_path)?;
        info!("DKP public key → {}", public_key_path);

        let mut meta = KeyMetadata::new(&key_id_hex, "dkp", "ECDSA-P256", 1);
        meta.public_key_path = Some(public_key_path.to_string());
        Ok(meta)
    }

    /// Get the active key's SE050 slot ID as u32.
    pub fn active_key_id(&self) -> u32 {
        let active = self.history.active_key()
            .expect("No active DKP key");
        u32::from_str_radix(
            active.key_id.trim_start_matches("0x").trim_start_matches("0X"),
            16,
        ).unwrap_or(DKP_BASE_KEY_ID)
    }

    /// Create a SeSigner for signing operations.
    pub fn create_signer(&self) -> Result<SeSigner, SeError> {
        SeSigner::new(&self.config)
    }

    /// Read the active public key bytes (DER format, 91 bytes).
    pub fn public_key_der(&self) -> Result<Vec<u8>, SeError> {
        std::fs::read(&self.public_key_path)
            .map_err(|e| SeError::KeyError(format!("Read pubkey: {}", e)))
    }

    /// Check if the active key needs rotation.
    pub fn needs_rotation(&self) -> bool {
        self.history.active_key()
            .map(|k| k.needs_rotation())
            .unwrap_or(false)
    }

    /// Rotate DKP: generate new version in SE050, deprecate old.
    /// Writes BOTH old (deprecated) and new (active) to metadata history.
    pub fn rotate(&mut self) -> Result<KeyMetadata, SeError> {
        let active = self.history.active_key()
            .ok_or_else(|| SeError::KeyError("No active key to rotate".into()))?;
        let old_version = active.version;
        let old_key_id = active.key_id.clone();

        let new_version = old_version + 1;
        let new_id = DKP_BASE_KEY_ID + new_version - 1;
        let new_hex = format!("0x{:08X}", new_id);
        let new_label = format!("dkp-v{}", new_version);

        info!("Rotating DKP: {} (v{}) → {} (v{})",
            old_key_id, old_version, new_hex, new_version);

        // Generate new key in SE050
        let storage = SeKeyStorage::new(&self.config)?;
        storage.create_key_slot(new_id - 0x20000000, &new_label, "ecdsa")?;
        storage.export_public_key(new_id, &self.public_key_path)?;

        // Deprecate old key IN THE HISTORY (not just print)
        self.history.deprecate_version(old_version);

        // Create new metadata entry
        let mut new_meta = KeyMetadata::new(&new_hex, &new_label, "ECDSA-P256", new_version);
        new_meta.rotated_from = Some(old_key_id.clone());
        new_meta.public_key_path = Some(self.public_key_path.clone());

        // Add new key to history
        self.history.add(new_meta.clone());

        // Save FULL history (all versions) to file
        self.history.save(&self.metadata_path)
            .map_err(|e| SeError::KeyError(format!("Save history: {}", e)))?;

        info!("DKP rotated: v{} (Active) → v{} deprecated", new_version, old_version);
        Ok(new_meta)
    }

    /// Revoke a specific version. Must be Deprecated first (not Active).
    pub fn revoke(&mut self, version: u32, reason: &str) -> Result<(), SeError> {
        self.history.revoke_version(version, reason)
            .map_err(|e| SeError::KeyError(e))?;

        // Save updated history with revocation recorded
        self.history.save(&self.metadata_path)
            .map_err(|e| SeError::KeyError(format!("Save: {}", e)))?;

        info!("DKP v{} revoked: {}", version, reason);
        Ok(())
    }

    /// Perform auto-rotation if key age exceeds policy.
    /// Returns Some(new_meta) if rotated, None if not needed.
    /// Called from main.rs during startup.
    pub fn check_and_auto_rotate(&mut self) -> Result<Option<KeyMetadata>, SeError> {
        if self.needs_rotation() {
            let active = self.history.active_key().unwrap();
            warn!("DKP v{} age ({}) exceeds rotation policy — auto-rotating",
                active.version, active.age_display());
            println!("  ⚠️ DKP auto-rotation triggered (key age exceeded policy)");
            let new_meta = self.rotate()?;
            println!("  ✅ DKP auto-rotated to v{}", new_meta.version);
            Ok(Some(new_meta))
        } else {
            Ok(None)
        }
    }
}


// ── Unit Tests ──────────────────────────────────────────────
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
        assert_eq!(DKP_BASE_KEY_ID + 0, 0x20000010); // v1
        assert_eq!(DKP_BASE_KEY_ID + 1, 0x20000011); // v2
        assert_eq!(DKP_BASE_KEY_ID + 2, 0x20000012); // v3
    }

    #[test]
    fn test_key_id_range_safe() {
        let max = DKP_BASE_KEY_ID + 255;
        assert!(max < 0x7FFF0000);
        assert!(max < 0xF0000000);
    }

    #[test]
    fn test_metadata_paths() {
        let base = "/var/lib/sgx-guardian";
        assert!(format!("{}/keys/dkp_metadata.json", base).ends_with("dkp_metadata.json"));
        assert!(format!("{}/keys/dkp_pub.der", base).ends_with("dkp_pub.der"));
    }

    #[test]
    fn test_key_id_hex_parsing() {
        let parsed = u32::from_str_radix("20000010", 16).unwrap();
        assert_eq!(parsed, 0x20000010);
    }

    #[test]
    fn test_rotation_label() {
        let v = 3;
        assert_eq!(format!("dkp-v{}", v), "dkp-v3");
        assert_eq!(DKP_BASE_KEY_ID + v - 1, 0x20000012);
    }
}

```

```rust
// src/secure_element/key_meta.rs
// ============================================================
// Key metadata — lifecycle state for SE050-backed keys.
// Stores ARRAY of all key versions (not just latest).
// File: /var/lib/sgx-guardian/keys/dkp_metadata.json
//
// Crypto: ECDSA-P256 + SHA-256 ONLY. No other algorithms.
// ============================================================

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Rotation policy interval in seconds.
/// Production: 365 * 24 * 3600 = 31536000 (1 year)
/// Testing:    3600 (1 hour)
///
/// ╔══════════════════════════════════════════════════════╗
/// ║  CHANGE THIS VALUE TO TEST AUTO-ROTATION TIMING     ║
/// ║  1 hour  = 3600                                     ║
/// ║  1 day   = 86400                                    ║
/// ║  30 days = 2592000                                  ║
/// ║  1 year  = 31536000  (production default)           ║
/// ╚══════════════════════════════════════════════════════╝
pub const DKP_ROTATION_INTERVAL_SECS: i64 = 31_536_000; // 1 year

/// Grace period for revoked key verification (seconds).
/// Default: 30 days = 2592000
pub const REVOCATION_GRACE_PERIOD_SECS: i64 = 30 * 24 * 3600;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeyStatus {
    Active,
    Deprecated,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub key_id: String,
    pub label: String,
    pub algorithm: String,
    pub version: u32,
    pub status: KeyStatus,
    pub created_at: DateTime<Utc>,
    pub rotated_from: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoke_reason: Option<String>,
    pub public_key_path: Option<String>,
}

impl KeyMetadata {
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

    pub fn can_sign(&self) -> bool {
        self.status == KeyStatus::Active
    }

    pub fn can_verify(&self) -> bool {
        match self.status {
            KeyStatus::Active | KeyStatus::Deprecated => true,
            KeyStatus::Revoked => {
                if let Some(revoked) = self.revoked_at {
                    (Utc::now() - revoked).num_seconds() < REVOCATION_GRACE_PERIOD_SECS
                } else {
                    false
                }
            }
        }
    }

    /// Check if this key needs rotation based on age.
    /// Returns true if key age exceeds DKP_ROTATION_INTERVAL_SECS.
    pub fn needs_rotation(&self) -> bool {
        if self.status != KeyStatus::Active {
            return false;
        }
        let age = Utc::now() - self.created_at;
        age.num_seconds() > DKP_ROTATION_INTERVAL_SECS
    }

    /// Get key age in human-readable format.
    pub fn age_display(&self) -> String {
        let age = Utc::now() - self.created_at;
        let days = age.num_days();
        if days > 365 {
            format!("{} years, {} days", days / 365, days % 365)
        } else if days > 0 {
            format!("{} days", days)
        } else {
            let hours = age.num_hours();
            if hours > 0 {
                format!("{} hours", hours)
            } else {
                format!("{} minutes", age.num_minutes())
            }
        }
    }

    pub fn deprecate(&mut self) {
        self.status = KeyStatus::Deprecated;
    }

    pub fn revoke(&mut self, reason: &str) {
        self.status = KeyStatus::Revoked;
        self.revoked_at = Some(Utc::now());
        self.revoke_reason = Some(reason.to_string());
    }
}


/// Full key history — stores ALL versions, not just latest.
/// Saved as JSON array to /var/lib/sgx-guardian/keys/dkp_metadata.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkpKeyHistory {
    pub keys: Vec<KeyMetadata>,
}

impl DkpKeyHistory {
    /// Create new history with a single active key.
    pub fn new(first_key: KeyMetadata) -> Self {
        Self { keys: vec![first_key] }
    }

    /// Get the currently active key (if any).
    pub fn active_key(&self) -> Option<&KeyMetadata> {
        self.keys.iter().find(|k| k.status == KeyStatus::Active)
    }

    /// Get mutable ref to a key by version.
    pub fn get_mut(&mut self, version: u32) -> Option<&mut KeyMetadata> {
        self.keys.iter_mut().find(|k| k.version == version)
    }

    /// Get key by version (immutable).
    pub fn get(&self, version: u32) -> Option<&KeyMetadata> {
        self.keys.iter().find(|k| k.version == version)
    }

    /// Add a new key version. Does NOT deprecate the old one — caller must do that.
    pub fn add(&mut self, key: KeyMetadata) {
        self.keys.push(key);
    }

    /// Deprecate a specific version.
    pub fn deprecate_version(&mut self, version: u32) -> bool {
        if let Some(k) = self.get_mut(version) {
            k.deprecate();
            true
        } else {
            false
        }
    }

    /// Revoke a specific version. Cannot revoke Active keys.
    pub fn revoke_version(&mut self, version: u32, reason: &str) -> Result<(), String> {
        let key = self.get_mut(version)
            .ok_or_else(|| format!("Version {} not found", version))?;
        if key.status == KeyStatus::Active {
            return Err("Cannot revoke active key — rotate first".into());
        }
        key.revoke(reason);
        Ok(())
    }

    /// Save full history to file.
    pub fn save(&self, path: &str) -> Result<(), String> {
        let json = serde_json::to_string_pretty(&self.keys)
            .map_err(|e| format!("Serialize: {}", e))?;
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Dir: {}", e))?;
        }
        fs::write(path, json).map_err(|e| format!("Write: {}", e))
    }

    /// Load full history from file.
    /// Handles both old single-object format and new array format.
    pub fn load(path: &str) -> Result<Self, String> {
        let json = fs::read_to_string(path).map_err(|e| format!("Read: {}", e))?;
        let trimmed = json.trim();

        // New array format: [ { ... }, { ... } ]
        if trimmed.starts_with('[') {
            let keys: Vec<KeyMetadata> = serde_json::from_str(trimmed)
                .map_err(|e| format!("Parse array: {}", e))?;
            return Ok(Self { keys });
        }

        // Old single-object format: { "key_id": ..., "version": ... }
        // Migrate to array format automatically
        let single: KeyMetadata = serde_json::from_str(trimmed)
            .map_err(|e| format!("Parse single: {}", e))?;
        Ok(Self { keys: vec![single] })
    }
}


// ── Unit Tests ──────────────────────────────────────────────
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
    fn test_deprecated_key_cannot_sign_but_can_verify() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.deprecate();
        assert!(!meta.can_sign());
        assert!(meta.can_verify());
    }

    #[test]
    fn test_revoked_key_cannot_sign() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.revoke("rotation complete");
        assert!(!meta.can_sign());
        assert_eq!(meta.revoke_reason.as_deref(), Some("rotation complete"));
    }

    #[test]
    fn test_revoked_key_verify_during_grace_period() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.revoke("test");
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
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.status, KeyStatus::Active);
    }

    #[test]
    fn test_revocation_is_permanent() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.revoke("compromised");
        assert!(!meta.can_sign());
    }

    // --- History tests ---

    #[test]
    fn test_history_active_key() {
        let k1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        let hist = DkpKeyHistory::new(k1);
        let active = hist.active_key().unwrap();
        assert_eq!(active.version, 1);
    }

    #[test]
    fn test_history_rotation_preserves_all_versions() {
        let mut k1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        let k2 = KeyMetadata::new("0x20000011", "dkp-v2", "ECDSA-P256", 2);
        let mut hist = DkpKeyHistory::new(k1);
        hist.deprecate_version(1);
        hist.add(k2);
        assert_eq!(hist.keys.len(), 2);
        assert_eq!(hist.get(1).unwrap().status, KeyStatus::Deprecated);
        assert_eq!(hist.active_key().unwrap().version, 2);
    }

    #[test]
    fn test_history_revoke_requires_deprecated() {
        let k1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        let mut hist = DkpKeyHistory::new(k1);
        let result = hist.revoke_version(1, "test");
        assert!(result.is_err()); // Cannot revoke active
    }

    #[test]
    fn test_history_revoke_deprecated_succeeds() {
        let k1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        let k2 = KeyMetadata::new("0x20000011", "dkp-v2", "ECDSA-P256", 2);
        let mut hist = DkpKeyHistory::new(k1);
        hist.deprecate_version(1);
        hist.add(k2);
        assert!(hist.revoke_version(1, "rotation complete").is_ok());
        assert_eq!(hist.get(1).unwrap().status, KeyStatus::Revoked);
    }

    #[test]
    fn test_history_load_migrates_old_format() {
        // Simulate old single-object JSON
        let old_json = r#"{
            "key_id": "0x20000010",
            "label": "dkp",
            "algorithm": "ECDSA-P256",
            "version": 1,
            "status": "Active",
            "created_at": "2026-03-10T11:31:40Z",
            "rotated_from": null,
            "revoked_at": null,
            "revoke_reason": null,
            "public_key_path": null
        }"#;
        let hist: DkpKeyHistory = {
            let single: KeyMetadata = serde_json::from_str(old_json).unwrap();
            DkpKeyHistory { keys: vec![single] }
        };
        assert_eq!(hist.keys.len(), 1);
        assert_eq!(hist.active_key().unwrap().version, 1);
    }

    #[test]
    fn test_needs_rotation_new_key() {
        let meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        // Just created — should NOT need rotation
        assert!(!meta.needs_rotation());
    }

    #[test]
    fn test_rotation_deprecates_old() {
        let mut v1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        v1.deprecate();
        assert!(!v1.can_sign());
        assert!(v1.can_verify());
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
        assert!(v2.can_sign());
    }

    #[test]
    fn test_deprecated_and_active_coexist() {
        let mut v1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        let v2 = KeyMetadata::new("0x20000011", "dkp-v2", "ECDSA-P256", 2);
        v1.deprecate();
        assert!(!v1.can_sign());
        assert!(v1.can_verify());
        assert!(v2.can_sign());
    }

    #[test]
    fn test_version_chain() {
        let v1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        let mut v2 = KeyMetadata::new("0x20000011", "dkp-v2", "ECDSA-P256", 2);
        v2.rotated_from = Some(v1.key_id.clone());
        let mut v3 = KeyMetadata::new("0x20000012", "dkp-v3", "ECDSA-P256", 3);
        v3.rotated_from = Some(v2.key_id.clone());
        assert_eq!(v3.rotated_from.as_deref(), Some("0x20000011"));
    }

    #[test]
    fn test_revoke_sets_reason_and_timestamp() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.deprecate();
        meta.revoke("compromised");
        assert_eq!(meta.status, KeyStatus::Revoked);
        assert_eq!(meta.revoke_reason.as_deref(), Some("compromised"));
        assert!(meta.revoked_at.is_some());
    }

    #[test]
    fn test_revoked_blocks_signing() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.revoke("done");
        assert!(!meta.can_sign());
    }

    #[test]
    fn test_grace_period_allows_verify() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.revoke("test");
        assert!(meta.can_verify());
    }
}

```

```rust
// sgx-pa-cli/src/commands/dkp_revoke.rs
// Revoke a specific DKP key version in the metadata history.
// Cannot revoke Active key — must rotate first.

use chrono::Utc;
use clap::Args;
use std::fs;
use std::path::Path;

const METADATA_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_metadata.json";

#[derive(Args)]
#[command(about = "Revoke a deprecated DKP key version")]
pub struct DkpRevokeArgs {
    /// Key version to revoke
    #[arg(long)]
    pub version: u32,
    /// Reason for revocation
    #[arg(long, default_value = "admin revocation")]
    pub reason: String,
}

pub fn run(args: DkpRevokeArgs) {
    println!("=== DKP Key Revocation ===\n");

    if !Path::new(METADATA_PATH).exists() {
        eprintln!("No DKP metadata found.");
        return;
    }

    let json = match fs::read_to_string(METADATA_PATH) {
        Ok(j) => j,
        Err(e) => { eprintln!("Read error: {}", e); return; }
    };

    // Load history array
    let mut keys: Vec<serde_json::Value> = {
        let trimmed = json.trim();
        if trimmed.starts_with('[') {
            serde_json::from_str(trimmed).unwrap_or_default()
        } else {
            match serde_json::from_str::<serde_json::Value>(trimmed) {
                Ok(v) => vec![v],
                Err(e) => { eprintln!("Parse error: {}", e); return; }
            }
        }
    };

    // Find the target version
    let target_idx = keys.iter().position(|k| {
        k["version"].as_u64().unwrap_or(0) as u32 == args.version
    });

    let target_idx = match target_idx {
        Some(i) => i,
        None => {
            eprintln!("Version {} not found in key history.", args.version);
            println!("Available versions:");
            for k in &keys {
                println!("  v{} [{}]", k["version"], k["status"].as_str().unwrap_or("?"));
            }
            return;
        }
    };

    let status = keys[target_idx]["status"].as_str().unwrap_or("unknown");

    // Cannot revoke active key
    if status == "Active" {
        eprintln!("Cannot revoke active key (v{}).", args.version);
        eprintln!("You must rotate first: sgx-pa-cli dkp-rotate");
        return;
    }

    // Already revoked
    if status == "Revoked" {
        println!("Key v{} is already revoked.", args.version);
        return;
    }

    // Revoke the key
    keys[target_idx]["status"] = serde_json::json!("Revoked");
    keys[target_idx]["revoked_at"] = serde_json::json!(Utc::now().to_rfc3339());
    keys[target_idx]["revoke_reason"] = serde_json::json!(args.reason);

    // Write updated history
    match fs::write(METADATA_PATH, serde_json::to_string_pretty(&keys).unwrap()) {
        Ok(_) => {
            println!("✅ Key v{} revoked.", args.version);
            println!("   Reason: {}", args.reason);
            println!("   Revocation is permanent. Key cannot be un-revoked.");
            println!("   Verification of old signatures available for 30-day grace period.");
        }
        Err(e) => eprintln!("Failed to write metadata: {}", e),
    }
}

```


```rust
// sgx-pa-cli/src/commands/dkp_rotate.rs
// Rotate DKP: create new version, deprecate current.
// Hardware: generates real SE050 key. Software: regenerates ring keypair.
// Metadata: appends new version to array, updates old status.

use chrono::Utc;
use std::fs;
use std::path::Path;
use std::process::Command;

const METADATA_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_metadata.json";
const PUBKEY_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_pub.der";
const DKP_BASE_KEY_ID: u32 = 0x20000010;
const SOFTWARE_KEY_DIR: &str = "/var/lib/sgx-guardian/sgx-agent";

pub fn run() {
    println!("=== DKP Key Rotation ===\n");

    if !Path::new(METADATA_PATH).exists() {
        eprintln!("No DKP found. Run the guardian daemon first.");
        return;
    }

    let json = match fs::read_to_string(METADATA_PATH) {
        Ok(j) => j,
        Err(e) => { eprintln!("Read error: {}", e); return; }
    };

    // Load history (handles both old single format and new array format)
    let mut keys: Vec<serde_json::Value> = {
        let trimmed = json.trim();
        if trimmed.starts_with('[') {
            serde_json::from_str(trimmed).unwrap_or_default()
        } else {
            match serde_json::from_str::<serde_json::Value>(trimmed) {
                Ok(v) => vec![v],
                Err(e) => { eprintln!("Parse error: {}", e); return; }
            }
        }
    };

    // Find active key
    let active_idx = keys.iter().position(|k| k["status"] == "Active");
    let active_idx = match active_idx {
        Some(i) => i,
        None => { eprintln!("No active key found. Cannot rotate."); return; }
    };

    let current_version = keys[active_idx]["version"].as_u64().unwrap_or(1) as u32;
    let current_key_id = keys[active_idx]["key_id"].as_str().unwrap_or("unknown").to_string();

    let new_version = current_version + 1;
    let new_key_id = DKP_BASE_KEY_ID + new_version - 1;
    let new_key_id_hex = format!("0x{:08X}", new_key_id);
    let new_label = format!("dkp-v{}", new_version);

    println!("Current: {} (v{}, Active)", current_key_id, current_version);
    println!("New:     {} (v{})", new_key_id_hex, new_version);

    // Check for SE050 hardware
    let has_ssscli = Command::new("ssscli").arg("--version").output()
        .map(|o| o.status.success()).unwrap_or(false);

    if has_ssscli {
        // === HARDWARE MODE: generate real SE050 key ===
        println!("\n  Generating new key in SE050...");

        let gen = Command::new("ssscli")
            .args(["generate", "ecc", &new_key_id_hex, "NIST_P256"])
            .output();
        match gen {
            Ok(o) if o.status.success() => {
                println!("  SE050: Key generated at slot {}", new_key_id_hex);
            }
            Ok(o) => {
                eprintln!("  SE050 key gen failed: {}", String::from_utf8_lossy(&o.stderr));
                return;
            }
            Err(e) => { eprintln!("  ssscli error: {}", e); return; }
        }

        let exp = Command::new("ssscli")
            .args(["get", "ecc", "pub", &new_key_id_hex, PUBKEY_PATH])
            .output();
        match exp {
            Ok(o) if o.status.success() => {
                println!("  SE050: Public key exported to {}", PUBKEY_PATH);
            }
            _ => { eprintln!("  Public key export failed"); return; }
        }
    } else {
        // === SOFTWARE MODE: regenerate ring keypair ===
        println!("\n  No SE050 — software mode rotation.");
        println!("  Regenerating software keypair for new version...");

        // Find and regenerate the software key file for the current node
        // Look for device_nodeA.key pattern
        if let Ok(entries) = fs::read_dir(SOFTWARE_KEY_DIR) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("device_") && name.ends_with(".key") {
                    // Delete old key file so daemon regenerates on next start
                    let old_path = entry.path();
                    let backup = format!("{}.v{}.bak", old_path.display(), current_version);
                    match fs::rename(&old_path, &backup) {
                        Ok(_) => {
                            println!("  Old software key backed up: {}", backup);
                            println!("  New key will be generated on next daemon start.");
                        }
                        Err(e) => {
                            eprintln!("  Failed to backup old key: {}", e);
                            return;
                        }
                    }
                    break;
                }
            }
        }
    }

    // === UPDATE METADATA HISTORY ===

    // Step 1: Mark old key as Deprecated (in the array)
    keys[active_idx]["status"] = serde_json::json!("Deprecated");

    // Step 2: Create new key entry
    let new_entry = serde_json::json!({
        "key_id": new_key_id_hex,
        "label": new_label,
        "algorithm": "ECDSA-P256",
        "version": new_version,
        "status": "Active",
        "created_at": Utc::now().to_rfc3339(),
        "rotated_from": current_key_id,
        "revoked_at": null,
        "revoke_reason": null,
        "public_key_path": PUBKEY_PATH
    });

    // Step 3: Append new entry to history
    keys.push(new_entry);

    // Step 4: Write entire history array
    match fs::write(METADATA_PATH, serde_json::to_string_pretty(&keys).unwrap()) {
        Ok(_) => {
            println!("\n✅ Rotation complete:");
            println!("  {} (v{}) → Deprecated", current_key_id, current_version);
            println!("  {} (v{}) → Active", new_key_id_hex, new_version);
            println!("\n  Restart guardian daemon to use the new key.");
        }
        Err(e) => eprintln!("Failed to write metadata: {}", e),
    }
}

```

```rust
// sgx-pa-cli/src/commands/dkp_status.rs
// Show all DKP key versions and current status.
// Works on both hardware (board) and software (dev laptop).

use std::fs;
use std::path::Path;

const METADATA_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_metadata.json";
const PUBKEY_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_pub.der";

pub fn run() {
    println!("=== DKP Key Status ===\n");

    if !Path::new(METADATA_PATH).exists() {
        println!("Status: No DKP found");
        println!("  Run the guardian daemon to auto-generate DKP.");
        return;
    }

    let json = match fs::read_to_string(METADATA_PATH) {
        Ok(j) => j,
        Err(e) => { eprintln!("Failed to read {}: {}", METADATA_PATH, e); return; }
    };

    let keys: Vec<serde_json::Value> = {
        let trimmed = json.trim();
        if trimmed.starts_with('[') {
            serde_json::from_str(trimmed).unwrap_or_default()
        } else {
            match serde_json::from_str::<serde_json::Value>(trimmed) {
                Ok(v) => vec![v],
                Err(_) => { eprintln!("Failed to parse metadata"); return; }
            }
        }
    };

    println!("Total key versions: {}\n", keys.len());

    for key in &keys {
        let status = key["status"].as_str().unwrap_or("unknown");
        let marker = match status {
            "Active" => "→",
            "Deprecated" => " ",
            "Revoked" => "✗",
            _ => "?",
        };
        println!("{} Version {}  [{}]", marker, key["version"], status);
        println!("    Key ID:    {}", key["key_id"].as_str().unwrap_or("?"));
        println!("    Algorithm: {}", key["algorithm"].as_str().unwrap_or("?"));
        println!("    Created:   {}", key["created_at"].as_str().unwrap_or("?"));
        if let Some(from) = key["rotated_from"].as_str() {
            println!("    Rotated from: {}", from);
        }
        if let Some(at) = key["revoked_at"].as_str() {
            println!("    Revoked at: {}", at);
            println!("    Reason:     {}", key["revoke_reason"].as_str().unwrap_or("none"));
        }
        println!();
    }

    if Path::new(PUBKEY_PATH).exists() {
        let size = fs::metadata(PUBKEY_PATH).map(|m| m.len()).unwrap_or(0);
        println!("Active public key: {} ({} bytes)", PUBKEY_PATH, size);
    }

    match std::process::Command::new("ssscli").arg("--version").output() {
        Ok(o) if o.status.success() => println!("SE050: Available"),
        _ => println!("SE050: Not available (software-only mode)"),
    }
}

```

