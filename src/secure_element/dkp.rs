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
use crate::secure_element::key_meta::{DkpKeyHistory, KeyMetadata};
use crate::secure_element::key_storage::SeKeyStorage;
use crate::secure_element::sign::SeSigner;
use std::path::Path;
use tracing::{info, warn};

pub const DKP_BASE_KEY_ID: u32 = 0x20000010;

/// Probe the SE050 for a slot with bounded retries. Between attempts, clear
/// the stale ssscli session pickle so connect() re-establishes a fresh
/// session (equivalent to the board's reset_ssscli.sh). Returns:
///   Some(true)  = slot confirmed present
///   Some(false) = chip reachable, slot confirmed absent
///   None        = could not reach the chip after all retries (UNKNOWN)
fn probe_slot_with_retry(config: &SeConfig, slot_hex: &str, attempts: u8) -> Option<bool> {
    for attempt in 1..=attempts {
        match SeKeyStorage::new(config) {
            Ok(store) => match store.list_slots() {
                Ok(list) => {
                    return Some(list.to_uppercase().contains(&slot_hex.to_uppercase()));
                }
                Err(e) => {
                    warn!(
                        "SE050 readidlist attempt {}/{} failed: {}",
                        attempt, attempts, e
                    );
                }
            },
            Err(e) => {
                warn!(
                    "SE050 connect attempt {}/{} failed: {}",
                    attempt, attempts, e
                );
            }
        }
        // Clear stale session pickle so the next connect() is clean.
        // ssscli writes ~/.ssscli_session.pkl (note the leading char varies
        // by ssscli version: "~.ssscli_session.pkl" on these boards).
        if let Some(home) = std::env::var_os("HOME") {
            let home = home.to_string_lossy().to_string();
            for candidate in [
                format!("{}/.ssscli_session.pkl", home),
                format!("{}/~.ssscli_session.pkl", home),
                format!("{}/~.ssscli_session.pkl", "/root"),
            ] {
                let _ = std::fs::remove_file(&candidate);
            }
        }
    }
    None
}

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
                let slot_hex = active.key_id.clone();

                // Three-state probe (Fix 1): distinguish a TRANSIENT SE050 read
                // failure from a GENUINELY-ABSENT slot. A network flap on a
                // CA/lighthouse node contends the ssscli/I2C session; a momentary
                // Err here previously caused the DKP to be regenerated, which
                // changed the device identity key and cascaded into DID mismatch
                // and baseline-signature invalidation across the whole mesh.
                enum SlotProbe {
                    Present,
                    Absent,
                    Unknown,
                }
                let probe = match probe_slot_with_retry(config, &slot_hex, 4) {
                    Some(true) => SlotProbe::Present,
                    Some(false) => SlotProbe::Absent,
                    None => SlotProbe::Unknown,
                };

                // Only a CONFIRMED-absent slot (chip talked to us and the key
                // is genuinely gone) justifies quarantining metadata and
                // re-provisioning. Unknown = keep the existing key, sign via
                // the slot the metadata points at; dkp_pub.der is already on
                // disk from original provisioning.
                if let SlotProbe::Absent = probe {
                    warn!(
                        "DKP metadata claims slot {} but SE050 confirms it is ABSENT — \
                         treating as fresh provisioning",
                        slot_hex
                    );
                    let quarantine =
                        format!("{}.stale.{}", metadata_path, chrono::Utc::now().timestamp());
                    let _ = std::fs::rename(&metadata_path, &quarantine);
                    // Fall through to fresh-provision branch below.
                } else {
                    if let SlotProbe::Unknown = probe {
                        println!(
                            "  ⚠️ SE050 not reachable this boot — keeping existing DKP \
                             (v{}) from metadata (no regeneration)",
                            active.version
                        );
                    }
                    println!(
                        "  Existing DKP found (v{}) — loading from SE050",
                        active.version
                    );
                    println!("  Using existing device identity key ({})", active.key_id);
                    info!(
                        "DKP loaded: {} (v{}, age: {})",
                        active.key_id,
                        active.version,
                        active.age_display()
                    );

                    if active.needs_rotation() {
                        warn!(
                            "DKP v{} age ({}) exceeds rotation policy — rotation recommended",
                            active.version,
                            active.age_display()
                        );
                        println!(
                            "  ⚠️ DKP age exceeds rotation policy — auto-rotation recommended"
                        );
                    }

                    return Ok(Self {
                        history,
                        metadata_path,
                        public_key_path,
                        config: config.clone(),
                    });
                }
            }
        }

        // Fix 5: before provisioning a brand-new DKP, try to restore a
        // metadata file that a previous (buggy) boot quarantined. If the
        // public key DER is still intact on disk, the SE050 slot almost
        // certainly still holds the original key — regenerating would
        // permanently change the device identity and break the DID/baseline.
        if !Path::new(&metadata_path).exists() {
            if let Some(parent) = Path::new(&metadata_path).parent() {
                if let Ok(entries) = std::fs::read_dir(parent) {
                    let mut quarantines: Vec<std::path::PathBuf> = entries
                        .flatten()
                        .map(|e| e.path())
                        .filter(|p| {
                            p.file_name()
                                .and_then(|n| n.to_str())
                                .map(|n| n.starts_with("dkp_metadata.json.stale."))
                                .unwrap_or(false)
                        })
                        .collect();
                    quarantines.sort();
                    if let Some(newest) = quarantines.last() {
                        let pub_ok = std::fs::metadata(&public_key_path)
                            .map(|m| m.len() == 91)
                            .unwrap_or(false);
                        if pub_ok {
                            if std::fs::rename(newest, &metadata_path).is_ok() {
                                println!(
                                    "  ♻️ Restored quarantined DKP metadata ({:?}) — \
                                     pubkey intact, NOT regenerating",
                                    newest.file_name().unwrap_or_default()
                                );
                                if let Ok(history) = DkpKeyHistory::load(&metadata_path) {
                                    if history.active_key().is_some() {
                                        return Ok(Self {
                                            history,
                                            metadata_path,
                                            public_key_path,
                                            config: config.clone(),
                                        });
                                    }
                                }
                            }
                        } else {
                            warn!(
                                "Quarantined DKP metadata found but dkp_pub.der is \
                                 missing/short — cannot safely restore, will provision"
                            );
                        }
                    }
                }
            }
        }

        // No existing DKP — generate new one
        println!("  No existing DKP found — generating new DKP inside SE050...");
        let meta = Self::generate_dkp(config, &public_key_path)?;
        println!("  DKP generated successfully (v1)");
        info!("New DKP generated: {} (v1)", meta.key_id);

        let history = DkpKeyHistory::new(meta);
        history
            .save(&metadata_path)
            .map_err(|e| SeError::KeyError(format!("Save history: {}", e)))?;

        Ok(Self {
            history,
            metadata_path,
            public_key_path,
            config: config.clone(),
        })
    }

    fn generate_dkp(config: &SeConfig, public_key_path: &str) -> Result<KeyMetadata, SeError> {
        let key_id = DKP_BASE_KEY_ID;
        let key_id_hex = format!("0x{:08X}", key_id);

        let storage = SeKeyStorage::new(config)?;

        // Check if key already exists in SE050 (idempotent)
        let id_list = storage.list_slots()?;
        let exists = id_list.to_uppercase().contains(&key_id_hex.to_uppercase());

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
        let active = self.history.active_key().expect("No active DKP key");
        u32::from_str_radix(
            active
                .key_id
                .trim_start_matches("0x")
                .trim_start_matches("0X"),
            16,
        )
        .unwrap_or(DKP_BASE_KEY_ID)
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
        self.history
            .active_key()
            .map(|k| k.needs_rotation())
            .unwrap_or(false)
    }

    /// Rotate DKP: generate new version in SE050, deprecate old.
    /// Writes BOTH old (deprecated) and new (active) to metadata history.
    pub fn rotate(&mut self) -> Result<KeyMetadata, SeError> {
        let active = self
            .history
            .active_key()
            .ok_or_else(|| SeError::KeyError("No active key to rotate".into()))?;
        let old_version = active.version;
        let old_key_id = active.key_id.clone();

        let new_version = old_version + 1;
        let new_id = DKP_BASE_KEY_ID + new_version - 1;
        let new_hex = format!("0x{:08X}", new_id);
        let new_label = format!("dkp-v{}", new_version);

        info!(
            "Rotating DKP: {} (v{}) → {} (v{})",
            old_key_id, old_version, new_hex, new_version
        );

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
        self.history
            .save(&self.metadata_path)
            .map_err(|e| SeError::KeyError(format!("Save history: {}", e)))?;

        info!(
            "DKP rotated: v{} (Active) → v{} deprecated",
            new_version, old_version
        );
        Ok(new_meta)
    }

    /// Revoke a specific version. Must be Deprecated first (not Active).
    pub fn revoke(&mut self, version: u32, reason: &str) -> Result<(), SeError> {
        self.history
            .revoke_version(version, reason)
            .map_err(SeError::KeyError)?;

        // Save updated history with revocation recorded
        self.history
            .save(&self.metadata_path)
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
            warn!(
                "DKP v{} age ({}) exceeds rotation policy — auto-rotating",
                active.version,
                active.age_display()
            );
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
        assert_eq!(DKP_BASE_KEY_ID, 0x20000010); // v1
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
