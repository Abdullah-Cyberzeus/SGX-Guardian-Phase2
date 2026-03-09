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
use tracing::info;

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
            self.active_key
                .key_id
                .trim_start_matches("0x")
                .trim_start_matches("0X"),
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

        info!(
            "Rotating DKP: {} → {}",
            self.active_key.key_id, new_key_id_hex
        );

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
        new_meta
            .save(&self.metadata_path)
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
        Err(SeError::KeyError(format!(
            "Key version {} not found",
            version
        )))
    }
}

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
        assert_eq!(DKP_BASE_KEY_ID, 0x20000010); // v1
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
        )
        .unwrap();
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
