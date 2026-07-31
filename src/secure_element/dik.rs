// src/secure_element/dik.rs
// ============================================================
// Device Identity Key (DIK) — PERMANENT, NON-ROTATING.
//
// Slot: 0x20000100 (fixed; distinct from DKP 0x20000010).
// Purpose: sole cryptographic anchor for did:guardian.
// NEVER rotated. NEVER used for operational signing.
// ============================================================

use crate::secure_element::config::SeConfig;
use crate::secure_element::error::SeError;
use crate::secure_element::key_storage::SeKeyStorage;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub const DIK_KEY_ID: u32 = 0x20000100;
pub const DIK_PUB_PATH: &str = "/var/lib/sgx-guardian/keys/dik_pub.der";
pub const DIK_META_PATH: &str = "/var/lib/sgx-guardian/keys/dik_metadata.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DikMetadata {
    pub key_id: String,
    pub algorithm: String,
    pub created_at: String,
    pub non_rotating: bool,
    pub purpose: String,
}

pub struct DeviceIdentityKey;

impl DeviceIdentityKey {
    /// Idempotent. Returns DIK public key DER.
    /// - Slot present: re-export + ensure metadata.
    /// - Slot absent and no metadata: create once.
    /// - Slot absent but metadata exists: hard error (avoid identity split).
    /// - SE unreachable: use cached DIK pubkey if available.
    pub fn ensure(config: &SeConfig) -> Result<Vec<u8>, SeError> {
        let dik_key_id = config.dik_key_id;
        let key_hex = format!("0x{:08X}", dik_key_id);
        let probe = Self::probe_slot(config, &key_hex, 4);
        let pub_path = Self::pub_path();
        let pub_path_str = pub_path.to_string_lossy().to_string();
        let meta_path = Self::meta_path();

        match probe {
            Some(true) => {
                if let Ok(store) = SeKeyStorage::new(config) {
                    let _ = store.export_public_key(dik_key_id, &pub_path_str);
                }
                Self::ensure_metadata(&meta_path, dik_key_id);
                Self::read_pub_or_err(&pub_path)
            }
            Some(false) => {
                if meta_path.exists() {
                    warn!(
                        "DIK metadata exists but SE050 slot {} is ABSENT; refusing to re-provision",
                        key_hex
                    );
                    return Err(SeError::KeyError(
                        "DIK slot missing but metadata present — manual recovery required".into(),
                    ));
                }

                info!(
                    "Provisioning Device Identity Key (DIK) once at {} (slot was free)",
                    key_hex
                );
                let store = SeKeyStorage::new(config)?;
                store.create_key_slot(dik_key_id - 0x20000000, "dik", "ecdsa")?;
                store.export_public_key(dik_key_id, &pub_path_str)?;
                Self::write_metadata(&meta_path, dik_key_id);
                Self::read_pub_or_err(&pub_path)
            }
            None => {
                if pub_path.exists() {
                    warn!(
                        "SE050 unreachable — using cached DIK pubkey {} (DID remains stable)",
                        pub_path.display()
                    );
                    Self::read_pub_or_err(&pub_path)
                } else {
                    Err(SeError::NotAvailable)
                }
            }
        }
    }

    fn probe_slot(config: &SeConfig, key_hex: &str, attempts: u8) -> Option<bool> {
        for _ in 0..attempts {
            if let Ok(store) = SeKeyStorage::new(config) {
                if let Ok(list) = store.list_slots() {
                    return Some(list.to_uppercase().contains(&key_hex.to_uppercase()));
                }
            }

            if let Some(home) = std::env::var_os("HOME") {
                let home = home.to_string_lossy().to_string();
                for candidate in [
                    format!("{}/.ssscli_session.pkl", home),
                    format!("{}/~.ssscli_session.pkl", home),
                    "/root/~.ssscli_session.pkl".to_string(),
                ] {
                    let _ = std::fs::remove_file(&candidate);
                }
            }
        }
        None
    }

    fn write_metadata(path: &Path, dik_key_id: u32) {
        let meta = DikMetadata {
            key_id: format!("0x{:08X}", dik_key_id),
            algorithm: "ECDSA-P256".into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            non_rotating: true,
            purpose: "did:guardian anchor only".into(),
        };
        if let Ok(j) = serde_json::to_string_pretty(&meta) {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(path, j);
        }
    }

    fn ensure_metadata(path: &Path, dik_key_id: u32) {
        if !path.exists() {
            Self::write_metadata(path, dik_key_id);
        }
    }

    fn read_pub_or_err(path: &Path) -> Result<Vec<u8>, SeError> {
        std::fs::read(path)
            .map_err(|e| SeError::KeyError(format!("Read DIK pubkey {}: {}", path.display(), e)))
    }

    fn guardian_home() -> PathBuf {
        std::env::var("SGX_GUARDIAN_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/var/lib/sgx-guardian"))
    }

    fn pub_path() -> PathBuf {
        match std::env::var("SGX_DIK_PUB_PATH") {
            Ok(p) => PathBuf::from(p),
            Err(_) => Self::guardian_home().join("keys/dik_pub.der"),
        }
    }

    fn meta_path() -> PathBuf {
        match std::env::var("SGX_DIK_META_PATH") {
            Ok(p) => PathBuf::from(p),
            Err(_) => Self::guardian_home().join("keys/dik_metadata.json"),
        }
    }
}
