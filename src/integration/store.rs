use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::integration::crypto::{decrypt_tokens, encrypt_tokens};
use crate::integration::provider::{
    IntegrationMetadata, IntegrationStatus, OAuthCredentials, VendorProvider,
};
use crate::storage::file_lock::SecureFileStore;
use crate::storage::resolve_data_file;

#[derive(Serialize, Deserialize, Default)]
struct EncryptedIntegrationRecord {
    pub provider: VendorProvider,
    pub name: String,
    pub status: IntegrationStatus,
    pub device_count: usize,
    pub last_synced: Option<chrono::DateTime<chrono::Utc>>,
    pub error_message: Option<String>,
    pub encrypted_credentials: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Default)]
struct IntegrationFileStore {
    pub integrations: HashMap<String, EncryptedIntegrationRecord>,
}

pub struct IntegrationStore {
    file_store: Arc<SecureFileStore>,
    file_path: PathBuf,
}

impl IntegrationStore {
    pub fn new(filename: &str) -> Self {
        let path_str = resolve_data_file(filename);
        let file_path = PathBuf::from(&path_str);
        let file_store = Arc::new(SecureFileStore::new(&path_str));

        let store = Self {
            file_store,
            file_path,
        };

        store.enforce_file_permissions();
        store
    }

    /// Enforces 0600 (read/write owner only) permissions on Unix systems
    fn enforce_file_permissions(&self) {
        if self.file_path.exists() {
            #[cfg(unix)]
            {
                if let Ok(file) = File::open(&self.file_path) {
                    let mut perms = file.metadata().unwrap().permissions();
                    perms.set_mode(0o600);
                    let _ = file.set_permissions(perms);
                }
            }
        }
    }

    /// Loads all integrations from `integrations.json` (decrypting OAuth credentials)
    pub fn load(&self) -> HashMap<VendorProvider, IntegrationMetadata> {
        let mut result = HashMap::new();

        let raw_bytes = match self.file_store.read() {
            Ok(Some(bytes)) => bytes,
            _ => return result,
        };

        let store_data: IntegrationFileStore = match serde_json::from_slice(&raw_bytes) {
            Ok(data) => data,
            Err(e) => {
                warn!("Failed to parse integrations.json: {}", e);
                return result;
            }
        };

        for (provider_key, record) in store_data.integrations {
            let mut creds = None;
            let mut kasa_creds = None;
            let mut nest_creds = None;

            if let Some(ref cipher_bytes) = record.encrypted_credentials {
                match decrypt_tokens(cipher_bytes) {
                    Ok(plain_bytes) => match record.provider {
                        VendorProvider::GoogleNest => {
                            if let Ok(parsed_nest) =
                                serde_json::from_slice::<crate::nest::NestCredentials>(&plain_bytes)
                            {
                                nest_creds = Some(parsed_nest);
                            } else if let Ok(parsed_creds) =
                                serde_json::from_slice::<OAuthCredentials>(&plain_bytes)
                            {
                                creds = Some(parsed_creds);
                            } else {
                                warn!(
                                    "Failed to parse Nest credentials for provider {}",
                                    provider_key
                                );
                            }
                        }
                        VendorProvider::TpLinkKasa => {
                            if let Ok(parsed_kasa) =
                                serde_json::from_slice::<crate::kasa::KasaCredentials>(&plain_bytes)
                            {
                                kasa_creds = Some(parsed_kasa);
                            } else {
                                warn!(
                                    "Failed to parse Kasa credentials for provider {}",
                                    provider_key
                                );
                            }
                        }
                    },
                    Err(e) => {
                        warn!("Failed to decrypt credentials for {}: {}", provider_key, e);
                    }
                }
            }

            let meta = IntegrationMetadata {
                provider: record.provider,
                name: record.name,
                status: record.status,
                device_count: record.device_count,
                last_synced: record.last_synced,
                error_message: record.error_message,
                credentials: creds,
                kasa_credentials: kasa_creds,
                nest_credentials: nest_creds,
            };

            result.insert(record.provider, meta);
        }

        println!(
            "⚙️ Loaded {} vendor integration(s) from disk.",
            result.len()
        );
        info!("Loaded {} vendor integration(s) from disk.", result.len());
        result
    }

    /// Saves all vendor integrations to `integrations.json` under `flock` atomic protection
    pub fn save(
        &self,
        integrations: &HashMap<VendorProvider, IntegrationMetadata>,
    ) -> Result<(), String> {
        let mut store_data = IntegrationFileStore::default();

        for (provider, meta) in integrations {
            let mut encrypted_creds = None;
            if let Some(ref creds) = meta.credentials {
                let json_bytes =
                    serde_json::to_vec(creds).map_err(|e| format!("Serialization error: {}", e))?;
                let cipher_bytes = encrypt_tokens(&json_bytes)?;
                encrypted_creds = Some(cipher_bytes);
            } else if let Some(ref kasa_creds) = meta.kasa_credentials {
                let json_bytes = serde_json::to_vec(kasa_creds)
                    .map_err(|e| format!("Serialization error: {}", e))?;
                let cipher_bytes = encrypt_tokens(&json_bytes)?;
                encrypted_creds = Some(cipher_bytes);
            } else if let Some(ref nest_creds) = meta.nest_credentials {
                let json_bytes = serde_json::to_vec(nest_creds)
                    .map_err(|e| format!("Serialization error: {}", e))?;
                let cipher_bytes = encrypt_tokens(&json_bytes)?;
                encrypted_creds = Some(cipher_bytes);
            }

            let record = EncryptedIntegrationRecord {
                provider: *provider,
                name: meta.name.clone(),
                status: meta.status.clone(),
                device_count: meta.device_count,
                last_synced: meta.last_synced,
                error_message: meta.error_message.clone(),
                encrypted_credentials: encrypted_creds,
            };

            store_data
                .integrations
                .insert(provider.as_str().to_string(), record);
        }

        let json_output = serde_json::to_vec_pretty(&store_data)
            .map_err(|e| format!("JSON encode error: {}", e))?;

        self.file_store
            .write_atomic(|_| Ok::<_, std::io::Error>(json_output))
            .map_err(|e| format!("Atomic write error: {}", e))?;

        self.enforce_file_permissions();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_store_save_load_roundtrip() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap();

        let store = IntegrationStore::new(path);
        let mut map = HashMap::new();

        // --- GoogleNest: must use NestCredentials ---
        let nest_creds = crate::nest::NestCredentials::new(
            Some("client_id_test".to_string()),
            Some("client_secret_test".to_string()),
            Some("project_id_test".to_string()),
            Some("test_access_token_abc123".to_string()),
            Some("test_refresh_token_xyz789".to_string()),
        );

        let nest_meta = IntegrationMetadata {
            provider: VendorProvider::GoogleNest,
            name: "Google Nest".to_string(),
            status: IntegrationStatus::Connected,
            device_count: 3,
            last_synced: Some(chrono::Utc::now()),
            error_message: None,
            credentials: None,
            kasa_credentials: None,
            nest_credentials: Some(nest_creds),
        };

        map.insert(VendorProvider::GoogleNest, nest_meta);

        // --- TpLinkKasa: must use KasaCredentials ---
        let kasa_creds = crate::kasa::KasaCredentials::new(
            Some("cloud".to_string()),
            Some("kasa@test.com".to_string()),
            Some("kasapassword".to_string()),
        );

        let kasa_meta = IntegrationMetadata {
            provider: VendorProvider::TpLinkKasa,
            name: "TP-Link Kasa".to_string(),
            status: IntegrationStatus::Connected,
            device_count: 2,
            last_synced: Some(chrono::Utc::now()),
            error_message: None,
            credentials: None,
            kasa_credentials: Some(kasa_creds),
            nest_credentials: None,
        };

        map.insert(VendorProvider::TpLinkKasa, kasa_meta);

        store.save(&map).expect("Save failed");

        let loaded = store.load();
        assert_eq!(loaded.len(), 2);

        // Verify Nest credentials
        let loaded_nest = loaded.get(&VendorProvider::GoogleNest).unwrap();
        assert_eq!(loaded_nest.provider, VendorProvider::GoogleNest);
        assert_eq!(loaded_nest.status, IntegrationStatus::Connected);
        assert_eq!(
            loaded_nest.nest_credentials.as_ref().unwrap().access_token,
            Some("test_access_token_abc123".to_string())
        );

        // Verify Kasa credentials
        let loaded_kasa = loaded.get(&VendorProvider::TpLinkKasa).unwrap();
        assert_eq!(loaded_kasa.provider, VendorProvider::TpLinkKasa);
        assert_eq!(loaded_kasa.status, IntegrationStatus::Connected);
        assert_eq!(
            loaded_kasa.kasa_credentials.as_ref().unwrap().username,
            Some("kasa@test.com".to_string())
        );
    }
}
