use super::crypto::{decrypt_password, encrypt_password};
use super::errors::RuntimeError;
use super::models::GuardianConfig;
use std::fs;

fn get_config_file() -> String {
    std::env::var("GUARDIAN_CONFIG_FILE")
        .unwrap_or_else(|_| "/etc/guardian/wifi_config.json".to_string())
}

pub struct ConfigStore;

impl ConfigStore {
    pub fn load() -> Result<GuardianConfig, RuntimeError> {
        if let Ok(content) = fs::read_to_string(get_config_file()) {
            let mut config: GuardianConfig = serde_json::from_str(&content)
                .map_err(|e| RuntimeError::InvalidConfig(e.to_string()))?;

            // Decrypt passwords
            if !config.hotspot.password.is_empty() {
                config.hotspot.password =
                    decrypt_password(&config.hotspot.password).map_err(|e| {
                        RuntimeError::InvalidConfig(format!(
                            "Failed to decrypt hotspot password: {}",
                            e
                        ))
                    })?;
            }

            for network in &mut config.uplink.networks {
                if let Some(ref enc) = network.password {
                    if !enc.is_empty() {
                        network.password = Some(decrypt_password(enc).map_err(|e| {
                            RuntimeError::InvalidConfig(format!(
                                "Failed to decrypt uplink password: {}",
                                e
                            ))
                        })?);
                    }
                }
            }
            Ok(config)
        } else {
            Ok(GuardianConfig::default())
        }
    }

    pub fn save(config: &GuardianConfig) -> Result<(), RuntimeError> {
        let mut encrypted_config = config.clone();

        // Encrypt password at rest
        if !config.hotspot.password.is_empty() {
            encrypted_config.hotspot.password = encrypt_password(&config.hotspot.password)
                .map_err(|e| RuntimeError::Internal(format!("Encryption failed: {}", e)))?;
        }

        for network in &mut encrypted_config.uplink.networks {
            if let Some(ref pw) = network.password {
                if !pw.is_empty() {
                    network.password = Some(encrypt_password(pw).map_err(|e| {
                        RuntimeError::Internal(format!("Encryption failed: {}", e))
                    })?);
                }
            }
        }

        let content = serde_json::to_string_pretty(&encrypted_config)
            .map_err(|e| RuntimeError::Internal(e.to_string()))?;

        if let Some(parent) = std::path::Path::new(&get_config_file()).parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(get_config_file(), content).map_err(|e| RuntimeError::Internal(e.to_string()))
    }
}
