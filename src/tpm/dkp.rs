use super::signer::TpmSigner;
use super::tools::Tpm2Cli;
use super::{should_attempt, TpmConfig, TpmError};
use crate::secure_element::key_meta::{DkpKeyHistory, KeyMetadata};
use tracing::{info, warn};

pub const DKP_PUB_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_pub.der";

pub struct TpmDkpManager {
    pub history: DkpKeyHistory,
    pub metadata_path: String,
    pub public_key_path: String,
    config: TpmConfig,
}

impl TpmDkpManager {
    pub fn init(cfg: &TpmConfig, base_path: &str) -> Result<Self, TpmError> {
        if !should_attempt(cfg) {
            return Err(TpmError::NotAvailable(format!(
                "TPM device {} is not present",
                cfg.device
            )));
        }

        let metadata_path = format!("{}/keys/dkp_metadata.json", base_path);
        let public_key_path = format!("{}/keys/dkp_pub.der", base_path);
        let cli = Tpm2Cli::new(cfg.clone());
        if !cli.available() {
            return Err(TpmError::NotAvailable(format!(
                "cannot reach TPM on {}",
                cfg.device
            )));
        }

        if let Ok(history) = DkpKeyHistory::load(&metadata_path) {
            if let Some(active) = history.active_key() {
                let handle = parse_handle(&active.key_id).unwrap_or(cfg.dkp_handle_base);
                if !cli.handle_exists(handle) {
                    return Err(TpmError::Key(format!(
                        "TPM DKP metadata points to {}, but that persistent handle is missing",
                        active.key_id
                    )));
                }

                cli.readpublic_der(handle, &public_key_path)?;
                info!(
                    "Existing TPM DKP found (v{}) at {}",
                    active.version, active.key_id
                );
                return Ok(Self {
                    history,
                    metadata_path,
                    public_key_path,
                    config: cfg.clone(),
                });
            }
        }

        let handle = cfg.dkp_handle_base;
        if cli.handle_exists(handle) {
            cli.readpublic_der(handle, &public_key_path)?;
        } else {
            cli.provision_persistent_signing_key(
                handle,
                &public_key_path,
                "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
                cfg.owner_auth.as_deref(),
            )?;
        }

        let mut meta = KeyMetadata::new(&format!("0x{:08X}", handle), "dkp", "ECDSA-P256", 1);
        meta.public_key_path = Some(public_key_path.clone());
        let history = DkpKeyHistory::new(meta);
        history.save(&metadata_path).map_err(TpmError::Key)?;

        Ok(Self {
            history,
            metadata_path,
            public_key_path,
            config: cfg.clone(),
        })
    }

    pub fn active_version(&self) -> u32 {
        self.history
            .active_key()
            .map(|key| key.version)
            .unwrap_or(1)
    }

    pub fn active_handle(&self) -> u32 {
        self.history
            .active_key()
            .and_then(|key| parse_handle(&key.key_id))
            .unwrap_or(self.config.dkp_handle_base)
    }

    pub fn create_signer(&self) -> TpmSigner {
        TpmSigner::new(&self.config)
    }

    pub fn public_key_export(&self) -> Result<Vec<u8>, TpmError> {
        Ok(std::fs::read(&self.public_key_path)?)
    }

    pub fn needs_rotation(&self) -> bool {
        self.history
            .active_key()
            .map(|key| key.needs_rotation())
            .unwrap_or(false)
    }

    pub fn rotate(&mut self) -> Result<KeyMetadata, TpmError> {
        let active = self
            .history
            .active_key()
            .cloned()
            .ok_or_else(|| TpmError::Key("no active TPM DKP to rotate".to_string()))?;
        let new_version = active.version + 1;
        let new_handle = self.config.dkp_handle_base + new_version - 1;

        let cli = Tpm2Cli::new(self.config.clone());
        if cli.handle_exists(new_handle) {
            cli.readpublic_der(new_handle, &self.public_key_path)?;
        } else {
            cli.provision_persistent_signing_key(
                new_handle,
                &self.public_key_path,
                "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
                self.config.owner_auth.as_deref(),
            )?;
        }

        self.history.deprecate_version(active.version);

        let mut new_meta = KeyMetadata::new(
            &format!("0x{:08X}", new_handle),
            &format!("dkp-v{}", new_version),
            "ECDSA-P256",
            new_version,
        );
        new_meta.rotated_from = Some(active.key_id.clone());
        new_meta.public_key_path = Some(self.public_key_path.clone());
        self.history.add(new_meta.clone());
        self.history
            .save(&self.metadata_path)
            .map_err(TpmError::Key)?;

        if let Some(old_handle) = parse_handle(&active.key_id) {
            if let Err(error) = cli.evict_handle(old_handle, self.config.owner_auth.as_deref()) {
                warn!(
                    "Old TPM DKP handle {} could not be evicted after rotation: {}",
                    active.key_id, error
                );
            }
        }

        Ok(new_meta)
    }

    pub fn check_and_auto_rotate(&mut self) -> Result<Option<KeyMetadata>, TpmError> {
        if self.needs_rotation() {
            warn!("TPM DKP exceeded rotation policy; rotating");
            return self.rotate().map(Some);
        }
        Ok(None)
    }
}

fn parse_handle(value: &str) -> Option<u32> {
    let value = value.trim();
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    u32::from_str_radix(value, 16).ok()
}
