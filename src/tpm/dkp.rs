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
                cfg.key_auth.as_deref(),
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
                self.config.key_auth.as_deref(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> TpmConfig {
        TpmConfig {
            device: "/definitely/missing/tpm".into(),
            tcti: "device:/definitely/missing/tpm".into(),
            explicit_backend: false,
            dik_handle: 0x8100_0100,
            dkp_handle_base: 0x8100_0010,
            ek_handle: 0x8101_0001,
            pcr_selection: "sha256:0,2,4,7".into(),
            owner_auth: None,
            key_auth: None,
        }
    }

    fn manager(history: DkpKeyHistory, public_key_path: String) -> TpmDkpManager {
        TpmDkpManager {
            history,
            metadata_path: "/unused/metadata.json".into(),
            public_key_path,
            config: config(),
        }
    }

    #[test]
    fn handle_parser_accepts_prefixed_plain_and_rejects_invalid_values() {
        assert_eq!(parse_handle("0x81000010"), Some(0x8100_0010));
        assert_eq!(parse_handle(" 0X81000011 "), Some(0x8100_0011));
        assert_eq!(parse_handle("81000012"), Some(0x8100_0012));
        assert_eq!(parse_handle(""), None);
        assert_eq!(parse_handle("0xnot-hex"), None);
    }

    #[test]
    fn inactive_or_malformed_history_uses_safe_fallbacks() {
        let mut key = KeyMetadata::new("invalid", "dkp", "ECDSA-P256", 4);
        key.deprecate();
        let mut empty = manager(DkpKeyHistory { keys: vec![] }, "/missing".into());
        assert_eq!(empty.active_version(), 1);
        assert_eq!(empty.active_handle(), config().dkp_handle_base);
        assert!(!empty.needs_rotation());
        assert!(empty
            .check_and_auto_rotate()
            .expect("no rotation")
            .is_none());

        let malformed = manager(
            DkpKeyHistory::new(KeyMetadata::new("bad", "dkp", "ECDSA-P256", 9)),
            "/missing".into(),
        );
        assert_eq!(malformed.active_version(), 9);
        assert_eq!(malformed.active_handle(), config().dkp_handle_base);
        assert!(!key.can_sign());
    }

    #[test]
    fn manager_reads_public_export_and_reports_missing_files() {
        let dir = tempfile::tempdir().expect("temporary key directory");
        let path = dir.path().join("dkp.der");
        std::fs::write(&path, b"public-key").expect("write public key");
        let manager = manager(
            DkpKeyHistory::new(KeyMetadata::new("0x81000022", "dkp", "ECDSA-P256", 2)),
            path.to_string_lossy().into_owned(),
        );
        assert_eq!(manager.active_handle(), 0x8100_0022);
        assert_eq!(
            manager.public_key_export().expect("public export"),
            b"public-key"
        );

        std::fs::remove_file(path).expect("remove public key");
        assert!(matches!(manager.public_key_export(), Err(TpmError::Io(_))));
    }

    #[test]
    fn init_rejects_an_unconfigured_missing_tpm_without_invoking_tools() {
        let error = TpmDkpManager::init(&config(), "/unused")
            .err()
            .expect("missing TPM must be rejected");
        assert!(
            matches!(error, TpmError::NotAvailable(message) if message.contains("not present"))
        );
    }

    #[test]
    fn rotation_requires_an_active_key_before_hardware_access() {
        let mut manager = manager(DkpKeyHistory { keys: vec![] }, "/missing".into());
        let error = manager.rotate().expect_err("empty history must fail");
        assert!(matches!(error, TpmError::Key(message) if message.contains("no active TPM DKP")));
    }
}
