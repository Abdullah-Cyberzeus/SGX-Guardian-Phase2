use super::tools::Tpm2Cli;
use super::{should_attempt, TpmConfig, TpmError};
use sha2::{Digest, Sha256};

pub const EK_PUB_PATH: &str = "/var/lib/sgx-guardian/keys/ek_pub.der";

pub fn ensure_uid(cfg: &TpmConfig) -> Result<Vec<u8>, TpmError> {
    if !should_attempt(cfg) {
        return Err(TpmError::NotAvailable(format!(
            "TPM device {} is not present",
            cfg.device
        )));
    }

    if let Some(parent) = std::path::Path::new(EK_PUB_PATH).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let cli = Tpm2Cli::new(cfg.clone());
    if cli.available() {
        if !cli.handle_exists(cfg.ek_handle) {
            let _ = cli.create_ek(cfg.ek_handle);
        }
        cli.readpublic_der(cfg.ek_handle, EK_PUB_PATH)?;
    } else if !std::path::Path::new(EK_PUB_PATH).exists() {
        return Err(TpmError::NotAvailable(
            "TPM not reachable and no cached EK public key is available".to_string(),
        ));
    }

    let der = std::fs::read(EK_PUB_PATH)?;
    Ok(Sha256::digest(&der).to_vec())
}

pub fn uid_hex(cfg: &TpmConfig) -> Result<String, TpmError> {
    Ok(hex::encode(ensure_uid(cfg)?))
}

/// Node-unique identity binding: SHA256(EK_pub DER || DKP_pub DER).
///
/// A single TPM has exactly one EK, so `ensure_uid` alone is identical across
/// every node sharing that TPM. Folding in the DKP public key (which is
/// distinct per node once handles are separated) makes this UID unique per
/// node while remaining bound to the physical TPM.
pub fn node_uid(cfg: &TpmConfig, dkp_pub_path: &str) -> Result<Vec<u8>, TpmError> {
    ensure_uid(cfg)?;
    let ek_pub_der = std::fs::read(EK_PUB_PATH)?;
    let dkp_pub_der = std::fs::read(dkp_pub_path).map_err(|error| {
        TpmError::Key(format!(
            "DKP public key required for node UID not found at {}: {}",
            dkp_pub_path, error
        ))
    })?;

    let mut hasher = Sha256::new();
    hasher.update(&ek_pub_der);
    hasher.update(&dkp_pub_der);
    Ok(hasher.finalize().to_vec())
}

pub fn node_uid_hex(cfg: &TpmConfig, dkp_pub_path: &str) -> Result<String, TpmError> {
    Ok(hex::encode(node_uid(cfg, dkp_pub_path)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unavailable_config() -> TpmConfig {
        TpmConfig {
            device: "/definitely/missing/tpm-ek".into(),
            tcti: "device:/definitely/missing/tpm-ek".into(),
            explicit_backend: false,
            ..TpmConfig::default()
        }
    }

    #[test]
    fn uid_helpers_reject_missing_implicit_device_before_filesystem_access() {
        let cfg = unavailable_config();
        assert!(matches!(ensure_uid(&cfg), Err(TpmError::NotAvailable(_))));
        assert!(matches!(uid_hex(&cfg), Err(TpmError::NotAvailable(_))));
        assert!(matches!(
            node_uid(&cfg, "/missing/dkp.der"),
            Err(TpmError::NotAvailable(_))
        ));
        assert!(matches!(
            node_uid_hex(&cfg, "/missing/dkp.der"),
            Err(TpmError::NotAvailable(_))
        ));
    }
}
