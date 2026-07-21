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
