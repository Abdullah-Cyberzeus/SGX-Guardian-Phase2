use super::tools::Tpm2Cli;
use super::{should_attempt, TpmConfig, TpmError};

pub const DIK_PUB_PATH: &str = "/var/lib/sgx-guardian/keys/dik_pub.der";

pub fn ensure(cfg: &TpmConfig) -> Result<Vec<u8>, TpmError> {
    if !should_attempt(cfg) {
        return Err(TpmError::NotAvailable(format!(
            "TPM device {} is not present",
            cfg.device
        )));
    }

    let cli = Tpm2Cli::new(cfg.clone());
    if !cli.available() {
        return Err(TpmError::NotAvailable(format!(
            "cannot reach TPM on {}",
            cfg.device
        )));
    }

    if cli.handle_exists(cfg.dik_handle) {
        cli.readpublic_der(cfg.dik_handle, DIK_PUB_PATH)?;
    } else {
        cli.provision_persistent_signing_key(
            cfg.dik_handle,
            DIK_PUB_PATH,
            "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
            cfg.owner_auth.as_deref(),
            cfg.key_auth.as_deref(),
        )?;
    }

    Ok(std::fs::read(DIK_PUB_PATH)?)
}
