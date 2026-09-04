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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_rejects_missing_implicit_device_before_running_tools() {
        let cfg = TpmConfig {
            device: "/definitely/missing/tpm-dik".into(),
            tcti: "device:/definitely/missing/tpm-dik".into(),
            explicit_backend: false,
            ..TpmConfig::default()
        };
        let error = ensure(&cfg).expect_err("missing TPM should fail");
        assert!(matches!(error, TpmError::NotAvailable(message) if message.contains("tpm-dik")));
    }

    #[test]
    fn ensure_reports_unreachable_tpm_when_backend_is_forced_but_tpm2_getcap_is_missing() {
        // `tpm2_getcap` genuinely isn't installed in this sandbox, so forcing past the
        // device-presence check (explicit_backend) deterministically reaches and fails the
        // real `cli.available()` probe — no actual hardware or root access involved.
        let cfg = TpmConfig {
            device: "/definitely/missing/tpm-dik-2".into(),
            tcti: "device:/definitely/missing/tpm-dik-2".into(),
            explicit_backend: true,
            ..TpmConfig::default()
        };
        let error = ensure(&cfg).expect_err("tpm2_getcap is not installed");
        assert!(matches!(error, TpmError::NotAvailable(message) if message.contains("cannot reach TPM")));
    }
}
