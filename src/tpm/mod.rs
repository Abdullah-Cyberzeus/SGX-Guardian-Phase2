//! TPM 2.0 hardware root-of-trust backend.
//!
//! This module mirrors the existing SE050 integration style: synchronous
//! shell-outs for provisioning and signing, exported public-key artifacts on
//! disk, and a small set of helpers that let the rest of the codebase keep
//! consuming the same DID/attestation inputs.

use std::path::Path;

pub mod dik;
pub mod dkp;
pub mod ek;
pub mod pcr;
pub mod quote;
pub mod signer;
pub mod tools;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

pub const TPM_BASE_PATH: &str = "/var/lib/sgx-guardian";

#[derive(Debug, Clone)]
pub struct TpmConfig {
    pub device: String,
    pub tcti: String,
    pub explicit_backend: bool,
    pub dik_handle: u32,
    pub dkp_handle_base: u32,
    pub ek_handle: u32,
    pub pcr_selection: String,
    pub owner_auth: Option<String>,
}

impl Default for TpmConfig {
    fn default() -> Self {
        let (device, tcti, explicit_backend) = configured_tpm_backend_from(
            std::env::var("SGX_TPM_DEVICE").ok().as_deref(),
            std::env::var("TPM2TOOLS_TCTI").ok().as_deref(),
        );
        Self {
            device,
            tcti,
            explicit_backend,
            dik_handle: parse_handle("SGX_TPM_DIK_HANDLE", 0x8100_0100),
            dkp_handle_base: parse_handle("SGX_TPM_DKP_HANDLE_BASE", 0x8100_0010),
            ek_handle: parse_handle("SGX_TPM_EK_HANDLE", 0x8101_0001),
            pcr_selection: std::env::var("SGX_TPM_PCR_SELECTION")
                .unwrap_or_else(|_| "sha256:0,2,4,7".to_string()),
            owner_auth: std::env::var("SGX_TPM_OWNER_AUTH")
                .ok()
                .filter(|value| !value.trim().is_empty()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TpmError {
    #[error("tpm2 tool `{0}` failed: {1}")]
    Tool(String, String),
    #[error("tpm not available: {0}")]
    NotAvailable(String),
    #[error("tpm key error: {0}")]
    Key(String),
    #[error("invalid TPM output: {0}")]
    Parse(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub fn should_attempt(cfg: &TpmConfig) -> bool {
    cfg.explicit_backend || Path::new(&cfg.device).exists()
}

pub fn dev_fallback_allowed() -> bool {
    env_true("SGX_ALLOW_TPM_DEV_FALLBACK")
}

pub fn tpm_required(cfg: &TpmConfig) -> bool {
    tpm_required_with_dev_fallback(cfg, dev_fallback_allowed())
}

pub(crate) fn tpm_required_with_dev_fallback(cfg: &TpmConfig, allow_dev_fallback: bool) -> bool {
    should_attempt(cfg) && !allow_dev_fallback
}

pub fn probe_required_capabilities(cfg: &TpmConfig) -> Result<(), TpmError> {
    let cli = tools::Tpm2Cli::new(cfg.clone());
    if !cli.available() {
        return Err(TpmError::NotAvailable(format!(
            "TPM capability probe failed for TCTI {}",
            cfg.tcti
        )));
    }
    cli.readpublic_der(cfg.dkp_handle_base, dkp::DKP_PUB_PATH)
        .map_err(|error| {
            TpmError::Key(format!(
                "TPM DKP read-public probe failed for handle 0x{:08X} via {}: {}",
                cfg.dkp_handle_base, cfg.tcti, error
            ))
        })?;
    signer::TpmSigner::new(cfg)
        .sign(cfg.dkp_handle_base, b"sgx-guardian-tpm-startup-probe")
        .map_err(|error| {
            TpmError::Key(format!(
                "TPM DKP signing probe failed for handle 0x{:08X} via {}: {}",
                cfg.dkp_handle_base, cfg.tcti, error
            ))
        })?;
    Ok(())
}

pub(crate) fn configured_tpm_backend_from(
    sgx_tpm_device: Option<&str>,
    tpm2tools_tcti: Option<&str>,
) -> (String, String, bool) {
    if let Some(device) = sgx_tpm_device {
        let device = device.trim().to_string();
        if !device.is_empty() {
            return (device.clone(), format!("device:{device}"), true);
        }
    }

    if let Some(tcti) = tpm2tools_tcti {
        let tcti = tcti.trim().to_string();
        if !tcti.is_empty() {
            let device = device_from_tcti(&tcti).unwrap_or_else(|| tcti.clone());
            return (device, tcti, true);
        }
    }

    let device = "/dev/tpmrm0".to_string();
    (device.clone(), format!("device:{device}"), false)
}

fn device_from_tcti(tcti: &str) -> Option<String> {
    tcti.strip_prefix("device:")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn env_true(key: &str) -> bool {
    matches!(
        std::env::var(key).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("on")
    )
}

fn parse_handle(var: &str, default: u32) -> u32 {
    std::env::var(var)
        .ok()
        .and_then(|value| {
            let value = value.trim();
            let value = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .unwrap_or(value);
            u32::from_str_radix(value, 16).ok()
        })
        .unwrap_or(default)
}
