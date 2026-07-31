use super::tools::Tpm2Cli;
use super::{TpmConfig, TpmError};
use p256::ecdsa::Signature;
use std::fs;

pub struct TpmSigner {
    cli: Tpm2Cli,
    key_auth: Option<String>,
}

impl TpmSigner {
    pub fn new(cfg: &TpmConfig) -> Self {
        Self {
            cli: Tpm2Cli::new(cfg.clone()),
            key_auth: cfg.key_auth.clone(),
        }
    }

    pub fn sign(&self, handle: u32, data: &[u8]) -> Result<Vec<u8>, TpmError> {
        let dir = tempfile::tempdir()?;
        let input_path = dir.path().join("sign-input.bin");
        let sig_path = dir.path().join("sign-output.bin");
        let input_path_str = input_path.to_string_lossy().to_string();
        let sig_path_str = sig_path.to_string_lossy().to_string();

        fs::write(&input_path, data)?;
        self.cli.sign_plain(
            handle,
            &input_path_str,
            &sig_path_str,
            self.key_auth.as_deref(),
        )?;
        let sig = fs::read(&sig_path)?;
        normalize_signature(sig)
    }
}

fn normalize_signature(sig: Vec<u8>) -> Result<Vec<u8>, TpmError> {
    if sig.len() == 64 {
        return Ok(sig);
    }

    if let Ok(parsed) = Signature::from_der(&sig) {
        return Ok(parsed.to_bytes().to_vec());
    }

    Err(TpmError::Key(format!(
        "unexpected TPM signature framing ({} bytes)",
        sig.len()
    )))
}
