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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_signature_accepts_64_byte_raw() {
        let raw = vec![0u8; 64];
        let out = normalize_signature(raw).expect("should accept 64-byte raw");
        assert_eq!(out.len(), 64);
    }

    #[test]
    fn normalize_signature_rejects_unknown_framing() {
        let bad = vec![0u8; 10];
        let res = normalize_signature(bad);
        assert!(res.is_err());
    }

    #[test]
    fn normalize_signature_converts_valid_der_to_fixed_width() {
        let signature = Signature::from_scalars([1u8; 32], [2u8; 32]).expect("valid scalars");
        let normalized = normalize_signature(signature.to_der().as_bytes().to_vec())
            .expect("DER signature should normalize");
        assert_eq!(normalized, signature.to_bytes().to_vec());
    }

    #[test]
    fn normalize_signature_error_includes_input_length() {
        let error = normalize_signature(vec![0xff; 17]).expect_err("invalid framing");
        assert!(matches!(error, TpmError::Key(message) if message.contains("17 bytes")));
    }

    #[test]
    fn sign_fails_deterministically_when_tpm2_tools_are_not_installed() {
        // tpm2_* binaries genuinely aren't installed in this sandbox, so sign_plain fails
        // fast and deterministically before ever reaching normalize_signature.
        let signer = TpmSigner::new(&TpmConfig::default());
        assert!(signer.sign(0x8100_0100, b"payload").is_err());
    }
}
