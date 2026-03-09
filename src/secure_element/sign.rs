// src/secure_element/sign.rs
// ============================================================
// SE050-backed ECDSA signing.
// Private key NEVER leaves the secure element.
//
// Syntax (POSITIONAL, verified from board):
//   ssscli sign <keyid> <input_file> <signature_file>
//   ssscli verify <keyid> <input_file> <signature_file>
// ============================================================

use crate::secure_element::config::SeConfig;
use crate::secure_element::error::SeError;
use crate::secure_element::ssscli::SssCli;
use std::fs;

pub struct SeSigner {
    cli: SssCli,
}

impl SeSigner {
    pub fn new(config: &SeConfig) -> Result<Self, SeError> {
        let cli = SssCli::new(config.clone());
        cli.connect()?;
        Ok(Self { cli })
    }

    /// Sign data — key never leaves SE050 hardware.
    /// Writes data to temp file, ssscli signs inside chip, reads signature back.
    pub fn sign(&self, key_id: u32, data: &[u8]) -> Result<Vec<u8>, SeError> {
        let hex_id = format!("0x{:08X}", key_id);
        let tmp_in = "/tmp/guardian_se_sign_in.bin";
        let tmp_out = "/tmp/guardian_se_sign_out.bin";

        fs::write(tmp_in, data).map_err(|e| SeError::CryptoError(format!("Write input: {}", e)))?;

        // ssscli sign <keyid> <input> <output>  (no sha256 subcommand!)
        self.cli.sign(&hex_id, tmp_in, tmp_out)?;

        let signature = fs::read(tmp_out)
            .map_err(|e| SeError::CryptoError(format!("Read signature: {}", e)))?;

        let _ = fs::remove_file(tmp_in);
        let _ = fs::remove_file(tmp_out);

        Ok(signature)
    }

    /// Verify signature using SE050.
    pub fn verify(&self, key_id: u32, data: &[u8], sig: &[u8]) -> Result<bool, SeError> {
        let hex_id = format!("0x{:08X}", key_id);
        let tmp_d = "/tmp/guardian_se_vfy_data.bin";
        let tmp_s = "/tmp/guardian_se_vfy_sig.bin";

        fs::write(tmp_d, data).map_err(|e| SeError::CryptoError(e.to_string()))?;
        fs::write(tmp_s, sig).map_err(|e| SeError::CryptoError(e.to_string()))?;

        // ssscli verify <keyid> <input> <sigfile>  (no sha256 subcommand!)
        let ok = self.cli.verify(&hex_id, tmp_d, tmp_s).is_ok();

        let _ = fs::remove_file(tmp_d);
        let _ = fs::remove_file(tmp_s);

        Ok(ok)
    }
}
