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
use uuid::Uuid;

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
        let sign_id = Uuid::new_v4().simple().to_string();
        let sign_tag = &sign_id[..8];
        let tmp_in = format!("/tmp/guardian_se_sign_{}_in.bin", sign_tag);
        let tmp_out = format!("/tmp/guardian_se_sign_{}_out.bin", sign_tag);

        let result = (|| -> Result<Vec<u8>, SeError> {
            fs::write(&tmp_in, data)
                .map_err(|e| SeError::CryptoError(format!("Write input: {}", e)))?;

            // ssscli sign <keyid> <input> <output>  (no sha256 subcommand!)
            self.cli.sign(&hex_id, &tmp_in, &tmp_out)?;

            fs::read(&tmp_out).map_err(|e| SeError::CryptoError(format!("Read signature: {}", e)))
        })();

        let _ = fs::remove_file(&tmp_in);
        let _ = fs::remove_file(&tmp_out);

        result
    }

    /// Verify signature using SE050.
    pub fn verify(&self, key_id: u32, data: &[u8], sig: &[u8]) -> Result<bool, SeError> {
        let hex_id = format!("0x{:08X}", key_id);
        let verify_id = Uuid::new_v4().simple().to_string();
        let verify_tag = &verify_id[..8];
        let tmp_d = format!("/tmp/guardian_se_vfy_{}_data.bin", verify_tag);
        let tmp_s = format!("/tmp/guardian_se_vfy_{}_sig.bin", verify_tag);

        let result = (|| -> Result<bool, SeError> {
            fs::write(&tmp_d, data).map_err(|e| SeError::CryptoError(e.to_string()))?;
            fs::write(&tmp_s, sig).map_err(|e| SeError::CryptoError(e.to_string()))?;

            // ssscli verify <keyid> <input> <sigfile>  (no sha256 subcommand!)
            match self.cli.verify(&hex_id, &tmp_d, &tmp_s) {
                Ok(_) => Ok(true),
                Err(e) => {
                    eprintln!("SE050 verify error (not just invalid sig): {}", e);
                    Ok(false)
                }
            }
        })();

        let _ = fs::remove_file(&tmp_d);
        let _ = fs::remove_file(&tmp_s);

        result
    }
}
