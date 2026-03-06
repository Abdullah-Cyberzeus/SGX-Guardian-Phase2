// src/secure_element/ssscli.rs
// ============================================================
// ssscli subprocess wrapper.
// Only file that directly calls the NXP CLI tool.
//
// Available ssscli se05x subcommands (verified from board):
//   certuid, getrng, readidlist, reset, uid
//
// CRITICAL: ssscli uses POSITIONAL arguments, NOT --flag style.
//   generate ecc <keyid> <curve>     (not --key_id --curvetype)
//   get ecc pub <keyid> <filename>   (not --key_id --output)
//   sign <keyid> <input> <output>    (not sign sha256 --key_id --in --out)
//   verify <keyid> <input> <sigfile> (not verify sha256 --key_id --in --signature)
//   erase <keyid>                    (not --key_id)
//
// Curve names: NIST_P256, NIST_P384 (not prime256v1, secp384r1)
// ============================================================

use crate::secure_element::config::SeConfig;
use crate::secure_element::error::SeError;
use std::process::Command;
use tracing::{debug, error};

/// Wrapper around NXP ssscli command-line tool.
pub struct SssCli {
    config: SeConfig,
}

impl SssCli {
    pub fn new(config: SeConfig) -> Self {
        Self { config }
    }

    // ── Session Management ──────────────────────────────────

    /// Establish authenticated PlatformSCP session with SE050.
    /// "Session already open" warning is normal and OK.
    pub fn connect(&self) -> Result<String, SeError> {
        self.run(&[
            "connect",
            "--auth_type",
            &self.config.auth_type,
            "--scpkey",
            &self.config.scp_key_path,
            &self.config.connection_type,
            &self.config.interface,
            "none",
        ])
    }

    // ── SE05X Subcommands ───────────────────────────────────

    pub fn reset(&self) -> Result<String, SeError> {
        self.run(&["se05x", "reset"])
    }

    /// Get Unique ID (18 bytes hex).
    /// Board output: "Unique ID: 040050011f595a6179b9b204783ebae51090"
    pub fn get_uid(&self) -> Result<String, SeError> {
        let output = self.run(&["se05x", "uid"])?;
        Self::parse_value(&output, "Unique ID:").ok_or_else(|| SeError::CommandFailed {
            cmd: "se05x uid".into(),
            stderr: "Could not parse Unique ID from output".into(),
        })
    }

    /// Get Certificate Unique ID (10 bytes hex).
    /// Board output: "Cert UID: 500179b9b204783ebae5"
    pub fn get_certuid(&self) -> Result<String, SeError> {
        let output = self.run(&["se05x", "certuid"])?;
        Self::parse_value(&output, "Cert UID:").ok_or_else(|| SeError::CommandFailed {
            cmd: "se05x certuid".into(),
            stderr: "Could not parse Cert UID from output".into(),
        })
    }

    /// Get random bytes from hardware TRNG (10 bytes per call).
    /// Board output: "Random number: 495b0ade5249153dbcac"
    pub fn get_rng(&self) -> Result<String, SeError> {
        self.run(&["se05x", "getrng"])
    }

    /// Read list of all object IDs stored in SE050.
    pub fn read_id_list(&self) -> Result<String, SeError> {
        self.run(&["se05x", "readidlist"])
    }

    // ── Key Management (POSITIONAL args, not flags) ─────────

    /// Generate ECC key pair inside SE050.
    /// Syntax: ssscli generate ecc <keyid> <curve>
    /// curve: NIST_P256, NIST_P384, ED_25519, etc.
    pub fn generate_ecc_key(&self, key_id: &str, curve: &str) -> Result<String, SeError> {
        self.run(&["generate", "ecc", key_id, curve])
    }

    /// Export ONLY the public key from SE050 (DER format).
    /// Syntax: ssscli get ecc pub <keyid> <filename>
    pub fn get_ecc_pub(&self, key_id: &str, output_path: &str) -> Result<String, SeError> {
        self.run(&["get", "ecc", "pub", key_id, output_path])
    }

    /// Delete a key/object from SE050.
    /// Syntax: ssscli erase <keyid>
    pub fn erase(&self, key_id: &str) -> Result<String, SeError> {
        self.run(&["erase", key_id])
    }

    // ── Crypto Operations (POSITIONAL args, no sha256 subcommand) ──

    /// Sign data using SE050-backed key.
    /// Syntax: ssscli sign <keyid> <input_file> <signature_file>
    pub fn sign(&self, key_id: &str, input: &str, output: &str) -> Result<String, SeError> {
        self.run(&["sign", key_id, input, output])
    }

    /// Verify signature using SE050-backed key.
    /// Syntax: ssscli verify <keyid> <input_file> <signature_file>
    pub fn verify(&self, key_id: &str, input: &str, sig: &str) -> Result<String, SeError> {
        self.run(&["verify", key_id, input, sig])
    }

    // ── Internal ────────────────────────────────────────────

    fn run(&self, args: &[&str]) -> Result<String, SeError> {
        let cmd_str = format!("ssscli {}", args.join(" "));
        debug!("Executing: {}", cmd_str);

        let output =
            Command::new("ssscli")
                .args(args)
                .output()
                .map_err(|e| SeError::CommandFailed {
                    cmd: cmd_str.clone(),
                    stderr: e.to_string(),
                })?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            error!("ssscli failed [{}]: {}", cmd_str, stderr);
            return Err(SeError::CommandFailed {
                cmd: cmd_str,
                stderr,
            });
        }

        let combined = if stdout.is_empty() {
            stderr
        } else {
            format!("{}\n{}", stderr, stdout)
        };

        debug!("ssscli output: {}", combined.trim());
        Ok(combined)
    }

    /// Parse "Key: Value" from ssscli output.
    /// Also handles "INFO:sss.se05x:value" Python log format.
    pub(crate) fn parse_value(output: &str, prefix: &str) -> Option<String> {
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with(prefix) {
                return Some(trimmed[prefix.len()..].trim().to_string());
            }
            if trimmed.contains("INFO:sss.se05x:") {
                if let Some(val) = trimmed.split("INFO:sss.se05x:").nth(1) {
                    return Some(val.trim().to_string());
                }
            }
        }
        None
    }
}

// ── Unit Tests (6 tests) ────────────────────────────────────
// Tests use REAL board output strings — NO subprocess, NO I/O.
// Run: cargo test secure_element::ssscli::tests -- --nocapture
#[cfg(test)]
mod tests {
    use super::*;

    const REAL_UID_OUTPUT: &str = "\
sss   :INFO :atr (Len=35)
      00 A0 00 00    03 96 04 03    E8 00 FE 02    0B 03 E8 08
sss   :INFO :Newer version of Applet Found
sss   :INFO :Compiled for 0x30100. Got newer 0x30600
INFO:sss.se05x:040050011f595a6179b9b204783ebae51090
Unique ID: 040050011f595a6179b9b204783ebae51090";

    const REAL_CERTUID_OUTPUT: &str = "\
sss   :INFO :atr (Len=35)
sss   :INFO :Newer version of Applet Found
sss   :INFO :Compiled for 0x30100. Got newer 0x30600
INFO:sss.se05x:500179b9b204783ebae5
Cert UID: 500179b9b204783ebae5";

    /// Real output from: ssscli se05x getrng
    const REAL_GETRNG_OUTPUT: &str = "\
sss   :INFO :atr (Len=35)
      00 A0 00 00    03 96 04 03    E8 00 FE 02    0B 03 E8 08
      01 00 00 00    00 64 00 00    0A 4A 43 4F    50 34 20 41
      54 50 4F
sss   :INFO :Newer version of Applet Found
sss   :INFO :Compiled for 0x30100. Got newer 0x30600
INFO:sss.se05x:495b0ade5249153dbcac
Random number: 495b0ade5249153dbcac";

    #[test]
    fn test_parse_uid_from_real_board_output() {
        let uid = SssCli::parse_value(REAL_UID_OUTPUT, "Unique ID:");
        assert_eq!(uid.unwrap(), "040050011f595a6179b9b204783ebae51090");
    }

    #[test]
    fn test_parse_certuid_from_real_board_output() {
        let cert = SssCli::parse_value(REAL_CERTUID_OUTPUT, "Cert UID:");
        assert_eq!(cert.unwrap(), "500179b9b204783ebae5");
    }

    #[test]
    fn test_parse_getrng_from_real_board_output() {
        let rng = SssCli::parse_value(REAL_GETRNG_OUTPUT, "Random number:");
        let rng_val = rng.unwrap();

        assert_eq!(rng_val, "495b0ade5249153dbcac");
        // Verify it's 10 bytes (20 hex chars)
        assert_eq!(rng_val.len(), 20);
    }

    #[test]
    fn test_parse_from_python_info_log_format() {
        let output = "INFO:sss.se05x:040050011f595a6179b9b204783ebae51090";
        let val = SssCli::parse_value(output, "Unique ID:");
        assert_eq!(val.unwrap(), "040050011f595a6179b9b204783ebae51090");
    }

    #[test]
    fn test_parse_returns_none_when_prefix_missing() {
        assert!(SssCli::parse_value("some random output", "Unique ID:").is_none());
    }

    #[test]
    fn test_parse_returns_none_for_empty_string() {
        assert!(SssCli::parse_value("", "Unique ID:").is_none());
    }
}
