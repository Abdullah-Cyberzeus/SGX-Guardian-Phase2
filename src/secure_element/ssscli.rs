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
//   generate rsa <keyid> <bits>
//   get ecc pub <keyid> <filename>   (not --key_id --output)
//   sign <keyid> <input> <output>    (not sign sha256 --key_id --in --out)
//   verify <keyid> <input> <sigfile> (not verify sha256 --key_id --in --signature)
//   encrypt <keyid> <input> <output> --algo <oaep|rsaes|AES_CTR>
//   decrypt <keyid> <input> <output> --algo <oaep|rsaes|AES_CTR>
//   erase <keyid>                    (not --key_id)
//
// Curve names: NIST_P256, NIST_P384 (not prime256v1, secp384r1)
// ============================================================

use crate::secure_element::config::SeConfig;
use crate::secure_element::error::SeError;
use once_cell::sync::Lazy;
use std::process::Command;
use std::sync::Mutex;
use tracing::{debug, error};

/// Serializes ALL SE050 subprocess access process-wide.
///
/// SE050 talks over a single I2C session (t1oi2c). Many independent call
/// sites — DKP loading, DIK, VC/CRL signing, attestation, PCR, key rotation —
/// each open their own ssscli session with zero coordination. Two concurrent
/// invocations race for the same physical session and `sss_session_open`
/// fails on the loser (seen as "SE050 sign failed ... sss_session_open
/// failed. status: FAILED" during member VC issuance while another SE050
/// operation was in flight). Every ssscli command funnels through `run()`
/// below, so locking there serializes all SE050 access with one guard.
static SE050_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

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
        let scp_key_path = expand_tilde(&self.config.scp_key_path);
        self.run(&[
            "connect",
            "--auth_type",
            &self.config.auth_type,
            "--scpkey",
            &scp_key_path,
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

    /// Generate RSA key pair inside SE050.
    /// Syntax: ssscli generate rsa <keyid> <bits>
    pub fn generate_rsa_key(&self, key_id: &str, bits: u16) -> Result<String, SeError> {
        let bits = bits.to_string();
        self.run(&["generate", "rsa", key_id, &bits])
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

    /// Encrypt data using an SE050-backed key.
    /// Syntax: ssscli encrypt <keyid> <input_data> <output_file> --algo <algo>
    pub fn encrypt(
        &self,
        key_id: &str,
        input: &str,
        output: &str,
        algo: &str,
    ) -> Result<String, SeError> {
        self.run(&["encrypt", key_id, input, output, "--algo", algo])
    }

    /// Decrypt data using an SE050-backed key.
    /// Syntax: ssscli decrypt <keyid> <input_data> <output_file> --algo <algo>
    pub fn decrypt(
        &self,
        key_id: &str,
        input: &str,
        output: &str,
        algo: &str,
    ) -> Result<String, SeError> {
        self.run(&["decrypt", key_id, input, output, "--algo", algo])
    }

    // ── Internal ────────────────────────────────────────────

    /// Every ssscli invocation, retried on failure.
    ///
    /// ssscli persists its session in `~/.ssscli_session.pkl` across process
    /// invocations. That session state can get stuck (seen as e.g. "SE050
    /// sign failed ... sss_session_open failed. status: FAILED" during VC
    /// issuance, even with SE050_LOCK preventing true concurrent access —
    /// the *previous* invocation's session wasn't left in a state the next
    /// one can resume). DkpManager's slot-probe path already worked around
    /// this for years by clearing the stale pickle and retrying; generalizing
    /// that proven fix here covers every ssscli caller (sign, verify,
    /// connect, key generation, ...), not just slot probing.
    const RUN_ATTEMPTS: u8 = 3;

    fn run(&self, args: &[&str]) -> Result<String, SeError> {
        let _se050_guard = SE050_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let mut last_err = None;
        for attempt in 1..=Self::RUN_ATTEMPTS {
            match self.run_once(args) {
                Ok(out) => return Ok(out),
                Err(e) => {
                    if attempt < Self::RUN_ATTEMPTS {
                        debug!(
                            "ssscli {} attempt {}/{} failed, clearing stale session and retrying: {}",
                            args.join(" "),
                            attempt,
                            Self::RUN_ATTEMPTS,
                            e
                        );
                        clear_stale_session_pickle();
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.expect("loop runs at least once"))
    }

    fn run_once(&self, args: &[&str]) -> Result<String, SeError> {
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
            if let Some(stripped) = trimmed.strip_prefix(prefix) {
                return Some(stripped.trim().to_string());
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

/// Remove ssscli's persisted session file so the next invocation opens a
/// fresh session instead of resuming a stuck one. Session file naming
/// varies by ssscli version (leading char observed as "~" on-board).
pub(crate) fn clear_stale_session_pickle() {
    if let Some(home) = std::env::var_os("HOME") {
        let home = home.to_string_lossy().to_string();
        for candidate in [
            format!("{}/.ssscli_session.pkl", home),
            format!("{}/~.ssscli_session.pkl", home),
            format!("{}/~.ssscli_session.pkl", "/root"),
        ] {
            let _ = std::fs::remove_file(&candidate);
        }
    }
}

fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return format!("{}{}", home.to_string_lossy(), &path[1..]);
        }
    }
    path.to_string()
}

// ── Unit Tests (6 tests) ────────────────────────────────────
// Tests use REAL board output strings — NO subprocess, NO I/O.
// Run: cargo test secure_element::ssscli::tests -- --nocapture
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    struct EnvGuard {
        path: Option<std::ffi::OsString>,
        log: Option<std::ffi::OsString>,
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.path.take() {
                Some(value) => std::env::set_var("PATH", value),
                None => std::env::remove_var("PATH"),
            }
            match self.log.take() {
                Some(value) => std::env::set_var("SGX_TEST_SSSCLI_LOG", value),
                None => std::env::remove_var("SGX_TEST_SSSCLI_LOG"),
            }
        }
    }

    fn config() -> SeConfig {
        SeConfig {
            enabled: true,
            scp_key_path: "/keys/scp.txt".into(),
            interface: "t1oi2c".into(),
            auth_type: "PlatformSCP".into(),
            connection_type: "se05x".into(),
            dkp_key_id_base: 0x2000_0010,
            dik_key_id: 0x2000_0001,
        }
    }

    #[cfg(unix)]
    fn install_ssscli(dir: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join("ssscli");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write fake ssscli");
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).expect("make executable");
    }

    #[cfg(unix)]
    fn use_fake_ssscli(dir: &Path, log: &Path) -> EnvGuard {
        let guard = EnvGuard {
            path: std::env::var_os("PATH"),
            log: std::env::var_os("SGX_TEST_SSSCLI_LOG"),
        };
        std::env::set_var("PATH", dir);
        std::env::set_var("SGX_TEST_SSSCLI_LOG", log);
        guard
    }

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

    #[test]
    fn parse_value_trims_direct_values_and_uses_first_python_value() {
        assert_eq!(
            SssCli::parse_value("  Cert UID:   abc123  ", "Cert UID:").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            SssCli::parse_value(
                "noise\nINFO:sss.se05x:first\nINFO:sss.se05x:second",
                "missing:"
            )
            .as_deref(),
            Some("first")
        );
    }

    #[cfg(unix)]
    #[test]
    fn wrapper_methods_emit_exact_positional_arguments_and_parse_ids() {
        let _lock = crate::test_support::blocking_env_lock();
        let dir = tempfile::tempdir().expect("fake tool directory");
        let log = dir.path().join("calls.log");
        install_ssscli(
            dir.path(),
            "printf '%s\\n' \"$*\" >> \"$SGX_TEST_SSSCLI_LOG\"\ncase \"$*\" in\n  'se05x uid') echo 'Unique ID: uid-value';;\n  'se05x certuid') echo 'Cert UID: cert-value';;\n  *) echo ok;;\nesac",
        );
        let _guard = use_fake_ssscli(dir.path(), &log);
        let cli = SssCli::new(config());

        assert!(cli.connect().expect("connect").contains("ok"));
        assert!(cli.reset().expect("reset").contains("ok"));
        assert_eq!(cli.get_uid().expect("UID"), "uid-value");
        assert_eq!(cli.get_certuid().expect("cert UID"), "cert-value");
        cli.get_rng().expect("random");
        cli.read_id_list().expect("IDs");
        cli.generate_ecc_key("0x20", "NIST_P256").expect("ECC");
        cli.generate_rsa_key("0x21", 2048).expect("RSA");
        cli.get_ecc_pub("0x20", "/tmp/public.der")
            .expect("public key");
        cli.erase("0x20").expect("erase");
        cli.sign("0x20", "/tmp/in", "/tmp/sig").expect("sign");
        cli.verify("0x20", "/tmp/in", "/tmp/sig").expect("verify");
        cli.encrypt("0x20", "plain", "/tmp/cipher", "oaep")
            .expect("encrypt");
        cli.decrypt("0x20", "cipher", "/tmp/plain", "AES_CTR")
            .expect("decrypt");

        let calls = std::fs::read_to_string(log).expect("command log");
        for expected in [
            "connect --auth_type PlatformSCP --scpkey /keys/scp.txt se05x t1oi2c none",
            "se05x reset",
            "generate ecc 0x20 NIST_P256",
            "generate rsa 0x21 2048",
            "get ecc pub 0x20 /tmp/public.der",
            "erase 0x20",
            "sign 0x20 /tmp/in /tmp/sig",
            "verify 0x20 /tmp/in /tmp/sig",
            "encrypt 0x20 plain /tmp/cipher --algo oaep",
            "decrypt 0x20 cipher /tmp/plain --algo AES_CTR",
        ] {
            assert!(
                calls.lines().any(|line| line == expected),
                "missing {expected}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn command_retries_then_succeeds_and_reports_final_failure() {
        let _lock = crate::test_support::blocking_env_lock();
        let dir = tempfile::tempdir().expect("fake tool directory");
        let marker = dir.path().join("marker");
        install_ssscli(
            dir.path(),
            "if [ ! -e \"$SGX_TEST_SSSCLI_LOG\" ]; then : > \"$SGX_TEST_SSSCLI_LOG\"; echo first-failure >&2; exit 2; fi\necho recovered",
        );
        let _guard = use_fake_ssscli(dir.path(), &marker);
        assert!(SssCli::new(config())
            .reset()
            .expect("second attempt succeeds")
            .contains("recovered"));

        install_ssscli(dir.path(), "echo permanent-failure >&2; exit 9");
        let error = SssCli::new(config())
            .reset()
            .expect_err("all attempts fail");
        assert!(
            matches!(error, SeError::CommandFailed { cmd, stderr } if cmd == "ssscli se05x reset" && stderr.contains("permanent-failure"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn missing_or_malformed_uid_output_maps_to_command_failure() {
        let _lock = crate::test_support::blocking_env_lock();
        let dir = tempfile::tempdir().expect("fake tool directory");
        let log = dir.path().join("unused");
        install_ssscli(dir.path(), "echo unrelated-output");
        let _guard = use_fake_ssscli(dir.path(), &log);
        let cli = SssCli::new(config());
        assert!(
            matches!(cli.get_uid(), Err(SeError::CommandFailed { cmd, .. }) if cmd == "se05x uid")
        );
        assert!(
            matches!(cli.get_certuid(), Err(SeError::CommandFailed { cmd, .. }) if cmd == "se05x certuid")
        );
    }
}
