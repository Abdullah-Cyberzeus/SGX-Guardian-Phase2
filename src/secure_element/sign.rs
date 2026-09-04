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
        if crate::secure_element::tamper::is_tampered() {
            return Err(SeError::TamperDetected);
        }
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
        if crate::secure_element::tamper::is_tampered() {
            return Err(SeError::TamperDetected);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_element::ssscli::SssCli;
    use std::path::Path;

    struct EnvGuard(Option<std::ffi::OsString>);

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.0.take() {
                Some(path) => std::env::set_var("PATH", path),
                None => std::env::remove_var("PATH"),
            }
            crate::secure_element::tamper::clear_tamper();
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
    fn signer_with_script(dir: &Path, body: &str) -> (SeSigner, EnvGuard) {
        use std::os::unix::fs::PermissionsExt;

        let tool = dir.join("ssscli");
        std::fs::write(&tool, format!("#!/bin/sh\n{body}\n")).expect("write fake ssscli");
        let mut permissions = std::fs::metadata(&tool).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(tool, permissions).expect("make executable");
        let old_path = std::env::var_os("PATH");
        std::env::set_var("PATH", dir);
        (
            SeSigner {
                cli: SssCli::new(config()),
            },
            EnvGuard(old_path),
        )
    }

    #[cfg(unix)]
    #[test]
    fn sign_round_trips_fake_signature_and_verify_maps_success_or_failure() {
        let _lock = crate::test_support::blocking_env_lock();
        crate::secure_element::tamper::clear_tamper();
        let dir = tempfile::tempdir().expect("fake tool directory");
        let (signer, _guard) = signer_with_script(
            dir.path(),
            "case \"$1\" in\n sign) /bin/cp \"$3\" \"$4\";;\n verify) exit 0;;\n *) exit 8;;\nesac",
        );
        assert_eq!(
            signer.sign(0x2000_0010, b"payload").expect("signature"),
            b"payload"
        );
        assert!(signer
            .verify(0x2000_0010, b"payload", b"signature")
            .expect("verification result"));

        std::fs::write(
            dir.path().join("ssscli"),
            "#!/bin/sh\n[ \"$1\" = verify ] && exit 3\nexit 0\n",
        )
        .expect("replace fake verifier");
        assert!(!signer
            .verify(0x2000_0010, b"payload", b"bad")
            .expect("invalid signature maps to false"));
    }

    #[cfg(unix)]
    #[test]
    fn new_connects_via_the_real_ssscli_invocation() {
        let _lock = crate::test_support::blocking_env_lock();
        let dir = tempfile::tempdir().expect("fake tool directory");
        use std::os::unix::fs::PermissionsExt;
        let tool = dir.path().join("ssscli");
        std::fs::write(&tool, "#!/bin/sh\n[ \"$1\" = connect ] && exit 0\nexit 9\n")
            .expect("write fake ssscli");
        let mut permissions = std::fs::metadata(&tool).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(tool, permissions).expect("make executable");
        let old_path = std::env::var_os("PATH");
        std::env::set_var("PATH", dir.path());
        let _guard = EnvGuard(old_path);

        SeSigner::new(&config()).expect("connect succeeds via fake ssscli");
    }

    #[cfg(unix)]
    #[test]
    fn new_reports_a_connect_failure() {
        let _lock = crate::test_support::blocking_env_lock();
        let dir = tempfile::tempdir().expect("fake tool directory");
        use std::os::unix::fs::PermissionsExt;
        let tool = dir.path().join("ssscli");
        std::fs::write(&tool, "#!/bin/sh\nexit 1\n").expect("write fake ssscli");
        let mut permissions = std::fs::metadata(&tool).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(tool, permissions).expect("make executable");
        let old_path = std::env::var_os("PATH");
        std::env::set_var("PATH", dir.path());
        let _guard = EnvGuard(old_path);

        assert!(SeSigner::new(&config()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn tamper_flag_blocks_sign_and_verify_before_creating_temp_files() {
        let _lock = crate::test_support::blocking_env_lock();
        let dir = tempfile::tempdir().expect("fake tool directory");
        let (signer, _guard) = signer_with_script(dir.path(), "exit 0");
        crate::secure_element::tamper::TAMPER_DETECTED
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            signer.sign(1, b"data"),
            Err(SeError::TamperDetected)
        ));
        assert!(matches!(
            signer.verify(1, b"data", b"sig"),
            Err(SeError::TamperDetected)
        ));
    }
}
