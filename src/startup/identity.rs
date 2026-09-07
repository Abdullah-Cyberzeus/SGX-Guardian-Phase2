//! Selection of the node's signing key backend, and the runtime VirtualID
//! session refresh that depends on it.
//!
//! The backend decision is security-relevant — `SGX_SE050_REQUIRED` must fail
//! closed rather than quietly fall back to software keys — so it lives here
//! with its conflict cases tested, instead of inline in `main()`.

use super::GuardianPaths;
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::key_manager::KeyManager;
use crate::runtime_gates::GATES;

/// Environment variable that makes an SE050 hardware backend mandatory.
pub const SE050_REQUIRED_ENV: &str = "SGX_SE050_REQUIRED";

/// Why a particular key backend was selected, for the audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendChoice {
    /// `SGX_FORCE_SOFTWARE_KEYS` overrode hardware detection.
    SoftwareForced,
    /// A TPM 2.0 was detected and initialised.
    Tpm,
    /// An SE050 secure element was detected and initialised.
    Se050,
    /// No hardware backend was available and none was required.
    SoftwareFallback,
}

impl BackendChoice {
    /// The console line printed at startup.
    pub fn console_message(self) -> &'static str {
        match self {
            Self::SoftwareForced => {
                "Key backend: software keys (forced by SGX_FORCE_SOFTWARE_KEYS)"
            }
            Self::Tpm => "TPM detected and initialized; key backend: TPM 2.0",
            Self::Se050 => "Secure Element detected and initialized; key backend: SE050",
            Self::SoftwareFallback => "No hardware key backend detected; key backend: software",
        }
    }

    /// The message recorded in the tamper-evident audit log.
    pub fn audit_message(self) -> &'static str {
        match self {
            Self::SoftwareForced => "Key backend selected: software forced",
            Self::Tpm => "Key backend selected: TPM 2.0 hardware",
            Self::Se050 => "Key backend selected: SE050 hardware",
            Self::SoftwareFallback => "Key backend selected: software fallback",
        }
    }
}

/// Records the selected backend in the audit log.
pub fn audit_key_backend(node_id: &str, message: &str) {
    log_audit(
        node_id,
        AuditCategory::Identity,
        AuditSeverity::Info,
        AuditAction::Loaded,
        message,
    );
}

/// Rejects mutually exclusive backend requirements before any hardware is
/// probed.
///
/// Requiring the SE050 while also forcing software keys is a configuration
/// contradiction: honouring either one silently would leave the operator
/// believing a guarantee that does not hold.
pub fn validate_backend_gates(se050_required: bool, force_software: bool) -> Result<(), String> {
    if se050_required && force_software {
        return Err(format!(
            "{SE050_REQUIRED_ENV} conflicts with SGX_FORCE_SOFTWARE_KEYS"
        ));
    }
    Ok(())
}

/// Whether the build can satisfy an SE050 requirement at all.
pub fn secure_element_compiled_in() -> bool {
    cfg!(feature = "secure-element")
}

/// The error returned when the SE050 is required but cannot be provided.
pub fn se050_unavailable_error(reason: &str) -> String {
    format!("SE050 is required but {reason}")
}

/// Chooses and initialises the node's signing key backend.
///
/// The selection order is: forced software → TPM → SE050 → software fallback.
/// Every early return is a *successful* hardware selection; falling through to
/// the end means no hardware was available, which is only permitted when
/// `SGX_SE050_REQUIRED` is unset.
pub fn initialize_key_manager(node_id: &str, node_key_path: &str) -> anyhow::Result<KeyManager> {
    let se050_required = super::env_true(SE050_REQUIRED_ENV);

    if GATES.force_software_keys {
        validate_backend_gates(se050_required, true).map_err(|e| anyhow::anyhow!(e))?;
        let km = KeyManager::load_or_generate(node_key_path)?;
        report_choice(node_id, BackendChoice::SoftwareForced);
        return Ok(km);
    }

    #[cfg(feature = "tpm")]
    {
        let tpm_config = crate::tpm::TpmConfig::default();
        if !se050_required && crate::tpm::should_attempt(&tpm_config) {
            match KeyManager::init_with_tpm(&tpm_config, crate::tpm::TPM_BASE_PATH, node_key_path) {
                Ok(km) => {
                    report_choice(node_id, BackendChoice::Tpm);
                    return Ok(km);
                }
                Err(error) => {
                    eprintln!("TPM probe failed: {}", error);
                }
            }
        }
    }

    #[cfg(feature = "secure-element")]
    {
        // The SE050 middleware may be usable even when its I2C device is
        // outside a small hard-coded range or hidden behind a container.
        // Always attempt the configured backend, matching the known-good
        // attestation builds, and only permit fallback when it is optional.
        let se_config = crate::secure_element::SeConfig::default();
        match KeyManager::init_with_se050(&se_config, "/var/lib/sgx-guardian", node_key_path) {
            Ok(km) if km.backend_name() == "SE050" => {
                report_choice(node_id, BackendChoice::Se050);
                return Ok(km);
            }
            Ok(_) if se050_required => {
                return Err(anyhow::anyhow!(se050_unavailable_error(
                    "initialization selected a software key backend"
                )));
            }
            Ok(km) => {
                println!("SE050 not active; key backend: software");
                audit_key_backend(node_id, BackendChoice::SoftwareFallback.audit_message());
                return Ok(km);
            }
            Err(error) => {
                if se050_required {
                    return Err(anyhow::anyhow!(se050_unavailable_error(&format!(
                        "initialization failed: {error}"
                    ))));
                }
                eprintln!("SE050 probe failed: {}", error);
            }
        }
    }

    if !secure_element_compiled_in() && se050_required {
        return Err(anyhow::anyhow!(
            "{SE050_REQUIRED_ENV} is set but secure-element support is not compiled in"
        ));
    }

    let km = KeyManager::load_or_generate(node_key_path)?;
    report_choice(node_id, BackendChoice::SoftwareFallback);
    Ok(km)
}

fn report_choice(node_id: &str, choice: BackendChoice) {
    println!("{}", choice.console_message());
    audit_key_backend(node_id, choice.audit_message());
}

/// Re-observes this node's runtime VirtualID from its current DID, DKP and PCR
/// state, so a session that survives a rotation still reports the live values.
pub fn refresh_runtime_virtual_id_session(node_id: &str) -> anyhow::Result<()> {
    refresh_runtime_virtual_id_session_at(node_id, &GuardianPaths::production())
}

/// [`refresh_runtime_virtual_id_session`] against explicit roots.
pub fn refresh_runtime_virtual_id_session_at(
    node_id: &str,
    paths: &GuardianPaths,
) -> anyhow::Result<()> {
    let pcr_snapshot = read_runtime_virtual_id_pcr_snapshot(node_id, paths);
    crate::virtual_id::observe_runtime_virtual_id(crate::virtual_id::RuntimeVirtualIdInputs {
        node: node_id.to_string(),
        state_path: None,
        did: crate::did::DidRecord::load(crate::did::DEFAULT_DID_PATH)
            .map(|record| record.did)
            .unwrap_or_default(),
        dkp_pubkey_der: std::fs::read(paths.var_root.join("keys/dkp_pub.der")).unwrap_or_default(),
        dkp_version: crate::secure_element::pcr::read_dkp_key_version(),
        pcr_values: pcr_snapshot
            .as_ref()
            .map(|snapshot| snapshot.pcr_values.clone())
            .unwrap_or_default(),
        pcr_digest: pcr_snapshot
            .as_ref()
            .map(|snapshot| snapshot.composite_digest.clone())
            .unwrap_or_default(),
        policy_digest: crate::policy::load_effective_policy_material().digest_hex,
    })?;
    Ok(())
}

/// The persisted PCR snapshot for `node_id`, if one has been written.
pub fn read_runtime_virtual_id_pcr_snapshot(
    node_id: &str,
    paths: &GuardianPaths,
) -> Option<crate::secure_element::pcr::PcrSnapshot> {
    crate::secure_element::pcr::PcrSnapshot::load(&paths.pcr_snapshot(node_id).to_string_lossy())
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn capture(key: &'static str) -> Self {
            Self {
                key,
                previous: std::env::var_os(key),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    #[test]
    fn conflicting_backend_gates_are_rejected_before_any_hardware_is_probed() {
        assert!(validate_backend_gates(true, true).is_err());
        assert!(validate_backend_gates(true, false).is_ok());
        assert!(validate_backend_gates(false, true).is_ok());
        assert!(validate_backend_gates(false, false).is_ok());

        let message = validate_backend_gates(true, true).expect_err("conflict");
        assert!(message.contains(SE050_REQUIRED_ENV), "{message}");
        assert!(message.contains("SGX_FORCE_SOFTWARE_KEYS"), "{message}");
    }

    #[test]
    fn every_backend_choice_has_distinct_console_and_audit_text() {
        let choices = [
            BackendChoice::SoftwareForced,
            BackendChoice::Tpm,
            BackendChoice::Se050,
            BackendChoice::SoftwareFallback,
        ];
        let mut audit: Vec<&str> = choices.iter().map(|c| c.audit_message()).collect();
        audit.sort_unstable();
        audit.dedup();
        assert_eq!(
            audit.len(),
            choices.len(),
            "audit messages must be distinct"
        );

        assert!(BackendChoice::SoftwareForced
            .console_message()
            .contains("SGX_FORCE_SOFTWARE_KEYS"));
        assert!(BackendChoice::Tpm.audit_message().contains("TPM 2.0"));
        assert!(BackendChoice::Se050.console_message().contains("SE050"));
        assert!(BackendChoice::SoftwareFallback
            .audit_message()
            .contains("fallback"));
    }

    #[test]
    fn the_se050_unavailable_error_names_the_reason() {
        let error = se050_unavailable_error("initialization failed: no such device");
        assert!(error.starts_with("SE050 is required but"), "{error}");
        assert!(error.contains("no such device"), "{error}");
    }

    // `GATES.force_software_keys` is a process-wide `Lazy` fixed at first
    // access, so tests cannot flip it. Both outcomes below hold under either
    // value of that gate, and use a tempdir key path so nothing touches the
    // real /var/lib/sgx-guardian tree.
    #[test]
    fn requiring_se050_without_the_hardware_fails_closed() {
        let _lock = crate::test_support::blocking_env_lock();
        let _guard = EnvGuard::capture(SE050_REQUIRED_ENV);
        std::env::set_var(SE050_REQUIRED_ENV, "1");
        let temp = tempfile::tempdir().expect("create temp key dir");
        let key_path = temp.path().join("node.key");

        let result =
            initialize_key_manager("identity-test-node", key_path.to_str().expect("utf-8"));

        assert!(
            result.is_err(),
            "SE050-required must never fall back to software keys"
        );
    }

    #[test]
    fn software_keys_are_generated_when_no_backend_is_required() {
        let _lock = crate::test_support::blocking_env_lock();
        let _guard = EnvGuard::capture(SE050_REQUIRED_ENV);
        std::env::remove_var(SE050_REQUIRED_ENV);
        let temp = tempfile::tempdir().expect("create temp key dir");
        let key_path = temp.path().join("node.key");

        let km = initialize_key_manager("identity-test-node", key_path.to_str().expect("utf-8"))
            .expect("software fallback must succeed");

        assert!(key_path.exists(), "the generated key is persisted");
        assert!(km.pubkey_der().is_ok());

        // A second call reuses the persisted key rather than regenerating it.
        let reloaded =
            initialize_key_manager("identity-test-node", key_path.to_str().expect("utf-8"))
                .expect("reload persisted key");
        assert_eq!(
            km.pubkey_der().expect("first pubkey"),
            reloaded.pubkey_der().expect("second pubkey"),
        );
    }

    #[test]
    fn a_missing_pcr_snapshot_reads_as_none() {
        let temp = tempfile::tempdir().expect("create sandbox");
        let paths = GuardianPaths::rooted_at(temp.path());
        assert!(read_runtime_virtual_id_pcr_snapshot("nodeA", &paths).is_none());
    }

    #[test]
    fn the_virtual_id_session_is_observed_into_an_isolated_state_dir() {
        let _lock = crate::test_support::blocking_env_lock();
        let _guard = EnvGuard::capture(crate::virtual_id::RUNTIME_VID_STATE_DIR_ENV);
        let temp = tempfile::tempdir().expect("create sandbox");
        let state_dir = temp.path().join("vid-state");
        std::env::set_var(crate::virtual_id::RUNTIME_VID_STATE_DIR_ENV, &state_dir);
        let paths = GuardianPaths::rooted_at(temp.path());
        let node_id = format!("identity-vid-test-{}", std::process::id());

        refresh_runtime_virtual_id_session_at(&node_id, &paths).expect("observe session");

        let entries: Vec<_> = std::fs::read_dir(&state_dir)
            .expect("read vid state dir")
            .collect();
        assert!(
            !entries.is_empty(),
            "observe_runtime_virtual_id must persist a state file"
        );
    }
}
