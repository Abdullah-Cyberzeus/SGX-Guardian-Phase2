use sgx_guardian_client::tpm::tools::Tpm2Cli;
use sgx_guardian_client::tpm::{
    dev_fallback_allowed, dik, dkp::TpmDkpManager, probe_required_capabilities, should_attempt,
    tpm_required, TpmConfig, TpmError,
};

struct EnvGuard {
    key: &'static str,
    old: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let old = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, old }
    }
    fn remove(key: &'static str) -> Self {
        let old = std::env::var_os(key);
        std::env::remove_var(key);
        Self { key, old }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(value) = self.old.take() {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

fn cfg() -> TpmConfig {
    TpmConfig {
        device: "/tmp/nonexistent-tpm".into(),
        tcti: "device:/tmp/nonexistent-tpm".into(),
        explicit_backend: true,
        dik_handle: 0x8100_0100,
        dkp_handle_base: 0x8100_0010,
        ek_handle: 0x8101_0001,
        pcr_selection: "sha256:0,2,4,7".into(),
        owner_auth: None,
        key_auth: None,
    }
}

fn with_empty_path<T>(f: impl FnOnce(Tpm2Cli) -> T) -> T {
    let dir = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set("PATH", dir.path());
    f(Tpm2Cli::new(cfg()))
}

#[test]
fn cli_available_false_when_tools_missing() {
    with_empty_path(|cli| assert!(!cli.available()));
}

#[test]
fn handle_exists_false_when_getcap_missing() {
    with_empty_path(|cli| assert!(!cli.handle_exists(0x8100_0010)));
}

#[test]
fn readpublic_der_errors_when_tool_missing() {
    with_empty_path(|cli| {
        assert!(cli
            .readpublic_der(0x8100_0010, "/tmp/sgx-no-tpm/pub.der")
            .is_err())
    });
}

#[test]
fn create_ek_errors_when_tool_missing() {
    with_empty_path(|cli| assert!(cli.create_ek(0x8101_0001).is_err()));
}

#[test]
fn evict_handle_errors_when_tool_missing() {
    with_empty_path(|cli| assert!(cli.evict_handle(0x8100_0010, None).is_err()));
}

#[test]
fn evict_handle_with_owner_auth_errors_when_tool_missing() {
    with_empty_path(|cli| assert!(cli.evict_handle(0x8100_0010, Some("auth")).is_err()));
}

#[test]
fn sign_plain_errors_when_tool_missing() {
    with_empty_path(|cli| {
        assert!(cli
            .sign_plain(0x8100_0010, "/tmp/in", "/tmp/out", None)
            .is_err())
    });
}

#[test]
fn sign_plain_with_key_auth_errors_when_tool_missing() {
    with_empty_path(|cli| {
        assert!(cli
            .sign_plain(0x8100_0010, "/tmp/in", "/tmp/out", Some("auth"))
            .is_err())
    });
}

#[test]
fn pcr_read_text_errors_when_tool_missing() {
    with_empty_path(|cli| assert!(cli.pcr_read_text("sha256:0").is_err()));
}

#[test]
fn provision_signing_key_errors_when_tool_missing() {
    with_empty_path(|cli| {
        assert!(cli
            .provision_persistent_signing_key(0x8100_0010, "/tmp/pub.der", "sign", None, None)
            .is_err());
    });
}

#[test]
fn tpm_error_tool_display_mentions_tool() {
    assert!(TpmError::Tool("tpm2_getcap".into(), "missing".into())
        .to_string()
        .contains("tpm2_getcap"));
}

#[test]
fn tpm_error_not_available_display() {
    assert!(TpmError::NotAvailable("no device".into())
        .to_string()
        .contains("tpm not available"));
}

#[test]
fn tpm_error_key_display() {
    assert!(TpmError::Key("bad".into())
        .to_string()
        .contains("tpm key error"));
}

#[test]
fn tpm_error_parse_display() {
    assert!(TpmError::Parse("bad".into())
        .to_string()
        .contains("invalid TPM output"));
}

#[test]
fn should_attempt_true_for_explicit_backend() {
    assert!(should_attempt(&cfg()));
}

#[test]
fn tpm_required_true_for_explicit_without_dev_fallback() {
    let _guard = EnvGuard::remove("SGX_ALLOW_TPM_DEV_FALLBACK");
    assert!(tpm_required(&cfg()));
}

#[test]
fn dev_fallback_allowed_accepts_true_values() {
    let _guard = EnvGuard::set("SGX_ALLOW_TPM_DEV_FALLBACK", "true");
    assert!(dev_fallback_allowed());
}

#[test]
fn tpm_config_default_parses_device_env() {
    let _guard = EnvGuard::set("SGX_TPM_DEVICE", "/tmp/tpm-test");
    assert_eq!(TpmConfig::default().tcti, "device:/tmp/tpm-test");
}

#[test]
fn tpm_config_default_parses_tcti_env() {
    let _a = EnvGuard::remove("SGX_TPM_DEVICE");
    let _b = EnvGuard::set("TPM2TOOLS_TCTI", "device:/tmp/tpmrm-test");
    assert_eq!(TpmConfig::default().device, "/tmp/tpmrm-test");
}

#[test]
fn tpm_config_default_parses_hex_handles() {
    let _guard = EnvGuard::set("SGX_TPM_DKP_HANDLE_BASE", "0x81000022");
    assert_eq!(TpmConfig::default().dkp_handle_base, 0x8100_0022);
}

#[test]
fn tpm_config_default_rejects_invalid_handle() {
    let _guard = EnvGuard::set("SGX_TPM_DKP_HANDLE_BASE", "not-hex");
    assert_eq!(TpmConfig::default().dkp_handle_base, 0x8100_0010);
}

#[test]
fn tpm_config_default_filters_empty_owner_auth() {
    let _guard = EnvGuard::set("SGX_TPM_OWNER_AUTH", "  ");
    assert!(TpmConfig::default().owner_auth.is_none());
}

#[test]
fn tpm_config_default_keeps_key_auth() {
    let _guard = EnvGuard::set("SGX_TPM_KEY_AUTH", "secret");
    assert_eq!(TpmConfig::default().key_auth.as_deref(), Some("secret"));
}

#[test]
fn tpm_config_default_uses_custom_pcr_selection() {
    let _guard = EnvGuard::set("SGX_TPM_PCR_SELECTION", "sha256:1,2");
    assert_eq!(TpmConfig::default().pcr_selection, "sha256:1,2");
}

#[test]
fn cli_new_accepts_config_without_running_tool() {
    let _cli = Tpm2Cli::new(cfg());
}

#[test]
fn config_clone_preserves_tcti() {
    assert_eq!(cfg().clone().tcti, "device:/tmp/nonexistent-tpm");
}

#[test]
fn should_attempt_false_for_implicit_missing_device() {
    let mut config = cfg();
    config.explicit_backend = false;
    assert!(!should_attempt(&config));
}

#[test]
fn tpm_required_false_when_dev_fallback_allowed() {
    let _guard = EnvGuard::set("SGX_ALLOW_TPM_DEV_FALLBACK", "true");
    assert!(!tpm_required(&cfg()));
}

#[test]
fn dev_fallback_allowed_rejects_false_values() {
    for value in ["0", "false", "FALSE", "no", "off", ""] {
        let _guard = EnvGuard::set("SGX_ALLOW_TPM_DEV_FALLBACK", value);
        assert!(!dev_fallback_allowed(), "{value}");
    }
}

#[test]
fn tpm_config_default_parses_other_handle_envs() {
    let _a = EnvGuard::set("SGX_TPM_DIK_HANDLE", "0x81000123");
    let _b = EnvGuard::set("SGX_TPM_EK_HANDLE", "81010023");
    let config = TpmConfig::default();
    assert_eq!(config.dik_handle, 0x8100_0123);
    assert_eq!(config.ek_handle, 0x8101_0023);
}

#[test]
fn probe_required_capabilities_errors_when_tools_missing() {
    with_empty_path(|_| {
        assert!(matches!(
            probe_required_capabilities(&cfg()),
            Err(TpmError::NotAvailable(_))
        ));
    });
}

#[test]
fn dik_ensure_errors_before_tooling_when_implicit_missing_device() {
    let mut config = cfg();
    config.explicit_backend = false;
    assert!(matches!(
        dik::ensure(&config),
        Err(TpmError::NotAvailable(_))
    ));
}

#[test]
fn dkp_init_errors_before_tooling_when_implicit_missing_device() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = cfg();
    config.explicit_backend = false;
    assert!(matches!(
        TpmDkpManager::init(&config, dir.path().to_str().unwrap()),
        Err(TpmError::NotAvailable(_))
    ));
}
