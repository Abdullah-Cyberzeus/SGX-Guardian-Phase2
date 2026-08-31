use super::pcr::selected_indices;
use super::{
    configured_tpm_backend_from, device_from_tcti, parse_handle, should_attempt,
    tpm_required_with_dev_fallback, TpmConfig, TpmError,
};

#[test]
fn parse_pcr_selection_indices() {
    assert_eq!(selected_indices("sha256:0,2,4,7"), vec![0, 2, 4, 7]);
    assert_eq!(selected_indices("sha256:10,11"), vec![10, 11]);
    assert!(selected_indices("sha256").is_empty());
}

#[test]
fn valid_explicit_tpm_device_is_required_and_attempted() {
    let temp = tempfile::NamedTempFile::new().expect("temp device marker");
    let device = temp.path().to_string_lossy().to_string();
    let cfg = TpmConfig {
        device: device.clone(),
        tcti: format!("device:{device}"),
        explicit_backend: true,
        ..TpmConfig::default()
    };

    assert_eq!(cfg.device, device);
    assert_eq!(cfg.tcti, format!("device:{}", cfg.device));
    assert!(cfg.explicit_backend);
    assert!(should_attempt(&cfg));
    assert!(tpm_required_with_dev_fallback(&cfg, false));
}

#[test]
fn invalid_tpm_tcti_is_respected_and_required() {
    let (device, tcti, explicit_backend) =
        configured_tpm_backend_from(None, Some("device:/dev/invalid-tpm-device"));
    let cfg = TpmConfig {
        device,
        tcti,
        explicit_backend,
        ..TpmConfig::default()
    };

    assert_eq!(cfg.device, "/dev/invalid-tpm-device");
    assert_eq!(cfg.tcti, "device:/dev/invalid-tpm-device");
    assert!(cfg.explicit_backend);
    assert!(should_attempt(&cfg));
    assert!(tpm_required_with_dev_fallback(&cfg, false));
}

#[test]
fn missing_default_tpm_is_not_required() {
    let cfg = TpmConfig {
        device: "/definitely/missing/tpm".into(),
        tcti: "device:/definitely/missing/tpm".into(),
        explicit_backend: false,
        ..TpmConfig::default()
    };

    assert!(!should_attempt(&cfg));
    assert!(!tpm_required_with_dev_fallback(&cfg, false));
}

#[test]
fn explicit_dev_fallback_makes_tpm_non_required() {
    let (device, tcti, explicit_backend) =
        configured_tpm_backend_from(None, Some("device:/dev/invalid-tpm-device"));
    let cfg = TpmConfig {
        device,
        tcti,
        explicit_backend,
        ..TpmConfig::default()
    };

    assert!(cfg.explicit_backend);
    assert!(should_attempt(&cfg));
    assert!(!tpm_required_with_dev_fallback(&cfg, true));
}

#[test]
fn backend_configuration_trims_values_and_uses_documented_precedence() {
    assert_eq!(
        configured_tpm_backend_from(Some(" /dev/tpm9 "), Some("mssim:host=ignored")),
        (
            "/dev/tpm9".to_string(),
            "device:/dev/tpm9".to_string(),
            true
        )
    );
    assert_eq!(
        configured_tpm_backend_from(Some("  "), Some(" device:/dev/tpm8 ")),
        (
            "/dev/tpm8".to_string(),
            "device:/dev/tpm8".to_string(),
            true
        )
    );
    assert_eq!(
        configured_tpm_backend_from(None, Some("mssim:host=127.0.0.1")),
        (
            "mssim:host=127.0.0.1".to_string(),
            "mssim:host=127.0.0.1".to_string(),
            true
        )
    );
    assert_eq!(
        configured_tpm_backend_from(Some(""), Some("")),
        (
            "/dev/tpmrm0".to_string(),
            "device:/dev/tpmrm0".to_string(),
            false
        )
    );
}

#[test]
fn tcti_device_and_handle_parsers_cover_boundaries() {
    assert_eq!(
        device_from_tcti("device: /dev/tpm0 ").as_deref(),
        Some("/dev/tpm0")
    );
    assert_eq!(device_from_tcti("device:").as_deref(), None);
    assert_eq!(device_from_tcti("tabrmd:bus_type=system").as_deref(), None);

    let _lock = crate::test_support::blocking_env_lock();
    let key = "SGX_TEST_TPM_HANDLE_PARSE";
    std::env::set_var(key, "0X8100ABCD");
    assert_eq!(parse_handle(key, 7), 0x8100_abcd);
    std::env::set_var(key, "not-hex");
    assert_eq!(parse_handle(key, 7), 7);
    std::env::remove_var(key);
    assert_eq!(parse_handle(key, 9), 9);
}

#[test]
fn tpm_error_display_covers_every_public_variant() {
    let errors = [
        TpmError::Tool("tpm2_sign".into(), "exit 1".into()),
        TpmError::NotAvailable("missing device".into()),
        TpmError::Key("bad key".into()),
        TpmError::Parse("bad output".into()),
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied").into(),
    ];
    let rendered = errors.iter().map(ToString::to_string).collect::<Vec<_>>();
    assert_eq!(rendered[0], "tpm2 tool `tpm2_sign` failed: exit 1");
    assert_eq!(rendered[1], "tpm not available: missing device");
    assert_eq!(rendered[2], "tpm key error: bad key");
    assert_eq!(rendered[3], "invalid TPM output: bad output");
    assert!(rendered[4].contains("denied"));
}
