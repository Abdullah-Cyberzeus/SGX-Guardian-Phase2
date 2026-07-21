use super::pcr::selected_indices;
use super::{
    configured_tpm_backend_from, should_attempt, tpm_required_with_dev_fallback, TpmConfig,
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
