use sgx_guardian_client::threat::SuricataConfig;
use std::path::PathBuf;

#[test]
fn committed_threat_config_matches_expected_defaults() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("config")
        .join("threat")
        .join("config.yaml");

    let cfg = SuricataConfig::load(&path).expect("load committed threat config");

    assert!(!cfg.enabled);
    assert_eq!(cfg.block_mode.as_str(), "alert_only");
    assert_eq!(
        cfg.block_exempt,
        vec!["127.0.0.0/8".to_string(), "192.168.100.0/24".to_string()]
    );
}
