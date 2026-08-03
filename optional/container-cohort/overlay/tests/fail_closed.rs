use sgx_guardian_client::config_loader::{AttestationConfig, NodeConfig, PlatformConfig};
use sgx_guardian_client::platform::PlatformContext;
use std::sync::{Mutex, OnceLock};

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn test_node_config() -> NodeConfig {
    NodeConfig {
        node_id: "nodeA".to_string(),
        hostname: "guardian-node-A".to_string(),
        ip: "127.0.0.1".to_string(),
        port: 50051,
        public_key: "placeholder".to_string(),
        metrics: None,
        relay: None,
        platform: PlatformConfig {
            mode: "auto".to_string(),
            virtual_pcr_seed: "guardian-dev".to_string(),
        },
        attestation: AttestationConfig::default(),
    }
}

#[test]
fn real_platform_refuses_when_se050_probe_fails() {
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("SGX_TEST_PLATFORM_FORCE", "real-se050-fail");
    std::env::remove_var("SGX_FORCE_SOFTWARE_KEYS");
    std::env::remove_var("SGX_DISABLE_SE050_DKP");
    std::env::remove_var("SGX_ALLOW_DEBUG_SOFT_KEYS");

    let err = PlatformContext::init(test_node_config())
        .err()
        .expect("real-se050-fail should refuse startup");
    let msg = err.to_string();
    assert!(
        msg.contains("SE050 probe failed"),
        "unexpected error: {}",
        msg
    );
    std::env::remove_var("SGX_TEST_PLATFORM_FORCE");
}

#[test]
fn real_platform_force_only_is_rejected() {
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("SGX_TEST_PLATFORM_FORCE", "real");
    std::env::set_var("SGX_FORCE_SOFTWARE_KEYS", "1");
    std::env::remove_var("SGX_DISABLE_SE050_DKP");
    std::env::remove_var("SGX_ALLOW_DEBUG_SOFT_KEYS");

    let ctx = PlatformContext::init(test_node_config()).unwrap();
    let err = ctx
        .initialize_key_manager("nodeA", "/tmp/fail-closed-force-only.key")
        .err()
        .expect("single-gate software-key mode must be rejected");
    assert!(
        err.to_string().contains("SGX_ALLOW_DEBUG_SOFT_KEYS"),
        "unexpected error: {}",
        err
    );

    let _ = std::fs::remove_file("/tmp/fail-closed-force-only.key");
    std::env::remove_var("SGX_TEST_PLATFORM_FORCE");
    std::env::remove_var("SGX_FORCE_SOFTWARE_KEYS");
}

#[test]
fn real_platform_double_gate_allows_debug_software_keys() {
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("SGX_TEST_PLATFORM_FORCE", "real");
    std::env::set_var("SGX_FORCE_SOFTWARE_KEYS", "1");
    std::env::set_var("SGX_ALLOW_DEBUG_SOFT_KEYS", "1");

    let ctx = PlatformContext::init(test_node_config()).unwrap();
    let km = ctx
        .initialize_key_manager("nodeA", "/tmp/fail-closed-double-gate.key")
        .unwrap();
    assert_eq!(km.backend_name(), "Software");

    let _ = std::fs::remove_file("/tmp/fail-closed-double-gate.key");
    std::env::remove_var("SGX_TEST_PLATFORM_FORCE");
    std::env::remove_var("SGX_FORCE_SOFTWARE_KEYS");
    std::env::remove_var("SGX_ALLOW_DEBUG_SOFT_KEYS");
}

#[test]
fn real_platform_alias_gate_matches_force_gate() {
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("SGX_TEST_PLATFORM_FORCE", "real");
    std::env::set_var("SGX_DISABLE_SE050_DKP", "1");
    std::env::set_var("SGX_ALLOW_DEBUG_SOFT_KEYS", "1");

    let ctx = PlatformContext::init(test_node_config()).unwrap();
    let km = ctx
        .initialize_key_manager("nodeA", "/tmp/fail-closed-alias-gate.key")
        .unwrap();
    assert_eq!(km.backend_name(), "Software");

    let _ = std::fs::remove_file("/tmp/fail-closed-alias-gate.key");
    std::env::remove_var("SGX_TEST_PLATFORM_FORCE");
    std::env::remove_var("SGX_DISABLE_SE050_DKP");
    std::env::remove_var("SGX_ALLOW_DEBUG_SOFT_KEYS");
}
