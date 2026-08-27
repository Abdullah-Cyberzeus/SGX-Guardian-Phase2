use sgx_guardian_client::config_loader::{MetricsConfig, NodeConfig, RelayLimitsConfig};

fn valid_config() -> NodeConfig {
    NodeConfig {
        node_id: "nodeA".to_string(),
        hostname: "guardian-node-a".to_string(),
        ip: "192.168.1.10".to_string(),
        port: 50051,
        public_key: "public-key".to_string(),
        metrics: None,
        relay: None,
        api: None,
    }
}

#[test]
fn valid_config_accepts_metrics_and_relay_settings() {
    let mut config = valid_config();
    config.metrics = Some(MetricsConfig {
        enabled: true,
        bind: "127.0.0.1".to_string(),
        port: 9090,
    });
    config.relay = Some(RelayLimitsConfig {
        enabled: true,
        max_peers: 10,
        max_bandwidth_mbps: 25,
        alert_threshold_pct: 100,
    });

    assert_eq!(config.validate(), Ok(()));
}

#[test]
fn validation_rejects_invalid_metrics_bind_address() {
    let mut config = valid_config();
    config.metrics = Some(MetricsConfig {
        enabled: true,
        bind: "not-an-ip".to_string(),
        port: 9090,
    });

    let error = config
        .validate()
        .expect_err("invalid metrics bind must fail");
    assert!(error.contains("Invalid metrics.bind IP"));
}

#[test]
fn validation_rejects_zero_metrics_port() {
    let mut config = valid_config();
    config.metrics = Some(MetricsConfig {
        enabled: false,
        bind: "127.0.0.1".to_string(),
        port: 0,
    });

    assert_eq!(
        config.validate(),
        Err("metrics.port cannot be 0".to_string())
    );
}

#[test]
fn validation_rejects_relay_threshold_above_one_hundred() {
    let mut config = valid_config();
    config.relay = Some(RelayLimitsConfig {
        enabled: true,
        max_peers: 1,
        max_bandwidth_mbps: 1,
        alert_threshold_pct: 101,
    });

    let error = config
        .validate()
        .expect_err("threshold above 100 must fail");
    assert!(error.contains("relay.alert_threshold_pct must be 0-100"));
}

#[test]
fn validation_rejects_zero_relay_peers() {
    let mut config = valid_config();
    config.relay = Some(RelayLimitsConfig {
        enabled: true,
        max_peers: 0,
        max_bandwidth_mbps: 1,
        alert_threshold_pct: 50,
    });

    assert_eq!(
        config.validate(),
        Err("relay.max_peers cannot be 0".to_string())
    );
}
