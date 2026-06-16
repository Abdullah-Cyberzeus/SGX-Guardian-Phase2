use sgx_guardian_client::discovery::{
    ConnectedDevice, DeviceStatus, DiscoveryScheduler, Inventory, NmapConfig, ScanIntensity,
    ScheduledScanKind,
};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

const FIXTURE_XML: &str = r#"
<nmaprun scanner="nmap" args="nmap -oX - 127.0.0.1/32">
  <host>
    <status state="up" reason="localhost-response"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="localhost" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.20.1"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.x" accuracy="98"/>
    </os>
  </host>
</nmaprun>
"#;

struct EnvVarGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &std::path::Path) -> Self {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.previous {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

#[tokio::test]
async fn scheduler_run_one_is_timeout_bounded() {
    let dir = tempdir().expect("tempdir should be created");
    let whitelist_path = dir.path().join("whitelist.yaml");
    let inventory_path = dir.path().join("inventory.json");
    let config_path = dir.path().join("nmap.yaml");
    let fixture_path = dir.path().join("nmap-fixture.xml");

    std::fs::write(&whitelist_path, "version: \"1.0\"\ndevices: []\n")
        .expect("whitelist fixture should be written");
    std::fs::write(&fixture_path, FIXTURE_XML).expect("xml fixture should be written");

    let scheduler = DiscoveryScheduler {
        node_id: "node-test".to_string(),
        config_path,
        whitelist_path,
        inventory_path: inventory_path.clone(),
        state: Arc::new(Mutex::new(Inventory::default())),
    };

    let mut cfg = NmapConfig::default();
    cfg.enabled = true;
    cfg.target_cidr = Some("127.0.0.1/32".to_string());
    cfg.timeout_secs = 10;

    let _fixture_guard = EnvVarGuard::set("SGX_TEST_NMAP_XML_FILE", &fixture_path);
    let outcome = timeout(
        Duration::from_secs(30),
        scheduler.run_one_for_test(&cfg, ScheduledScanKind::Hourly, ScanIntensity::Stealth),
    )
    .await
    .expect("run_one should not hang beyond 30s");

    outcome.expect("fixture-backed scheduler run should succeed");

    let bytes = std::fs::read(&inventory_path).expect("inventory should be written");
    let parsed: Vec<ConnectedDevice> =
        serde_json::from_slice(&bytes).expect("inventory should be valid JSON");
    assert_eq!(
        parsed.len(),
        1,
        "fixture should yield one discovered device"
    );

    let device = &parsed[0];
    assert_eq!(device.ip, "127.0.0.1");
    assert_eq!(device.hostname.as_deref(), Some("localhost"));
    assert_eq!(device.os_fingerprint.as_deref(), Some("Linux 5.x"));
    assert_eq!(device.status, DeviceStatus::Unauthorized);
    assert_eq!(device.open_ports.len(), 1);
    assert_eq!(device.open_ports[0].port, 443);
}
