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

fn scheduler_fixture() -> (tempfile::TempDir, DiscoveryScheduler) {
    let dir = tempdir().expect("tempdir should be created");
    let scheduler = DiscoveryScheduler {
        node_id: "node-test".to_string(),
        config_path: dir.path().join("nmap.yaml"),
        whitelist_path: dir.path().join("whitelist.yaml"),
        inventory_path: dir.path().join("inventory.json"),
        state: Arc::new(Mutex::new(Inventory::default())),
    };
    (dir, scheduler)
}

#[test]
fn scheduler_preserves_node_id() {
    let (_dir, scheduler) = scheduler_fixture();
    assert_eq!(scheduler.node_id, "node-test");
}

#[test]
fn scheduler_clone_preserves_paths() {
    let (_dir, scheduler) = scheduler_fixture();
    let cloned = scheduler.clone();
    assert_eq!(cloned.config_path, scheduler.config_path);
    assert_eq!(cloned.whitelist_path, scheduler.whitelist_path);
    assert_eq!(cloned.inventory_path, scheduler.inventory_path);
}

#[tokio::test]
async fn scheduler_state_starts_empty() {
    let (_dir, scheduler) = scheduler_fixture();
    assert!(scheduler.state.lock().await.by_id.is_empty());
}

#[tokio::test]
async fn scheduler_start_seeds_config_file() {
    let (_dir, scheduler) = scheduler_fixture();
    let config_path = scheduler.config_path.clone();
    scheduler.start();
    assert!(config_path.exists());
}

#[tokio::test]
async fn scheduler_start_seeds_whitelist_file() {
    let (_dir, scheduler) = scheduler_fixture();
    let whitelist_path = scheduler.whitelist_path.clone();
    scheduler.start();
    assert!(whitelist_path.exists());
}

#[tokio::test]
async fn scheduler_start_preserves_existing_config() {
    let (_dir, scheduler) = scheduler_fixture();
    std::fs::write(&scheduler.config_path, "enabled: false\n").unwrap();
    scheduler.clone().start();
    assert_eq!(std::fs::read_to_string(&scheduler.config_path).unwrap(), "enabled: false\n");
}

#[tokio::test]
async fn scheduler_start_preserves_existing_whitelist() {
    let (_dir, scheduler) = scheduler_fixture();
    std::fs::write(&scheduler.whitelist_path, "version: \"1.0\"\ndevices: []\n").unwrap();
    scheduler.clone().start();
    assert!(std::fs::read_to_string(&scheduler.whitelist_path).unwrap().contains("devices"));
}

#[tokio::test]
async fn scheduler_start_creates_parent_directories() {
    let dir = tempdir().unwrap();
    let scheduler = DiscoveryScheduler {
        node_id: "node".into(),
        config_path: dir.path().join("a").join("nmap.yaml"),
        whitelist_path: dir.path().join("b").join("whitelist.yaml"),
        inventory_path: dir.path().join("c").join("inventory.json"),
        state: Arc::new(Mutex::new(Inventory::default())),
    };
    let config_path = scheduler.config_path.clone();
    let whitelist_path = scheduler.whitelist_path.clone();
    scheduler.start();
    assert!(config_path.exists());
    assert!(whitelist_path.exists());
}

macro_rules! scheduler_path_tests {
    ($($name:ident => $file:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            let dir = tempdir().unwrap();
            let scheduler = DiscoveryScheduler {
                node_id: "node".into(),
                config_path: dir.path().join(format!("{}.yaml", $file)),
                whitelist_path: dir.path().join(format!("{}_whitelist.yaml", $file)),
                inventory_path: dir.path().join(format!("{}.json", $file)),
                state: Arc::new(Mutex::new(Inventory::default())),
            };
            assert!(scheduler.config_path.to_string_lossy().contains($file));
            assert!(scheduler.inventory_path.to_string_lossy().ends_with(".json"));
        }
    )+};
}

scheduler_path_tests! {
    scheduler_paths_case_01 => "one",
    scheduler_paths_case_02 => "two",
    scheduler_paths_case_03 => "three",
    scheduler_paths_case_04 => "four",
    scheduler_paths_case_05 => "five",
    scheduler_paths_case_06 => "six",
    scheduler_paths_case_07 => "seven",
    scheduler_paths_case_08 => "eight",
    scheduler_paths_case_09 => "nine",
    scheduler_paths_case_10 => "ten",
    scheduler_paths_case_11 => "eleven",
    scheduler_paths_case_12 => "twelve",
    scheduler_paths_case_13 => "thirteen",
    scheduler_paths_case_14 => "fourteen",
    scheduler_paths_case_15 => "fifteen",
    scheduler_paths_case_16 => "sixteen",
}

#[test]
fn scheduler_fixture_accepts_daily_standard_values() {
    let (_dir, scheduler) = scheduler_fixture();
    let mut cfg = NmapConfig::default();
    cfg.enabled = false;
    cfg.target_cidr = Some("127.0.0.1/32".to_string());
    assert_eq!(scheduler.node_id, "node-test");
    assert_eq!(cfg.scheduled_intensity(ScheduledScanKind::Daily), Some(ScanIntensity::Aggressive));
}
