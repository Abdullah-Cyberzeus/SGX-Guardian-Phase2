use super::*;
use once_cell::sync::Lazy;
use std::ffi::OsString;
use std::path::Path;
use tempfile::TempDir;

static ENV_LOCK: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));

struct EnvGuard {
    values: Vec<(&'static str, Option<OsString>)>,
}

impl EnvGuard {
    fn set(pairs: &[(&'static str, OsString)]) -> Self {
        let mut values = Vec::new();
        for (key, value) in pairs {
            values.push((*key, std::env::var_os(key)));
            std::env::set_var(key, value);
        }
        for key in [
            "SGX_DUSAGE_QUOTA_BYTES",
            "SGX_DUSAGE_CATEGORIES_ENABLED",
            devices::CONNTRACK_ENABLED_ENV,
        ] {
            values.push((key, std::env::var_os(key)));
            std::env::remove_var(key);
        }
        Self { values }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in self.values.drain(..).rev() {
            if let Some(value) = value {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }
    }
}

fn test_config(sys_root: &Path) -> DusageConfig {
    DusageConfig {
        enabled: true,
        sample_secs: 60,
        period: "daily".to_string(),
        sys_class_net: sys_root.to_path_buf(),
        enable_categories: false,
        enable_devices: false,
    }
}

fn write_iface(root: &Path, iface: &str, rx: u64, tx: u64) {
    let stats = root.join(iface).join("statistics");
    std::fs::create_dir_all(&stats).expect("create stats dir");
    std::fs::write(stats.join("rx_bytes"), format!("{}\n", rx)).expect("rx bytes");
    std::fs::write(stats.join("tx_bytes"), format!("{}\n", tx)).expect("tx bytes");
    std::fs::write(stats.join("rx_packets"), "1\n").expect("rx packets");
    std::fs::write(stats.join("tx_packets"), "1\n").expect("tx packets");
}

#[tokio::test]
async fn sys_reader_and_sampler_compute_period_delta() {
    let _guard = ENV_LOCK.lock().await;
    let td = TempDir::new().expect("tempdir");
    let sys_root = td.path().join("sys/class/net");
    let dusage_base = td.path().join("dusage");
    let _env = EnvGuard::set(&[(
        state::DUSAGE_BASE_ENV,
        dusage_base.as_os_str().to_os_string(),
    )]);

    write_iface(&sys_root, "eth0", 100, 200);
    let first = sampler::sample_once(&test_config(&sys_root))
        .await
        .expect("first sample");
    assert_eq!(first.total_bytes, 0);

    write_iface(&sys_root, "eth0", 150, 260);
    let second = sampler::sample_once(&test_config(&sys_root))
        .await
        .expect("second sample");
    assert_eq!(second.interfaces[0].rx_bytes, 50);
    assert_eq!(second.interfaces[0].tx_bytes, 60);
    assert_eq!(second.total_bytes, 110);
}

#[tokio::test]
async fn counter_reset_rebaselines_without_spurious_spike() {
    let _guard = ENV_LOCK.lock().await;
    let td = TempDir::new().expect("tempdir");
    let sys_root = td.path().join("sys/class/net");
    let dusage_base = td.path().join("dusage");
    let _env = EnvGuard::set(&[(
        state::DUSAGE_BASE_ENV,
        dusage_base.as_os_str().to_os_string(),
    )]);

    write_iface(&sys_root, "eth0", 500, 700);
    sampler::sample_once(&test_config(&sys_root))
        .await
        .expect("baseline sample");

    write_iface(&sys_root, "eth0", 30, 40);
    let reset = sampler::sample_once(&test_config(&sys_root))
        .await
        .expect("reset sample");
    assert_eq!(reset.total_bytes, 0);

    write_iface(&sys_root, "eth0", 45, 65);
    let after = sampler::sample_once(&test_config(&sys_root))
        .await
        .expect("after reset sample");
    assert_eq!(after.total_bytes, 40);
}

#[tokio::test]
async fn new_and_removed_interfaces_are_handled() {
    let _guard = ENV_LOCK.lock().await;
    let td = TempDir::new().expect("tempdir");
    let sys_root = td.path().join("sys/class/net");
    let dusage_base = td.path().join("dusage");
    let _env = EnvGuard::set(&[(
        state::DUSAGE_BASE_ENV,
        dusage_base.as_os_str().to_os_string(),
    )]);

    write_iface(&sys_root, "eth0", 100, 100);
    sampler::sample_once(&test_config(&sys_root))
        .await
        .expect("baseline");

    write_iface(&sys_root, "eth0", 150, 170);
    write_iface(&sys_root, "wlan0", 10, 10);
    let with_new = sampler::sample_once(&test_config(&sys_root))
        .await
        .expect("with new iface");
    let wlan = with_new
        .interfaces
        .iter()
        .find(|usage| usage.iface == "wlan0")
        .expect("wlan usage");
    assert_eq!(wlan.rx_bytes + wlan.tx_bytes, 0);

    std::fs::remove_dir_all(sys_root.join("eth0")).expect("remove eth0");
    let after_removed = sampler::sample_once(&test_config(&sys_root))
        .await
        .expect("after removed iface");
    let eth = after_removed
        .interfaces
        .iter()
        .find(|usage| usage.iface == "eth0")
        .expect("eth retained");
    assert_eq!(eth.rx_bytes, 50);
    assert_eq!(eth.tx_bytes, 70);
}

#[test]
fn quota_thresholds_match_frontend_bands() {
    assert_eq!(quota::used_pct(51, Some(100)), Some(51.0));
    assert_eq!(quota::usage_band(Some(49.0)), "green");
    assert_eq!(quota::usage_band(Some(50.1)), "amber");
    assert_eq!(quota::usage_band(Some(80.1)), "red");
    assert_eq!(quota::usage_band(None), "none");
}

#[test]
fn parses_nft_named_counter_json() {
    let json = br#"{
      "nftables": [
        {"metainfo": {"json_schema_version": 1}},
        {"counter": {"family": "inet", "table": "sgx_guardian", "name": "gossip", "packets": 2, "bytes": 99}},
        {"counter": {"family": "inet", "table": "sgx_guardian", "name": "registry", "packets": 1, "bytes": 44}}
      ]
    }"#;
    let counters = counters::parse_nft_counters_json(json).expect("parse counters");
    assert_eq!(counters.len(), 2);
    assert_eq!(counters[0].category, "gossip");
    assert_eq!(counters[0].bytes, 99);
}

#[test]
fn parses_conntrack_device_usage_when_available() {
    let line = "ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.2 dst=10.0.0.3 sport=1 dport=2 packets=3 bytes=120 src=10.0.0.3 dst=10.0.0.2 sport=2 dport=1 packets=4 bytes=80";
    let usage = devices::parse_conntrack_usage(line);
    let a = usage
        .iter()
        .find(|usage| usage.ip == "10.0.0.2")
        .expect("device a");
    assert_eq!(a.tx_bytes, 120);
    assert_eq!(a.rx_bytes, 80);
}
