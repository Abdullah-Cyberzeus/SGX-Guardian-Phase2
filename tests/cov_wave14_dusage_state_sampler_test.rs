use chrono::Utc;
use sgx_guardian_client::dusage::counters;
use sgx_guardian_client::dusage::devices::{
    self, parse_conntrack_usage, CONNTRACK_ENABLED_ENV, CONNTRACK_PATH_ENV,
};
use sgx_guardian_client::dusage::errors::DusageError;
use sgx_guardian_client::dusage::model::{
    CategoryUsage, DeviceUsage, DusageQuota, DusageState, InterfaceUsage, RawCategoryCounter,
    RawInterfaceCounters, UsageSnapshot,
};
use sgx_guardian_client::dusage::{self, sampler, state, DusageConfig};
use std::error::Error;
use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use tempfile::{tempdir, TempDir};

static ENV_LOCK: Mutex<()> = Mutex::new(());

const ENV_KEYS: [&str; 9] = [
    state::DUSAGE_BASE_ENV,
    counters::SYS_CLASS_NET_ENV,
    CONNTRACK_ENABLED_ENV,
    CONNTRACK_PATH_ENV,
    "SGX_DUSAGE_ENABLED",
    "SGX_DUSAGE_SAMPLE_SECS",
    "SGX_DUSAGE_PERIOD",
    "SGX_DUSAGE_QUOTA_BYTES",
    "SGX_DUSAGE_CATEGORIES_ENABLED",
];

struct DusageEnv {
    dir: TempDir,
    original: Vec<(&'static str, Option<String>)>,
    _lock: MutexGuard<'static, ()>,
}

impl DusageEnv {
    fn new() -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let dir = tempdir().unwrap();
        let original = ENV_KEYS
            .into_iter()
            .map(|key| (key, std::env::var(key).ok()))
            .collect();
        for key in ENV_KEYS {
            std::env::remove_var(key);
        }
        std::env::set_var(state::DUSAGE_BASE_ENV, dir.path().join("state"));
        Self {
            dir,
            original,
            _lock: lock,
        }
    }

    fn set(&self, key: &'static str, value: impl AsRef<std::ffi::OsStr>) {
        std::env::set_var(key, value);
    }
}

impl Drop for DusageEnv {
    fn drop(&mut self) {
        for (key, value) in &self.original {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

fn snapshot(id: u64) -> UsageSnapshot {
    UsageSnapshot {
        period: "monthly".into(),
        period_start: "2026-01-01T00:00:00Z".into(),
        interfaces: vec![InterfaceUsage {
            iface: "eth0".into(),
            rx_bytes: id,
            tx_bytes: id + 1,
            rx_total: id + 10,
            tx_total: id + 20,
        }],
        categories: vec![CategoryUsage {
            category: "web".into(),
            bytes: id,
        }],
        devices: vec![DeviceUsage {
            ip: "10.0.0.2".into(),
            rx_bytes: id,
            tx_bytes: id,
        }],
        total_bytes: id * 2 + 1,
        quota_bytes: Some(1_000),
        used_pct: Some(id as f64 / 5.0),
        usage_band: "green".into(),
        sampled_at: Utc::now().to_rfc3339(),
    }
}

fn write_stats(root: &Path, iface: &str, rx: u64, tx: u64, rx_packets: u64, tx_packets: u64) {
    let stats = root.join(iface).join("statistics");
    fs::create_dir_all(&stats).unwrap();
    for (name, value) in [
        ("rx_bytes", rx),
        ("tx_bytes", tx),
        ("rx_packets", rx_packets),
        ("tx_packets", tx_packets),
    ] {
        fs::write(stats.join(name), format!(" {value}\n")).unwrap();
    }
}

fn config(sys_root: &Path) -> DusageConfig {
    DusageConfig {
        enabled: true,
        sample_secs: 60,
        period: "daily".into(),
        sys_class_net: sys_root.to_path_buf(),
        enable_categories: false,
        enable_devices: false,
    }
}

#[test]
fn conntrack_parser_aggregates_both_directions_ipv4_ipv6_and_ignores_bad_tokens() {
    let text = concat!(
        "tcp 6 src=10.0.0.2 dst=8.8.8.8 bytes=100 src=8.8.8.8 dst=10.0.0.2 bytes=40\n",
        "udp 17 src=10.0.0.2 dst=1.1.1.1 bytes=30 src=1.1.1.1 dst=10.0.0.2 bytes=20\n",
        "tcp src=2001:db8::1 dst=2001:db8::2 bytes=7\n",
        "bad src=not-an-ip dst=also-bad bytes=nope bytes=9\n",
        "short src=10.0.0.9 dst=10.0.0.8\n",
    );
    let usage = parse_conntrack_usage(text);
    assert_eq!(
        usage.iter().map(|row| row.ip.as_str()).collect::<Vec<_>>(),
        vec![
            "1.1.1.1",
            "10.0.0.2",
            "2001:db8::1",
            "2001:db8::2",
            "8.8.8.8"
        ]
    );
    let local = usage.iter().find(|row| row.ip == "10.0.0.2").unwrap();
    assert_eq!((local.rx_bytes, local.tx_bytes), (60, 130));
    let dns = usage.iter().find(|row| row.ip == "8.8.8.8").unwrap();
    assert_eq!((dns.rx_bytes, dns.tx_bytes), (100, 40));
    assert!(parse_conntrack_usage("").is_empty());
}

#[tokio::test]
async fn device_usage_respects_enable_aliases_missing_files_custom_paths_and_io_errors() {
    let env = DusageEnv::new();
    for disabled in ["0", "false", "off", "no", "garbage"] {
        env.set(CONNTRACK_ENABLED_ENV, disabled);
        assert!(devices::read_device_usage().await.unwrap().is_empty());
    }
    env.set(CONNTRACK_ENABLED_ENV, "yes");
    env.set(CONNTRACK_PATH_ENV, env.dir.path().join("missing"));
    assert!(devices::read_device_usage().await.unwrap().is_empty());

    let path = env.dir.path().join("conntrack");
    fs::write(&path, "tcp src=10.0.0.2 dst=10.0.0.3 bytes=25\n").unwrap();
    env.set(CONNTRACK_PATH_ENV, &path);
    let usage = devices::read_device_usage().await.unwrap();
    assert_eq!(usage.len(), 2);
    assert_eq!(usage[0].ip, "10.0.0.2");
    assert_eq!(usage[0].tx_bytes, 25);

    env.set(CONNTRACK_PATH_ENV, env.dir.path());
    assert!(matches!(
        devices::read_device_usage().await,
        Err(DusageError::Io(_))
    ));
}

#[test]
fn dusage_models_initialize_strip_proofs_and_round_trip_serde() {
    let mut usage_state = DusageState::new("weekly".into(), "2026-01-05T00:00:00Z".into());
    assert_eq!(usage_state.sequence, 0);
    assert!(usage_state.iface_baselines.is_empty());
    usage_state.iface_baselines.insert("eth0".into(), (1, 2));
    usage_state.proof.proof_value = "proof".into();
    let unsigned = usage_state.without_proof();
    assert!(unsigned.proof.proof_value.is_empty());
    assert_eq!(unsigned.iface_baselines["eth0"], (1, 2));

    let mut quota = DusageQuota::new(5_000, "daily".into(), 7);
    assert_eq!((quota.quota_bytes, quota.sequence), (5_000, 7));
    quota.proof.proof_value = "proof".into();
    assert!(quota.without_proof().proof.proof_value.is_empty());

    let encoded = serde_json::to_string(&usage_state).unwrap();
    assert_eq!(
        serde_json::from_str::<DusageState>(&encoded).unwrap(),
        usage_state
    );
    let mut legacy = serde_json::to_value(DusageState::new("daily".into(), "now".into())).unwrap();
    legacy.as_object_mut().unwrap().remove("iface_last_seen");
    legacy.as_object_mut().unwrap().remove("category_last_seen");
    let legacy: DusageState = serde_json::from_value(legacy).unwrap();
    assert!(legacy.iface_last_seen.is_empty());
    assert!(legacy.category_last_seen.is_empty());
    let snapshot = snapshot(4);
    assert_eq!(
        serde_json::from_value::<UsageSnapshot>(serde_json::to_value(&snapshot).unwrap()).unwrap(),
        snapshot
    );
}

#[tokio::test]
async fn state_and_quota_persistence_seal_round_trip_and_reject_tampering() {
    let _env = DusageEnv::new();
    assert!(state::load_state().await.unwrap().is_none());
    assert!(state::load_quota().await.unwrap().is_none());

    let mut usage_state = DusageState::new("daily".into(), "2026-01-01T00:00:00Z".into());
    usage_state.sequence = 4;
    state::save_state(&mut usage_state).await.unwrap();
    assert_eq!(usage_state.proof.proof_value.len(), 64);
    assert_eq!(usage_state.proof.cryptosuite, "sha256-local-2026");
    assert_eq!(state::load_state().await.unwrap().unwrap().sequence, 4);

    let mut quota = DusageQuota::new(10_000, "monthly".into(), 2);
    state::save_quota(&mut quota).await.unwrap();
    assert_eq!(quota.proof.proof_value.len(), 64);
    assert_eq!(
        state::load_quota().await.unwrap().unwrap().quota_bytes,
        10_000
    );

    let mut tampered: serde_json::Value =
        serde_json::from_slice(&fs::read(state::state_path()).unwrap()).unwrap();
    tampered["sequence"] = serde_json::json!(99);
    fs::write(state::state_path(), serde_json::to_vec(&tampered).unwrap()).unwrap();
    assert!(state::load_state().await.unwrap().is_none());
    let mut tampered: serde_json::Value =
        serde_json::from_slice(&fs::read(state::quota_path()).unwrap()).unwrap();
    tampered["quota_bytes"] = serde_json::json!(1);
    fs::write(state::quota_path(), serde_json::to_vec(&tampered).unwrap()).unwrap();
    assert!(state::load_quota().await.unwrap().is_none());
}

#[tokio::test]
async fn state_loaders_report_malformed_json_and_unreadable_paths() {
    let _env = DusageEnv::new();
    fs::create_dir_all(state::base_dir()).unwrap();
    fs::write(state::state_path(), "{bad").unwrap();
    assert!(matches!(
        state::load_state().await,
        Err(DusageError::Json(_))
    ));
    fs::write(state::quota_path(), "{bad").unwrap();
    assert!(matches!(
        state::load_quota().await,
        Err(DusageError::Json(_))
    ));
    fs::write(state::history_path(), "{bad\n").unwrap();
    assert!(matches!(
        state::load_history().await,
        Err(DusageError::Json(_))
    ));

    fs::remove_file(state::state_path()).unwrap();
    fs::create_dir(state::state_path()).unwrap();
    assert!(matches!(state::load_state().await, Err(DusageError::Io(_))));
}

#[tokio::test]
async fn history_append_keeps_latest_four_hundred_and_ignores_blank_lines() {
    let _env = DusageEnv::new();
    assert!(state::load_history().await.unwrap().is_empty());
    fs::create_dir_all(state::base_dir()).unwrap();
    let mut text = String::new();
    for id in 0..state::MAX_HISTORY_ROWS as u64 {
        text.push_str(&serde_json::to_string(&snapshot(id)).unwrap());
        text.push('\n');
        if id == 4 {
            text.push('\n');
        }
    }
    fs::write(state::history_path(), text).unwrap();
    state::append_history(&snapshot(999)).await.unwrap();
    let rows = state::load_history().await.unwrap();
    assert_eq!(rows.len(), state::MAX_HISTORY_ROWS);
    assert_eq!(rows.first().unwrap().interfaces[0].rx_bytes, 1);
    assert_eq!(rows.last().unwrap().interfaces[0].rx_bytes, 999);
}

#[test]
fn dusage_config_environment_covers_defaults_flags_clamps_period_and_sys_root() {
    let env = DusageEnv::new();
    let defaults = DusageConfig::from_env();
    assert!(defaults.enabled);
    assert_eq!(defaults.sample_secs, 60);
    assert_eq!(defaults.period, "monthly");
    assert!(defaults.enable_categories);
    assert!(defaults.enable_devices);

    env.set("SGX_DUSAGE_ENABLED", "false");
    env.set("SGX_DUSAGE_SAMPLE_SECS", "1");
    env.set("SGX_DUSAGE_PERIOD", " WEEKLY ");
    env.set("SGX_DUSAGE_CATEGORIES_ENABLED", "yes");
    env.set(CONNTRACK_ENABLED_ENV, "on");
    env.set(counters::SYS_CLASS_NET_ENV, "/tmp/test-net-root");
    let configured = DusageConfig::from_env();
    assert!(!configured.enabled);
    assert_eq!(configured.sample_secs, 5);
    assert_eq!(configured.period, "weekly");
    assert!(configured.enable_categories);
    assert!(configured.enable_devices);
    assert_eq!(configured.sys_class_net, Path::new("/tmp/test-net-root"));

    env.set("SGX_DUSAGE_SAMPLE_SECS", "99999");
    env.set("SGX_DUSAGE_PERIOD", "yearly");
    assert_eq!(DusageConfig::from_env().sample_secs, 3600);
    assert_eq!(DusageConfig::from_env().period, "monthly");
}

#[tokio::test]
async fn sampler_baselines_accumulates_resets_counters_and_handles_interface_changes() {
    let env = DusageEnv::new();
    let sys_root = env.dir.path().join("net");
    write_stats(&sys_root, "eth0", 100, 200, 1, 2);
    let config = config(&sys_root);

    let first = sampler::sample_once(&config).await.unwrap();
    assert_eq!(first.total_bytes, 0);
    assert_eq!(first.interfaces[0].iface, "eth0");
    write_stats(&sys_root, "eth0", 160, 290, 3, 4);
    let second = sampler::sample_once(&config).await.unwrap();
    assert_eq!(
        (second.interfaces[0].rx_bytes, second.interfaces[0].tx_bytes),
        (60, 90)
    );
    assert_eq!(second.total_bytes, 150);

    write_stats(&sys_root, "eth0", 5, 6, 1, 1);
    let reset = sampler::sample_once(&config).await.unwrap();
    assert_eq!(
        (reset.interfaces[0].rx_bytes, reset.interfaces[0].tx_bytes),
        (0, 0)
    );
    write_stats(&sys_root, "wlan0", 50, 70, 2, 2);
    let added = sampler::sample_once(&config).await.unwrap();
    assert!(added
        .interfaces
        .iter()
        .any(|row| row.iface == "wlan0" && row.rx_bytes == 0));

    fs::remove_dir_all(sys_root.join("eth0")).unwrap();
    let missing = sampler::sample_once(&config).await.unwrap();
    assert!(missing.interfaces.iter().any(|row| row.iface == "eth0"));
    let reset = sampler::reset_now(&config).await.unwrap();
    assert_eq!(reset.total_bytes, 0);
}

#[tokio::test]
async fn sampler_rolls_period_archives_history_and_rebaselines_changed_configuration() {
    let env = DusageEnv::new();
    let sys_root = env.dir.path().join("net");
    write_stats(&sys_root, "eth0", 500, 800, 5, 8);
    let config = config(&sys_root);

    let mut old = DusageState::new("daily".into(), "2020-01-01T00:00:00Z".into());
    old.iface_baselines.insert("eth0".into(), (100, 100));
    old.iface_last_seen.insert("eth0".into(), (400, 700));
    state::save_state(&mut old).await.unwrap();
    let rolled = sampler::sample_once(&config).await.unwrap();
    assert_eq!(rolled.total_bytes, 0);
    let history = state::load_history().await.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].total_bytes, 1_100);

    let mut wrong_period = DusageState::new("monthly".into(), "".into());
    wrong_period.sequence = 10;
    state::save_state(&mut wrong_period).await.unwrap();
    let reconfigured = sampler::sample_once(&config).await.unwrap();
    assert_eq!(reconfigured.period, "daily");
    assert_eq!(reconfigured.total_bytes, 0);
}

#[tokio::test]
async fn public_quota_history_and_error_contracts_cover_sequences_defaults_and_failures() {
    let env = DusageEnv::new();
    assert!(dusage::history().await.unwrap().is_empty());
    assert!(dusage::get_quota().await.unwrap().is_none());
    env.set("SGX_DUSAGE_QUOTA_BYTES", "2048");
    let default = dusage::get_quota().await.unwrap().unwrap();
    assert_eq!((default.quota_bytes, default.sequence), (2048, 0));

    let first = dusage::put_quota(5_000, " DAILY ".into()).await.unwrap();
    assert_eq!((first.period.as_str(), first.sequence), ("daily", 1));
    let second = dusage::put_quota(7_000, "weekly".into()).await.unwrap();
    assert_eq!(second.sequence, 2);
    assert_eq!(
        dusage::get_quota().await.unwrap().unwrap().quota_bytes,
        7_000
    );
    assert!(matches!(
        dusage::put_quota(1, "yearly".into()).await,
        Err(DusageError::InvalidPeriod(_))
    ));

    let errors = [
        DusageError::InvalidPeriod("bad".into()).to_string(),
        DusageError::Nft("exit 1".into()).to_string(),
    ];
    assert_eq!(errors[0], "invalid data-usage period: bad");
    assert_eq!(errors[1], "nft counter command failed: exit 1");
    let io: DusageError = std::io::Error::other("disk").into();
    assert!(io.source().is_some());
    let json: DusageError = serde_json::from_str::<serde_json::Value>("{")
        .unwrap_err()
        .into();
    assert!(json.source().is_some());

    let raw_iface = RawInterfaceCounters {
        iface: "eth0".into(),
        rx_bytes: 1,
        tx_bytes: 2,
        rx_packets: 3,
        tx_packets: 4,
    };
    let raw_category = RawCategoryCounter {
        category: "dns".into(),
        bytes: 5,
    };
    assert_eq!(
        serde_json::from_value::<RawInterfaceCounters>(serde_json::to_value(&raw_iface).unwrap())
            .unwrap(),
        raw_iface
    );
    assert_eq!(
        serde_json::from_value::<RawCategoryCounter>(serde_json::to_value(&raw_category).unwrap())
            .unwrap(),
        raw_category
    );
}
