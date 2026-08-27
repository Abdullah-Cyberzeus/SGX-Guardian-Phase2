use chrono::{TimeZone, Utc};
use sgx_guardian_client::dusage::model::{
    CategoryUsage, DeviceUsage, DusageQuota, DusageState, InterfaceUsage, UsageSnapshot,
};
use sgx_guardian_client::dusage::quota::{
    next_period_start, normalize_period, period_has_rolled, period_start_for, usage_band, used_pct,
};

#[test]
fn test_dusage_quota_periods_and_rollover_integration() {
    // 1. Period Normalization
    assert_eq!(normalize_period("  DAILY ").unwrap(), "daily");
    assert_eq!(normalize_period("weekly").unwrap(), "weekly");
    assert_eq!(normalize_period("Monthly").unwrap(), "monthly");
    assert!(normalize_period("hourly").is_err());

    // 2. Exact Timestamp Boundaries
    let test_time = Utc.with_ymd_and_hms(2026, 8, 27, 14, 30, 0).unwrap();

    let day_start = period_start_for(test_time, "daily").unwrap();
    assert_eq!(day_start, Utc.with_ymd_and_hms(2026, 8, 27, 0, 0, 0).unwrap());

    let month_start = period_start_for(test_time, "monthly").unwrap();
    assert_eq!(month_start, Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap());

    let next_month = next_period_start(month_start, "monthly").unwrap();
    assert_eq!(next_month, Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).unwrap());

    // 3. Rollover Detection
    let start_str = "2026-08-01T00:00:00Z";
    let before_roll = Utc.with_ymd_and_hms(2026, 8, 31, 23, 59, 59).unwrap();
    let after_roll = Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).unwrap();

    assert!(!period_has_rolled(start_str, "monthly", before_roll));
    assert!(period_has_rolled(start_str, "monthly", after_roll));
}

#[test]
fn test_usage_snapshot_and_threshold_bands() {
    let quota_bytes = 10_000_000_000; // 10 GB
    let quota = DusageQuota::new(quota_bytes, "monthly".into(), 1);
    assert_eq!(quota.quota_bytes, quota_bytes);

    // Green Band (<= 50%)
    let consumed_green = 4_000_000_000; // 4 GB (40%)
    let pct_green = used_pct(consumed_green, Some(quota_bytes));
    assert_eq!(pct_green, Some(40.0));
    assert_eq!(usage_band(pct_green), "green");

    // Amber Band (> 50%, <= 80%)
    let consumed_amber = 7_500_000_000; // 7.5 GB (75%)
    let pct_amber = used_pct(consumed_amber, Some(quota_bytes));
    assert_eq!(pct_amber, Some(75.0));
    assert_eq!(usage_band(pct_amber), "amber");

    // Red Band (> 80%)
    let consumed_red = 9_200_000_000; // 9.2 GB (92%)
    let pct_red = used_pct(consumed_red, Some(quota_bytes));
    assert_eq!(pct_red, Some(92.0));
    assert_eq!(usage_band(pct_red), "red");

    // Construct full snapshot and verify serialization
    let snapshot = UsageSnapshot {
        period: "monthly".into(),
        period_start: "2026-08-01T00:00:00Z".into(),
        interfaces: vec![InterfaceUsage {
            iface: "wlan0".into(),
            rx_bytes: 5_000_000_000,
            tx_bytes: 4_200_000_000,
            rx_total: 10_000_000_000,
            tx_total: 8_000_000_000,
        }],
        categories: vec![CategoryUsage {
            category: "media".into(),
            bytes: 6_000_000_000,
        }],
        devices: vec![DeviceUsage {
            ip: "192.168.1.105".into(),
            rx_bytes: 3_000_000_000,
            tx_bytes: 2_000_000_000,
        }],
        total_bytes: consumed_red,
        quota_bytes: Some(quota_bytes),
        used_pct: pct_red,
        usage_band: usage_band(pct_red),
        sampled_at: "2026-08-27T12:00:00Z".into(),
    };

    let serialized = serde_json::to_string(&snapshot).expect("serialize snapshot");
    let deserialized: UsageSnapshot =
        serde_json::from_str(&serialized).expect("deserialize snapshot");

    assert_eq!(deserialized.total_bytes, consumed_red);
    assert_eq!(deserialized.usage_band, "red");
    assert_eq!(deserialized.interfaces.len(), 1);
    assert_eq!(deserialized.devices.len(), 1);
}

#[test]
fn test_dusage_state_without_proof_helper() {
    let mut state = DusageState::new("daily".into(), "2026-08-27T00:00:00Z".into());
    state
        .iface_baselines
        .insert("eth0".into(), (1000, 2000));
    state.proof.proof_value = "proof_abc123".into();

    let unproven = state.without_proof();
    assert_eq!(unproven.period, "daily");
    assert_eq!(unproven.iface_baselines.get("eth0"), Some(&(1000, 2000)));
    assert!(unproven.proof.proof_value.is_empty());
}
