use crate::dusage::counters::{read_interface_counters, read_nft_category_counters};
use crate::dusage::devices::read_device_usage;
use crate::dusage::errors::DusageResult;
use crate::dusage::model::{
    CategoryUsage, DusageState, InterfaceUsage, RawCategoryCounter, RawInterfaceCounters,
    UsageSnapshot,
};
use crate::dusage::{quota, state, DusageConfig};
use chrono::Utc;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use tokio::time::{interval, MissedTickBehavior};

pub async fn run_loop(node_id: String, config: DusageConfig) {
    let mut ticker = interval(Duration::from_secs(config.sample_secs));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        match sample_once(&config).await {
            Ok(snapshot) => {
                tracing::debug!(
                    node_id = %node_id,
                    total_bytes = snapshot.total_bytes,
                    interfaces = snapshot.interfaces.len(),
                    categories = snapshot.categories.len(),
                    "data-usage sample complete"
                );
            }
            Err(error) => {
                tracing::warn!("data-usage sample failed on {}: {}", node_id, error);
            }
        }
    }
}

pub async fn sample_once(config: &DusageConfig) -> DusageResult<UsageSnapshot> {
    let raw_ifaces = read_interface_counters(&config.sys_class_net).await?;
    let raw_categories = if config.enable_categories {
        read_nft_category_counters().await.unwrap_or_default()
    } else {
        Vec::new()
    };
    let devices = if config.enable_devices {
        read_device_usage().await.unwrap_or_default()
    } else {
        Vec::new()
    };
    let quota_record = state::load_quota()
        .await?
        .or_else(|| quota::env_default_quota(&config.period));

    let now = Utc::now();
    let current_period_start = quota::period_start_for(now, &config.period)?.to_rfc3339();
    let mut state_record = match state::load_state().await? {
        Some(existing) => existing,
        None => {
            let mut fresh = DusageState::new(config.period.clone(), current_period_start.clone());
            rebaseline(
                &mut fresh,
                &raw_ifaces,
                &raw_categories,
                &config.period,
                &current_period_start,
            );
            state::save_state(&mut fresh).await?;
            return Ok(build_snapshot(
                &mut fresh,
                &raw_ifaces,
                &raw_categories,
                devices,
                quota_record.as_ref().map(|quota| quota.quota_bytes),
                now,
                false,
            ));
        }
    };

    if state_record.period != config.period || state_record.period_start.is_empty() {
        rebaseline(
            &mut state_record,
            &raw_ifaces,
            &raw_categories,
            &config.period,
            &current_period_start,
        );
        state::save_state(&mut state_record).await?;
        return Ok(build_snapshot(
            &mut state_record,
            &raw_ifaces,
            &raw_categories,
            devices,
            quota_record.as_ref().map(|quota| quota.quota_bytes),
            now,
            false,
        ));
    }

    if quota::period_has_rolled(&state_record.period_start, &state_record.period, now) {
        let completed = build_snapshot(
            &mut state_record,
            &raw_ifaces,
            &raw_categories,
            Vec::new(),
            quota_record.as_ref().map(|quota| quota.quota_bytes),
            now,
            true,
        );
        state::append_history(&completed).await?;
        rebaseline(
            &mut state_record,
            &raw_ifaces,
            &raw_categories,
            &config.period,
            &current_period_start,
        );
        state::save_state(&mut state_record).await?;
        return Ok(build_snapshot(
            &mut state_record,
            &raw_ifaces,
            &raw_categories,
            devices,
            quota_record.as_ref().map(|quota| quota.quota_bytes),
            now,
            false,
        ));
    }

    let snapshot = build_snapshot(
        &mut state_record,
        &raw_ifaces,
        &raw_categories,
        devices,
        quota_record.as_ref().map(|quota| quota.quota_bytes),
        now,
        false,
    );
    state_record.sequence = state_record.sequence.saturating_add(1);
    state::save_state(&mut state_record).await?;
    Ok(snapshot)
}

pub async fn reset_now(config: &DusageConfig) -> DusageResult<UsageSnapshot> {
    let raw_ifaces = read_interface_counters(&config.sys_class_net).await?;
    let raw_categories = if config.enable_categories {
        read_nft_category_counters().await.unwrap_or_default()
    } else {
        Vec::new()
    };
    let devices = if config.enable_devices {
        read_device_usage().await.unwrap_or_default()
    } else {
        Vec::new()
    };
    let quota_record = state::load_quota()
        .await?
        .or_else(|| quota::env_default_quota(&config.period));
    let now = Utc::now();
    let period_start = quota::period_start_for(now, &config.period)?.to_rfc3339();
    let mut state_record = DusageState::new(config.period.clone(), period_start);
    let period_start = state_record.period_start.clone();
    rebaseline(
        &mut state_record,
        &raw_ifaces,
        &raw_categories,
        &config.period,
        &period_start,
    );
    state::save_state(&mut state_record).await?;

    Ok(build_snapshot(
        &mut state_record,
        &raw_ifaces,
        &raw_categories,
        devices,
        quota_record.as_ref().map(|quota| quota.quota_bytes),
        now,
        false,
    ))
}

fn rebaseline(
    state: &mut DusageState,
    raw_ifaces: &[RawInterfaceCounters],
    raw_categories: &[RawCategoryCounter],
    period: &str,
    period_start: &str,
) {
    state.period = period.to_string();
    state.period_start = period_start.to_string();
    state.iface_baselines = raw_ifaces
        .iter()
        .map(|raw| (raw.iface.clone(), (raw.rx_bytes, raw.tx_bytes)))
        .collect();
    state.iface_last_seen = state.iface_baselines.clone();
    state.category_baselines = raw_categories
        .iter()
        .map(|raw| (raw.category.clone(), raw.bytes))
        .collect();
    state.category_last_seen = state.category_baselines.clone();
    state.sequence = state.sequence.saturating_add(1);
}

fn build_snapshot(
    state: &mut DusageState,
    raw_ifaces: &[RawInterfaceCounters],
    raw_categories: &[RawCategoryCounter],
    devices: Vec<crate::dusage::model::DeviceUsage>,
    quota_bytes: Option<u64>,
    now: chrono::DateTime<Utc>,
    read_only: bool,
) -> UsageSnapshot {
    let interfaces = interface_usage(state, raw_ifaces, read_only);
    let categories = category_usage(state, raw_categories, read_only);
    let total_bytes = interfaces
        .iter()
        .map(|iface| iface.rx_bytes.saturating_add(iface.tx_bytes))
        .sum::<u64>();
    let used_pct = quota::used_pct(total_bytes, quota_bytes);
    let usage_band = quota::usage_band(used_pct);

    UsageSnapshot {
        period: state.period.clone(),
        period_start: state.period_start.clone(),
        interfaces,
        categories,
        devices,
        total_bytes,
        quota_bytes,
        used_pct,
        usage_band,
        sampled_at: now.to_rfc3339(),
    }
}

fn interface_usage(
    state: &mut DusageState,
    raw_ifaces: &[RawInterfaceCounters],
    read_only: bool,
) -> Vec<InterfaceUsage> {
    let raw_by_iface: BTreeMap<String, (u64, u64)> = raw_ifaces
        .iter()
        .map(|raw| (raw.iface.clone(), (raw.rx_bytes, raw.tx_bytes)))
        .collect();
    let mut names: BTreeSet<String> = state.iface_baselines.keys().cloned().collect();
    names.extend(raw_by_iface.keys().cloned());

    let mut out = Vec::new();
    for iface in names {
        match raw_by_iface.get(&iface).copied() {
            Some((rx_total, tx_total)) => {
                let baseline = state
                    .iface_baselines
                    .entry(iface.clone())
                    .or_insert((rx_total, tx_total));
                let reset = rx_total < baseline.0 || tx_total < baseline.1;
                let (rx_bytes, tx_bytes) = if reset {
                    if !read_only {
                        *baseline = (rx_total, tx_total);
                    }
                    (0, 0)
                } else {
                    (
                        rx_total.saturating_sub(baseline.0),
                        tx_total.saturating_sub(baseline.1),
                    )
                };
                if !read_only {
                    state
                        .iface_last_seen
                        .insert(iface.clone(), (rx_total, tx_total));
                }
                out.push(InterfaceUsage {
                    iface,
                    rx_bytes,
                    tx_bytes,
                    rx_total,
                    tx_total,
                });
            }
            None => {
                if let (Some((base_rx, base_tx)), Some((last_rx, last_tx))) = (
                    state.iface_baselines.get(&iface),
                    state.iface_last_seen.get(&iface),
                ) {
                    out.push(InterfaceUsage {
                        iface,
                        rx_bytes: last_rx.saturating_sub(*base_rx),
                        tx_bytes: last_tx.saturating_sub(*base_tx),
                        rx_total: *last_rx,
                        tx_total: *last_tx,
                    });
                }
            }
        }
    }
    out
}

fn category_usage(
    state: &mut DusageState,
    raw_categories: &[RawCategoryCounter],
    read_only: bool,
) -> Vec<CategoryUsage> {
    let raw_by_category: BTreeMap<String, u64> = raw_categories
        .iter()
        .map(|raw| (raw.category.clone(), raw.bytes))
        .collect();
    let mut names: BTreeSet<String> = state.category_baselines.keys().cloned().collect();
    names.extend(raw_by_category.keys().cloned());

    let mut out = Vec::new();
    for category in names {
        match raw_by_category.get(&category).copied() {
            Some(raw_bytes) => {
                let baseline = state
                    .category_baselines
                    .entry(category.clone())
                    .or_insert(raw_bytes);
                let bytes = if raw_bytes < *baseline {
                    if !read_only {
                        *baseline = raw_bytes;
                    }
                    0
                } else {
                    raw_bytes.saturating_sub(*baseline)
                };
                if !read_only {
                    state.category_last_seen.insert(category.clone(), raw_bytes);
                }
                out.push(CategoryUsage { category, bytes });
            }
            None => {
                if let (Some(baseline), Some(last_seen)) = (
                    state.category_baselines.get(&category),
                    state.category_last_seen.get(&category),
                ) {
                    out.push(CategoryUsage {
                        category,
                        bytes: last_seen.saturating_sub(*baseline),
                    });
                }
            }
        }
    }
    out
}
