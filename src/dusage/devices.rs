use crate::dusage::errors::DusageResult;
use crate::dusage::model::DeviceUsage;
use std::collections::BTreeMap;
use std::path::PathBuf;
use tokio::fs;

pub const CONNTRACK_ENABLED_ENV: &str = "SGX_DUSAGE_CONNTRACK_ENABLED";
pub const CONNTRACK_PATH_ENV: &str = "SGX_DUSAGE_CONNTRACK_PATH";

pub async fn read_device_usage() -> DusageResult<Vec<DeviceUsage>> {
    if !conntrack_enabled() {
        return Ok(Vec::new());
    }
    let path = std::env::var(CONNTRACK_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/proc/net/nf_conntrack"));
    let text = match fs::read_to_string(path).await {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    Ok(parse_conntrack_usage(&text))
}

pub fn parse_conntrack_usage(text: &str) -> Vec<DeviceUsage> {
    let mut usage: BTreeMap<String, (u64, u64)> = BTreeMap::new();

    for line in text.lines() {
        let mut srcs = Vec::new();
        let mut dsts = Vec::new();
        let mut bytes = Vec::new();

        for token in line.split_whitespace() {
            if let Some(value) = token.strip_prefix("src=") {
                if value.parse::<std::net::IpAddr>().is_ok() {
                    srcs.push(value.to_string());
                }
            } else if let Some(value) = token.strip_prefix("dst=") {
                if value.parse::<std::net::IpAddr>().is_ok() {
                    dsts.push(value.to_string());
                }
            } else if let Some(value) = token.strip_prefix("bytes=") {
                if let Ok(parsed) = value.parse::<u64>() {
                    bytes.push(parsed);
                }
            }
        }

        for idx in 0..bytes.len().min(srcs.len()).min(dsts.len()).min(2) {
            let amount = bytes[idx];
            usage
                .entry(srcs[idx].clone())
                .and_modify(|(_, tx)| *tx = tx.saturating_add(amount))
                .or_insert((0, amount));
            usage
                .entry(dsts[idx].clone())
                .and_modify(|(rx, _)| *rx = rx.saturating_add(amount))
                .or_insert((amount, 0));
        }
    }

    usage
        .into_iter()
        .map(|(ip, (rx_bytes, tx_bytes))| DeviceUsage {
            ip,
            rx_bytes,
            tx_bytes,
        })
        .collect()
}

fn conntrack_enabled() -> bool {
    std::env::var(CONNTRACK_ENABLED_ENV)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}
