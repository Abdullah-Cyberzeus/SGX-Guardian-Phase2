use crate::dusage::errors::DusageResult;
use crate::dusage::model::{RawCategoryCounter, RawInterfaceCounters};
use serde_json::Value;
use std::path::Path;
use tokio::fs;
use tokio::process::Command;

pub const SYS_CLASS_NET_ENV: &str = "SGX_DUSAGE_SYS_CLASS_NET";

pub async fn read_interface_counters(root: &Path) -> DusageResult<Vec<RawInterfaceCounters>> {
    let mut entries = match fs::read_dir(root).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };

    let mut out = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let iface = entry.file_name().to_string_lossy().to_string();
        if iface.starts_with('.') {
            continue;
        }
        let stats = entry.path().join("statistics");
        let Some(rx_bytes) = read_stat_u64(&stats, "rx_bytes").await? else {
            continue;
        };
        let Some(tx_bytes) = read_stat_u64(&stats, "tx_bytes").await? else {
            continue;
        };
        let rx_packets = read_stat_u64(&stats, "rx_packets").await?.unwrap_or(0);
        let tx_packets = read_stat_u64(&stats, "tx_packets").await?.unwrap_or(0);
        out.push(RawInterfaceCounters {
            iface,
            rx_bytes,
            tx_bytes,
            rx_packets,
            tx_packets,
        });
    }

    out.sort_by(|a, b| a.iface.cmp(&b.iface));
    Ok(out)
}

async fn read_stat_u64(stats_dir: &Path, name: &str) -> DusageResult<Option<u64>> {
    let path = stats_dir.join(name);
    let text = match fs::read_to_string(&path).await {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    Ok(text.trim().parse::<u64>().ok())
}

pub async fn read_nft_category_counters() -> DusageResult<Vec<RawCategoryCounter>> {
    let output = match Command::new("nft")
        .args(["-j", "list", "counters"])
        .output()
        .await
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };

    if !output.status.success() {
        return Ok(Vec::new());
    }

    parse_nft_counters_json(&output.stdout)
}

pub fn parse_nft_counters_json(bytes: &[u8]) -> DusageResult<Vec<RawCategoryCounter>> {
    let value: Value = serde_json::from_slice(bytes)?;
    let Some(items) = value.get("nftables").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };

    let mut counters = Vec::new();
    for item in items {
        let Some(counter) = item.get("counter") else {
            continue;
        };
        let Some(name) = counter.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(bytes) = counter.get("bytes").and_then(Value::as_u64) else {
            continue;
        };
        counters.push(RawCategoryCounter {
            category: name.to_string(),
            bytes,
        });
    }

    counters.sort_by(|a, b| a.category.cmp(&b.category));
    Ok(counters)
}
