use anyhow::{anyhow, Result};
use clap::{Args, Subcommand};
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Table};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const RELAY_REGISTRY_PATH: &str = "/var/lib/sgx-guardian/nebula/relay_registry.json";
const RELAY_STATS_PATH: &str = "/var/lib/sgx-guardian/nebula/relay_stats.json";
const NODE_CFG_DIR: &str = "/etc/sgx-guardian/config";

#[derive(Args)]
#[command(about = "Relay management commands")]
pub struct RelayArgs {
    #[command(subcommand)]
    pub command: RelayCommand,
}

#[derive(Subcommand)]
pub enum RelayCommand {
    /// List relay nodes from relay_registry.json
    List,
    /// Show relay stats for a node
    Stats(RelayStatsArgs),
    /// Set relay limits for a node config
    SetLimit(RelaySetLimitArgs),
    /// Enable/disable relay in node config
    Toggle(RelayToggleArgs),
}

#[derive(Args)]
pub struct RelayStatsArgs {
    pub node: String,
}

#[derive(Args)]
pub struct RelaySetLimitArgs {
    pub node: String,
    #[arg(long)]
    pub max_peers: Option<u32>,
    #[arg(long = "max-bandwidth-mbps")]
    pub max_bandwidth_mbps: Option<u32>,
}

#[derive(Args)]
pub struct RelayToggleArgs {
    pub node: String,
    #[arg(long, default_value_t = false, conflicts_with = "disable")]
    pub enable: bool,
    #[arg(long, default_value_t = false, conflicts_with = "enable")]
    pub disable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RelayEntry {
    node_name: String,
    overlay_ip: String,
    physical_endpoint: String,
    is_active: bool,
    is_lighthouse: bool,
    max_peers: u32,
    max_bandwidth_mbps: u32,
    last_seen: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RelayRegistryDoc {
    circle_id: String,
    relays: HashMap<String, RelayEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RelayStatsDoc {
    node_id: String,
    updated_at: String,
    active_peers: u32,
    total_bytes_relayed: u64,
    current_mbps: f64,
    direct_tunnels: u32,
    relay_tunnels: u32,
}

pub fn run(args: RelayArgs) -> Result<()> {
    match args.command {
        RelayCommand::List => run_list(),
        RelayCommand::Stats(a) => run_stats(a),
        RelayCommand::SetLimit(a) => run_set_limit(a),
        RelayCommand::Toggle(a) => run_toggle(a),
    }
}

pub fn run_list() -> Result<()> {
    let reg = load_registry()?;
    if reg.relays.is_empty() {
        println!("No relay nodes found.");
        return Ok(());
    }

    let stats = load_stats().ok();

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec![
            "Node",
            "Overlay IP",
            "Active",
            "Max Peers",
            "Max BW",
            "Current",
        ]);

    let mut nodes = reg.relays.keys().cloned().collect::<Vec<_>>();
    nodes.sort();
    for node in nodes {
        let entry = reg.relays.get(&node).expect("node exists");
        let current = stats
            .as_ref()
            .filter(|s| s.node_id == node)
            .map(|s| format!("{:.2} Mbps", s.current_mbps))
            .unwrap_or_else(|| "n/a".to_string());

        let max_bw = if entry.max_bandwidth_mbps == 0 {
            "0 (∞)".to_string()
        } else {
            format!("{} Mbps", entry.max_bandwidth_mbps)
        };

        table.add_row(vec![
            entry.node_name.clone(),
            entry.overlay_ip.clone(),
            if entry.is_active { "yes" } else { "no" }.to_string(),
            entry.max_peers.to_string(),
            max_bw,
            current,
        ]);
    }

    println!("{table}");
    Ok(())
}

pub fn run_stats(args: RelayStatsArgs) -> Result<()> {
    let node = args.node;
    let reg = load_registry().unwrap_or_default();
    let stats = load_stats().unwrap_or_default();
    let entry = reg.relays.get(&node).cloned().unwrap_or_default();

    println!("Node:               {}", node);
    println!(
        "Active peers:       {}",
        if stats.node_id == node {
            stats.active_peers
        } else {
            0
        }
    );
    println!(
        "Total bytes:        {}",
        if stats.node_id == node {
            stats.total_bytes_relayed
        } else {
            0
        }
    );
    println!(
        "Current bandwidth:  {:.2} Mbps",
        if stats.node_id == node {
            stats.current_mbps
        } else {
            0.0
        }
    );
    println!(
        "Direct tunnels:     {}",
        if stats.node_id == node {
            stats.direct_tunnels
        } else {
            0
        }
    );
    println!(
        "Relayed tunnels:    {}",
        if stats.node_id == node {
            stats.relay_tunnels
        } else {
            0
        }
    );
    println!("Registry active:    {}", entry.is_active);
    println!("Registry max_peers: {}", entry.max_peers);
    println!(
        "Registry max_bw:    {}",
        if entry.max_bandwidth_mbps == 0 {
            "0 (∞)".to_string()
        } else {
            format!("{} Mbps", entry.max_bandwidth_mbps)
        }
    );
    Ok(())
}

pub fn run_set_limit(args: RelaySetLimitArgs) -> Result<()> {
    if args.max_peers.is_none() && args.max_bandwidth_mbps.is_none() {
        return Err(anyhow!(
            "set-limit requires at least one of --max-peers or --max-bandwidth-mbps"
        ));
    }

    let cfg_path = format!("{}/{}.yaml", NODE_CFG_DIR, args.node);
    mutate_relay_yaml(&cfg_path, |relay_map| {
        if let Some(max_peers) = args.max_peers {
            relay_map.insert(
                serde_yaml::Value::String("max_peers".to_string()),
                serde_yaml::Value::Number(serde_yaml::Number::from(max_peers)),
            );
        }
        if let Some(max_bw) = args.max_bandwidth_mbps {
            relay_map.insert(
                serde_yaml::Value::String("max_bandwidth_mbps".to_string()),
                serde_yaml::Value::Number(serde_yaml::Number::from(max_bw)),
            );
        }
        relay_map
            .entry(serde_yaml::Value::String("enabled".to_string()))
            .or_insert(serde_yaml::Value::Bool(true));
        relay_map
            .entry(serde_yaml::Value::String("alert_threshold_pct".to_string()))
            .or_insert(serde_yaml::Value::Number(serde_yaml::Number::from(80)));
    })?;

    let mut reg = load_registry().unwrap_or_default();
    if let Some(entry) = reg.relays.get_mut(&args.node) {
        if let Some(v) = args.max_peers {
            entry.max_peers = v;
        }
        if let Some(v) = args.max_bandwidth_mbps {
            entry.max_bandwidth_mbps = v;
        }
        save_registry(&reg)?;
    }

    println!("✅ Updated relay limits in {}", cfg_path);
    println!(
        "ℹ️ Restart required: sudo systemctl restart sgx-guardian@{}",
        args.node
    );
    Ok(())
}

pub fn run_toggle(args: RelayToggleArgs) -> Result<()> {
    let enable = if args.enable {
        true
    } else if args.disable {
        false
    } else {
        return Err(anyhow!("Use exactly one of --enable or --disable"));
    };

    let cfg_path = format!("{}/{}.yaml", NODE_CFG_DIR, args.node);
    mutate_relay_yaml(&cfg_path, |relay_map| {
        relay_map.insert(
            serde_yaml::Value::String("enabled".to_string()),
            serde_yaml::Value::Bool(enable),
        );
        relay_map
            .entry(serde_yaml::Value::String("max_peers".to_string()))
            .or_insert(serde_yaml::Value::Number(serde_yaml::Number::from(5)));
        relay_map
            .entry(serde_yaml::Value::String("max_bandwidth_mbps".to_string()))
            .or_insert(serde_yaml::Value::Number(serde_yaml::Number::from(10)));
        relay_map
            .entry(serde_yaml::Value::String("alert_threshold_pct".to_string()))
            .or_insert(serde_yaml::Value::Number(serde_yaml::Number::from(80)));
    })?;

    println!(
        "✅ Relay {} for {} in {}",
        if enable { "enabled" } else { "disabled" },
        args.node,
        cfg_path
    );
    println!(
        "ℹ️ Restart required: sudo systemctl restart sgx-guardian@{}",
        args.node
    );
    Ok(())
}

fn mutate_relay_yaml<F>(path: &str, mutator: F) -> Result<()>
where
    F: FnOnce(&mut serde_yaml::Mapping),
{
    let content = fs::read_to_string(path)?;
    let mut doc: serde_yaml::Value = serde_yaml::from_str(&content)?;

    if !doc.is_mapping() {
        return Err(anyhow!("node config root is not a mapping"));
    }
    let root = doc
        .as_mapping_mut()
        .ok_or_else(|| anyhow!("invalid mapping"))?;
    let relay_key = serde_yaml::Value::String("relay".to_string());
    let relay_val = root
        .entry(relay_key)
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));

    if !relay_val.is_mapping() {
        *relay_val = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    }
    let relay_map = relay_val
        .as_mapping_mut()
        .ok_or_else(|| anyhow!("relay section is not mapping"))?;

    mutator(relay_map);
    fs::write(path, serde_yaml::to_string(&doc)?)?;
    Ok(())
}

fn load_registry() -> Result<RelayRegistryDoc> {
    if !Path::new(RELAY_REGISTRY_PATH).exists() {
        return Ok(RelayRegistryDoc::default());
    }
    let data = fs::read_to_string(RELAY_REGISTRY_PATH)?;
    Ok(serde_json::from_str::<RelayRegistryDoc>(&data).unwrap_or_default())
}

fn save_registry(reg: &RelayRegistryDoc) -> Result<()> {
    if let Some(parent) = Path::new(RELAY_REGISTRY_PATH).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(RELAY_REGISTRY_PATH, serde_json::to_string_pretty(reg)?)?;
    Ok(())
}

fn load_stats() -> Result<RelayStatsDoc> {
    if !Path::new(RELAY_STATS_PATH).exists() {
        return Ok(RelayStatsDoc::default());
    }
    let data = fs::read_to_string(RELAY_STATS_PATH)?;
    Ok(serde_json::from_str::<RelayStatsDoc>(&data).unwrap_or_default())
}
