use anyhow::{anyhow, Result};
use clap::{Args, Subcommand};
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Table};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

const RELAY_REGISTRY_PATH: &str = "/var/lib/sgx-guardian/nebula/relay_registry.json";
const RELAY_STATS_PATH: &str = "/var/lib/sgx-guardian/nebula/relay_stats.json";
const OVERLAY_REGISTRY_PATH: &str = "/var/lib/sgx-guardian/nebula/overlay_registry.json";
const LIGHTHOUSE_REGISTRY_PATH: &str = "/var/lib/sgx-guardian/nebula/lighthouse_registry.json";
const NODE_CFG_DIR: &str = "/etc/sgx-guardian/config";
const DEFAULT_RELAY_MAX_PEERS: u32 = 5;
const DEFAULT_RELAY_MAX_BANDWIDTH_MBPS: u32 = 10;

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

    let cfg_path = node_config_path(&args.node);
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

    let cfg_path = node_config_path(&args.node);
    mutate_relay_yaml(&cfg_path, |relay_map| {
        relay_map.insert(
            serde_yaml::Value::String("enabled".to_string()),
            serde_yaml::Value::Bool(enable),
        );
        relay_map
            .entry(serde_yaml::Value::String("max_peers".to_string()))
            .or_insert(serde_yaml::Value::Number(serde_yaml::Number::from(
                DEFAULT_RELAY_MAX_PEERS,
            )));
        relay_map
            .entry(serde_yaml::Value::String("max_bandwidth_mbps".to_string()))
            .or_insert(serde_yaml::Value::Number(serde_yaml::Number::from(
                DEFAULT_RELAY_MAX_BANDWIDTH_MBPS,
            )));
        relay_map
            .entry(serde_yaml::Value::String("alert_threshold_pct".to_string()))
            .or_insert(serde_yaml::Value::Number(serde_yaml::Number::from(80)));
    })?;

    sync_registry_from_yaml_toggle(&args.node, &cfg_path, enable)?;

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

fn sync_registry_from_yaml_toggle(node: &str, cfg_path: &str, enable: bool) -> Result<()> {
    let cfg = crate::config::NodeConfig::load(cfg_path)
        .map_err(|e| anyhow!("failed to load node YAML {}: {}", cfg_path, e))?;
    let relay_cfg = cfg.relay;
    let max_peers = relay_cfg
        .as_ref()
        .map(|r| r.max_peers)
        .unwrap_or(DEFAULT_RELAY_MAX_PEERS);
    let max_bw = relay_cfg
        .as_ref()
        .map(|r| r.max_bandwidth_mbps)
        .unwrap_or(DEFAULT_RELAY_MAX_BANDWIDTH_MBPS);

    let overlay_ip = resolve_overlay_ip(node);
    let overlay_for_new_entry = overlay_ip
        .clone()
        .unwrap_or_else(|| cfg.ip.trim().to_string());
    let endpoint_ip = if cfg.ip.trim().is_empty() {
        "0.0.0.0".to_string()
    } else {
        cfg.ip.trim().to_string()
    };
    let endpoint = format!("{}:4242", endpoint_ip);
    let now = chrono::Utc::now().timestamp();

    let mut reg = load_registry().unwrap_or_default();
    if reg.circle_id.trim().is_empty() {
        reg.circle_id = "guardian-circle-alpha".to_string();
    }
    if enable {
        let entry = reg
            .relays
            .entry(node.to_string())
            .or_insert_with(|| RelayEntry {
                node_name: node.to_string(),
                overlay_ip: overlay_for_new_entry.clone(),
                physical_endpoint: endpoint.clone(),
                is_active: true,
                is_lighthouse: false,
                max_peers,
                max_bandwidth_mbps: max_bw,
                last_seen: now,
            });

        if entry.node_name.is_empty() {
            entry.node_name = node.to_string();
        }
        if let Some(overlay_ip) = &overlay_ip {
            entry.overlay_ip = overlay_ip.clone();
        }
        if entry.physical_endpoint.is_empty() || entry.physical_endpoint == "0.0.0.0:4242" {
            entry.physical_endpoint = endpoint.clone();
        }
        if entry.max_peers == 0 {
            entry.max_peers = max_peers;
        }
        if entry.max_bandwidth_mbps == 0 {
            entry.max_bandwidth_mbps = max_bw;
        }
        entry.is_active = true;
        entry.last_seen = now;
    } else {
        reg.relays.remove(node);
    }

    save_registry(&reg)?;
    sync_lighthouse_relay_role(node, enable, &overlay_for_new_entry, &endpoint)?;
    Ok(())
}

fn sync_lighthouse_relay_role(
    node: &str,
    enable: bool,
    overlay_ip: &str,
    endpoint: &str,
) -> Result<()> {
    let path = lighthouse_registry_path();
    if !Path::new(&path).exists() {
        return Ok(());
    }

    let mut lh = match sgx_guardian_client::nebula::lighthouse::LighthouseRegistry::load(&path) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };

    let mut changed = false;
    if enable {
        if !lh.set_relay_role(node, true) {
            lh.upsert_node(node, overlay_ip, endpoint, false, true);
            changed = true;
        } else {
            changed = true;
        }
        let _ = lh.update_endpoint(node, endpoint);
        lh.mark_active(node);
    } else {
        if lh.set_relay_role(node, false) {
            changed = true;
        }
    }

    if changed {
        lh.save(&path)
            .map_err(|e| anyhow!("failed to save lighthouse registry {}: {}", path, e))?;
    }

    Ok(())
}

fn resolve_overlay_ip(node: &str) -> Option<String> {
    let path = overlay_registry_path();
    let registry =
        sgx_guardian_client::nebula::overlay_registry::OverlayRegistry::load(&path).ok()?;
    registry.get_ip(node).map(|ip| ip.to_string())
}

fn node_config_path(node: &str) -> String {
    format!("{}/{}.yaml", node_cfg_dir(), node)
}

fn node_cfg_dir() -> String {
    env::var("SGX_GUARDIAN_NODE_CFG_DIR").unwrap_or_else(|_| NODE_CFG_DIR.to_string())
}

fn relay_registry_path() -> String {
    env::var("SGX_GUARDIAN_RELAY_REGISTRY_PATH").unwrap_or_else(|_| RELAY_REGISTRY_PATH.to_string())
}

fn relay_stats_path() -> String {
    env::var("SGX_GUARDIAN_RELAY_STATS_PATH").unwrap_or_else(|_| RELAY_STATS_PATH.to_string())
}

fn overlay_registry_path() -> String {
    env::var("SGX_GUARDIAN_OVERLAY_REGISTRY_PATH")
        .unwrap_or_else(|_| OVERLAY_REGISTRY_PATH.to_string())
}

fn lighthouse_registry_path() -> String {
    env::var("SGX_GUARDIAN_LIGHTHOUSE_REGISTRY_PATH")
        .unwrap_or_else(|_| LIGHTHOUSE_REGISTRY_PATH.to_string())
}

fn load_registry() -> Result<RelayRegistryDoc> {
    let path = relay_registry_path();
    if !Path::new(&path).exists() {
        return Ok(RelayRegistryDoc::default());
    }
    let data = fs::read_to_string(path)?;
    Ok(serde_json::from_str::<RelayRegistryDoc>(&data).unwrap_or_default())
}

fn save_registry(reg: &RelayRegistryDoc) -> Result<()> {
    let path = relay_registry_path();
    if let Some(parent) = Path::new(&path).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(reg)?)?;
    Ok(())
}

fn load_stats() -> Result<RelayStatsDoc> {
    let path = relay_stats_path();
    if !Path::new(&path).exists() {
        return Ok(RelayStatsDoc::default());
    }
    let data = fs::read_to_string(path)?;
    Ok(serde_json::from_str::<RelayStatsDoc>(&data).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use tempfile::tempdir;

    const ENV_NODE_CFG_DIR: &str = "SGX_GUARDIAN_NODE_CFG_DIR";
    const ENV_RELAY_REGISTRY_PATH: &str = "SGX_GUARDIAN_RELAY_REGISTRY_PATH";
    const ENV_RELAY_STATS_PATH: &str = "SGX_GUARDIAN_RELAY_STATS_PATH";
    const ENV_OVERLAY_REGISTRY_PATH: &str = "SGX_GUARDIAN_OVERLAY_REGISTRY_PATH";
    const ENV_LIGHTHOUSE_REGISTRY_PATH: &str = "SGX_GUARDIAN_LIGHTHOUSE_REGISTRY_PATH";

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct EnvGuard {
        node_cfg_prev: Option<String>,
        relay_registry_prev: Option<String>,
        relay_stats_prev: Option<String>,
        overlay_registry_prev: Option<String>,
        lighthouse_registry_prev: Option<String>,
    }

    impl EnvGuard {
        fn new(
            node_cfg_dir: &str,
            relay_registry: &str,
            relay_stats: &str,
            overlay: &str,
            lighthouse: &str,
        ) -> Self {
            let node_cfg_prev = env::var(ENV_NODE_CFG_DIR).ok();
            let relay_registry_prev = env::var(ENV_RELAY_REGISTRY_PATH).ok();
            let relay_stats_prev = env::var(ENV_RELAY_STATS_PATH).ok();
            let overlay_registry_prev = env::var(ENV_OVERLAY_REGISTRY_PATH).ok();
            let lighthouse_registry_prev = env::var(ENV_LIGHTHOUSE_REGISTRY_PATH).ok();

            env::set_var(ENV_NODE_CFG_DIR, node_cfg_dir);
            env::set_var(ENV_RELAY_REGISTRY_PATH, relay_registry);
            env::set_var(ENV_RELAY_STATS_PATH, relay_stats);
            env::set_var(ENV_OVERLAY_REGISTRY_PATH, overlay);
            env::set_var(ENV_LIGHTHOUSE_REGISTRY_PATH, lighthouse);

            Self {
                node_cfg_prev,
                relay_registry_prev,
                relay_stats_prev,
                overlay_registry_prev,
                lighthouse_registry_prev,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(v) = self.node_cfg_prev.take() {
                env::set_var(ENV_NODE_CFG_DIR, v);
            } else {
                env::remove_var(ENV_NODE_CFG_DIR);
            }

            if let Some(v) = self.relay_registry_prev.take() {
                env::set_var(ENV_RELAY_REGISTRY_PATH, v);
            } else {
                env::remove_var(ENV_RELAY_REGISTRY_PATH);
            }

            if let Some(v) = self.relay_stats_prev.take() {
                env::set_var(ENV_RELAY_STATS_PATH, v);
            } else {
                env::remove_var(ENV_RELAY_STATS_PATH);
            }

            if let Some(v) = self.overlay_registry_prev.take() {
                env::set_var(ENV_OVERLAY_REGISTRY_PATH, v);
            } else {
                env::remove_var(ENV_OVERLAY_REGISTRY_PATH);
            }

            if let Some(v) = self.lighthouse_registry_prev.take() {
                env::set_var(ENV_LIGHTHOUSE_REGISTRY_PATH, v);
            } else {
                env::remove_var(ENV_LIGHTHOUSE_REGISTRY_PATH);
            }
        }
    }

    fn write_node_yaml(
        path: &Path,
        node: &str,
        ip: &str,
        relay_enabled: bool,
        max_peers: u32,
        max_bw: u32,
    ) {
        let yaml = format!(
            r#"---
node_id: "{node}"
hostname: "{node}-host"
ip: "{ip}"
port: 50052
public_key: "pk-{node}"

relay:
  enabled: {relay_enabled}
  max_peers: {max_peers}
  max_bandwidth_mbps: {max_bw}
  alert_threshold_pct: 80
"#
        );
        fs::write(path, yaml).expect("write node yaml");
    }

    #[test]
    fn toggle_enable_creates_missing_registry_entry_from_yaml_and_overlay() {
        let _guard = env_lock().lock().expect("env lock");
        let tmp = tempdir().expect("tempdir");
        let cfg_dir = tmp.path().join("config");
        let nebula_dir = tmp.path().join("nebula");
        fs::create_dir_all(&cfg_dir).expect("cfg dir");
        fs::create_dir_all(&nebula_dir).expect("nebula dir");

        write_node_yaml(
            &cfg_dir.join("nodeB.yaml"),
            "nodeB",
            "10.20.30.40",
            false,
            9,
            15,
        );

        let mut overlay = sgx_guardian_client::nebula::overlay_registry::OverlayRegistry::new(
            "guardian-circle-alpha",
            "192.168.100",
            "nodeA",
        );
        overlay.assign_ip("nodeB").expect("assign overlay");
        let overlay_path = nebula_dir.join("overlay_registry.json");
        overlay
            .save(overlay_path.to_string_lossy().as_ref())
            .expect("save overlay registry");

        let relay_registry_path = nebula_dir.join("relay_registry.json");
        let relay_stats_path = nebula_dir.join("relay_stats.json");
        let lighthouse_registry_path = nebula_dir.join("lighthouse_registry.json");
        let mut lh = sgx_guardian_client::nebula::lighthouse::LighthouseRegistry::new(
            "guardian-circle-alpha",
            "nodeA",
            "192.168.100.1",
            "10.0.0.1:4242",
        );
        lh.upsert_node("nodeB", "192.168.100.2", "10.20.30.40:4242", false, false);
        lh.save(lighthouse_registry_path.to_string_lossy().as_ref())
            .expect("save lighthouse registry");
        let _env = EnvGuard::new(
            cfg_dir.to_string_lossy().as_ref(),
            relay_registry_path.to_string_lossy().as_ref(),
            relay_stats_path.to_string_lossy().as_ref(),
            overlay_path.to_string_lossy().as_ref(),
            lighthouse_registry_path.to_string_lossy().as_ref(),
        );

        run_toggle(RelayToggleArgs {
            node: "nodeB".to_string(),
            enable: true,
            disable: false,
        })
        .expect("toggle enable");

        let updated = fs::read_to_string(&relay_registry_path).expect("read relay registry");
        let doc: RelayRegistryDoc = serde_json::from_str(&updated).expect("parse relay registry");
        let entry = doc.relays.get("nodeB").expect("nodeB relay entry");
        assert!(entry.is_active);
        assert_eq!(entry.overlay_ip, "192.168.100.2");
        assert_eq!(entry.max_peers, 9);
        assert_eq!(entry.max_bandwidth_mbps, 15);
        assert_eq!(entry.physical_endpoint, "10.20.30.40:4242");

        let node_yaml = fs::read_to_string(cfg_dir.join("nodeB.yaml")).expect("read node yaml");
        assert!(node_yaml.contains("enabled: true"));

        let lh_json = fs::read_to_string(&lighthouse_registry_path).expect("read lighthouse");
        let lh: sgx_guardian_client::nebula::lighthouse::LighthouseRegistry =
            serde_json::from_str(&lh_json).expect("parse lighthouse");
        let node_b = lh
            .lighthouses
            .iter()
            .find(|e| e.node_name == "nodeB")
            .expect("nodeB in lighthouse registry");
        assert!(node_b.am_relay);
    }

    #[test]
    fn toggle_disable_updates_existing_registry_entry_active_flag() {
        let _guard = env_lock().lock().expect("env lock");
        let tmp = tempdir().expect("tempdir");
        let cfg_dir = tmp.path().join("config");
        let nebula_dir = tmp.path().join("nebula");
        fs::create_dir_all(&cfg_dir).expect("cfg dir");
        fs::create_dir_all(&nebula_dir).expect("nebula dir");

        write_node_yaml(
            &cfg_dir.join("nodeB.yaml"),
            "nodeB",
            "10.20.30.40",
            true,
            6,
            12,
        );

        let relay_registry_path = nebula_dir.join("relay_registry.json");
        let initial = RelayRegistryDoc {
            circle_id: "guardian-circle-alpha".to_string(),
            relays: {
                let mut m = HashMap::new();
                m.insert(
                    "nodeB".to_string(),
                    RelayEntry {
                        node_name: "nodeB".to_string(),
                        overlay_ip: "192.168.100.2".to_string(),
                        physical_endpoint: "10.20.30.40:4242".to_string(),
                        is_active: true,
                        is_lighthouse: false,
                        max_peers: 6,
                        max_bandwidth_mbps: 12,
                        last_seen: 123,
                    },
                );
                m
            },
        };
        fs::write(
            &relay_registry_path,
            serde_json::to_string_pretty(&initial).expect("serialize"),
        )
        .expect("write relay registry");

        let overlay_path = nebula_dir.join("overlay_registry.json");
        let relay_stats_path = nebula_dir.join("relay_stats.json");
        let lighthouse_registry_path = nebula_dir.join("lighthouse_registry.json");
        let mut lh = sgx_guardian_client::nebula::lighthouse::LighthouseRegistry::new(
            "guardian-circle-alpha",
            "nodeA",
            "192.168.100.1",
            "10.0.0.1:4242",
        );
        lh.upsert_node("nodeB", "192.168.100.2", "10.20.30.40:4242", false, true);
        lh.save(lighthouse_registry_path.to_string_lossy().as_ref())
            .expect("save lighthouse registry");
        let _env = EnvGuard::new(
            cfg_dir.to_string_lossy().as_ref(),
            relay_registry_path.to_string_lossy().as_ref(),
            relay_stats_path.to_string_lossy().as_ref(),
            overlay_path.to_string_lossy().as_ref(),
            lighthouse_registry_path.to_string_lossy().as_ref(),
        );

        run_toggle(RelayToggleArgs {
            node: "nodeB".to_string(),
            enable: false,
            disable: true,
        })
        .expect("toggle disable");

        let updated = fs::read_to_string(&relay_registry_path).expect("read relay registry");
        let doc: RelayRegistryDoc = serde_json::from_str(&updated).expect("parse relay registry");
        assert!(!doc.relays.contains_key("nodeB"));

        let node_yaml = fs::read_to_string(cfg_dir.join("nodeB.yaml")).expect("read node yaml");
        assert!(node_yaml.contains("enabled: false"));

        let lh_json = fs::read_to_string(&lighthouse_registry_path).expect("read lighthouse");
        let lh: sgx_guardian_client::nebula::lighthouse::LighthouseRegistry =
            serde_json::from_str(&lh_json).expect("parse lighthouse");
        let node_b = lh
            .lighthouses
            .iter()
            .find(|e| e.node_name == "nodeB")
            .expect("nodeB in lighthouse registry");
        assert!(!node_b.am_relay);
    }

    #[test]
    fn toggle_enable_disable_enable_has_no_duplicate_entries() {
        let _guard = env_lock().lock().expect("env lock");
        let tmp = tempdir().expect("tempdir");
        let cfg_dir = tmp.path().join("config");
        let nebula_dir = tmp.path().join("nebula");
        fs::create_dir_all(&cfg_dir).expect("cfg dir");
        fs::create_dir_all(&nebula_dir).expect("nebula dir");

        write_node_yaml(
            &cfg_dir.join("nodeB.yaml"),
            "nodeB",
            "10.20.30.40",
            false,
            5,
            10,
        );

        let mut overlay = sgx_guardian_client::nebula::overlay_registry::OverlayRegistry::new(
            "guardian-circle-alpha",
            "192.168.100",
            "nodeA",
        );
        overlay.assign_ip("nodeB").expect("assign overlay");
        let overlay_path = nebula_dir.join("overlay_registry.json");
        overlay
            .save(overlay_path.to_string_lossy().as_ref())
            .expect("save overlay registry");

        let relay_registry_path = nebula_dir.join("relay_registry.json");
        let relay_stats_path = nebula_dir.join("relay_stats.json");
        let lighthouse_registry_path = nebula_dir.join("lighthouse_registry.json");
        let mut lh = sgx_guardian_client::nebula::lighthouse::LighthouseRegistry::new(
            "guardian-circle-alpha",
            "nodeA",
            "192.168.100.1",
            "10.0.0.1:4242",
        );
        lh.upsert_node("nodeB", "192.168.100.2", "10.20.30.40:4242", false, false);
        lh.save(lighthouse_registry_path.to_string_lossy().as_ref())
            .expect("save lighthouse registry");
        let _env = EnvGuard::new(
            cfg_dir.to_string_lossy().as_ref(),
            relay_registry_path.to_string_lossy().as_ref(),
            relay_stats_path.to_string_lossy().as_ref(),
            overlay_path.to_string_lossy().as_ref(),
            lighthouse_registry_path.to_string_lossy().as_ref(),
        );

        run_toggle(RelayToggleArgs {
            node: "nodeB".to_string(),
            enable: true,
            disable: false,
        })
        .expect("enable");
        run_toggle(RelayToggleArgs {
            node: "nodeB".to_string(),
            enable: false,
            disable: true,
        })
        .expect("disable");
        run_toggle(RelayToggleArgs {
            node: "nodeB".to_string(),
            enable: true,
            disable: false,
        })
        .expect("enable again");

        let updated = fs::read_to_string(&relay_registry_path).expect("read relay registry");
        let doc: RelayRegistryDoc = serde_json::from_str(&updated).expect("parse relay registry");
        assert_eq!(doc.relays.len(), 1);
        assert!(doc.relays.contains_key("nodeB"));
    }
}
