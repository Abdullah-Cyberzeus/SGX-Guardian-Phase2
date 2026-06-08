use anyhow::{anyhow, Result};
use clap::{Args, Subcommand};
use sgx_guardian_client::threat::{
    blocker::{load_block_records, BlockRecord},
    rule_manager::RuleManager,
    threat_alert::ThreatAlert,
    SuricataConfig,
};
use std::fs;
use std::path::{Path, PathBuf};

const THREAT_CFG_PATH: &str = "/etc/sgx-guardian/threat/config.yaml";
const ALERTS_PATH: &str = "/var/lib/sgx-guardian/threat/alerts.jsonl";
const BLOCKS_PATH: &str = "/var/lib/sgx-guardian/threat/blocked_ips.json";

#[derive(Args)]
#[command(about = "Suricata IDS/IPS administration (Sprint 8, SUR-series)")]
pub struct ThreatArgs {
    #[command(subcommand)]
    pub command: ThreatCommand,
}

#[derive(Subcommand)]
pub enum ThreatCommand {
    /// Show SGX Guardian threat-service and Suricata status.
    Status,
    /// Print recent alerts from alerts.jsonl.
    Alerts(AlertsArgs),
    /// Print the active block list.
    Blocks,
    /// Remove an IP from the active block list.
    Unblock(UnblockArgs),
    /// Force a suricata-update run.
    RulesUpdate,
    /// Validate Guardian + Suricata threat config.
    Validate,
}

#[derive(Args)]
pub struct AlertsArgs {
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
    #[arg(long)]
    pub severity: Option<String>,
}

#[derive(Args)]
pub struct UnblockArgs {
    pub ip: String,
}

pub fn run(args: ThreatArgs) -> Result<()> {
    match args.command {
        ThreatCommand::Status => cmd_status(),
        ThreatCommand::Alerts(args) => cmd_alerts(args),
        ThreatCommand::Blocks => cmd_blocks(),
        ThreatCommand::Unblock(args) => cmd_unblock(args),
        ThreatCommand::RulesUpdate => cmd_rules_update(),
        ThreatCommand::Validate => cmd_validate(),
    }
}

fn cmd_status() -> Result<()> {
    let cfg = SuricataConfig::load(Path::new(THREAT_CFG_PATH)).unwrap_or_default();
    println!("threat-config: {}", THREAT_CFG_PATH);
    println!("enabled: {}", cfg.enabled);
    println!("block_mode: {}", cfg.block_mode.as_str());
    println!("eve_path: {}", cfg.eve_path);
    println!("suricata_yaml: {}", cfg.suricata_yaml);
    println!("suricata: {}", systemctl_status("suricata"));
    println!("sgx-guardian: {}", systemctl_status("sgx-guardian"));
    println!("alerts: {}", count_alerts(ALERTS_PATH).unwrap_or(0));
    println!(
        "active_blocks: {}",
        load_block_records(Path::new(BLOCKS_PATH))
            .map(|value| value.len())
            .unwrap_or(0)
    );
    Ok(())
}

fn cmd_alerts(args: AlertsArgs) -> Result<()> {
    let alerts = load_alerts(ALERTS_PATH)?;
    let severity_filter = args.severity.as_deref().map(str::to_ascii_lowercase);
    let filtered = alerts
        .into_iter()
        .filter(|alert| {
            severity_filter
                .as_deref()
                .map(|expected| alert.severity.as_str().eq_ignore_ascii_case(expected))
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();

    let start = filtered.len().saturating_sub(args.limit);
    for alert in &filtered[start..] {
        println!("{}", serde_json::to_string(alert)?);
    }
    Ok(())
}

fn cmd_blocks() -> Result<()> {
    let blocks = load_block_records(Path::new(BLOCKS_PATH)).unwrap_or_default();
    if blocks.is_empty() {
        println!("No active threat blocks.");
        return Ok(());
    }

    for block in blocks {
        println!("{} {}", block.ip, block.expires_at);
    }
    Ok(())
}

fn cmd_unblock(args: UnblockArgs) -> Result<()> {
    let path = PathBuf::from(BLOCKS_PATH);
    let mut blocks = load_block_records(&path)?;
    let before = blocks.len();
    blocks.retain(|record| record.ip != args.ip);
    if blocks.len() == before {
        return Err(anyhow!("{} is not currently blocked", args.ip));
    }

    save_block_records(&path, &blocks)?;
    flush_threat_chain()?;
    for block in &blocks {
        insert_drop(&block.ip)?;
    }
    println!("unblocked {}", args.ip);
    Ok(())
}

fn cmd_rules_update() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let summary = runtime.block_on(RuleManager::update_rules("sgx-pa-cli"))?;
    println!("{}", summary);
    Ok(())
}

fn cmd_validate() -> Result<()> {
    let cfg = SuricataConfig::load(Path::new(THREAT_CFG_PATH))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(RuleManager::validate_config(&cfg.suricata_yaml))?;
    println!("ok");
    Ok(())
}

fn load_alerts(path: &str) -> Result<Vec<ThreatAlert>> {
    let text = fs::read_to_string(path)
        .map_err(|_| anyhow!("no alerts.jsonl yet - has the service run?"))?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str::<ThreatAlert>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn count_alerts(path: &str) -> Result<usize> {
    let text = fs::read_to_string(path)?;
    Ok(text.lines().filter(|line| !line.trim().is_empty()).count())
}

fn systemctl_status(unit: &str) -> String {
    std::process::Command::new("systemctl")
        .args(["is-active", unit])
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|status| !status.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn save_block_records(path: &Path, blocks: &[BlockRecord]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut ordered = blocks.to_vec();
    ordered.sort_by(|lhs, rhs| lhs.ip.cmp(&rhs.ip));
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(&ordered)?)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn flush_threat_chain() -> Result<()> {
    let status = std::process::Command::new("nft")
        .args(["flush", "chain", "inet", "sgx_threat", "input"])
        .status();

    match status {
        Ok(status) if status.success() => Ok(()),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Err(anyhow!("nft binary not found"))
        }
        Err(err) => Err(err.into()),
    }
}

fn insert_drop(ip: &str) -> Result<()> {
    let addr = ip.parse::<std::net::IpAddr>()?;
    let family = if addr.is_ipv4() { "ip" } else { "ip6" };
    let status = std::process::Command::new("nft")
        .args([
            "add",
            "rule",
            "inet",
            "sgx_threat",
            "input",
            family,
            "saddr",
            ip,
            "drop",
        ])
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("failed to restore nft rule for {}", ip))
    }
}
