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
    /// Manually block an IP address (adds nft drop rule + persists to blocked_ips.json).
    Block(BlockArgs),
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
pub struct BlockArgs {
    pub ip: String,
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
        ThreatCommand::Block(args) => cmd_block(args),
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

fn cmd_block(args: BlockArgs) -> Result<()> {
    let ip = args.ip.trim();
    ip.parse::<std::net::IpAddr>()
        .map_err(|_| anyhow!("{} is not a valid IP address", ip))?;

    let path = PathBuf::from(BLOCKS_PATH);
    let mut blocks = load_block_records(&path).unwrap_or_default();

    if blocks.iter().any(|r| r.ip == ip) {
        println!("{} is already blocked", ip);
        return Ok(());
    }

    let cfg = SuricataConfig::load(Path::new(THREAT_CFG_PATH)).unwrap_or_default();
    let expires_at = chrono::Utc::now().timestamp() + cfg.block_ttl_secs as i64;

    blocks.push(BlockRecord {
        ip: ip.to_string(),
        expires_at,
    });
    save_block_records(&path, &blocks)?;
    ensure_threat_table()?;
    insert_drop(ip)?;

    println!("blocked {} (ttl={}s)", ip, cfg.block_ttl_secs);
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

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use sgx_guardian_client::threat::blocker::BlockRecord;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn load_alerts_parses_lines_and_count_alerts_matches() {
        let td = TempDir::new().expect("tempdir");
        let p = td.path().join("alerts.jsonl");
        let content = r#"{"alert_id":"a1","timestamp":"2026-08-31T00:00:00Z","src_ip":"192.0.2.1","src_port":1234,"dst_ip":"198.51.100.2","dst_port":80,"protocol":"tcp","signature_id":1,"signature":"sig","category":"malware","severity":"high","rev":1,"gid":0,"event_type":"alert"}
    {"alert_id":"b2","timestamp":"2026-08-31T00:01:00Z","src_ip":"192.0.2.2","src_port":4321,"dst_ip":"198.51.100.3","dst_port":443,"protocol":"tcp","signature_id":2,"signature":"sig2","category":"reconnaissance","severity":"low","rev":1,"gid":0,"event_type":"alert"}
    "#;
        fs::write(&p, content).expect("write alerts");

        let alerts = load_alerts(p.to_str().unwrap()).expect("load alerts");
        assert_eq!(alerts.len(), 2);
        let cnt = count_alerts(p.to_str().unwrap()).expect("count alerts");
        assert_eq!(cnt, 2);
    }

    #[test]
    fn save_block_records_writes_sorted_json() {
        let td = TempDir::new().expect("tempdir");
        let p = td.path().join("blocked_ips.json");
        let records = vec![
            BlockRecord {
                ip: "192.0.2.5".into(),
                expires_at: 2,
            },
            BlockRecord {
                ip: "198.51.100.1".into(),
                expires_at: 1,
            },
        ];
        save_block_records(&p, &records).expect("save blocks");
        let text = fs::read_to_string(&p).expect("read blocks");
        assert!(
            text.find("192.0.2.5").expect("first IP")
                < text.find("198.51.100.1").expect("second IP")
        );
        assert!(!p.with_extension("json.tmp").exists());
    }

    #[test]
    fn alert_loading_covers_empty_missing_and_malformed_files() {
        let td = TempDir::new().expect("tempdir");
        let empty = td.path().join("empty.jsonl");
        fs::write(&empty, "\n  \n").expect("empty alert file");
        assert!(load_alerts(empty.to_str().unwrap())
            .expect("empty alerts")
            .is_empty());
        assert_eq!(
            count_alerts(empty.to_str().unwrap()).expect("empty count"),
            0
        );

        let malformed = td.path().join("malformed.jsonl");
        fs::write(&malformed, "{bad json}\n").expect("malformed alerts");
        assert!(load_alerts(malformed.to_str().unwrap()).is_err());
        assert!(load_alerts(td.path().join("missing").to_str().unwrap()).is_err());
    }

    #[test]
    fn invalid_drop_address_fails_before_invoking_nft() {
        let error = insert_drop("not-an-ip").expect_err("invalid address");
        assert!(error.to_string().to_ascii_lowercase().contains("invalid"));
    }

    #[test]
    fn saving_empty_block_list_creates_parent_and_valid_json() {
        let td = TempDir::new().expect("tempdir");
        let path = td.path().join("nested/blocks.json");
        save_block_records(&path, &[]).expect("save empty records");
        let parsed: Vec<BlockRecord> =
            serde_json::from_slice(&fs::read(path).expect("saved file")).expect("valid JSON");
        assert!(parsed.is_empty());
    }

    // ── cmd_* : none of these call std::process::exit, so all are safe in-process.
    // Every hardcoded path (THREAT_CFG_PATH/ALERTS_PATH/BLOCKS_PATH) genuinely doesn't exist
    // in this sandbox, giving real, deterministic "absent" branches.

    #[test]
    fn cmd_status_succeeds_with_defaults_when_nothing_is_configured() {
        cmd_status().expect("status always succeeds, falling back to defaults");
    }

    #[test]
    fn cmd_alerts_errors_when_alerts_file_is_absent() {
        let err = cmd_alerts(AlertsArgs {
            limit: 50,
            severity: None,
        })
        .expect_err("no alerts.jsonl in this sandbox");
        assert!(err.to_string().contains("no alerts.jsonl yet"));
    }

    #[test]
    fn cmd_blocks_reports_no_active_blocks_when_absent() {
        cmd_blocks().expect("blocks always succeeds, falling back to empty");
    }

    #[test]
    fn cmd_block_rejects_an_invalid_ip_before_any_file_access() {
        let err = cmd_block(BlockArgs {
            ip: "not-an-ip".to_string(),
        })
        .expect_err("invalid IP");
        assert!(err.to_string().contains("not a valid IP address"));
    }

    #[cfg(unix)]
    #[test]
    fn cmd_block_with_a_valid_ip_fails_on_the_unwritable_state_directory() {
        // /var/lib/sgx-guardian/threat can't be created without root, so save_block_records
        // fails deterministically after the (successful) validation step.
        let result = cmd_block(BlockArgs {
            ip: "203.0.113.77".to_string(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn cmd_unblock_reports_not_currently_blocked_when_the_block_list_is_absent() {
        let err = cmd_unblock(UnblockArgs {
            ip: "203.0.113.78".to_string(),
        })
        .expect_err("nothing is blocked in this sandbox");
        assert!(err.to_string().contains("is not currently blocked"));
    }

    #[test]
    fn cmd_rules_update_fails_deterministically_without_suricata_update_installed() {
        assert!(cmd_rules_update().is_err());
    }

    #[test]
    fn cmd_validate_fails_deterministically_without_suricata_installed() {
        assert!(cmd_validate().is_err());
    }

    #[test]
    fn flush_threat_chain_fails_deterministically_when_nft_is_not_installed() {
        // Use a deliberately nonexistent executable so the result does not depend on
        // whether the host (for example, a GitHub runner) happens to provide `nft`.
        let err = flush_threat_chain_with("sgx-guardian-test-missing-nft")
            .expect_err("the injected nft executable is not installed");
        assert!(err.to_string().contains("nft binary not found"));
    }

    #[test]
    fn ensure_threat_table_does_not_panic_when_nft_is_not_installed() {
        ensure_threat_table().expect("ensure_threat_table swallows nft errors");
    }
}

fn ensure_threat_table() -> Result<()> {
    let _ = std::process::Command::new("nft")
        .args(["add", "table", "inet", "sgx_threat"])
        .status();
    let _ = std::process::Command::new("nft")
        .args([
            "add",
            "chain",
            "inet",
            "sgx_threat",
            "input",
            "{",
            "type",
            "filter",
            "hook",
            "input",
            "priority",
            "-10",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ])
        .status();
    Ok(())
}

fn flush_threat_chain() -> Result<()> {
    flush_threat_chain_with("nft")
}

fn flush_threat_chain_with(program: &str) -> Result<()> {
    let status = std::process::Command::new(program)
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
