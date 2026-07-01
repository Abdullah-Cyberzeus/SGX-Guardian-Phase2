use clap::{ArgAction, Args, Subcommand};
use serde::{Deserialize, Serialize};
use sgx_guardian_client::discovery::{
    inventory::Inventory,
    nmap_parser,
    nmap_runner::NmapRunner,
    run_history::{self, ScanRunSource},
    whitelist::{Whitelist, WhitelistEntry},
    ConnectedDevice, DeviceStatus, NmapConfig, ScanIntensity, ScanSchedule, ScheduledScans,
};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Args)]
#[command(about = "NMAP-based network discovery commands")]
pub struct DiscoveryArgs {
    #[command(subcommand)]
    pub command: DiscoveryCommand,
}

#[derive(Debug, Subcommand)]
pub enum DiscoveryCommand {
    /// Run one NMAP discovery scan now
    Scan(ScanArgs),

    /// Show latest discovered device inventory
    List,

    /// Show unauthorized or drifted devices only
    Unauthorized,

    /// Show discovery scan run history.
    Runs(RunsArgs),

    /// Add a MAC to the whitelist.
    Approve(ApproveArgs),

    /// Show scheduled discovery config.
    #[command(alias = "config-show")]
    ScheduleShow,

    /// Update scheduled discovery config.
    ScheduleSet(ScheduleSetArgs),
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Override target CIDR, host IP, or hostname for this run
    #[arg(long)]
    pub target: Option<String>,

    /// Scan intensity: stealth, standard, aggressive
    #[arg(long)]
    pub intensity: Option<String>,
}

#[derive(Debug, Args)]
pub struct ApproveArgs {
    /// MAC address to approve in whitelist (for example AA:BB:CC:11:22:33)
    pub mac: String,

    /// Optional label for operator readability
    #[arg(long)]
    pub label: Option<String>,
}

#[derive(Debug, Args)]
pub struct RunsArgs {
    /// Maximum number of recent scan runs to print.
    #[arg(long, default_value_t = 20)]
    pub limit: usize,
}

#[derive(Debug, Args)]
pub struct ScheduleSetArgs {
    /// Enable or disable scheduled scans
    #[arg(long)]
    pub enabled: Option<bool>,

    /// Override target CIDR. Use `auto` or `null` to restore runtime auto-detection.
    #[arg(long)]
    pub target: Option<String>,

    /// Hourly scan intensity: stealth, standard, aggressive
    #[arg(long)]
    pub hourly: Option<String>,

    /// Daily scan intensity: stealth, standard, aggressive
    #[arg(long)]
    pub daily: Option<String>,

    /// Per-scan timeout in seconds
    #[arg(long)]
    pub timeout: Option<u64>,

    /// Excluded IPs or CIDRs. Repeat the flag for multiple values.
    /// Use `none` to clear all exclusions.
    #[arg(long, action = ArgAction::Append)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ScheduleShowOutput {
    enabled: bool,
    target_cidr: Option<String>,
    timeout_secs: u64,
    exclude: Vec<String>,
    schedules: ScheduledScans,
    #[serde(skip_serializing_if = "Option::is_none")]
    legacy_schedule_mode: Option<ScanSchedule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WhitelistFile {
    #[serde(default = "default_whitelist_version")]
    version: String,
    #[serde(default)]
    devices: Vec<WhitelistEntry>,
}

const CONFIG_PATH: &str = "/etc/sgx-guardian/discovery/nmap.yaml";
const WHITELIST_PATH: &str = "/etc/sgx-guardian/discovery/whitelist.yaml";
const INVENTORY_PATH: &str = "/var/lib/sgx-guardian/discovery/inventory.json";

pub fn run(args: DiscoveryArgs) -> Result<(), Box<dyn std::error::Error>> {
    match args.command {
        DiscoveryCommand::Scan(scan_args) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(scan_now(scan_args))?;
        }
        DiscoveryCommand::List => list_devices(false)?,
        DiscoveryCommand::Unauthorized => list_devices(true)?,
        DiscoveryCommand::Runs(args) => list_runs(args)?,
        DiscoveryCommand::Approve(approve_args) => approve_mac(approve_args)?,
        DiscoveryCommand::ScheduleShow => schedule_show()?,
        DiscoveryCommand::ScheduleSet(set_args) => schedule_set(set_args)?,
    }

    Ok(())
}

async fn scan_now(args: ScanArgs) -> Result<(), Box<dyn std::error::Error>> {
    ensure_dirs()?;
    let started_at = chrono::Utc::now();

    let cfg = NmapConfig::load(Path::new(CONFIG_PATH)).unwrap_or_default();
    let intensity = match args.intensity.as_deref() {
        Some(value) => parse_intensity(value)?,
        None => cfg.ad_hoc_intensity(),
    };

    let target = match args.target {
        Some(target) => {
            normalize_target_override(Some(target)).unwrap_or_else(|| cfg.resolved_target_cidr())
        }
        None => cfg.resolved_target_cidr(),
    };

    let xml = match NmapRunner::run_with_intensity(&cfg, &target, intensity).await {
        Ok(xml) => xml,
        Err(err) => {
            append_manual_history(
                started_at,
                chrono::Utc::now(),
                intensity,
                target.clone(),
                false,
                Some(err.to_string()),
                None,
                None,
            );
            return Err(err.into());
        }
    };

    // CLI scan also persists raw XML so manual runs aren't invisible.
    let state_dir = std::path::Path::new(INVENTORY_PATH)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("/var/lib/sgx-guardian/discovery"));
    let raw_xml_path =
        sgx_guardian_client::discovery::raw_store::RawXmlStore::persist(state_dir, &xml).ok();

    let whitelist = Whitelist::load(Path::new(WHITELIST_PATH)).unwrap_or_default();
    let devices = match nmap_parser::parse(&xml) {
        Ok(devices) => devices,
        Err(err) => {
            append_manual_history(
                started_at,
                chrono::Utc::now(),
                intensity,
                target.clone(),
                false,
                Some(err.to_string()),
                raw_xml_path,
                None,
            );
            return Err(err.into());
        }
    };
    let semantics = cfg.scan_semantics_for_intensity(&target, intensity);

    let inv_path = PathBuf::from(INVENTORY_PATH);
    let mut inventory = Inventory::load(&inv_path).unwrap_or_default();
    let delta = inventory.merge(devices, semantics);
    for id in delta.updated.iter().chain(delta.newly_seen.iter()) {
        if let Some(device) = inventory.by_id.get_mut(id) {
            whitelist.classify(device);
        }
    }
    let counts = run_history::status_counts(&inventory);
    inventory.save_atomic(&inv_path)?;
    let record = run_history::build_record(
        started_at,
        chrono::Utc::now(),
        ScanRunSource::Manual,
        None,
        intensity,
        target.clone(),
        true,
        None,
        Some(&delta),
        counts,
        raw_xml_path,
        &inv_path,
    );
    append_history_record(&record);

    println!("✅ Discovery scan completed");
    println!("target: {}", target);
    println!("intensity: {}", intensity_name(intensity));
    println!("new_devices: {}", delta.newly_seen.len());
    println!("updated_devices: {}", delta.updated.len());
    println!("inventory: {}", INVENTORY_PATH);

    Ok(())
}

fn list_runs(args: RunsArgs) -> Result<(), Box<dyn std::error::Error>> {
    let path = run_history_path();
    let runs = run_history::list_recent(&path, Some(args.limit))?;
    if runs.is_empty() {
        println!("No discovery scan history found.");
        return Ok(());
    }

    for run in runs {
        println!("{}", serde_json::to_string(&run)?);
    }

    Ok(())
}

fn list_devices(only_unauthorized: bool) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = match std::fs::read(INVENTORY_PATH) {
        Ok(b) => b,
        Err(_) => {
            println!("No inventory found. Run discovery scan first.");
            return Ok(());
        }
    };

    let mut devices: Vec<ConnectedDevice> = serde_json::from_slice(&bytes)?;

    if only_unauthorized {
        devices.retain(|d| matches!(d.status, DeviceStatus::Unauthorized | DeviceStatus::Drifted));
    }

    if devices.is_empty() {
        println!("No devices found.");
        return Ok(());
    }

    for d in &devices {
        for line in format_device_lines(d) {
            println!("{}", line);
        }
    }

    Ok(())
}

/// Render one device to display lines (summary + rich detail). Pure and
/// side-effect-free so it can be unit-tested; `list_devices` just prints it.
fn format_device_lines(d: &ConnectedDevice) -> Vec<String> {
    let mut out = Vec::new();

    let ports_summary = d
        .open_ports
        .iter()
        .map(|p| format!("{}/{}", p.port, p.protocol))
        .collect::<Vec<_>>()
        .join(",");

    out.push(format!(
        "{} | ip={} | mac={} | vendor={} | status={:?} | os={} | ports={}",
        d.device_id,
        d.ip,
        d.mac.as_deref().unwrap_or("-"),
        d.vendor.as_deref().unwrap_or("-"),
        d.status,
        d.os_fingerprint.as_deref().unwrap_or("-"),
        if ports_summary.is_empty() {
            "-"
        } else {
            &ports_summary
        },
    ));

    // Rich detail (only present when the scan collected it: Standard/Aggressive).
    // Stealth devices stay one-liners.
    if !d.os_cpe.is_empty() {
        out.push(format!("    os_cpe: {}", d.os_cpe.join(", ")));
    }

    for p in &d.open_ports {
        let svc = p.service.as_deref().unwrap_or("");
        let ver = p.product_version.as_deref().unwrap_or("");
        let has_detail =
            !svc.is_empty() || !ver.is_empty() || !p.cpe.is_empty() || !p.scripts.is_empty();
        if !has_detail {
            continue;
        }

        let mut line = format!("    {}/{}", p.port, p.protocol);
        if !svc.is_empty() {
            line.push_str(&format!(" {}", svc));
        }
        if !ver.is_empty() {
            line.push_str(&format!(" ({})", ver));
        }
        if !p.cpe.is_empty() {
            line.push_str(&format!(" [{}]", p.cpe.join(" ")));
        }
        out.push(line);

        for s in &p.scripts {
            push_script_lines(&mut out, 8, &s.id, &s.output);
        }
    }

    for s in &d.host_scripts {
        push_script_lines(&mut out, 4, &s.id, &s.output);
    }

    out
}

/// Append one NSE script result as `<id>: <first line>` plus indented
/// continuation lines, so multi-line vuln/cert output stays readable.
fn push_script_lines(out: &mut Vec<String>, indent: usize, id: &str, output: &str) {
    let pad = " ".repeat(indent);
    let mut lines = output.lines().map(str::trim).filter(|l| !l.is_empty());
    match lines.next() {
        Some(first) => out.push(format!("{}- {}: {}", pad, id, first)),
        None => {
            out.push(format!("{}- {}", pad, id));
            return;
        }
    }
    for l in lines {
        out.push(format!("{}    {}", pad, l));
    }
}

fn schedule_show() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = NmapConfig::load(Path::new(CONFIG_PATH)).unwrap_or_default();
    let show = ScheduleShowOutput {
        enabled: cfg.enabled,
        target_cidr: cfg.target_cidr.clone(),
        timeout_secs: cfg.timeout_secs,
        exclude: cfg.exclude.clone(),
        schedules: cfg.schedules.clone(),
        legacy_schedule_mode: cfg.legacy_schedule_mode(),
    };
    print!("{}", serde_yaml::to_string(&show)?);
    Ok(())
}

fn schedule_set(args: ScheduleSetArgs) -> Result<(), Box<dyn std::error::Error>> {
    ensure_dirs()?;

    let mut cfg = NmapConfig::load(Path::new(CONFIG_PATH)).unwrap_or_default();

    if let Some(enabled) = args.enabled {
        cfg.enabled = enabled;
    }

    if let Some(target) = args.target {
        cfg.target_cidr = normalize_target_override(Some(target));
    }

    if let Some(hourly) = args.hourly {
        cfg.schedules.hourly.intensity = parse_intensity(&hourly)?;
    }

    if let Some(daily) = args.daily {
        cfg.schedules.daily.intensity = parse_intensity(&daily)?;
    }

    if let Some(timeout) = args.timeout {
        cfg.timeout_secs = timeout;
    }

    if !args.exclude.is_empty() {
        cfg.exclude = normalize_excludes(args.exclude)?;
    }

    cfg.validate()?;
    save_nmap_config(Path::new(CONFIG_PATH), &cfg)?;

    println!("✅ Discovery schedule updated");
    println!("config: {}", CONFIG_PATH);
    schedule_show()?;
    Ok(())
}

fn default_whitelist_version() -> String {
    "1.0".to_string()
}

impl Default for WhitelistFile {
    fn default() -> Self {
        Self {
            version: default_whitelist_version(),
            devices: Vec::new(),
        }
    }
}

fn approve_mac(args: ApproveArgs) -> Result<(), Box<dyn std::error::Error>> {
    ensure_dirs()?;

    let mac = normalize_mac(&args.mac);
    if mac.is_empty() {
        return Err("mac must not be empty".into());
    }

    let mut whitelist = load_whitelist_file(Path::new(WHITELIST_PATH))?;
    let mut inserted = false;

    match whitelist
        .devices
        .iter_mut()
        .find(|entry| normalize_mac(&entry.mac) == mac)
    {
        Some(existing) => {
            if let Some(label) = args.label {
                existing.label = Some(label);
            }
        }
        None => {
            whitelist.devices.push(WhitelistEntry {
                mac: mac.clone(),
                label: args.label,
                expected_os: None,
                expected_ports: Vec::new(),
                expected_ips: Vec::new(),
            });
            inserted = true;
        }
    }

    whitelist
        .devices
        .sort_by_key(|entry| normalize_mac(entry.mac.as_str()));

    save_whitelist_file(Path::new(WHITELIST_PATH), &whitelist)?;

    if inserted {
        println!("✅ Approved MAC {}", mac);
    } else {
        println!("ℹ️ MAC {} already present, whitelist updated", mac);
    }
    println!("whitelist: {}", WHITELIST_PATH);
    Ok(())
}

fn normalize_mac(mac: &str) -> String {
    mac.trim().to_uppercase()
}

fn load_whitelist_file(path: &Path) -> Result<WhitelistFile, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(WhitelistFile::default());
    }

    let text = std::fs::read_to_string(path)?;
    if text.trim().is_empty() {
        return Ok(WhitelistFile::default());
    }

    let parsed = serde_yaml::from_str::<WhitelistFile>(&text)?;
    Ok(parsed)
}

fn save_whitelist_file(
    path: &Path,
    whitelist: &WhitelistFile,
) -> Result<(), Box<dyn std::error::Error>> {
    let yaml = serde_yaml::to_string(whitelist)?;
    atomic_write(path, yaml.as_bytes())
}

fn save_nmap_config(path: &Path, config: &NmapConfig) -> Result<(), Box<dyn std::error::Error>> {
    let yaml = serde_yaml::to_string(config)?;
    atomic_write(path, yaml.as_bytes())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let tmp_path = path.with_extension("yaml.tmp");
    {
        let mut file = std::fs::File::create(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp_path, path)?;

    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

fn append_manual_history(
    started_at: chrono::DateTime<chrono::Utc>,
    completed_at: chrono::DateTime<chrono::Utc>,
    intensity: ScanIntensity,
    target: String,
    success: bool,
    error: Option<String>,
    raw_xml_path: Option<PathBuf>,
    delta: Option<&sgx_guardian_client::discovery::inventory::InventoryDelta>,
) {
    let inv_path = PathBuf::from(INVENTORY_PATH);
    let counts = Inventory::load(&inv_path)
        .map(|inventory| run_history::status_counts(&inventory))
        .unwrap_or_default();
    let record = run_history::build_record(
        started_at,
        completed_at,
        ScanRunSource::Manual,
        None,
        intensity,
        target,
        success,
        error,
        delta,
        counts,
        raw_xml_path,
        &inv_path,
    );
    append_history_record(&record);
}

fn append_history_record(record: &run_history::ScanRunRecord) {
    let path = run_history_path();
    if let Err(err) = run_history::append_record(&path, record) {
        eprintln!("⚠️ discovery run history persist failed: {}", err);
    }
}

fn run_history_path() -> PathBuf {
    PathBuf::from(INVENTORY_PATH)
        .parent()
        .map(run_history::history_path)
        .unwrap_or_else(|| PathBuf::from("/var/lib/sgx-guardian/discovery/runs.jsonl"))
}

fn parse_intensity(value: &str) -> Result<ScanIntensity, Box<dyn std::error::Error>> {
    match value.trim().to_ascii_lowercase().as_str() {
        "stealth" => Ok(ScanIntensity::Stealth),
        "standard" => Ok(ScanIntensity::Standard),
        "aggressive" => Ok(ScanIntensity::Aggressive),
        _ => Err(format!("invalid intensity: {}", value).into()),
    }
}

fn intensity_name(intensity: ScanIntensity) -> &'static str {
    match intensity {
        ScanIntensity::Stealth => "stealth",
        ScanIntensity::Standard => "standard",
        ScanIntensity::Aggressive => "aggressive",
    }
}

fn normalize_target_override(target: Option<String>) -> Option<String> {
    target.and_then(|raw| {
        let value = raw.trim();
        if value.is_empty()
            || value.eq_ignore_ascii_case("auto")
            || value.eq_ignore_ascii_case("null")
            || value.eq_ignore_ascii_case("none")
        {
            None
        } else {
            Some(value.to_string())
        }
    })
}

fn normalize_excludes(values: Vec<String>) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    let mut clear = false;

    for raw in values {
        for value in raw.split(',') {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                continue;
            }

            if trimmed.eq_ignore_ascii_case("none")
                || trimmed.eq_ignore_ascii_case("null")
                || trimmed.eq_ignore_ascii_case("clear")
            {
                clear = true;
                continue;
            }

            out.push(trimmed.to_string());
        }
    }

    if clear && !out.is_empty() {
        return Err("exclude cannot mix clear tokens with concrete IP/CIDR values".into());
    }

    if clear {
        return Ok(Vec::new());
    }

    Ok(out)
}

fn ensure_dirs() -> std::io::Result<()> {
    std::fs::create_dir_all("/etc/sgx-guardian/discovery")?;
    std::fs::create_dir_all("/var/lib/sgx-guardian/discovery")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        format_device_lines, normalize_excludes, normalize_target_override, ScheduleShowOutput,
    };
    use sgx_guardian_client::discovery::{
        ConnectedDevice, DeviceStatus, NmapConfig, OpenPort, ScanIntensity, ScanSchedule,
        ScriptResult,
    };

    fn rich_device() -> ConnectedDevice {
        ConnectedDevice {
            device_id: "abc123".to_string(),
            ip: "192.168.50.103".to_string(),
            mac: Some("B2:95:75:0E:06:6A".to_string()),
            vendor: Some("Variscite".to_string()),
            hostname: Some("node.local".to_string()),
            os_fingerprint: Some("Linux 5.4".to_string()),
            os_cpe: vec!["cpe:/o:linux:linux_kernel:5".to_string()],
            open_ports: vec![OpenPort {
                port: 443,
                protocol: "tcp".to_string(),
                service: Some("https".to_string()),
                product_version: Some("nginx 1.20.1".to_string()),
                cpe: vec!["cpe:/a:nginx:nginx:1.20.1".to_string()],
                scripts: vec![ScriptResult {
                    id: "ssl-cert".to_string(),
                    output: "Subject: commonName=guardian.local\nNot valid after: 2027-01-01"
                        .to_string(),
                }],
            }],
            host_scripts: vec![ScriptResult {
                id: "smb2-security-mode".to_string(),
                output: "signing not required".to_string(),
            }],
            status: DeviceStatus::Unauthorized,
            first_seen: "2026-06-01T00:00:00Z".to_string(),
            last_seen: "2026-06-09T00:00:00Z".to_string(),
            vuln_triaged: false,
        }
    }

    #[test]
    fn renders_status_and_rich_detail_exactly() {
        let lines = format_device_lines(&rich_device());
        assert_eq!(
            lines,
            vec![
                "abc123 | ip=192.168.50.103 | mac=B2:95:75:0E:06:6A | vendor=Variscite | \
                 status=Unauthorized | os=Linux 5.4 | ports=443/tcp"
                    .to_string(),
                "    os_cpe: cpe:/o:linux:linux_kernel:5".to_string(),
                "    443/tcp https (nginx 1.20.1) [cpe:/a:nginx:nginx:1.20.1]".to_string(),
                "        - ssl-cert: Subject: commonName=guardian.local".to_string(),
                "            Not valid after: 2027-01-01".to_string(),
                "    - smb2-security-mode: signing not required".to_string(),
            ]
        );
    }

    #[test]
    fn stealth_device_is_a_single_line_with_status() {
        let mut d = rich_device();
        d.os_fingerprint = None;
        d.os_cpe.clear();
        d.host_scripts.clear();
        d.open_ports.clear();

        let lines = format_device_lines(&d);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("status=Unauthorized"));
        assert!(lines[0].ends_with("os=- | ports=-"));
    }

    #[test]
    fn normalize_target_can_clear_back_to_auto_detection() {
        assert_eq!(normalize_target_override(Some("auto".to_string())), None);
        assert_eq!(normalize_target_override(Some("null".to_string())), None);
        assert_eq!(
            normalize_target_override(Some("192.168.50.0/24".to_string())),
            Some("192.168.50.0/24".to_string())
        );
    }

    #[test]
    fn normalize_excludes_supports_clear_token() {
        let parsed = normalize_excludes(vec!["none".to_string()]).expect("clear token should work");
        assert!(parsed.is_empty());
    }

    #[test]
    fn schedule_show_serializes_new_layout() {
        let cfg = NmapConfig::default();
        let show = ScheduleShowOutput {
            enabled: cfg.enabled,
            target_cidr: cfg.target_cidr.clone(),
            timeout_secs: cfg.timeout_secs,
            exclude: cfg.exclude.clone(),
            schedules: cfg.schedules.clone(),
            legacy_schedule_mode: Some(ScanSchedule::Hourly),
        };

        let yaml = serde_yaml::to_string(&show).expect("show output should serialize");
        assert!(yaml.contains("schedules:"));
        assert!(yaml.contains("hourly:"));
        assert!(yaml.contains("intensity: standard"));
        assert!(yaml.contains("daily:"));
        assert!(yaml.contains("intensity: aggressive"));
        assert!(yaml.contains("legacy_schedule_mode: hourly"));
    }

    #[test]
    fn legacy_config_keeps_hourly_ad_hoc_intensity_visible() {
        let yaml = r#"
enabled: true
target_cidr: 192.168.50.0/24
intensity: aggressive
schedule: hourly
timeout_secs: 600
exclude: []
"#;

        let cfg: NmapConfig = serde_yaml::from_str(yaml).expect("legacy config should parse");
        assert_eq!(cfg.ad_hoc_intensity(), ScanIntensity::Aggressive);
    }
}
