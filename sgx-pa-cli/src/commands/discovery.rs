use clap::{ArgAction, Args, Subcommand};
use serde::{Deserialize, Serialize};
use sgx_guardian_client::discovery::{
    inventory::Inventory,
    nmap_parser,
    nmap_runner::NmapRunner,
    run_history::{self, ScanRunSource},
    whitelist::{
        enrich_entries, infer_label_for_mac, Whitelist, WhitelistEntry, WhitelistEntryView,
    },
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

    /// Show whitelist entries enriched with current inventory matches.
    Whitelist,

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

#[derive(Debug, Clone, Serialize)]
struct WhitelistShowOutput {
    version: String,
    devices: Vec<WhitelistEntryView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WhitelistFile {
    #[serde(default = "default_whitelist_version")]
    version: String,
    #[serde(default)]
    devices: Vec<WhitelistEntry>,
}

const CONFIG_DIR_ENV: &str = "SGX_GUARDIAN_DISCOVERY_CONFIG_DIR";
const STATE_DIR_ENV: &str = "SGX_GUARDIAN_DISCOVERY_STATE_DIR";
const CONFIG_PATH: &str = "/etc/sgx-guardian/discovery/nmap.yaml";
const WHITELIST_PATH: &str = "/etc/sgx-guardian/discovery/whitelist.yaml";
const INVENTORY_PATH: &str = "/var/lib/sgx-guardian/discovery/inventory.json";

fn config_path() -> PathBuf {
    PathBuf::from(
        std::env::var(CONFIG_DIR_ENV).unwrap_or_else(|_| "/etc/sgx-guardian/discovery".into()),
    )
    .join("nmap.yaml")
}

fn whitelist_path() -> PathBuf {
    PathBuf::from(
        std::env::var(CONFIG_DIR_ENV).unwrap_or_else(|_| "/etc/sgx-guardian/discovery".into()),
    )
    .join("whitelist.yaml")
}

fn inventory_path() -> PathBuf {
    PathBuf::from(
        std::env::var(STATE_DIR_ENV).unwrap_or_else(|_| "/var/lib/sgx-guardian/discovery".into()),
    )
    .join("inventory.json")
}

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
        DiscoveryCommand::Whitelist => show_whitelist()?,
        DiscoveryCommand::ScheduleShow => schedule_show()?,
        DiscoveryCommand::ScheduleSet(set_args) => schedule_set(set_args)?,
    }

    Ok(())
}

async fn scan_now(args: ScanArgs) -> Result<(), Box<dyn std::error::Error>> {
    ensure_dirs()?;
    let started_at = chrono::Utc::now();
    let config_path = config_path();
    let whitelist_path = whitelist_path();
    let inventory_path = inventory_path();

    let cfg = match NmapConfig::load(&config_path) {
        Ok(cfg) => cfg,
        Err(_) if !config_path.exists() => NmapConfig::default(),
        Err(e) => {
            eprintln!("❌ Failed to load {}: {}", config_path.display(), e);
            return Ok(());
        }
    };
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
    let state_dir = inventory_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("/var/lib/sgx-guardian/discovery"));
    let raw_xml_path =
        sgx_guardian_client::discovery::raw_store::RawXmlStore::persist(state_dir, &xml).ok();

    let whitelist = Whitelist::load(&whitelist_path).unwrap_or_default();
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

    let inv_path = inventory_path;
    let mut inventory = Inventory::load(&inv_path).unwrap_or_default();
    let intensity_label = intensity_name(intensity);
    let delta = inventory.merge(devices, semantics);
    for id in delta.updated.iter().chain(delta.newly_seen.iter()) {
        if let Some(device) = inventory.by_id.get_mut(id) {
            device.last_scan_intensity = Some(intensity_label.to_string());
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
    println!("inventory: {}", inv_path.display());

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

fn show_whitelist() -> Result<(), Box<dyn std::error::Error>> {
    let whitelist = load_whitelist_file(Path::new(WHITELIST_PATH))?;
    let inventory = load_inventory_file(Path::new(INVENTORY_PATH))?;
    let output = WhitelistShowOutput {
        version: whitelist.version,
        devices: enrich_entries(&whitelist.devices, &inventory),
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn list_devices(only_unauthorized: bool) -> Result<(), Box<dyn std::error::Error>> {
    let inv_path = inventory_path();
    if !inv_path.exists() {
        println!("No inventory found. Run discovery scan first.");
        return Ok(());
    }
    let inv = Inventory::load(&PathBuf::from(INVENTORY_PATH))?;
    let mut devices: Vec<ConnectedDevice> = inv.by_id.into_values().collect();
    devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));

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
    let cfg = match NmapConfig::load(Path::new(CONFIG_PATH)) {
        Ok(cfg) => cfg,
        Err(_) if !Path::new(CONFIG_PATH).exists() => NmapConfig::default(),
        Err(e) => {
            eprintln!("❌ Failed to load {}: {}", CONFIG_PATH, e);
            return Ok(());
        }
    };
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

    let mut cfg = match NmapConfig::load(Path::new(CONFIG_PATH)) {
        Ok(cfg) => cfg,
        Err(_) if !Path::new(CONFIG_PATH).exists() => NmapConfig::default(),
        Err(e) => {
            eprintln!("❌ Failed to load {}: {}", CONFIG_PATH, e);
            return Ok(());
        }
    };

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

    let inventory = load_inventory_file(Path::new(INVENTORY_PATH)).unwrap_or_default();
    let requested_label = normalize_optional_label(args.label);
    let resolved_label = requested_label
        .clone()
        .or_else(|| infer_label_for_mac(&mac, &inventory));
    let mut whitelist = load_whitelist_file(Path::new(WHITELIST_PATH))?;
    let mut inserted = false;

    match whitelist
        .devices
        .iter_mut()
        .find(|entry| normalize_mac(&entry.mac) == mac)
    {
        Some(existing) => {
            if let Some(label) = resolved_label.clone().filter(|_| {
                requested_label.is_some() || existing.label.as_deref().unwrap_or("").is_empty()
            }) {
                existing.label = Some(label);
            }
        }
        None => {
            whitelist.devices.push(WhitelistEntry {
                mac: mac.clone(),
                label: resolved_label,
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

fn normalize_optional_label(label: Option<String>) -> Option<String> {
    label
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn load_inventory_file(path: &Path) -> Result<Vec<ConnectedDevice>, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let bytes = std::fs::read(path)?;
    if bytes.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Ok(Vec::new());
    }

    let devices = serde_json::from_slice(&bytes)?;
    Ok(devices)
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

#[allow(clippy::too_many_arguments)]
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
    let inv_path = inventory_path();
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
    inventory_path()
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
    let config_dir = config_path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/etc/sgx-guardian/discovery"));
    let state_dir = inventory_path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/var/lib/sgx-guardian/discovery"));
    std::fs::create_dir_all(config_dir)?;
    std::fs::create_dir_all(state_dir)?;
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
            last_scan_intensity: None,
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

    use super::{
        approve_mac, atomic_write, intensity_name, list_devices, list_runs, load_inventory_file,
        load_whitelist_file, normalize_mac, normalize_optional_label, parse_intensity,
        save_whitelist_file, schedule_set, schedule_show, show_whitelist, ApproveArgs, RunsArgs,
        ScheduleSetArgs, WhitelistFile,
    };
    use sgx_guardian_client::discovery::whitelist::WhitelistEntry;

    #[test]
    fn normalize_mac_trims_and_uppercases() {
        assert_eq!(normalize_mac("  aa:bb:cc:11:22:33 "), "AA:BB:CC:11:22:33");
    }

    #[test]
    fn normalize_optional_label_trims_and_treats_blank_as_none() {
        assert_eq!(
            normalize_optional_label(Some("  Office  ".to_string())),
            Some("Office".to_string())
        );
        assert_eq!(normalize_optional_label(Some("   ".to_string())), None);
        assert_eq!(normalize_optional_label(None), None);
    }

    #[test]
    fn parse_intensity_accepts_known_values_and_rejects_unknown() {
        assert_eq!(parse_intensity("stealth").unwrap(), ScanIntensity::Stealth);
        assert_eq!(
            parse_intensity("STANDARD").unwrap(),
            ScanIntensity::Standard
        );
        assert_eq!(
            parse_intensity(" aggressive ").unwrap(),
            ScanIntensity::Aggressive
        );
        assert!(parse_intensity("bogus").is_err());
    }

    #[test]
    fn intensity_name_covers_every_variant() {
        assert_eq!(intensity_name(ScanIntensity::Stealth), "stealth");
        assert_eq!(intensity_name(ScanIntensity::Standard), "standard");
        assert_eq!(intensity_name(ScanIntensity::Aggressive), "aggressive");
    }

    #[test]
    fn normalize_excludes_rejects_mixing_clear_with_concrete_values() {
        let err = normalize_excludes(vec!["none,192.168.1.1".to_string()])
            .expect_err("mixing clear and concrete values must fail");
        assert!(err.to_string().contains("cannot mix clear tokens"));
    }

    #[test]
    fn normalize_excludes_splits_and_trims_comma_separated_values() {
        let parsed = normalize_excludes(vec![" 10.0.0.1 , 10.0.0.2".to_string()])
            .expect("comma-separated values should parse");
        assert_eq!(parsed, vec!["10.0.0.1", "10.0.0.2"]);
    }

    #[test]
    fn load_whitelist_file_defaults_when_absent_or_blank() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing.yaml");
        let file = load_whitelist_file(&missing).expect("missing whitelist defaults");
        assert_eq!(file.version, "1.0");
        assert!(file.devices.is_empty());

        let blank = temp.path().join("blank.yaml");
        std::fs::write(&blank, "   \n").unwrap();
        let file = load_whitelist_file(&blank).expect("blank whitelist defaults");
        assert!(file.devices.is_empty());
    }

    #[test]
    fn whitelist_file_round_trips_through_save_and_load() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("nested").join("whitelist.yaml");
        let whitelist = WhitelistFile {
            version: "1.0".to_string(),
            devices: vec![WhitelistEntry {
                mac: "AA:BB:CC:11:22:33".to_string(),
                label: Some("Office printer".to_string()),
                expected_os: None,
                expected_ports: Vec::new(),
                expected_ips: Vec::new(),
            }],
        };
        save_whitelist_file(&path, &whitelist).expect("save whitelist");
        assert!(!path.with_extension("yaml.tmp").exists());

        let loaded = load_whitelist_file(&path).expect("load saved whitelist");
        assert_eq!(loaded.devices.len(), 1);
        assert_eq!(loaded.devices[0].mac, "AA:BB:CC:11:22:33");
    }

    #[test]
    fn load_inventory_file_returns_empty_when_absent_or_blank() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing.json");
        assert!(load_inventory_file(&missing).unwrap().is_empty());

        let blank = temp.path().join("blank.json");
        std::fs::write(&blank, "  \n").unwrap();
        assert!(load_inventory_file(&blank).unwrap().is_empty());
    }

    #[test]
    fn atomic_write_creates_parent_dirs_and_leaves_no_tmp_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("a").join("b").join("file.yaml");
        atomic_write(&path, b"hello").expect("atomic write");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello");
        assert!(!path.with_extension("yaml.tmp").exists());
    }

    // ── top-level command entry points: none call std::process::exit, and the hardcoded
    // /etc/sgx-guardian and /var/lib/sgx-guardian paths genuinely don't exist in this
    // sandbox, giving real, deterministic branches without any writes outside a tempdir.

    #[test]
    fn list_devices_reports_no_inventory_when_absent() {
        list_devices(false).expect("no inventory found is not an error");
        list_devices(true).expect("no inventory found is not an error (unauthorized-only)");
    }

    #[test]
    fn list_runs_reports_no_history_when_absent() {
        list_runs(RunsArgs { limit: 20 }).expect("no run history is not an error");
    }

    #[test]
    fn show_whitelist_succeeds_with_defaults_when_nothing_configured() {
        show_whitelist().expect("show_whitelist succeeds with defaults");
    }

    #[test]
    fn schedule_show_succeeds_with_defaults_when_config_absent() {
        schedule_show().expect("schedule_show succeeds with defaults");
    }

    #[test]
    fn approve_mac_fails_on_the_unwritable_state_directory() {
        // ensure_dirs() tries /etc/sgx-guardian/discovery first, which can't be created
        // without root, so this fails deterministically before any real I/O.
        let result = approve_mac(ApproveArgs {
            mac: "AA:BB:CC:11:22:33".to_string(),
            label: None,
        });
        assert!(result.is_err());
    }

    #[test]
    fn schedule_set_fails_on_the_unwritable_state_directory() {
        let result = schedule_set(ScheduleSetArgs {
            enabled: Some(true),
            target: None,
            hourly: None,
            daily: None,
            timeout: None,
            exclude: Vec::new(),
        });
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn scan_now_fails_on_the_unwritable_state_directory() {
        let result = super::scan_now(super::ScanArgs {
            target: None,
            intensity: None,
        })
        .await;
        assert!(result.is_err());
    }
}
