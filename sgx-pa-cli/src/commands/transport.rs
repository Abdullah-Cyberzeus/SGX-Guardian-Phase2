use clap::{Args, Subcommand};
use std::fs;
use std::net::IpAddr;
use std::path::Path;

const LOCK_DIR: &str = "/var/lib/sgx-guardian/cot";

#[derive(Args)]
#[command(about = "CoT transport administration")]
pub struct TransportArgs {
    #[command(subcommand)]
    pub command: TransportCommand,
}

#[derive(Subcommand)]
pub enum TransportCommand {
    /// List detected transports and their interface names
    List(TransportListArgs),
    /// Show active and lock status
    Show(TransportListArgs),
    /// Show probe/failure style summary from current snapshot
    Stats(TransportListArgs),
    /// Lock failover selection to a specific interface name
    Lock(TransportLockArgs),
    /// Remove manual transport lock
    Unlock(TransportUnlockArgs),
}

#[derive(Args)]
pub struct TransportListArgs {
    #[arg(long, default_value = "nodeA")]
    pub node: String,
}

#[derive(Args)]
pub struct TransportLockArgs {
    pub interface_name: String,
    #[arg(long, default_value = "nodeA")]
    pub node: String,
}

#[derive(Args)]
pub struct TransportUnlockArgs {
    #[arg(long, default_value = "nodeA")]
    pub node: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportType {
    Ethernet,
    WiFi,
    Bluetooth,
    Cellular,
    Satellite,
}

impl TransportType {
    fn default_priority(self) -> u8 {
        match self {
            Self::Ethernet => 10,
            Self::WiFi => 20,
            Self::Bluetooth => 40,
            Self::Cellular => 5,
            Self::Satellite => 50,
        }
    }
}

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ethernet => write!(f, "Ethernet"),
            Self::WiFi => write!(f, "WiFi"),
            Self::Bluetooth => write!(f, "Bluetooth"),
            Self::Cellular => write!(f, "Cellular"),
            Self::Satellite => write!(f, "Satellite"),
        }
    }
}

#[derive(Debug)]
struct InterfaceRecord {
    name: String,
    transport: TransportType,
    ip: Option<IpAddr>,
    is_up: bool,
}

fn lock_path(node: &str) -> String {
    format!("{}/transport_lock_{}.txt", LOCK_DIR, node)
}

fn classify(name: &str) -> Option<TransportType> {
    let lower = name.to_lowercase();

    if lower.starts_with("sat") || lower.starts_with("ppp") {
        return Some(TransportType::Satellite);
    }
    if lower.starts_with("eth")
        || lower.starts_with("en")
        || lower.starts_with("eno")
        || lower.starts_with("enp")
    {
        return Some(TransportType::Ethernet);
    }
    if lower.starts_with("wlan") || lower.starts_with("wl") || lower.starts_with("wlp") {
        return Some(TransportType::WiFi);
    }
    if lower.starts_with("bnep") || lower.starts_with("bt") || lower.starts_with("hci") {
        return Some(TransportType::Bluetooth);
    }
    if lower.starts_with("wwan") || lower.starts_with("rmnet") || lower.starts_with("usb") {
        return Some(TransportType::Cellular);
    }

    None
}

fn detect_interfaces() -> Vec<InterfaceRecord> {
    let mut records = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return records;
    };

    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };

        if name == "lo"
            || name.starts_with("docker")
            || name.starts_with("veth")
            || name.starts_with("br-")
            || name.starts_with("virbr")
            || name.starts_with("nebula")
        {
            continue;
        }

        let Some(transport) = classify(&name) else {
            continue;
        };

        let operstate_path = format!("/sys/class/net/{}/operstate", name);
        let is_up = fs::read_to_string(operstate_path)
            .map(|s| s.trim() == "up")
            .unwrap_or(false);

        let ip = std::process::Command::new("bash")
            .args([
                "-lc",
                &format!(
                    "ip -4 addr show dev {} | awk '/inet / {{print $2}}' | head -n1",
                    name
                ),
            ])
            .output()
            .ok()
            .and_then(|o| {
                let out = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if out.is_empty() {
                    None
                } else {
                    out.split('/')
                        .next()
                        .and_then(|ip| ip.parse::<IpAddr>().ok())
                }
            });

        records.push(InterfaceRecord {
            name,
            transport,
            ip,
            is_up,
        });
    }

    records.sort_by_key(|r| (r.transport.default_priority(), r.name.clone()));
    records
}

pub fn run(args: TransportArgs) {
    match args.command {
        TransportCommand::List(list_args) => run_list(list_args),
        TransportCommand::Show(show_args) => run_show(show_args),
        TransportCommand::Stats(stats_args) => run_stats(stats_args),
        TransportCommand::Lock(lock_args) => run_lock(lock_args),
        TransportCommand::Unlock(unlock_args) => run_unlock(unlock_args),
    }
}

fn run_list(args: TransportListArgs) {
    let interfaces = detect_interfaces();

    println!("📡 Detected {} network interfaces:", interfaces.len());
    for iface in &interfaces {
        let status = if iface.is_up && iface.ip.is_some() {
            "UP"
        } else {
            "DOWN"
        };
        let ip = iface
            .ip
            .map(|v| v.to_string())
            .unwrap_or_else(|| "no-ip".to_string());
        println!(
            "   {} → {} [{}] \"{}\"",
            iface.name, iface.transport, status, ip
        );
    }

    let mut summary = Vec::new();
    for iface in &interfaces {
        let available = iface.is_up && iface.ip.is_some();
        summary.push(format!(
            "{}:{}(pri={}, avail={})",
            iface.name,
            iface.transport,
            iface.transport.default_priority(),
            available
        ));
    }
    summary.sort();
    println!("🚛 Transport Registry: [{}]", summary.join(", "));

    let path = lock_path(&args.node);
    if let Ok(locked) = fs::read_to_string(&path) {
        println!("🔒 Manual lock: {}", locked.trim());
    } else if let Some(active) = interfaces
        .iter()
        .find(|i| i.is_up && i.ip.is_some())
        .map(|i| i.transport.to_string())
    {
        println!("✅ Active: {} (auto)", active);
    }
}

fn run_show(args: TransportListArgs) {
    let interfaces = detect_interfaces();
    let active_iface = interfaces
        .iter()
        .find(|i| i.is_up && i.ip.is_some())
        .map(|i| (i.name.clone(), i.transport.to_string()));
    let lock = fs::read_to_string(lock_path(&args.node))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    match active_iface {
        Some((iface, transport)) => println!("Active: {} ({})", transport, iface),
        None => println!("Active: none"),
    }
    match lock {
        Some(lock_iface) => println!("Lock: {}", lock_iface),
        None => println!("Lock: none"),
    }
}

fn run_stats(args: TransportListArgs) {
    let interfaces = detect_interfaces();
    println!(
        "{:<12} {:<8} {:<8} {:<12} {:<12} {:<10}",
        "Transport", "Priority", "Status", "Latency", "Bandwidth", "Interface"
    );
    for iface in interfaces {
        let status = if iface.is_up && iface.ip.is_some() {
            "UP"
        } else {
            "DOWN"
        };
        let (latency, bandwidth) = if status == "UP" {
            ("n/a".to_string(), "n/a".to_string())
        } else {
            ("-".to_string(), "-".to_string())
        };
        println!(
            "{:<12} {:<8} {:<8} {:<12} {:<12} {:<10}",
            iface.transport,
            iface.transport.default_priority(),
            status,
            latency,
            bandwidth,
            iface.name
        );
    }
    let lock = fs::read_to_string(lock_path(&args.node))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let Some(lock_iface) = lock {
        println!("Lock: {}", lock_iface);
    } else {
        println!("Lock: none");
    }
}

fn run_lock(args: TransportLockArgs) {
    if !Path::new(LOCK_DIR).exists() {
        if let Err(e) = fs::create_dir_all(LOCK_DIR) {
            eprintln!("❌ Failed to create lock directory {}: {}", LOCK_DIR, e);
            std::process::exit(1);
        }
    }

    let interfaces = detect_interfaces();
    if !interfaces.iter().any(|i| i.name == args.interface_name) {
        eprintln!(
            "❌ Interface '{}' not found. Run `sgx-pa-cli transport list` first.",
            args.interface_name
        );
        std::process::exit(1);
    }

    let path = lock_path(&args.node);
    if let Err(e) = fs::write(&path, format!("{}\n", args.interface_name)) {
        eprintln!("❌ Failed to write lock file {}: {}", path, e);
        std::process::exit(1);
    }

    println!("🔒 Transport locked to {}", args.interface_name);
    println!("   lock file: {}", path);
}

fn run_unlock(args: TransportUnlockArgs) {
    let path = lock_path(&args.node);
    if !Path::new(&path).exists() {
        println!("🔓 No transport lock present for {}", args.node);
        return;
    }

    if let Err(e) = fs::remove_file(&path) {
        eprintln!("❌ Failed to remove lock file {}: {}", path, e);
        std::process::exit(1);
    }

    println!("🔓 Transport lock removed");
}
