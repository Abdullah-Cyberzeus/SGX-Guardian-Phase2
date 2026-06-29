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

fn is_interface_available(iface: &InterfaceRecord) -> bool {
    iface.is_up && iface.ip.is_some()
}

fn read_transport_lock(node: &str) -> Option<String> {
    fs::read_to_string(lock_path(node))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn resolve_active_interface<'a>(
    interfaces: &'a [InterfaceRecord],
    lock: Option<&str>,
) -> Option<&'a InterfaceRecord> {
    if let Some(locked_iface) = lock {
        return interfaces
            .iter()
            .find(|iface| iface.name == locked_iface && is_interface_available(iface));
    }

    interfaces
        .iter()
        .find(|iface| is_interface_available(iface))
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

        let ip = std::process::Command::new("ip")
            .args(["-4", "addr", "show", "dev", &name])
            .output()
            .ok()
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .find(|l| l.contains("inet "))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|cidr| cidr.split('/').next())
                    .and_then(|s| s.parse::<IpAddr>().ok())
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
    let lock = read_transport_lock(&args.node);
    let active_iface = resolve_active_interface(&interfaces, lock.as_deref());

    println!("📡 Detected {} network interfaces:", interfaces.len());
    for iface in &interfaces {
        let status = if is_interface_available(iface) {
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
        let available = is_interface_available(iface);
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

    if let Some(locked_iface) = &lock {
        println!("🔒 Manual lock: {}", locked_iface);
        if let Some(active) = active_iface {
            println!("✅ Active: {} ({}) [locked]", active.transport, active.name);
        } else {
            println!(
                "❌ Active: none (locked interface unavailable: {})",
                locked_iface
            );
        }
    } else if let Some(active) = active_iface {
        println!("✅ Active: {} ({}) (auto)", active.transport, active.name);
    } else {
        println!("❌ Active: none");
    }
}

fn run_show(args: TransportListArgs) {
    let interfaces = detect_interfaces();
    let lock = read_transport_lock(&args.node);
    let active_iface = resolve_active_interface(&interfaces, lock.as_deref());

    if let Some(lock_iface) = lock {
        if let Some(active) = active_iface {
            println!("Active: {} ({})", active.transport, active.name);
        } else {
            println!("Active: none");
        }
        println!("Lock: {}", lock_iface);
    } else {
        if let Some(active) = active_iface {
            println!("Active: {} ({})", active.transport, active.name);
        } else {
            println!("Active: none");
        }
        println!("Lock: none");
    }
}

fn run_stats(args: TransportListArgs) {
    let interfaces = detect_interfaces();
    let lock = read_transport_lock(&args.node);
    let active_iface = resolve_active_interface(&interfaces, lock.as_deref());
    println!(
        "{:<12} {:<8} {:<8} {:<12} {:<12} {:<10}",
        "Transport", "Priority", "Status", "Latency", "Bandwidth", "Interface"
    );
    for iface in &interfaces {
        let status = if is_interface_available(iface) {
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
    if let Some(lock_iface) = lock {
        println!("Lock: {}", lock_iface);
        if let Some(active) = active_iface {
            println!("Active: {} ({})", active.transport, active.name);
        } else {
            println!("Active: none");
        }
    } else {
        println!("Lock: none");
        if let Some(active) = active_iface {
            println!("Active: {} ({})", active.transport, active.name);
        } else {
            println!("Active: none");
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(
        name: &str,
        transport: TransportType,
        is_up: bool,
        ip: Option<&str>,
    ) -> InterfaceRecord {
        InterfaceRecord {
            name: name.to_string(),
            transport,
            ip: ip.and_then(|v| v.parse::<IpAddr>().ok()),
            is_up,
        }
    }

    #[test]
    fn strict_lock_returns_none_when_locked_iface_unavailable() {
        let interfaces = vec![
            iface("eth0", TransportType::Ethernet, false, None),
            iface("wlan0", TransportType::WiFi, true, Some("192.168.1.8")),
        ];
        let active = resolve_active_interface(&interfaces, Some("eth0"));
        assert!(active.is_none());
    }

    #[test]
    fn strict_lock_uses_locked_iface_when_available() {
        let interfaces = vec![
            iface("eth0", TransportType::Ethernet, true, Some("10.0.0.12")),
            iface("wlan0", TransportType::WiFi, true, Some("192.168.1.8")),
        ];
        let active = resolve_active_interface(&interfaces, Some("eth0"));
        assert_eq!(active.map(|v| v.name.as_str()), Some("eth0"));
    }

    #[test]
    fn no_lock_keeps_auto_selection() {
        let interfaces = vec![
            iface("eth0", TransportType::Ethernet, false, None),
            iface("wlan0", TransportType::WiFi, true, Some("192.168.1.8")),
        ];
        let active = resolve_active_interface(&interfaces, None);
        assert_eq!(active.map(|v| v.name.as_str()), Some("wlan0"));
    }
}
