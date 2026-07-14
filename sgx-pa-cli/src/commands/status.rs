//! Implements the `status` subcommand for inspecting node metadata.
use crate::config::NodeConfig;
use clap::Args;
use std::path::Path;
use std::path::PathBuf;

/// Command-line arguments for the `status` command, allowing selection
/// of a target SGX Guardian node whose configuration will be displayed.
#[derive(Args)]
#[command(about = "Show status information for a specific SGX Guardian node")]
pub struct StatusArgs {
    /// Node name to load config for (e.g., nodeA, nodeB, nodeC)
    #[arg(long, default_value = "nodeA")]
    pub node: String,
}

/// Loads the configuration file for the specified SGX Guardian node and
/// prints a summary of its identity, hostname, IP, port, and public key.
/// Performs validation of input node names and resolves config paths safely.
pub fn run(args: StatusArgs) {
    // 1) Validate node name
    if !args
        .node
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        eprintln!(
            "❌ Invalid node name '{}'. Allowed: a-z, A-Z, 0-9, -, _",
            args.node
        );
        std::process::exit(1);
    }

    // 2) Resolve executable directory safely
    let exe_path = match std::env::current_exe() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("❌ Failed to get executable path: {}", e);
            std::process::exit(1);
        }
    };

    let exe_dir = match exe_path.parent() {
        Some(dir) => dir.to_path_buf(),
        None => {
            eprintln!("❌ Failed to resolve executable directory");
            std::process::exit(1);
        }
    };

    // 3) Resolve config path with fallbacks across common runtime layouts.
    let filename = format!("{}.yaml", args.node);
    let candidates: Vec<PathBuf> = vec![
        // Installed/runtime path expected by daemon packaging.
        Path::new("/etc/sgx-guardian/config").join(&filename),
        // Monorepo layout when run via `cargo run` in this workspace.
        exe_dir.join("..").join("..").join("config").join(&filename),
        // Historical relative path used by previous CLI versions.
        exe_dir.join("..").join("config").join(&filename),
    ];

    let config_path = candidates.iter().find_map(|p| p.canonicalize().ok());
    let config_path = match config_path {
        Some(path) => path,
        None => {
            eprintln!("❌ Config file not found for node '{}'. Tried:", args.node);
            for p in &candidates {
                eprintln!("   - {}", p.display());
            }
            std::process::exit(1);
        }
    };

    // 4) Load config safely
    let node_config = match NodeConfig::load(config_path.to_str().unwrap()) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("❌ Failed to load or parse node configuration: {}", e);
            std::process::exit(1);
        }
    };

    // 5) Print status (no logic change)
    println!("🟢 Node Status:");
    println!(
        " - ID: {}\n - Hostname: {}\n - IP: {}\n - Port: {}\n - Public Key: {}",
        node_config.node_id,
        node_config.hostname,
        node_config.ip,
        node_config.port,
        node_config.public_key
    );
    if let Some(relay) = node_config.relay {
        println!(
            " - Relay: enabled={}, max_peers={}, max_bw={} Mbps, alert={}%",
            relay.enabled, relay.max_peers, relay.max_bandwidth_mbps, relay.alert_threshold_pct
        );
    }
}
