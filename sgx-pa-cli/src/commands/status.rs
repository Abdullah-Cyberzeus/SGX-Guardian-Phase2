use crate::config::NodeConfig;
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
#[command(about = "Show status information for a specific SGX Guardian node")]
pub struct StatusArgs {
    /// Node name to load config for (e.g., nodeA, nodeB, nodeC)
    #[arg(long, default_value = "nodeA")]
    pub node: String,
}

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

    // 3) Build config path
    let config_path: PathBuf = exe_dir
        .join("..")
        .join("config")
        .join(format!("{}.yaml", args.node));

    let config_path = match config_path.canonicalize() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("❌ Config file not found at {:?}: {}", config_path, e);
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
}
