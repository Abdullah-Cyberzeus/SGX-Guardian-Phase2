use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

const DEFAULT_NEBULA_DIR: &str = "/etc/nebula";

/// Generates /etc/nebula/config.yaml if it does not exist.
pub fn ensure_nebula_config(nebula_dir: &str) -> std::io::Result<()> {
    let config_path = format!("{}/config.yaml", nebula_dir);
    if Path::new(&config_path).exists() {
        return Ok(());
    }

    std::fs::create_dir_all(nebula_dir)?;

    let config_content = format!(
        r#"pki:
  ca: {dir}/ca.crt
  cert: {dir}/vps-lighthouse.crt
  key: {dir}/vps-lighthouse.key

static_host_map: {{}}

listen:
  host: 0.0.0.0
  port: 4242

tun:
  dev: nebula0
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500

lighthouse:
  am_lighthouse: true
  interval: 60

relay:
  am_relay: true
  use_relays: false

punchy:
  punch: true
  respond: true

logging:
  level: info

firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
"#,
        dir = nebula_dir
    );

    std::fs::write(&config_path, config_content)?;
    tracing::info!("📋 Generated Nebula lighthouse config at {}", config_path);
    Ok(())
}

/// Checks if all 3 required certificate files exist in the nebula directory.
pub fn certificates_exist(nebula_dir: &str) -> bool {
    let ca = format!("{}/ca.crt", nebula_dir);
    let cert = format!("{}/vps-lighthouse.crt", nebula_dir);
    let key = format!("{}/vps-lighthouse.key", nebula_dir);

    Path::new(&ca).exists() && Path::new(&cert).exists() && Path::new(&key).exists()
}

/// Background worker that monitors /etc/nebula, auto-generates config,
/// and maintains the running `nebula` lighthouse + relay process.
pub async fn start_lighthouse_manager() {
    let nebula_dir = std::env::var("NEBULA_DIR").unwrap_or_else(|_| DEFAULT_NEBULA_DIR.to_string());
    let mut instructions_printed = false;

    loop {
        if !certificates_exist(&nebula_dir) {
            if !instructions_printed {
                println!();
                println!("╔════════════════════════════════════════════════════════════════════════╗");
                println!("║                 ⚠️  VPS CLOUD LIGHTHOUSE NOT CONFIGURED                ║");
                println!("╠════════════════════════════════════════════════════════════════════════╣");
                println!("║ Missing certificates in {}/                                     ║", nebula_dir);
                println!("║ Required: ca.crt, vps-lighthouse.crt, vps-lighthouse.key               ║");
                println!("║                                                                        ║");
                println!("║ 👉 To activate Lighthouse & Relay:                                     ║");
                println!("║   1. On Node A (Home CA), run:                                         ║");
                println!("║      nebula-cert sign -name \"vps-lighthouse\" -ip \"192.168.100.10/24\"   ║");
                println!("║        -groups \"lighthouse,relay\"                                      ║");
                println!("║        -ca-crt /var/lib/sgx-guardian/nebula/ca/ca.crt                  ║");
                println!("║        -ca-key /var/lib/sgx-guardian/nebula/ca/ca.key                  ║");
                println!("║   2. Copy ca.crt, vps-lighthouse.crt, and vps-lighthouse.key           ║");
                println!("║      to {} on this VPS.                                        ║", nebula_dir);
                println!("║                                                                        ║");
                println!("║ ⏳ Waiting for certificate files...                                    ║");
                println!("╚════════════════════════════════════════════════════════════════════════╝");
                println!();
                instructions_printed = true;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        // Reset flag in case certs are deleted/re-added later
        instructions_printed = false;

        // Ensure config.yaml is generated
        if let Err(e) = ensure_nebula_config(&nebula_dir) {
            tracing::error!("Failed to generate Nebula config: {}", e);
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        let config_path = format!("{}/config.yaml", nebula_dir);

        // Check if nebula binary exists
        let nebula_bin = match which::which("nebula") {
            Ok(p) => p,
            Err(_) => {
                if Path::new("/usr/local/bin/nebula").exists() {
                    std::path::PathBuf::from("/usr/local/bin/nebula")
                } else {
                    tracing::error!("'nebula' binary not found in PATH or /usr/local/bin/nebula");
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
            }
        };

        tracing::info!(
            "🚀 Starting Nebula Lighthouse & Relay daemon: {:?} -config {}",
            nebula_bin,
            config_path
        );

        let mut child = match Command::new(&nebula_bin)
            .arg("-config")
            .arg(&config_path)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to spawn nebula process: {}", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        println!();
        println!("✅ [VPS Lighthouse] Nebula Lighthouse & Relay active on port 4242 (overlay: 192.168.100.10/24)");
        println!();

        // Wait for process to exit or crash, then loop and restart
        let status = child.wait().await;
        tracing::warn!("Nebula daemon exited with status: {:?}. Restarting...", status);
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}
