use crate::netbridge::config::DnsmasqConfigGenerator;
use crate::netbridge::process::ProcessRunner;
use crate::netbridge::types::{DnsmasqSettings, NetbridgeError};
use std::fs;
use tracing::{error, info};

use std::sync::Arc;

pub struct DnsmasqOrchestrator {
    pub settings: DnsmasqSettings,
    pub runner: Option<Arc<ProcessRunner>>,
}

impl DnsmasqOrchestrator {
    pub fn new(settings: DnsmasqSettings) -> Self {
        DnsmasqOrchestrator {
            settings,
            runner: None,
        }
    }

    pub async fn start(&mut self) -> Result<(), NetbridgeError> {
        info!("Starting Dnsmasq orchestration flow...");

        let validator = crate::netbridge::validator::Validator::new();

        info!("Validating dnsmasq installation...");
        if let Err(e) = validator.check_dnsmasq_installed() {
            error!("Validation failed: {}", e);
            return Err(NetbridgeError::BootstrapFailed(e.to_string()));
        }

        // Note: We bypass naive global port checks for 53 and 67 here.
        // Because dnsmasq uses `bind-interfaces`, it natively handles binding to specific
        // interfaces (like wlan2) without conflicting with other dnsmasq or systemd-resolved
        // instances on different interfaces (like wlan0 or lo).

        // Ensure dnsmasq.d blocklist directory exists
        let blocklist_dir = "/etc/sgx-guardian/dnsmasq.d/";
        if !std::path::Path::new(blocklist_dir).exists() {
            fs::create_dir_all(blocklist_dir).map_err(NetbridgeError::IoError)?;
        }

        let generator = DnsmasqConfigGenerator::new();
        info!("Generating dnsmasq configuration...");
        if let Err(e) = generator.generate_default(&self.settings) {
            error!("Failed to generate dnsmasq config: {}", e);
            return Err(e);
        }

        let config_path = "/tmp/netbridge/dnsmasq.conf".to_string();
        let args = vec![
            "-d".to_string(),
            "-u".to_string(),
            "root".to_string(),
            "-C".to_string(),
            config_path,
        ];
        let runner = Arc::new(ProcessRunner::new("dnsmasq".to_string(), args));

        let mut status_rx = runner.subscribe();

        // Ensure any pre-existing dnsmasq instance is stopped before binding sockets
        let _ = tokio::process::Command::new("killall")
            .args(["-q", "-9", "dnsmasq"])
            .output()
            .await;

        info!("Starting dnsmasq process...");
        if let Err(e) = runner.start().await {
            error!("Failed to start dnsmasq process: {}", e);
            return Err(NetbridgeError::ProcessExecutionFailed(e.to_string()));
        }

        // Enable the true process lifecycle manager
        runner.clone().enable_auto_restart();

        self.runner = Some(runner);

        // Brief check to monitor initial process state transitions
        if let Ok(Ok(())) = tokio::time::timeout(std::time::Duration::from_millis(500), async {
            let _ = status_rx.changed().await;
            Ok::<(), ()>(())
        })
        .await
        {}

        info!("Dnsmasq successfully started.");
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), NetbridgeError> {
        info!("Stopping Dnsmasq orchestration flow...");
        if let Some(runner) = &self.runner {
            if let Err(e) = runner.stop().await {
                error!("Failed to stop dnsmasq process: {}", e);
                return Err(NetbridgeError::ProcessExecutionFailed(e.to_string()));
            }
        }
        self.runner = None;
        info!("Dnsmasq stopped successfully.");
        Ok(())
    }
}
