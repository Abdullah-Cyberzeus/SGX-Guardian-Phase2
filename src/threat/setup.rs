use super::config::SuricataConfig;
use std::io;
use std::path::Path;
use tokio::fs::{self, OpenOptions};

const DEFAULT_THREAT_CONFIG: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/config/threat/config.yaml"
));
const DEFAULT_SURICATA_YAML_TEMPLATE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/packaging/suricata.yaml.template"
));
const DEFAULT_GUARDIAN_CUSTOM_RULES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/packaging/guardian-custom.rules"
));
const DEFAULT_HOME_NET: &str = "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuricataRuntimeMode {
    ManagedService,
    BinaryOnly,
    TailerOnly,
}

impl SuricataRuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ManagedService => "managed_service",
            Self::BinaryOnly => "binary_only",
            Self::TailerOnly => "tailer_only",
        }
    }

    pub fn note(self) -> Option<&'static str> {
        match self {
            Self::ManagedService => None,
            Self::BinaryOnly => Some(
                "Suricata is available only as a direct binary on this runtime; service-manager controls are limited.",
            ),
            Self::TailerOnly => Some(
                "This runtime ingests injected /var/log/suricata/eve.json alerts only; the Suricata daemon is not bundled here.",
            ),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SuricataRuntimeCapabilities {
    pub mode: SuricataRuntimeMode,
    pub systemctl_path: Option<&'static str>,
    pub can_start: bool,
    pub can_validate: bool,
    pub can_update_rules: bool,
}

pub fn resolve_systemctl() -> Option<&'static str> {
    ["/usr/bin/systemctl", "/bin/systemctl", "/sbin/systemctl"]
        .into_iter()
        .find(|path| Path::new(path).exists())
}

pub fn detect_runtime_capabilities() -> SuricataRuntimeCapabilities {
    let systemctl_path = resolve_systemctl();
    let suricata_binary = Path::new("/opt/suricata/bin/suricata").exists();
    let suricata_update = Path::new("/opt/suricata/bin/suricata-update").exists();

    let mode = if systemctl_path.is_some() && suricata_binary {
        SuricataRuntimeMode::ManagedService
    } else if suricata_binary {
        SuricataRuntimeMode::BinaryOnly
    } else {
        SuricataRuntimeMode::TailerOnly
    };

    SuricataRuntimeCapabilities {
        mode,
        systemctl_path,
        can_start: systemctl_path.is_some() || suricata_binary,
        can_validate: suricata_binary,
        can_update_rules: systemctl_path.is_some() && suricata_binary && suricata_update,
    }
}

pub fn effective_interface(cfg: Option<&SuricataConfig>) -> String {
    if let Some(interface) = cfg.and_then(|value| value.interface.as_deref()) {
        let trimmed = interface.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    for candidate in ["wlan0", "eth0", "nebula0"] {
        if Path::new("/sys/class/net").join(candidate).exists() {
            return candidate.to_string();
        }
    }

    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if let Some(name) = name.to_str() {
                if name != "lo" {
                    return name.to_string();
                }
            }
        }
    }

    "lo".to_string()
}

pub async fn ensure_suricata_layout(
    config_path: Option<&Path>,
    cfg: Option<&SuricataConfig>,
) -> io::Result<()> {
    let dirs = [
        "/etc/sgx-guardian/threat",
        "/etc/suricata/rules",
        "/var/lib/suricata/rules",
        "/var/log/suricata",
        "/run/suricata",
    ];

    for dir in dirs {
        fs::create_dir_all(dir).await?;
    }

    if let Some(path) = config_path {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        write_if_missing(path, DEFAULT_THREAT_CONFIG).await?;
    }

    write_if_missing(
        Path::new("/etc/suricata/suricata.yaml"),
        &rendered_suricata_yaml(cfg),
    )
    .await?;
    write_if_missing(
        Path::new("/etc/suricata/rules/guardian-custom.rules"),
        DEFAULT_GUARDIAN_CUSTOM_RULES,
    )
    .await?;
    write_if_missing(
        Path::new("/var/lib/suricata/rules/suricata.rules"),
        "# Auto-generated placeholder Suricata ruleset.\n",
    )
    .await?;
    write_if_missing(
        Path::new("/etc/suricata/rules/suricata.rules"),
        "# Auto-generated placeholder Suricata ruleset.\n",
    )
    .await?;
    touch_file(Path::new("/var/log/suricata/eve.json")).await?;
    touch_file(Path::new("/var/log/suricata/fast.log")).await?;

    Ok(())
}

pub async fn ensure_suricata_service_unit(cfg: Option<&SuricataConfig>) -> io::Result<()> {
    let Some(systemctl) = resolve_systemctl() else {
        return Ok(());
    };

    let unit_path = Path::new("/etc/systemd/system/suricata.service");
    if unit_path.exists() {
        return Ok(());
    }

    let interface = effective_interface(cfg);
    let contents = format!(
        "[Unit]\nDescription=Suricata IDS/IPS\nAfter=network.target\n\n\
         [Service]\nExecStart=/opt/suricata/bin/suricata \
         -c /etc/suricata/suricata.yaml \
         --pidfile /run/suricata/suricata.pid -i {interface} -D\n\
         ExecReload=/bin/kill -HUP $MAINPID\nRestart=on-failure\n\n\
         [Install]\nWantedBy=multi-user.target\n"
    );

    fs::write(unit_path, contents).await?;
    let _ = tokio::process::Command::new(systemctl)
        .args(["daemon-reload"])
        .output()
        .await;
    Ok(())
}

fn rendered_suricata_yaml(cfg: Option<&SuricataConfig>) -> String {
    DEFAULT_SURICATA_YAML_TEMPLATE
        .replace("__INTERFACE__", &effective_interface(cfg))
        .replace("__HOME_NET__", DEFAULT_HOME_NET)
}

async fn write_if_missing(path: &Path, contents: &str) -> io::Result<()> {
    if path.exists() {
        return Ok(());
    }
    fs::write(path, contents).await
}

async fn touch_file(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::{effective_interface, rendered_suricata_yaml};
    use crate::threat::config::SuricataConfig;

    #[test]
    fn effective_interface_prefers_explicit_config() {
        let cfg = SuricataConfig {
            interface: Some("mesh0".into()),
            ..SuricataConfig::default()
        };

        assert_eq!(effective_interface(Some(&cfg)), "mesh0");
    }

    #[test]
    fn rendered_suricata_yaml_replaces_template_placeholders() {
        let cfg = SuricataConfig {
            interface: Some("mesh0".into()),
            ..SuricataConfig::default()
        };
        let rendered = rendered_suricata_yaml(Some(&cfg));

        assert!(rendered.contains("interface: mesh0"));
        assert!(!rendered.contains("__INTERFACE__"));
        assert!(!rendered.contains("__HOME_NET__"));
    }
}
