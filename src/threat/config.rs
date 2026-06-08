use crate::threat::error::{ThreatError, ThreatResult};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlockMode {
    /// IDS only: alerts logged and forwarded; no nftables changes.
    AlertOnly,
    /// High/Critical alerts trigger nftables drops in the `sgx_threat` table.
    InlineBlock,
}

impl BlockMode {
    pub fn as_str(self) -> &'static str {
        match self {
            BlockMode::AlertOnly => "alert_only",
            BlockMode::InlineBlock => "inline_block",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuricataConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default = "default_eve_path")]
    pub eve_path: String,
    #[serde(default = "default_suricata_yaml")]
    pub suricata_yaml: String,
    #[serde(default = "default_block_mode")]
    pub block_mode: BlockMode,
    #[serde(default = "default_block_ttl_secs")]
    pub block_ttl_secs: u64,
    /// CIDRs that are never auto-blocked.
    #[serde(default = "default_exempt")]
    pub block_exempt: Vec<String>,
    /// Rule auto-update cadence in hours. 0 = manual only.
    #[serde(default = "default_rule_update_hours")]
    pub rule_update_hours: u64,
}

fn default_eve_path() -> String {
    "/var/log/suricata/eve.json".into()
}

fn default_suricata_yaml() -> String {
    "/etc/suricata/suricata.yaml".into()
}

fn default_block_mode() -> BlockMode {
    BlockMode::AlertOnly
}

fn default_block_ttl_secs() -> u64 {
    86_400
}

fn default_rule_update_hours() -> u64 {
    24
}

fn default_exempt() -> Vec<String> {
    vec!["127.0.0.0/8".into(), "192.168.100.0/24".into()]
}

impl Default for SuricataConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: None,
            eve_path: default_eve_path(),
            suricata_yaml: default_suricata_yaml(),
            block_mode: default_block_mode(),
            block_ttl_secs: default_block_ttl_secs(),
            block_exempt: default_exempt(),
            rule_update_hours: default_rule_update_hours(),
        }
    }
}

impl SuricataConfig {
    pub fn load(path: &Path) -> ThreatResult<Self> {
        if !path.exists() {
            let cfg = Self::default();
            cfg.validate()?;
            return Ok(cfg);
        }

        let text = std::fs::read_to_string(path)?;
        let cfg: SuricataConfig = serde_yaml::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> ThreatResult<()> {
        if self.block_ttl_secs == 0 || self.block_ttl_secs > 7 * 86_400 {
            return Err(ThreatError::BadConfig(
                "block_ttl_secs must be 1..=604800 (7 days)".into(),
            ));
        }

        for cidr in &self.block_exempt {
            if cidr.parse::<ipnet::IpNet>().is_err() && cidr.parse::<std::net::IpAddr>().is_err() {
                return Err(ThreatError::InvalidCidr(cidr.clone()));
            }
        }

        Ok(())
    }
}
