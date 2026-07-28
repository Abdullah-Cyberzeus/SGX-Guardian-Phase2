use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeMode {
    Off,
    HotspotOnly,
    ClientOnly,
    DualWifi,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeFlags {
    pub restore_on_boot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HotspotConfig {
    pub interface: String,
    pub ssid: String,
    pub password: String,
    pub channel: u8,
    pub band: Option<String>,
    #[serde(default)]
    pub client_isolation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SavedWifi {
    pub ssid: String,
    pub bssid: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UplinkConfig {
    pub interface: String,
    #[serde(default)]
    pub networks: Vec<SavedWifi>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianConfig {
    pub mode: RuntimeMode,
    pub flags: RuntimeFlags,
    pub hotspot: HotspotConfig,
    pub uplink: UplinkConfig,
}

impl Default for GuardianConfig {
    fn default() -> Self {
        Self {
            mode: RuntimeMode::Off,
            flags: RuntimeFlags::default(),
            hotspot: HotspotConfig::default(),
            uplink: UplinkConfig::default(),
        }
    }
}
