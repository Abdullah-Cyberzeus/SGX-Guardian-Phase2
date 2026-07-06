use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One device observed on the local network during an NMAP scan.
/// Maps directly to the canonical `ConnectedDevice` discovery entity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectedDevice {
    /// Stable per-device id: prefer MAC-only identity, fall back to IP-only.
    /// This keeps a DHCP-renumbered device on the same record as long as its
    /// trusted MAC stays the same.
    pub device_id: String,

    pub ip: String,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,

    /// `Linux 5.x` / `Windows 10` / `unknown`. Free-form string from NMAP.
    pub os_fingerprint: Option<String>,

    /// OS CPE identifiers from NMAP's best `<osmatch>/<osclass>`, e.g.
    /// "cpe:/o:linux:linux_kernel:5". Populated by OS-detect scans (`-O`);
    /// empty for Stealth. `#[serde(default)]` keeps old inventories loadable.
    #[serde(default)]
    pub os_cpe: Vec<String>,

    pub open_ports: Vec<OpenPort>,

    /// Host-level NSE script output (`<hostscript>`), e.g. `smb-os-discovery`,
    /// `broadcast-*`. This is the bulk of an Aggressive scan's richness;
    /// empty for Stealth/Standard which run no scripts.
    #[serde(default)]
    pub host_scripts: Vec<ScriptResult>,

    pub status: DeviceStatus,

    /// RFC-3339 UTC timestamps.
    pub first_seen: String,
    pub last_seen: String,

    /// Set to `true` after the AI / vuln pipeline has triaged this device.
    #[serde(default)]
    pub vuln_triaged: bool,

    /// Intensity of the last scan that updated this device's ports/OS data.
    /// One of "stealth" | "standard" | "aggressive". `None` for legacy records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_scan_intensity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenPort {
    pub port: u16,
    /// "tcp" | "udp"
    pub protocol: String,
    /// e.g. "ssh", "http"
    pub service: Option<String>,
    /// e.g. "OpenSSH 7.6p1"
    pub product_version: Option<String>,

    /// Service CPE identifiers from `-sV`, e.g. "cpe:/a:openbsd:openssh:7.6p1".
    /// Empty when version detection found none. `#[serde(default)]` for back-compat.
    #[serde(default)]
    pub cpe: Vec<String>,

    /// Per-port NSE script output (Aggressive `--script` results), e.g.
    /// `http-title`, `ssl-cert`, `vulners`. Empty for Stealth/Standard.
    #[serde(default)]
    pub scripts: Vec<ScriptResult>,
}

/// One NSE script result, captured verbatim from an NMAP `<script>` element.
/// This is where Aggressive-scan richness (vuln findings, banners, certs) lives.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScriptResult {
    /// NSE script id, e.g. "http-title", "ssl-cert", "vulners".
    pub id: String,
    /// Flattened human-readable script output (NMAP's `output` attribute).
    pub output: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    /// Found in whitelist.yaml and matches expected fingerprint.
    Approved,
    /// New, not in whitelist - pending admin review.
    Unauthorized,
    /// In whitelist but OS/ports drifted from approved baseline.
    Drifted,
    /// Was approved, hasn't been seen in N consecutive scans.
    Stale,
}

impl ConnectedDevice {
    /// Stable id: prefer MAC-only, fall back to IP-only when no MAC is known.
    pub fn compute_id(ip: &str, mac: Option<&str>) -> String {
        let mut hasher = Sha256::new();
        if let Some(m) = mac {
            hasher.update(m.as_bytes());
        } else {
            hasher.update(ip.as_bytes());
        }
        hex::encode(&hasher.finalize()[..8]) // 16-char prefix
    }
}
