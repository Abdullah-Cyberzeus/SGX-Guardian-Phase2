use crate::discovery::error::{DiscoveryError, DiscoveryResult};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanIntensity {
    /// `-sn -PR` - ARP ping sweep only. Fast, near-invisible on switched LAN.
    Stealth,
    /// `-sS -O --top-ports 1000 -sV` - SYN scan, OS detect, version probes.
    /// Default; balanced for shared LAN.
    Standard,
    /// `-sS -O -p 1-65535 -sV --script vuln` - full port + NSE vuln scripts.
    /// Loud, slow, only for ad-hoc admin runs.
    Aggressive,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanSchedule {
    Hourly,
    Daily,
    Manual,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScheduledScanKind {
    Hourly,
    Daily,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleFrequency {
    Once,
    Daily,
    Weekly,
    Monthly,
    Yearly,
    Custom,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScheduleDay {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScheduleProfile {
    pub intensity: ScanIntensity,
    #[serde(default)]
    pub days: Vec<ScheduleDay>,
    #[serde(default = "default_schedule_time")]
    pub time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScheduledScans {
    #[serde(default = "default_hourly_profile")]
    pub hourly: ScheduleProfile,
    #[serde(default = "default_daily_profile")]
    pub daily: ScheduleProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanScheduleProfile {
    #[serde(default = "default_schedule_id")]
    pub id: String,
    #[serde(default = "default_schedule_frequency")]
    pub frequency: ScheduleFrequency,
    pub intensity: ScanIntensity,
    #[serde(default)]
    pub days: Vec<ScheduleDay>,
    #[serde(default)]
    pub day_of_month: Option<u8>,
    #[serde(default)]
    pub month: Option<u8>,
    #[serde(default = "default_schedule_time")]
    pub time: String,
    #[serde(default = "default_schedule_timezone")]
    pub timezone: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortMergeStrategy {
    Preserve,
    Merge,
    Replace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanSemantics {
    pub port_strategy: PortMergeStrategy,
    pub os_scan: bool,
    /// True when this scan runs NSE scripts (Aggressive). Script output is the
    /// *current* truth for a host, so on a script-running scan we replace the
    /// stored scripts wholesale - even with an empty set - so resolved/removed
    /// findings don't linger. Non-script scans (Stealth/Standard) instead
    /// preserve the last rich result so they can't wipe it.
    pub runs_scripts: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct NmapConfig {
    pub enabled: bool,

    /// CIDR of the segment to scan, e.g. "192.168.50.0/24".
    /// If `None` at runtime, the active LAN CIDR is auto-detected.
    pub target_cidr: Option<String>,

    /// Per-scan timeout. NMAP gets SIGTERM if it exceeds this.
    pub timeout_secs: u64,

    /// Hosts to never scan (legal/contractual exclusions).
    pub exclude: Vec<String>,

    #[serde(default)]
    pub schedules: ScheduledScans,

    #[serde(default, rename = "scan_schedules")]
    pub scan_schedules: Vec<ScanScheduleProfile>,

    #[serde(skip)]
    legacy_schedule: Option<ScanSchedule>,

    #[serde(skip)]
    legacy_intensity: Option<ScanIntensity>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawNmapConfig {
    #[serde(default)]
    enabled: bool,
    target_cidr: Option<String>,
    #[serde(default = "default_timeout_secs")]
    timeout_secs: u64,
    #[serde(default)]
    exclude: Vec<String>,
    schedules: Option<ScheduledScans>,
    #[serde(default, rename = "scan_schedules")]
    scan_schedules: Option<Vec<ScanScheduleProfile>>,
    #[serde(default, rename = "scan_schedule")]
    scan_schedule: Option<ScanScheduleProfile>,
    intensity: Option<ScanIntensity>,
    legacy_schedule: Option<ScanSchedule>,
}

fn default_intensity() -> ScanIntensity {
    ScanIntensity::Standard
}

fn default_schedule() -> ScanSchedule {
    ScanSchedule::Hourly
}

fn default_schedule_frequency() -> ScheduleFrequency {
    ScheduleFrequency::Weekly
}

fn default_hourly_profile() -> ScheduleProfile {
    ScheduleProfile {
        intensity: ScanIntensity::Standard,
        days: Vec::new(),
        time: default_schedule_time(),
    }
}

fn default_daily_profile() -> ScheduleProfile {
    ScheduleProfile {
        intensity: ScanIntensity::Aggressive,
        days: default_schedule_days(),
        time: default_schedule_time(),
    }
}

fn default_schedule_days() -> Vec<ScheduleDay> {
    vec![
        ScheduleDay::Monday,
        ScheduleDay::Wednesday,
        ScheduleDay::Friday,
    ]
}

fn default_schedule_time() -> String {
    "23:00".to_string()
}

fn default_schedule_timezone() -> String {
    "America/New_York".to_string()
}

fn default_schedule_id() -> String {
    format!("sched-{}", Uuid::new_v4().simple())
}

fn default_timeout_secs() -> u64 {
    600
}

impl Default for ScheduledScans {
    fn default() -> Self {
        Self {
            hourly: default_hourly_profile(),
            daily: default_daily_profile(),
        }
    }
}

impl Default for ScanScheduleProfile {
    fn default() -> Self {
        Self {
            id: default_schedule_id(),
            frequency: default_schedule_frequency(),
            intensity: default_intensity(),
            days: default_schedule_days(),
            day_of_month: Some(1),
            month: None,
            time: default_schedule_time(),
            timezone: default_schedule_timezone(),
        }
    }
}

impl Default for NmapConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            target_cidr: None,
            timeout_secs: default_timeout_secs(),
            exclude: Vec::new(),
            schedules: ScheduledScans::default(),
            scan_schedules: Vec::new(),
            legacy_schedule: None,
            legacy_intensity: None,
        }
    }
}

impl<'de> Deserialize<'de> for NmapConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawNmapConfig::deserialize(deserializer)?;
        let schedules_present = raw.schedules.is_some();
        let scan_schedules_present = raw.scan_schedules.is_some();
        let mut scan_schedules = raw.scan_schedules.unwrap_or_default();
        if !scan_schedules_present {
            if let Some(schedule) = raw.scan_schedule {
                scan_schedules.push(schedule);
            } else {
                scan_schedules.push(ScanScheduleProfile {
                    id: default_schedule_id(),
                    frequency: ScheduleFrequency::Weekly,
                    intensity: raw
                        .schedules
                        .as_ref()
                        .map(|s| s.daily.intensity)
                        .unwrap_or_else(default_intensity),
                    days: raw
                        .schedules
                        .as_ref()
                        .map(|s| {
                            if s.daily.days.is_empty() {
                                default_schedule_days()
                            } else {
                                s.daily.days.clone()
                            }
                        })
                        .unwrap_or_else(default_schedule_days),
                    day_of_month: None,
                    month: None,
                    time: raw
                        .schedules
                        .as_ref()
                        .map(|s| s.daily.time.clone())
                        .unwrap_or_else(default_schedule_time),
                    timezone: default_schedule_timezone(),
                });
            }
        }
        let legacy_intensity = raw.intensity;
        let legacy_schedule = raw.legacy_schedule;

        let mut cfg = Self {
            enabled: raw.enabled,
            target_cidr: normalize_optional_target(raw.target_cidr),
            timeout_secs: raw.timeout_secs,
            exclude: raw.exclude,
            schedules: raw.schedules.unwrap_or_default(),
            scan_schedules,
            legacy_schedule: None,
            legacy_intensity: None,
        };

        if !schedules_present && (legacy_intensity.is_some() || legacy_schedule.is_some()) {
            let mapped_intensity = legacy_intensity.unwrap_or_else(default_intensity);
            let mapped_schedule = legacy_schedule.unwrap_or_else(default_schedule);
            cfg.legacy_intensity = Some(mapped_intensity);
            cfg.legacy_schedule = Some(mapped_schedule);

            match mapped_schedule {
                ScanSchedule::Hourly => cfg.schedules.hourly.intensity = mapped_intensity,
                ScanSchedule::Daily => cfg.schedules.daily.intensity = mapped_intensity,
                ScanSchedule::Manual => {}
            }
        }

        if cfg.schedules.daily.days.is_empty() {
            cfg.schedules.daily.days = default_schedule_days();
        }
        if cfg.schedules.daily.time.trim().is_empty() {
            cfg.schedules.daily.time = default_schedule_time();
        }

        // Preserve an explicitly saved empty list. It means the administrator
        // removed all tasks; recreating a legacy weekly task here made the UI
        // appear to ignore deletes and user-selected schedules.
        if cfg.scan_schedules.is_empty() && !scan_schedules_present {
            cfg.scan_schedules.push(ScanScheduleProfile {
                id: default_schedule_id(),
                frequency: ScheduleFrequency::Weekly,
                intensity: cfg.schedules.daily.intensity,
                days: if cfg.schedules.daily.days.is_empty() {
                    default_schedule_days()
                } else {
                    cfg.schedules.daily.days.clone()
                },
                day_of_month: None,
                month: None,
                time: cfg.schedules.daily.time.clone(),
                timezone: default_schedule_timezone(),
            });
        }
        Ok(cfg)
    }
}

impl NmapConfig {
    pub fn load(path: &Path) -> DiscoveryResult<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)?;
        let cfg: NmapConfig = serde_yaml::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> DiscoveryResult<()> {
        if self.timeout_secs == 0 || self.timeout_secs > 3600 {
            return Err(DiscoveryError::BadConfig(
                "timeout_secs must be 1..=3600".into(),
            ));
        }

        if let Some(cidr) = &self.target_cidr {
            validate_ipv4_cidr(cidr, "target_cidr")?;
        }

        for value in &self.exclude {
            validate_ip_or_cidr(value, "exclude")?;
        }

        validate_scan_time(&self.schedules.daily.time)?;
        if self.schedules.daily.days.is_empty() {
            return Err(DiscoveryError::BadConfig(
                "schedules.daily.days must include at least one day".into(),
            ));
        }

        for schedule in &self.scan_schedules {
            validate_scan_time(&schedule.time)?;
            if schedule.timezone.trim().is_empty() {
                return Err(DiscoveryError::BadConfig(
                    "scan_schedules.timezone must not be empty".into(),
                ));
            }
            if !schedule
                .timezone
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '_' | '+' | '-'))
            {
                return Err(DiscoveryError::BadConfig(
                    "scan_schedules.timezone contains unsupported characters".into(),
                ));
            }
            if let Some(day) = schedule.day_of_month {
                if !(1..=31).contains(&day) {
                    return Err(DiscoveryError::BadConfig(
                        "scan_schedules.day_of_month must be 1..=31".into(),
                    ));
                }
            }
            if let Some(month) = schedule.month {
                if !(1..=12).contains(&month) {
                    return Err(DiscoveryError::BadConfig(
                        "scan_schedules.month must be 1..=12".into(),
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn legacy_schedule_mode(&self) -> Option<ScanSchedule> {
        self.legacy_schedule
    }

    pub fn active_schedules(&self) -> &[ScanScheduleProfile] {
        &self.scan_schedules
    }

    pub fn ad_hoc_intensity(&self) -> ScanIntensity {
        self.legacy_intensity
            .unwrap_or(self.schedules.hourly.intensity)
    }

    pub fn scheduled_intensity(&self, kind: ScheduledScanKind) -> Option<ScanIntensity> {
        if !self.scan_schedules.is_empty() {
            return None;
        }
        if let Some(legacy_schedule) = self.legacy_schedule {
            let legacy_intensity = self.legacy_intensity.unwrap_or_else(default_intensity);
            return match (legacy_schedule, kind) {
                (ScanSchedule::Hourly, ScheduledScanKind::Hourly)
                | (ScanSchedule::Daily, ScheduledScanKind::Daily) => Some(legacy_intensity),
                _ => None,
            };
        }

        None
    }

    pub fn resolved_target_cidr(&self) -> String {
        self.target_cidr
            .clone()
            .unwrap_or_else(auto_detect_local_cidr_or_default)
    }

    pub fn nmap_args(&self, target: &str) -> Vec<String> {
        self.nmap_args_for_intensity(target, self.ad_hoc_intensity())
    }

    /// Connected Devices per-device security scan (targeted `/32`-style).
    ///
    /// Lighter than discovery `Aggressive` single-host (`-p 1-65535` + high
    /// version intensity), which times out on ARM boards. Still runs NSE
    /// `vuln` scripts and emits XML on stdout for the existing parser.
    pub fn nmap_args_for_device_security_scan(&self, target: &str) -> Vec<String> {
        let mut args: Vec<String> = [
            "-sS",
            "-O",
            "-sV",
            "--version-light",
            "-T4",
            "--top-ports",
            "1000",
            "--script",
            "vuln",
            "--script-timeout",
            "15s",
            "--max-retries",
            "1",
            "--host-timeout",
            "150s",
            "--max-rate",
            "500",
            "--min-rate",
            "100",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        // Always: XML output to stdout, no DNS, no privileged probes we didn't ask for.
        args.extend(["-oX", "-"].iter().map(|s| s.to_string()));
        args.push("-n".to_string());
        for ex in &self.exclude {
            args.push("--exclude".to_string());
            args.push(ex.clone());
        }
        args.push("--".to_string());
        args.push(target.to_string());
        args
    }

    pub fn nmap_args_for_intensity(&self, target: &str, intensity: ScanIntensity) -> Vec<String> {
        // Adaptive sizing: a /24 (~254 hosts) needs tighter per-host budget than a /32.
        // We treat any target that is NOT a /32 (single-IP, single-CIDR, or hostname)
        // as a "subnet" for budgeting purposes and add hard upper bounds.
        let is_subnet = target_is_subnet(target);

        let mut args: Vec<String> = match intensity {
            // Stealth: ARP sweep - already cheap, unchanged.
            ScanIntensity::Stealth => vec!["-sn", "-PR", "-T2"]
                .into_iter()
                .map(String::from)
                .collect(),

            // Standard: SYN + OS + service probe.
            // For subnets: reduce top-ports + version intensity to keep /24 < 5 min.
            // For /32: full top-1000, since cost is bounded by a single host.
            ScanIntensity::Standard => {
                let mut v = vec!["-sS", "-O", "-sV", "-T3"]
                    .into_iter()
                    .map(String::from)
                    .collect::<Vec<_>>();
                if is_subnet {
                    v.extend(
                        ["--top-ports", "100", "--version-intensity", "2"]
                            .iter()
                            .map(|s| s.to_string()),
                    );
                } else {
                    v.extend(
                        ["--top-ports", "1000", "--version-intensity", "5"]
                            .iter()
                            .map(|s| s.to_string()),
                    );
                }
                v
            }

            // Aggressive: full port range + NSE vuln scripts.
            // For subnets we *still* cap port-range, otherwise a /24 NEVER completes
            // on a 4-core i.MX8MP. Operator who wants full 1-65535 must scan a /32.
            ScanIntensity::Aggressive => {
                let mut v = vec!["-sS", "-O", "-sV", "-T4"]
                    .into_iter()
                    .map(String::from)
                    .collect::<Vec<_>>();
                if is_subnet {
                    v.extend(
                        [
                            "-p",
                            "1-1024",
                            "--script",
                            "default,safe",
                            "--version-intensity",
                            "5",
                        ]
                        .iter()
                        .map(|s| s.to_string()),
                    );
                } else {
                    v.extend(
                        [
                            "-p",
                            "1-65535",
                            "--script",
                            "vuln",
                            "--version-intensity",
                            "7",
                        ]
                        .iter()
                        .map(|s| s.to_string()),
                    );
                }
                v
            }
        };

        // === Bounded budget - applies to Standard + Aggressive on any target ===
        // These are NMAP's defence against unbounded scans. Per-host hard timeout
        // makes /24 completion deterministic; per-host max-retries kills the
        // exponential back-off that was eating 30 min on the board.
        if !matches!(intensity, ScanIntensity::Stealth) {
            args.extend(
                [
                    "--max-retries",
                    "1",
                    "--host-timeout",
                    if is_subnet { "60s" } else { "180s" },
                    "--max-rate",
                    "300",
                    "--min-rate",
                    "50",
                    "--max-parallelism",
                    "64",
                ]
                .iter()
                .map(|s| s.to_string()),
            );
        }

        // Always: XML output to stdout, no DNS, no privileged probes we didn't ask for.
        args.extend(["-oX", "-"].iter().map(|s| s.to_string()));
        args.push("-n".to_string()); // no DNS
        for ex in &self.exclude {
            args.push("--exclude".to_string());
            args.push(ex.clone());
        }
        // `--` ends option parsing: an ad-hoc scan target (REST/CLI-supplied,
        // only trimmed upstream) can never be misparsed as an nmap flag
        // (e.g. "--script=...", "-oN ...") regardless of its content.
        args.push("--".to_string());
        args.push(target.to_string());
        args
    }

    pub fn scan_semantics(&self, target: &str) -> ScanSemantics {
        self.scan_semantics_for_intensity(target, self.ad_hoc_intensity())
    }

    pub fn scan_semantics_for_intensity(
        &self,
        target: &str,
        intensity: ScanIntensity,
    ) -> ScanSemantics {
        let is_subnet = target_is_subnet(target);
        let port_strategy = match intensity {
            ScanIntensity::Stealth => PortMergeStrategy::Preserve,
            ScanIntensity::Standard => PortMergeStrategy::Merge,
            ScanIntensity::Aggressive => {
                if is_subnet {
                    PortMergeStrategy::Merge
                } else {
                    PortMergeStrategy::Replace
                }
            }
        };

        ScanSemantics {
            port_strategy,
            os_scan: !matches!(intensity, ScanIntensity::Stealth),
            runs_scripts: matches!(intensity, ScanIntensity::Aggressive),
        }
    }
}

impl ScanSemantics {
    pub fn for_intensity(intensity: ScanIntensity) -> Self {
        match intensity {
            ScanIntensity::Stealth => Self {
                port_strategy: PortMergeStrategy::Preserve,
                os_scan: false,
                runs_scripts: false,
            },
            ScanIntensity::Standard => Self {
                port_strategy: PortMergeStrategy::Merge,
                os_scan: true,
                runs_scripts: false,
            },
            ScanIntensity::Aggressive => Self {
                port_strategy: PortMergeStrategy::Replace,
                os_scan: true,
                runs_scripts: true,
            },
        }
    }
}

pub fn auto_detect_local_cidr_or_default() -> String {
    if let Ok(ip) = crate::dynamic_config::detect_local_lan_ip() {
        if let Some(cidr) = read_interface_cidr_for_ip(ip) {
            return cidr;
        }

        let octets = ip.octets();
        return format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
    }

    "192.168.100.0/24".to_string()
}

/// `target` is considered a "subnet" if it contains a `/` AND the prefix is `< 32`.
/// Single hostnames, IPs without prefix, and `/32` all count as single-target.
fn target_is_subnet(target: &str) -> bool {
    if let Some((_ip, prefix)) = target.rsplit_once('/') {
        if let Ok(p) = prefix.parse::<u8>() {
            return p < 32;
        }
    }
    false
}

fn normalize_optional_target(target: Option<String>) -> Option<String> {
    target.and_then(|raw| {
        let value = raw.trim();
        if value.is_empty()
            || value.eq_ignore_ascii_case("auto")
            || value.eq_ignore_ascii_case("null")
        {
            None
        } else {
            Some(value.to_string())
        }
    })
}

fn validate_ipv4_cidr(value: &str, field_name: &str) -> DiscoveryResult<()> {
    parse_ipv4_cidr(value)
        .map(|_| ())
        .map_err(|message| DiscoveryError::BadConfig(format!("{field_name} {message}")))
}

fn validate_ip_or_cidr(value: &str, field_name: &str) -> DiscoveryResult<()> {
    if value.contains('/') {
        return validate_ipv4_cidr(value, field_name);
    }

    value.parse::<Ipv4Addr>().map(|_| ()).map_err(|_| {
        DiscoveryError::BadConfig(format!(
            "{field_name} '{}' must be an IPv4 address or CIDR",
            value
        ))
    })
}

fn validate_scan_time(value: &str) -> DiscoveryResult<()> {
    let Some((hour, minute)) = value.split_once(':') else {
        return Err(DiscoveryError::BadConfig(
            "schedules.daily.time must use HH:MM".into(),
        ));
    };
    let hour = hour.parse::<u8>().map_err(|_| {
        DiscoveryError::BadConfig("schedules.daily.time hour must be 00..=23".into())
    })?;
    let minute = minute.parse::<u8>().map_err(|_| {
        DiscoveryError::BadConfig("schedules.daily.time minute must be 00..=59".into())
    })?;
    if hour > 23 || minute > 59 {
        return Err(DiscoveryError::BadConfig(
            "schedules.daily.time must be between 00:00 and 23:59".into(),
        ));
    }
    Ok(())
}

fn parse_ipv4_cidr(value: &str) -> Result<(Ipv4Addr, u8), String> {
    let (ip_str, prefix_str) = value
        .rsplit_once('/')
        .ok_or_else(|| format!("'{}' missing /prefix", value))?;
    let ip = ip_str
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("'{}' is not a valid IPv4 CIDR", value))?;
    let prefix = prefix_str
        .parse::<u8>()
        .map_err(|_| format!("'{}' has an invalid prefix", value))?;
    if prefix > 32 {
        return Err(format!("'{}' has prefix outside 0..=32", value));
    }
    Ok((ip, prefix))
}

fn read_interface_cidr_for_ip(target_ip: Ipv4Addr) -> Option<String> {
    use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};

    let interfaces = NetworkInterface::show().ok()?;
    for iface in interfaces {
        for addr in &iface.addr {
            if let Addr::V4(v4) = addr {
                if v4.ip != target_ip {
                    continue;
                }

                let mask = v4.netmask?;
                let prefix = netmask_to_prefix(mask)?;
                let network = ipv4_network(target_ip, prefix);
                return Some(format!("{}/{}", network, prefix));
            }
        }
    }
    None
}

fn netmask_to_prefix(mask: Ipv4Addr) -> Option<u8> {
    let raw = u32::from(mask);
    let prefix = raw.leading_ones() as u8;
    if raw == prefix_to_mask(prefix) {
        Some(prefix)
    } else {
        None
    }
}

fn ipv4_network(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(ip) & prefix_to_mask(prefix))
}

fn prefix_to_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        auto_detect_local_cidr_or_default, NmapConfig, PortMergeStrategy, ScanIntensity,
        ScanSchedule, ScheduleFrequency, ScheduledScanKind,
    };

    #[test]
    fn default_profiles_match_new_schedule_defaults() {
        let cfg = NmapConfig::default();
        assert_eq!(cfg.schedules.hourly.intensity, ScanIntensity::Standard);
        assert_eq!(cfg.schedules.daily.intensity, ScanIntensity::Aggressive);
        assert_eq!(cfg.ad_hoc_intensity(), ScanIntensity::Standard);
    }

    #[test]
    fn empty_scan_schedule_backfills_default_task_and_enables_config() {
        let yaml = r#"
enabled: false
target_cidr: null
timeout_secs: 600
exclude: []
scan_schedules: []
schedules:
  hourly:
    intensity: standard
  daily:
    intensity: aggressive
    days: [monday, wednesday, friday]
    time: "23:00"
"#;

        let cfg: NmapConfig = serde_yaml::from_str(yaml).expect("config should parse");
        assert!(cfg.enabled);
        assert_eq!(cfg.scan_schedules.len(), 1);
        assert_eq!(cfg.scan_schedules[0].frequency, ScheduleFrequency::Weekly);
        assert_eq!(cfg.scan_schedules[0].intensity, ScanIntensity::Aggressive);
    }

    #[test]
    fn legacy_yaml_maps_without_breaking_runtime_schedule() {
        let yaml = r#"
enabled: true
target_cidr: 192.168.50.0/24
intensity: stealth
schedule: daily
timeout_secs: 120
exclude:
  - 192.168.50.1
"#;

        let cfg: NmapConfig = serde_yaml::from_str(yaml).expect("legacy config should parse");
        assert_eq!(cfg.legacy_schedule_mode(), Some(ScanSchedule::Daily));
        assert_eq!(
            cfg.scheduled_intensity(ScheduledScanKind::Hourly),
            None,
            "legacy daily config should not start hourly scans"
        );
        assert_eq!(
            cfg.scheduled_intensity(ScheduledScanKind::Daily),
            Some(ScanIntensity::Stealth)
        );
        assert_eq!(cfg.ad_hoc_intensity(), ScanIntensity::Stealth);
    }

    #[test]
    fn validate_rejects_invalid_exclude_entry() {
        let cfg = NmapConfig {
            exclude: vec!["not-an-ip".to_string()],
            ..NmapConfig::default()
        };

        let err = cfg.validate().expect_err("exclude should be validated");
        assert!(err.to_string().contains("exclude"));
    }

    #[test]
    fn validate_accepts_auto_target_when_cleared() {
        let yaml = r#"
enabled: true
target_cidr: auto
timeout_secs: 600
exclude: []
schedules:
  hourly:
    intensity: standard
  daily:
    intensity: aggressive
"#;

        let cfg: NmapConfig = serde_yaml::from_str(yaml).expect("auto target should normalize");
        assert!(cfg.target_cidr.is_none());
        cfg.validate().expect("normalized config should validate");
    }

    #[test]
    fn nmap_args_stealth_profile_flags() {
        let cfg = NmapConfig::default();
        let args = cfg.nmap_args_for_intensity("192.168.1.0/24", ScanIntensity::Stealth);

        assert!(args.iter().any(|a| a == "-sn"));
        assert!(args.iter().any(|a| a == "-PR"));
        assert!(args.iter().any(|a| a == "-T2"));
    }

    #[test]
    fn standard_subnet_uses_bounded_flags() {
        let cfg = NmapConfig::default();
        let args = cfg.nmap_args_for_intensity("192.168.50.0/24", ScanIntensity::Standard);
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--top-ports" && w[1] == "100"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--max-retries" && w[1] == "1"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--host-timeout" && w[1] == "60s"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--max-rate" && w[1] == "300"));
    }

    #[test]
    fn standard_single_host_keeps_top_1000() {
        let cfg = NmapConfig::default();
        let args = cfg.nmap_args_for_intensity("192.168.50.103/32", ScanIntensity::Standard);
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--top-ports" && w[1] == "1000"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--host-timeout" && w[1] == "180s"));
    }

    #[test]
    fn target_is_preceded_by_end_of_options_separator() {
        // A malicious/malformed target (e.g. "--script=evil.nse") must never
        // be parsed by nmap as a flag — `--` must immediately precede it.
        let cfg = NmapConfig::default();
        let malicious_target = "--script=evil.nse";
        let args = cfg.nmap_args_for_intensity(malicious_target, ScanIntensity::Standard);
        let target_pos = args
            .iter()
            .position(|a| a == malicious_target)
            .expect("target present in args");
        assert_eq!(args[target_pos - 1], "--");
        assert_eq!(target_pos, args.len() - 1, "target must be the last arg");
    }

    #[test]
    fn aggressive_subnet_drops_full_range_for_safety() {
        let cfg = NmapConfig::default();
        let args = cfg.nmap_args_for_intensity("192.168.50.0/24", ScanIntensity::Aggressive);
        assert!(!args.windows(2).any(|w| w[0] == "-p" && w[1] == "1-65535"));
        assert!(args.windows(2).any(|w| w[0] == "-p" && w[1] == "1-1024"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--script" && w[1] == "default,safe"));
    }

    #[test]
    fn aggressive_single_host_keeps_full_vuln_scan() {
        let cfg = NmapConfig::default();
        let args = cfg.nmap_args_for_intensity("192.168.50.103/32", ScanIntensity::Aggressive);
        assert!(args.windows(2).any(|w| w[0] == "-p" && w[1] == "1-65535"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--script" && w[1] == "vuln"));
    }

    #[test]
    fn device_security_scan_uses_bounded_vuln_profile() {
        let cfg = NmapConfig::default();
        let args = cfg.nmap_args_for_device_security_scan("192.168.50.103");

        for flag in ["-sS", "-O", "-sV", "--version-light", "-T4", "-n"] {
            assert!(
                args.iter().any(|a| a == flag),
                "missing device-security flag {flag}"
            );
        }
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--top-ports" && w[1] == "1000"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--script" && w[1] == "vuln"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--script-timeout" && w[1] == "15s"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--max-retries" && w[1] == "1"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--host-timeout" && w[1] == "150s"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--max-rate" && w[1] == "500"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--min-rate" && w[1] == "100"));
        assert!(args.windows(2).any(|w| w[0] == "-oX" && w[1] == "-"));
        assert!(!args.windows(2).any(|w| w[0] == "-p" && w[1] == "1-65535"));
        assert!(!args.iter().any(|a| a == "--version-intensity"));
        assert_eq!(args[args.len() - 2], "--");
        assert_eq!(args.last().map(String::as_str), Some("192.168.50.103"));
    }

    #[test]
    fn device_security_scan_does_not_alter_discovery_aggressive_args() {
        let cfg = NmapConfig::default();
        let discovery = cfg.nmap_args_for_intensity("192.168.50.103/32", ScanIntensity::Aggressive);
        let device = cfg.nmap_args_for_device_security_scan("192.168.50.103");
        assert!(discovery
            .windows(2)
            .any(|w| w[0] == "-p" && w[1] == "1-65535"));
        assert!(device
            .windows(2)
            .any(|w| w[0] == "--top-ports" && w[1] == "1000"));
        assert_ne!(discovery, device);
    }

    #[test]
    fn standard_scan_semantics_merge_ports() {
        let cfg = NmapConfig::default();
        let semantics =
            cfg.scan_semantics_for_intensity("192.168.50.0/24", ScanIntensity::Standard);
        assert_eq!(semantics.port_strategy, PortMergeStrategy::Merge);
        assert!(semantics.os_scan);
    }

    #[test]
    fn aggressive_subnet_scan_semantics_merge_ports() {
        let cfg = NmapConfig::default();
        let semantics =
            cfg.scan_semantics_for_intensity("192.168.50.0/24", ScanIntensity::Aggressive);
        assert_eq!(semantics.port_strategy, PortMergeStrategy::Merge);
        assert!(semantics.os_scan);
    }

    #[test]
    fn aggressive_single_host_scan_semantics_replace_ports() {
        let cfg = NmapConfig::default();
        let semantics =
            cfg.scan_semantics_for_intensity("192.168.50.103/32", ScanIntensity::Aggressive);
        assert_eq!(semantics.port_strategy, PortMergeStrategy::Replace);
        assert!(semantics.os_scan);
    }

    #[test]
    fn autodetect_helper_always_returns_a_cidr_like_string() {
        let cidr = auto_detect_local_cidr_or_default();
        assert!(cidr.contains('/'));
    }
}
