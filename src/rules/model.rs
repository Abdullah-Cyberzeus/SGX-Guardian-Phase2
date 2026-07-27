use crate::did::document::Proof;
use crate::discovery::{ConnectedDevice, DeviceStatus};
use crate::threat::threat_alert::{Severity as ThreatSeverity, ThreatAlert};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub const DEFAULT_COOLDOWN_SECS: u64 = 300;
pub const DEFAULT_MAX_ACTIONS_PER_HOUR: u32 = 20;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RuleTrigger {
    ThreatAlert,
    DeviceDiscovered,
    DeviceUnauthorized,
    GeofenceEntry,
    GeofenceExit,
    AttestationFailed,
    CrlRevocation,
}

impl Default for RuleTrigger {
    fn default() -> Self {
        Self::ThreatAlert
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Condition {
    SeverityAtLeast(String),
    CategoryIs(String),
    SignatureIdIn(Vec<u32>),
    SrcIpInCidr(String),
    PortIn(Vec<u16>),
    DeviceStatusIs(String),
    ZoneIs(String),
    All(Vec<Condition>),
    Any(Vec<Condition>),
    Not(Box<Condition>),
}

impl Default for Condition {
    fn default() -> Self {
        Self::All(Vec::new())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleAction {
    RaiseAlert { severity: String },
    Notify { severity: String },
    BlockIp { ttl_secs: Option<u64> },
    RunScan { intensity: String },
    RevokeDid,
    LockTransport,
    EmergencyKeyRotation,
}

impl RuleAction {
    pub fn label(&self) -> String {
        match self {
            Self::RaiseAlert { severity } => format!("RaiseAlert({})", severity),
            Self::Notify { severity } => format!("Notify({})", severity),
            Self::BlockIp { ttl_secs } => match ttl_secs {
                Some(ttl) => format!("BlockIp(ttl={}s)", ttl),
                None => "BlockIp".to_string(),
            },
            Self::RunScan { intensity } => format!("RunScan({})", intensity),
            Self::RevokeDid => "RevokeDid".to_string(),
            Self::LockTransport => "LockTransport".to_string(),
            Self::EmergencyKeyRotation => "EmergencyKeyRotation".to_string(),
        }
    }

    pub fn destructive(&self) -> bool {
        matches!(
            self,
            Self::RevokeDid | Self::LockTransport | Self::EmergencyKeyRotation
        )
    }
}

fn default_enabled() -> bool {
    true
}

fn default_actions() -> Vec<RuleAction> {
    vec![RuleAction::RaiseAlert {
        severity: "high".to_string(),
    }]
}

fn default_cooldown_secs() -> u64 {
    DEFAULT_COOLDOWN_SECS
}

fn default_max_actions_per_hour() -> u32 {
    DEFAULT_MAX_ACTIONS_PER_HOUR
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    pub rule_id: String,
    pub name: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub trigger: RuleTrigger,
    #[serde(default)]
    pub condition: Condition,
    #[serde(default = "default_actions")]
    pub actions: Vec<RuleAction>,
    #[serde(default)]
    pub notify: bool,
    #[serde(default)]
    pub allow_destructive: bool,
    #[serde(default = "default_cooldown_secs")]
    pub cooldown_secs: u64,
    #[serde(default = "default_max_actions_per_hour")]
    pub max_actions_per_hour: u32,
    pub created_at: String,
    pub updated_at: String,
}

impl Rule {
    pub fn from_draft(draft: RuleDraft) -> Self {
        let now = Utc::now().to_rfc3339();
        let actions = draft
            .actions
            .filter(|actions| !actions.is_empty())
            .unwrap_or_else(default_actions);
        Self {
            rule_id: draft
                .rule_id
                .unwrap_or_else(|| format!("urn:uuid:{}", Uuid::new_v4())),
            name: draft.name.unwrap_or_else(|| "Untitled rule".to_string()),
            enabled: draft.enabled.unwrap_or(true),
            trigger: draft.trigger.unwrap_or_default(),
            condition: draft.condition.unwrap_or_default(),
            actions,
            notify: draft.notify.unwrap_or(false),
            allow_destructive: draft.allow_destructive.unwrap_or(false),
            cooldown_secs: draft.cooldown_secs.unwrap_or(DEFAULT_COOLDOWN_SECS),
            max_actions_per_hour: draft
                .max_actions_per_hour
                .unwrap_or(DEFAULT_MAX_ACTIONS_PER_HOUR),
            created_at: now.clone(),
            updated_at: now,
        }
    }

    pub fn apply_patch(&mut self, patch: RulePatch) {
        if let Some(name) = patch.name {
            self.name = name;
        }
        if let Some(enabled) = patch.enabled {
            self.enabled = enabled;
        }
        if let Some(trigger) = patch.trigger {
            self.trigger = trigger;
        }
        if let Some(condition) = patch.condition {
            self.condition = condition;
        }
        if let Some(actions) = patch.actions {
            self.actions = if actions.is_empty() {
                default_actions()
            } else {
                actions
            };
        }
        if let Some(notify) = patch.notify {
            self.notify = notify;
        }
        if let Some(allow_destructive) = patch.allow_destructive {
            self.allow_destructive = allow_destructive;
        }
        if let Some(cooldown_secs) = patch.cooldown_secs {
            self.cooldown_secs = cooldown_secs;
        }
        if let Some(max_actions_per_hour) = patch.max_actions_per_hour {
            self.max_actions_per_hour = max_actions_per_hour;
        }
        self.updated_at = Utc::now().to_rfc3339();
    }

    pub fn effective_actions(&self) -> Vec<RuleAction> {
        let mut actions = if self.actions.is_empty() {
            default_actions()
        } else {
            self.actions.clone()
        };
        if self.notify
            && !actions
                .iter()
                .any(|action| matches!(action, RuleAction::Notify { .. }))
        {
            actions.push(RuleAction::Notify {
                severity: "info".to_string(),
            });
        }
        actions
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuleDraft {
    pub rule_id: Option<String>,
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub trigger: Option<RuleTrigger>,
    pub condition: Option<Condition>,
    pub actions: Option<Vec<RuleAction>>,
    pub notify: Option<bool>,
    pub allow_destructive: Option<bool>,
    pub cooldown_secs: Option<u64>,
    pub max_actions_per_hour: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RulePatch {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub trigger: Option<RuleTrigger>,
    pub condition: Option<Condition>,
    pub actions: Option<Vec<RuleAction>>,
    pub notify: Option<bool>,
    pub allow_destructive: Option<bool>,
    pub cooldown_secs: Option<u64>,
    pub max_actions_per_hour: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleRegistry {
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub sequence: u64,
    #[serde(default)]
    pub proof: Proof,
}

impl RuleRegistry {
    pub fn without_proof(&self) -> Self {
        let mut clone = self.clone();
        clone.proof = Proof::default();
        clone
    }

    pub fn canonical_bytes_for_sign(&self) -> crate::rules::RulesResult<Vec<u8>> {
        let value = serde_json::to_value(self.without_proof())?;
        let sorted = sort_value(&value);
        Ok(serde_json::to_vec(&sorted)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleExecution {
    pub id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub trigger_summary: String,
    pub actions: Vec<String>,
    pub outcome: String,
    pub at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum RuleEvent {
    ThreatAlert {
        node_id: String,
        alert: ThreatAlert,
    },
    DeviceDiscovered {
        node_id: String,
        device_id: String,
        ip: String,
        status: String,
        ports: Vec<u16>,
        zone: Option<String>,
    },
    DeviceUnauthorized {
        node_id: String,
        device_id: String,
        ip: String,
        status: String,
        ports: Vec<u16>,
        zone: Option<String>,
    },
    GeofenceEntry {
        node_id: String,
        device_id: String,
        zone: String,
    },
    GeofenceExit {
        node_id: String,
        device_id: String,
        zone: String,
    },
    AttestationFailed {
        node_id: String,
        peer: String,
        did: Option<String>,
        reason: String,
        severity: String,
    },
    CrlRevocation {
        node_id: String,
        revoked_did: String,
        reason: String,
        severity: String,
    },
}

impl RuleEvent {
    pub fn from_threat_alert(node_id: &str, alert: &ThreatAlert) -> Self {
        Self::ThreatAlert {
            node_id: node_id.to_string(),
            alert: alert.clone(),
        }
    }

    pub fn from_device_discovered(node_id: &str, device: &ConnectedDevice) -> Self {
        Self::DeviceDiscovered {
            node_id: node_id.to_string(),
            device_id: device.device_id.clone(),
            ip: device.ip.clone(),
            status: device_status_name(device.status).to_string(),
            ports: device.open_ports.iter().map(|port| port.port).collect(),
            zone: None,
        }
    }

    pub fn from_device_unauthorized(node_id: &str, device: &ConnectedDevice) -> Self {
        Self::DeviceUnauthorized {
            node_id: node_id.to_string(),
            device_id: device.device_id.clone(),
            ip: device.ip.clone(),
            status: device_status_name(device.status).to_string(),
            ports: device.open_ports.iter().map(|port| port.port).collect(),
            zone: None,
        }
    }

    pub fn trigger(&self) -> RuleTrigger {
        match self {
            Self::ThreatAlert { .. } => RuleTrigger::ThreatAlert,
            Self::DeviceDiscovered { .. } => RuleTrigger::DeviceDiscovered,
            Self::DeviceUnauthorized { .. } => RuleTrigger::DeviceUnauthorized,
            Self::GeofenceEntry { .. } => RuleTrigger::GeofenceEntry,
            Self::GeofenceExit { .. } => RuleTrigger::GeofenceExit,
            Self::AttestationFailed { .. } => RuleTrigger::AttestationFailed,
            Self::CrlRevocation { .. } => RuleTrigger::CrlRevocation,
        }
    }

    pub fn target_key(&self) -> String {
        match self {
            Self::ThreatAlert { alert, .. } => alert.src_ip.clone(),
            Self::DeviceDiscovered { device_id, ip, .. }
            | Self::DeviceUnauthorized { device_id, ip, .. } => {
                if device_id.trim().is_empty() {
                    ip.clone()
                } else {
                    device_id.clone()
                }
            }
            Self::GeofenceEntry {
                device_id, zone, ..
            }
            | Self::GeofenceExit {
                device_id, zone, ..
            } => format!("{}:{}", device_id, zone),
            Self::AttestationFailed { did, peer, .. } => {
                did.clone().unwrap_or_else(|| peer.clone())
            }
            Self::CrlRevocation { revoked_did, .. } => revoked_did.clone(),
        }
    }

    pub fn summary(&self) -> String {
        match self {
            Self::ThreatAlert { alert, .. } => format!(
                "ThreatAlert sid={} sev={} src={} dst={}",
                alert.signature_id,
                alert.severity.as_str(),
                alert.src_ip,
                alert.dst_ip
            ),
            Self::DeviceDiscovered {
                device_id,
                ip,
                status,
                ..
            } => format!(
                "DeviceDiscovered id={} ip={} status={}",
                device_id, ip, status
            ),
            Self::DeviceUnauthorized {
                device_id,
                ip,
                status,
                ..
            } => format!(
                "DeviceUnauthorized id={} ip={} status={}",
                device_id, ip, status
            ),
            Self::GeofenceEntry {
                device_id, zone, ..
            } => {
                format!("GeofenceEntry id={} zone={}", device_id, zone)
            }
            Self::GeofenceExit {
                device_id, zone, ..
            } => {
                format!("GeofenceExit id={} zone={}", device_id, zone)
            }
            Self::AttestationFailed {
                peer,
                did,
                reason,
                severity,
                ..
            } => format!(
                "AttestationFailed peer={} did={} sev={} reason={}",
                peer,
                did.as_deref().unwrap_or(""),
                severity,
                reason
            ),
            Self::CrlRevocation {
                revoked_did,
                reason,
                severity,
                ..
            } => format!(
                "CrlRevocation did={} sev={} reason={}",
                revoked_did, severity, reason
            ),
        }
    }

    pub fn src_ip(&self) -> Option<&str> {
        match self {
            Self::ThreatAlert { alert, .. } => Some(&alert.src_ip),
            Self::DeviceDiscovered { ip, .. } | Self::DeviceUnauthorized { ip, .. } => Some(ip),
            _ => None,
        }
    }

    pub fn ports(&self) -> Vec<u16> {
        match self {
            Self::ThreatAlert { alert, .. } => vec![alert.src_port, alert.dst_port],
            Self::DeviceDiscovered { ports, .. } | Self::DeviceUnauthorized { ports, .. } => {
                ports.clone()
            }
            _ => Vec::new(),
        }
    }

    pub fn severity_name(&self) -> Option<&str> {
        match self {
            Self::ThreatAlert { alert, .. } => Some(alert.severity.as_str()),
            Self::AttestationFailed { severity, .. } | Self::CrlRevocation { severity, .. } => {
                Some(severity)
            }
            _ => None,
        }
    }

    pub fn category_name(&self) -> Option<&str> {
        match self {
            Self::ThreatAlert { alert, .. } => Some(alert.category.as_str()),
            Self::CrlRevocation { reason, .. } => Some(reason),
            Self::AttestationFailed { reason, .. } => Some(reason),
            _ => None,
        }
    }

    pub fn signature_id(&self) -> Option<u32> {
        match self {
            Self::ThreatAlert { alert, .. } => Some(alert.signature_id),
            _ => None,
        }
    }

    pub fn device_status(&self) -> Option<&str> {
        match self {
            Self::DeviceDiscovered { status, .. } | Self::DeviceUnauthorized { status, .. } => {
                Some(status)
            }
            _ => None,
        }
    }

    pub fn zone(&self) -> Option<&str> {
        match self {
            Self::DeviceDiscovered { zone, .. } | Self::DeviceUnauthorized { zone, .. } => {
                zone.as_deref()
            }
            Self::GeofenceEntry { zone, .. } | Self::GeofenceExit { zone, .. } => Some(zone),
            _ => None,
        }
    }

    pub fn target_did(&self) -> Option<&str> {
        match self {
            Self::AttestationFailed { did, .. } => did.as_deref(),
            Self::CrlRevocation { revoked_did, .. } => Some(revoked_did),
            _ => None,
        }
    }

    pub fn sample_threat(node_id: &str) -> Self {
        let alert = ThreatAlert {
            alert_id: ThreatAlert::compute_id(9_999_001, "203.0.113.55", "198.51.100.10"),
            timestamp: Utc::now(),
            src_ip: "203.0.113.55".to_string(),
            src_port: 44_444,
            dst_ip: "198.51.100.10".to_string(),
            dst_port: 443,
            protocol: "TCP".to_string(),
            signature_id: 9_999_001,
            signature: "Rules engine dry-run sample".to_string(),
            category: crate::threat::threat_alert::ThreatCategory::PolicyViolation,
            severity: ThreatSeverity::High,
            rev: 1,
            gid: 1,
            event_type: "alert".to_string(),
            blocked: false,
        };
        Self::from_threat_alert(node_id, &alert)
    }
}

fn device_status_name(status: DeviceStatus) -> &'static str {
    match status {
        DeviceStatus::Approved => "approved",
        DeviceStatus::Unauthorized => "unauthorized",
        DeviceStatus::Drifted => "drifted",
        DeviceStatus::Stale => "stale",
    }
}

fn sort_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted = serde_json::Map::new();
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort();
            for key in keys {
                sorted.insert(key.clone(), sort_value(&map[key]));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_value).collect()),
        _ => value.clone(),
    }
}
