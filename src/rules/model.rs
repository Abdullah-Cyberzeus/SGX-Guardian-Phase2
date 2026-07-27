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

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn rule_action_label_formats_variants() {
        assert_eq!(
            RuleAction::RaiseAlert { severity: "high".to_string() }.label(),
            "RaiseAlert(high)"
        );
        assert_eq!(
            RuleAction::BlockIp { ttl_secs: Some(60) }.label(),
            "BlockIp(ttl=60s)"
        );
        assert_eq!(RuleAction::BlockIp { ttl_secs: None }.label(), "BlockIp");
        assert_eq!(RuleAction::RevokeDid.label(), "RevokeDid");
    }

    #[test]
    fn rule_action_destructive_flags_only_high_impact_actions() {
        assert!(RuleAction::RevokeDid.destructive());
        assert!(RuleAction::LockTransport.destructive());
        assert!(RuleAction::EmergencyKeyRotation.destructive());
        assert!(!RuleAction::RaiseAlert { severity: "low".to_string() }.destructive());
        assert!(!RuleAction::Notify { severity: "low".to_string() }.destructive());
    }

    #[test]
    fn rule_from_draft_applies_defaults_when_fields_absent() {
        let rule = Rule::from_draft(RuleDraft::default());
        assert!(rule.enabled);
        assert_eq!(rule.trigger, RuleTrigger::ThreatAlert);
        assert_eq!(rule.condition, Condition::All(Vec::new()));
        assert_eq!(rule.actions, default_actions());
        assert!(!rule.notify);
        assert!(!rule.allow_destructive);
        assert_eq!(rule.cooldown_secs, DEFAULT_COOLDOWN_SECS);
        assert_eq!(rule.max_actions_per_hour, DEFAULT_MAX_ACTIONS_PER_HOUR);
        assert_eq!(rule.name, "Untitled rule");
    }

    #[test]
    fn rule_from_draft_empty_actions_falls_back_to_default() {
        let rule = Rule::from_draft(RuleDraft {
            actions: Some(Vec::new()),
            ..RuleDraft::default()
        });
        assert_eq!(rule.actions, default_actions());
    }

    #[test]
    fn rule_apply_patch_updates_only_provided_fields() {
        let mut rule = Rule::from_draft(RuleDraft::default());
        let original_created_at = rule.created_at.clone();

        rule.apply_patch(RulePatch {
            name: Some("Renamed".to_string()),
            cooldown_secs: Some(42),
            ..RulePatch::default()
        });

        assert_eq!(rule.name, "Renamed");
        assert_eq!(rule.cooldown_secs, 42);
        // Untouched fields keep their defaults.
        assert!(rule.enabled);
        assert_eq!(rule.trigger, RuleTrigger::ThreatAlert);
        assert_eq!(rule.created_at, original_created_at);
    }

    #[test]
    fn rule_apply_patch_empty_actions_falls_back_to_default() {
        let mut rule = Rule::from_draft(RuleDraft::default());
        rule.apply_patch(RulePatch {
            actions: Some(Vec::new()),
            ..RulePatch::default()
        });
        assert_eq!(rule.actions, default_actions());
    }

    #[test]
    fn rule_effective_actions_appends_notify_when_requested_but_absent() {
        let mut rule = Rule::from_draft(RuleDraft::default());
        rule.notify = true;
        let actions = rule.effective_actions();
        assert!(actions
            .iter()
            .any(|action| matches!(action, RuleAction::Notify { .. })));

        // If a Notify action is already present, it must not be duplicated.
        rule.actions.push(RuleAction::Notify {
            severity: "high".to_string(),
        });
        let actions = rule.effective_actions();
        let notify_count = actions
            .iter()
            .filter(|action| matches!(action, RuleAction::Notify { .. }))
            .count();
        assert_eq!(notify_count, 1);
    }

    #[test]
    fn rule_registry_without_proof_clears_proof_but_keeps_rules() {
        let mut registry = RuleRegistry {
            rules: vec![Rule::from_draft(RuleDraft::default())],
            sequence: 3,
            proof: Proof {
                verification_method: "did:guardian:owner#dkp-v1".to_string(),
                proof_value: "sig".to_string(),
                ..Proof::default()
            },
        };
        let cleared = registry.without_proof();
        assert_eq!(cleared.proof, Proof::default());
        assert_eq!(cleared.rules.len(), registry.rules.len());
        assert_eq!(cleared.sequence, registry.sequence);
        registry.proof = Proof::default();
    }

    #[test]
    fn rule_registry_canonical_bytes_ignore_proof_but_detect_field_changes() {
        let mut registry = RuleRegistry {
            rules: vec![Rule::from_draft(RuleDraft::default())],
            sequence: 1,
            proof: Proof::default(),
        };
        let baseline = registry.canonical_bytes_for_sign().expect("canonical");
        registry.proof = Proof {
            verification_method: "did:guardian:owner#dkp-v1".to_string(),
            proof_value: "sig".to_string(),
            ..Proof::default()
        };
        assert_eq!(baseline, registry.canonical_bytes_for_sign().expect("canonical"));

        registry.sequence = 2;
        assert_ne!(baseline, registry.canonical_bytes_for_sign().expect("canonical"));
    }

    #[test]
    fn rule_event_accessors_for_threat_alert() {
        let event = RuleEvent::sample_threat("nodeA");
        assert_eq!(event.trigger(), RuleTrigger::ThreatAlert);
        assert_eq!(event.target_key(), "203.0.113.55");
        assert_eq!(event.src_ip(), Some("203.0.113.55"));
        assert_eq!(event.ports(), vec![44_444, 443]);
        assert_eq!(event.severity_name(), Some("high"));
        assert_eq!(event.signature_id(), Some(9_999_001));
        assert!(event.device_status().is_none());
        assert!(event.zone().is_none());
        assert!(event.target_did().is_none());
        assert!(event.summary().starts_with("ThreatAlert"));
    }

    #[test]
    fn rule_event_accessors_for_device_discovered_uses_ip_when_device_id_blank() {
        let event = RuleEvent::DeviceDiscovered {
            node_id: "nodeA".to_string(),
            device_id: "".to_string(),
            ip: "192.168.1.20".to_string(),
            status: "unauthorized".to_string(),
            ports: vec![22, 80],
            zone: Some("warehouse".to_string()),
        };
        assert_eq!(event.trigger(), RuleTrigger::DeviceDiscovered);
        assert_eq!(event.target_key(), "192.168.1.20");
        assert_eq!(event.ports(), vec![22, 80]);
        assert_eq!(event.device_status(), Some("unauthorized"));
        assert_eq!(event.zone(), Some("warehouse"));
        assert!(event.severity_name().is_none());
    }

    #[test]
    fn rule_event_accessors_for_geofence_and_crl_revocation() {
        let entry = RuleEvent::GeofenceEntry {
            node_id: "nodeA".to_string(),
            device_id: "dev-1".to_string(),
            zone: "warehouse".to_string(),
        };
        assert_eq!(entry.target_key(), "dev-1:warehouse");
        assert_eq!(entry.zone(), Some("warehouse"));
        assert!(entry.summary().contains("GeofenceEntry"));

        let revocation = RuleEvent::CrlRevocation {
            node_id: "nodeA".to_string(),
            revoked_did: "did:guardian:revoked".to_string(),
            reason: "key_compromise".to_string(),
            severity: "critical".to_string(),
        };
        assert_eq!(revocation.target_key(), "did:guardian:revoked");
        assert_eq!(revocation.target_did(), Some("did:guardian:revoked"));
        assert_eq!(revocation.category_name(), Some("key_compromise"));
        assert_eq!(revocation.severity_name(), Some("critical"));
    }

    #[test]
    fn device_status_name_maps_every_variant() {
        assert_eq!(device_status_name(DeviceStatus::Approved), "approved");
        assert_eq!(device_status_name(DeviceStatus::Unauthorized), "unauthorized");
        assert_eq!(device_status_name(DeviceStatus::Drifted), "drifted");
        assert_eq!(device_status_name(DeviceStatus::Stale), "stale");
    }

    #[test]
    fn sort_value_orders_object_keys_recursively() {
        let value: Value = serde_json::json!({
            "b": 1,
            "a": {"z": 1, "y": 2},
            "c": [{"b": 1, "a": 2}]
        });
        let sorted = sort_value(&value);
        let rendered = serde_json::to_string(&sorted).unwrap();
        assert_eq!(rendered, r#"{"a":{"y":2,"z":1},"b":1,"c":[{"a":2,"b":1}]}"#);
    }
}
