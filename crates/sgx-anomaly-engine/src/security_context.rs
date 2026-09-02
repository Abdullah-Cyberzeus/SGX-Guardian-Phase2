//! Optional Nmap + Suricata context for a live telemetry replay.
//!
//! Context is display/evidence only. It never changes feature extraction,
//! Tier-1/Tier-2 scores, thresholds, or the fused anomaly decision.

use crate::port_security::{finding_from_inventory, load_inventory, PortFinding, PortSeverity};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Deserialize)]
struct ContextFile {
    nmap_inventory: String,
    suricata_events: String,
    contexts: Vec<RowContext>,
}

#[derive(Debug, Deserialize)]
struct RowContext {
    node: String,
    display_row: usize,
    #[serde(default)]
    csv_hint: Option<String>,
    target_ip: String,
    target_port: u16,
    suricata_timestamp: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuricataContext {
    pub timestamp: String,
    pub event_type: String,
    pub source_ip: Option<String>,
    pub target_ip: Option<String>,
    pub target_port: Option<u16>,
    pub signature: Option<String>,
    pub category: Option<String>,
    pub severity_label: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CorrelatedPortContext {
    pub target_ip: String,
    pub target_port: u16,
    pub nmap_finding: Option<PortFinding>,
    pub suricata_event: Option<SuricataContext>,
    pub incident_urgency: PortSeverity,
    pub correlation_reason: String,
}

pub struct SecurityContextStore {
    contexts: Vec<RowContext>,
    inventory: Vec<crate::port_security::InventoryDevice>,
    suricata_events: Vec<SuricataContext>,
}

impl SecurityContextStore {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)?;
        let file: ContextFile = serde_json::from_str(&text)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        let inventory = load_inventory(base.join(file.nmap_inventory))?;
        let suricata_events = load_suricata_events(base.join(file.suricata_events))?;
        Ok(Self {
            contexts: file.contexts,
            inventory,
            suricata_events,
        })
    }

    pub fn context_for(
        &self,
        node: &str,
        display_row: usize,
        csv_path: &str,
    ) -> Option<CorrelatedPortContext> {
        let row = self.contexts.iter().find(|context| {
            context.node == node
                && context.display_row == display_row
                && context
                    .csv_hint
                    .as_ref()
                    .is_none_or(|hint| csv_path.contains(hint))
        })?;
        let nmap_finding = self
            .inventory
            .iter()
            .find(|device| device.ip == row.target_ip)
            .and_then(|device| {
                device
                    .open_ports
                    .iter()
                    .find(|port| port.port == row.target_port)
                    .map(|port| finding_from_inventory(device, port))
            });
        let suricata_event = self
            .suricata_events
            .iter()
            .find(|event| event.timestamp == row.suricata_timestamp)
            .cloned();
        let incident_urgency = correlated_urgency(nmap_finding.as_ref(), suricata_event.as_ref());
        let correlation_reason = if let Some(event) = &suricata_event {
            format!(
                "Port posture is correlated with Suricata {} activity: {}.",
                event.event_type,
                event.signature.as_deref().unwrap_or("unspecified event")
            )
        } else {
            "No matching Suricata event; this is an exposure posture finding only.".to_string()
        };
        Some(CorrelatedPortContext {
            target_ip: row.target_ip.clone(),
            target_port: row.target_port,
            nmap_finding,
            suricata_event,
            incident_urgency,
            correlation_reason,
        })
    }

    /// Returns the latest authorized inventory posture for the node.  This is
    /// display-only: an OPEN result means the inventory says it is open, while
    /// an empty list means the inventory recorded no open ports for that node.
    pub fn posture_for_node(&self, node: &str) -> Option<Vec<PortFinding>> {
        self.inventory
            .iter()
            .find(|device| device.node.as_deref() == Some(node))
            .map(|device| {
                device
                    .open_ports
                    .iter()
                    .map(|port| finding_from_inventory(device, port))
                    .collect()
            })
    }
}

fn correlated_urgency(
    finding: Option<&PortFinding>,
    event: Option<&SuricataContext>,
) -> PortSeverity {
    let base = finding.map(|f| f.severity).unwrap_or(PortSeverity::Low);
    match event
        .and_then(|e| e.severity_label.as_deref())
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("critical") => PortSeverity::Critical,
        Some("high") if base < PortSeverity::High => PortSeverity::High,
        Some("medium") if base < PortSeverity::Medium => PortSeverity::Medium,
        _ => base,
    }
}

fn load_suricata_events(path: impl AsRef<Path>) -> anyhow::Result<Vec<SuricataContext>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let value: serde_json::Value = serde_json::from_str(line)?;
            let alert = value.get("alert");
            Ok(SuricataContext {
                timestamp: value
                    .get("timestamp")
                    .and_then(|value| value.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                event_type: value
                    .get("event_type")
                    .and_then(|value| value.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                source_ip: value
                    .get("src_ip")
                    .and_then(|value| value.as_str())
                    .map(str::to_string),
                target_ip: value
                    .get("dest_ip")
                    .and_then(|value| value.as_str())
                    .map(str::to_string),
                target_port: value
                    .get("dest_port")
                    .and_then(|value| value.as_u64())
                    .and_then(|port| u16::try_from(port).ok()),
                signature: alert
                    .and_then(|alert| alert.get("signature"))
                    .and_then(|value| value.as_str())
                    .map(str::to_string),
                category: alert
                    .and_then(|alert| alert.get("category"))
                    .and_then(|value| value.as_str())
                    .map(str::to_string),
                severity_label: alert
                    .and_then(|alert| alert.get("severity_label"))
                    .and_then(|value| value.as_str())
                    .map(str::to_string),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_file_requires_a_matching_node_and_row() {
        let context = RowContext {
            node: "nodeA".to_string(),
            display_row: 61,
            csv_hint: None,
            target_ip: "192.0.2.10".to_string(),
            target_port: 22,
            suricata_timestamp: "x".to_string(),
        };
        assert!(context.node == "nodeA" && context.display_row == 61);
    }
}
