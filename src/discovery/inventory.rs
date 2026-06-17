use crate::discovery::{
    config::{PortMergeStrategy, ScanSemantics},
    connected_device::{ConnectedDevice, DeviceStatus, OpenPort},
    error::DiscoveryResult,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

const STALE_AFTER_MISSED_SCANS: u8 = 3;

#[derive(Debug, Clone, Default)]
pub struct Inventory {
    pub by_id: HashMap<String, ConnectedDevice>,
    missed_scans: HashMap<String, u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InventoryDelta {
    pub newly_seen: Vec<String>,
    pub updated: Vec<String>,
    pub marked_stale: Vec<String>,
}

impl Inventory {
    pub fn load(path: &Path) -> DiscoveryResult<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let bytes = std::fs::read(path)?;
        if bytes.is_empty() {
            return Ok(Self::default());
        }

        let devices: Vec<ConnectedDevice> = serde_json::from_slice(&bytes)?;
        let mut by_id = HashMap::with_capacity(devices.len());
        for dev in devices {
            by_id.insert(dev.device_id.clone(), dev);
        }

        Ok(Self {
            by_id,
            missed_scans: HashMap::new(),
        })
    }

    pub fn merge(
        &mut self,
        freshly_seen: Vec<ConnectedDevice>,
        semantics: ScanSemantics,
    ) -> InventoryDelta {
        let mut delta = InventoryDelta::default();
        let mut seen_ids: HashSet<String> = HashSet::with_capacity(freshly_seen.len());

        for mut new_dev in freshly_seen {
            let id = self
                .find_existing_id(&new_dev)
                .unwrap_or_else(|| new_dev.device_id.clone());
            seen_ids.insert(id.clone());
            self.missed_scans.remove(&id);

            match self.by_id.get_mut(&id) {
                Some(existing) => {
                    merge_device(existing, &new_dev, semantics);
                    delta.updated.push(id);
                }
                None => {
                    new_dev.device_id = id.clone();
                    delta.newly_seen.push(id.clone());
                    self.by_id.insert(id, new_dev);
                }
            }
        }

        let all_ids: Vec<String> = self.by_id.keys().cloned().collect();
        for id in all_ids {
            if seen_ids.contains(&id) {
                continue;
            }

            let missed = self.missed_scans.entry(id.clone()).or_insert(0);
            *missed = missed.saturating_add(1);

            if *missed >= STALE_AFTER_MISSED_SCANS {
                if let Some(dev) = self.by_id.get_mut(&id) {
                    if dev.status != DeviceStatus::Stale {
                        dev.status = DeviceStatus::Stale;
                        delta.marked_stale.push(id);
                    }
                }
            }
        }

        delta
    }

    fn find_existing_id(&self, new_dev: &ConnectedDevice) -> Option<String> {
        if let Some(new_mac) = normalized_mac(new_dev.mac.as_deref()) {
            if let Some((id, _)) = self.by_id.iter().find(|(_, existing)| {
                normalized_mac(existing.mac.as_deref()) == Some(new_mac.clone())
            }) {
                return Some(id.clone());
            }
        }

        self.by_id.iter().find_map(|(id, existing)| {
            if existing.ip != new_dev.ip {
                return None;
            }

            let existing_mac = normalized_mac(existing.mac.as_deref());
            let new_mac = normalized_mac(new_dev.mac.as_deref());
            if existing_mac.is_some() && new_mac.is_some() && existing_mac != new_mac {
                return None;
            }

            Some(id.clone())
        })
    }

    /// Atomic write: write to .tmp + fsync + rename.
    pub fn save_atomic(&self, path: &Path) -> DiscoveryResult<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let tmp = path.with_extension("json.tmp");
        let mut devices: Vec<&ConnectedDevice> = self.by_id.values().collect();
        devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        let bytes = serde_json::to_vec_pretty(&devices)?;

        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }

        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

fn merge_device(
    existing: &mut ConnectedDevice,
    new_dev: &ConnectedDevice,
    semantics: ScanSemantics,
) {
    existing.last_seen = new_dev.last_seen.clone();
    let mut attack_surface_changed = false;

    if !new_dev.ip.is_empty() {
        existing.ip = new_dev.ip.clone();
    }

    if let Some(new_mac) = normalized_mac(new_dev.mac.as_deref()) {
        existing.mac = Some(new_mac);
    }

    if let Some(new_vendor) = new_dev.vendor.as_deref() {
        let should_replace = match existing.vendor.as_deref() {
            None => true,
            Some(old_vendor) => !is_alias_vendor(new_vendor) || is_alias_vendor(old_vendor),
        };
        if should_replace && !new_vendor.is_empty() {
            existing.vendor = Some(new_vendor.to_string());
        }
    }

    if let Some(new_hostname) = new_dev.hostname.as_deref() {
        if !new_hostname.is_empty() {
            existing.hostname = Some(new_hostname.to_string());
        }
    }

    if semantics.os_scan {
        if let Some(new_os) = new_dev.os_fingerprint.as_deref() {
            if !new_os.is_empty() {
                if existing.os_fingerprint.as_deref() != Some(new_os) {
                    attack_surface_changed = true;
                }
                existing.os_fingerprint = Some(new_os.to_string());
            }
        }
        // OS CPE rides with OS detection; only overwrite when this scan found some,
        // so a later Stealth scan can't wipe a previous OS-scan's enrichment.
        if !new_dev.os_cpe.is_empty() {
            existing.os_cpe = new_dev.os_cpe.clone();
        }
    }

    // Host-level NSE output: on a script-running scan it is the *current* truth,
    // so replace wholesale (even with an empty set) to clear resolved findings.
    // A non-script scan (Stealth/Standard) must never wipe the last rich result.
    if semantics.runs_scripts || !new_dev.host_scripts.is_empty() {
        existing.host_scripts = new_dev.host_scripts.clone();
    }

    if merge_ports(
        &mut existing.open_ports,
        &new_dev.open_ports,
        semantics.port_strategy,
        semantics.runs_scripts,
    ) {
        attack_surface_changed = true;
    }

    existing.vuln_triaged = if attack_surface_changed {
        false
    } else {
        existing.vuln_triaged || new_dev.vuln_triaged
    };
}

fn normalized_mac(mac: Option<&str>) -> Option<String> {
    mac.map(str::trim)
        .filter(|m| !m.is_empty())
        .map(|m| m.to_uppercase())
}

fn is_alias_vendor(vendor: &str) -> bool {
    vendor.starts_with("(mac_aliased to ")
}

fn merge_ports(
    existing: &mut Vec<OpenPort>,
    new_ports: &[OpenPort],
    strategy: PortMergeStrategy,
    runs_scripts: bool,
) -> bool {
    match strategy {
        PortMergeStrategy::Preserve => false,
        PortMergeStrategy::Replace => {
            let changed = *existing != new_ports;
            *existing = new_ports.to_vec();
            changed
        }
        PortMergeStrategy::Merge => {
            let before = existing.clone();
            let mut merged: BTreeMap<(u16, String), OpenPort> = existing
                .iter()
                .cloned()
                .map(|port| ((port.port, port.protocol.clone()), port))
                .collect();

            for new_port in new_ports {
                let key = (new_port.port, new_port.protocol.clone());
                match merged.get_mut(&key) {
                    Some(existing_port) => {
                        if let Some(service) = new_port.service.as_ref() {
                            if !service.is_empty() {
                                existing_port.service = Some(service.clone());
                            }
                        }
                        if let Some(product_version) = new_port.product_version.as_ref() {
                            if !product_version.is_empty() {
                                existing_port.product_version = Some(product_version.clone());
                            }
                        }
                        // CPE is stable identity enrichment -> preserve-on-empty.
                        if !new_port.cpe.is_empty() {
                            existing_port.cpe = new_port.cpe.clone();
                        }
                        // Scripts are volatile findings: on a script-running scan
                        // replace wholesale (even empty) so resolved vulns clear;
                        // otherwise keep the last rich result.
                        if runs_scripts || !new_port.scripts.is_empty() {
                            existing_port.scripts = new_port.scripts.clone();
                        }
                    }
                    None => {
                        merged.insert(key, new_port.clone());
                    }
                }
            }

            *existing = merged.into_values().collect();
            *existing != before
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Inventory;
    use crate::discovery::config::{PortMergeStrategy, ScanIntensity, ScanSemantics};
    use crate::discovery::connected_device::{
        ConnectedDevice, DeviceStatus, OpenPort, ScriptResult,
    };

    fn device(
        device_id: &str,
        ip: &str,
        mac: Option<&str>,
        vendor: Option<&str>,
        hostname: Option<&str>,
        os: Option<&str>,
        ports: &[(u16, &str)],
        first_seen: &str,
        last_seen: &str,
    ) -> ConnectedDevice {
        ConnectedDevice {
            device_id: device_id.to_string(),
            ip: ip.to_string(),
            mac: mac.map(str::to_string),
            vendor: vendor.map(str::to_string),
            hostname: hostname.map(str::to_string),
            os_fingerprint: os.map(str::to_string),
            os_cpe: Vec::new(),
            open_ports: ports
                .iter()
                .map(|(port, protocol)| OpenPort {
                    port: *port,
                    protocol: (*protocol).to_string(),
                    service: None,
                    product_version: None,
                    cpe: Vec::new(),
                    scripts: Vec::new(),
                })
                .collect(),
            host_scripts: Vec::new(),
            status: DeviceStatus::Unauthorized,
            first_seen: first_seen.to_string(),
            last_seen: last_seen.to_string(),
            vuln_triaged: false,
        }
    }

    #[test]
    fn stealth_merge_preserves_rich_fields() {
        let existing = device(
            "stable-id",
            "192.168.50.101",
            Some("AA:BB:CC:DD:EE:FF"),
            Some("VendorA"),
            Some("nodeA"),
            Some("Linux 6.x"),
            &[(22, "tcp"), (8443, "tcp")],
            "2026-06-01T00:00:00Z",
            "2026-06-01T00:00:00Z",
        );
        let fresh = device(
            "new-id",
            "192.168.50.103",
            Some("AA:BB:CC:DD:EE:FF"),
            None,
            None,
            None,
            &[],
            "2026-06-09T00:00:00Z",
            "2026-06-09T00:00:00Z",
        );

        let mut inventory = Inventory::default();
        inventory.by_id.insert(existing.device_id.clone(), existing);
        let delta = inventory.merge(
            vec![fresh],
            ScanSemantics::for_intensity(ScanIntensity::Stealth),
        );

        assert!(delta.newly_seen.is_empty());
        assert_eq!(delta.updated, vec!["stable-id".to_string()]);

        let merged = inventory.by_id.get("stable-id").unwrap();
        assert_eq!(merged.ip, "192.168.50.103");
        assert_eq!(merged.first_seen, "2026-06-01T00:00:00Z");
        assert_eq!(merged.last_seen, "2026-06-09T00:00:00Z");
        assert_eq!(merged.os_fingerprint.as_deref(), Some("Linux 6.x"));
        assert_eq!(merged.open_ports.len(), 2);
        assert_eq!(merged.hostname.as_deref(), Some("nodeA"));
        assert_eq!(merged.vendor.as_deref(), Some("VendorA"));
    }

    #[test]
    fn standard_merge_updates_enrichment_and_preserves_unseen_ports() {
        let existing = device(
            "stable-id",
            "192.168.50.101",
            Some("AA:BB:CC:DD:EE:FF"),
            Some("VendorA"),
            Some("old-host"),
            Some("Linux 5.x"),
            &[(22, "tcp"), (8443, "tcp")],
            "2026-06-01T00:00:00Z",
            "2026-06-01T00:00:00Z",
        );
        let fresh = device(
            "new-id",
            "192.168.50.101",
            Some("AA:BB:CC:DD:EE:FF"),
            Some("VendorB"),
            Some("new-host"),
            Some("Linux 6.x"),
            &[(443, "tcp")],
            "2026-06-09T00:00:00Z",
            "2026-06-09T00:00:00Z",
        );

        let mut inventory = Inventory::default();
        inventory.by_id.insert(existing.device_id.clone(), existing);
        inventory.merge(
            vec![fresh],
            ScanSemantics::for_intensity(ScanIntensity::Standard),
        );

        let merged = inventory.by_id.get("stable-id").unwrap();
        assert_eq!(merged.vendor.as_deref(), Some("VendorB"));
        assert_eq!(merged.hostname.as_deref(), Some("new-host"));
        assert_eq!(merged.os_fingerprint.as_deref(), Some("Linux 6.x"));
        assert_eq!(merged.open_ports.len(), 3);
        assert!(merged.open_ports.iter().any(|p| p.port == 22));
        assert!(merged.open_ports.iter().any(|p| p.port == 443));
        assert!(merged.open_ports.iter().any(|p| p.port == 8443));
    }

    #[test]
    fn merge_matches_existing_record_by_mac_when_ip_changes() {
        let existing = device(
            "stable-id",
            "192.168.50.101",
            Some("AA:BB:CC:DD:EE:FF"),
            Some("VendorA"),
            None,
            None,
            &[],
            "2026-06-01T00:00:00Z",
            "2026-06-01T00:00:00Z",
        );
        let fresh = device(
            "fresh-id",
            "192.168.50.115",
            Some("AA:BB:CC:DD:EE:FF"),
            None,
            None,
            None,
            &[],
            "2026-06-09T00:00:00Z",
            "2026-06-09T00:00:00Z",
        );

        let mut inventory = Inventory::default();
        inventory.by_id.insert(existing.device_id.clone(), existing);
        let delta = inventory.merge(
            vec![fresh],
            ScanSemantics::for_intensity(ScanIntensity::Stealth),
        );

        assert!(delta.newly_seen.is_empty());
        assert_eq!(inventory.by_id.len(), 1);
        assert_eq!(
            inventory.by_id.get("stable-id").unwrap().ip,
            "192.168.50.115"
        );
    }

    #[test]
    fn partial_port_scan_preserves_deeper_history() {
        let mut existing = device(
            "stable-id",
            "192.168.50.101",
            Some("AA:BB:CC:DD:EE:FF"),
            Some("VendorA"),
            Some("nodeA"),
            Some("Linux 6.x"),
            &[(22, "tcp"), (8443, "tcp")],
            "2026-06-01T00:00:00Z",
            "2026-06-01T00:00:00Z",
        );
        existing.vuln_triaged = true;

        let fresh = device(
            "new-id",
            "192.168.50.101",
            Some("AA:BB:CC:DD:EE:FF"),
            Some("VendorA"),
            Some("nodeA"),
            Some("Linux 6.x"),
            &[(22, "tcp")],
            "2026-06-09T00:00:00Z",
            "2026-06-09T00:00:00Z",
        );

        let mut inventory = Inventory::default();
        inventory.by_id.insert(existing.device_id.clone(), existing);
        inventory.merge(
            vec![fresh],
            ScanSemantics::for_intensity(ScanIntensity::Standard),
        );

        let merged = inventory.by_id.get("stable-id").unwrap();
        assert_eq!(merged.open_ports.len(), 2);
        assert!(merged.open_ports.iter().any(|p| p.port == 8443));
        assert!(merged.vuln_triaged);
    }

    fn script(id: &str, output: &str) -> ScriptResult {
        ScriptResult {
            id: id.to_string(),
            output: output.to_string(),
        }
    }

    /// Finding 2: a later script-running (Aggressive) scan that finds a host
    /// clean must clear stale script findings, while a non-script (Standard)
    /// scan must preserve the last rich result rather than wipe it.
    #[test]
    fn script_findings_clear_on_aggressive_rescan_but_survive_standard() {
        let mut seeded = device(
            "stable-id",
            "192.168.50.50",
            Some("AA:BB:CC:DD:EE:01"),
            Some("VendorA"),
            Some("nodeA"),
            Some("Linux 6.x"),
            &[(443, "tcp")],
            "2026-06-01T00:00:00Z",
            "2026-06-01T00:00:00Z",
        );
        seeded.host_scripts = vec![script("smb2-security-mode", "signing not required")];
        seeded.open_ports[0].scripts = vec![script("vulners", "CVE-2021-23017 7.7")];

        // Same host re-seen with NO scripts (host responded, but clean this time).
        let clean = device(
            "new",
            "192.168.50.50",
            Some("AA:BB:CC:DD:EE:01"),
            Some("VendorA"),
            Some("nodeA"),
            Some("Linux 6.x"),
            &[(443, "tcp")],
            "2026-06-09T00:00:00Z",
            "2026-06-09T00:00:00Z",
        );

        // Standard rescan (no scripts) -> findings preserved.
        let mut std_inv = Inventory::default();
        std_inv
            .by_id
            .insert(seeded.device_id.clone(), seeded.clone());
        std_inv.merge(
            vec![clean.clone()],
            ScanSemantics::for_intensity(ScanIntensity::Standard),
        );
        let after_std = std_inv.by_id.get("stable-id").unwrap();
        assert_eq!(
            after_std.host_scripts.len(),
            1,
            "standard must not wipe host scripts"
        );
        assert_eq!(
            after_std.open_ports[0].scripts.len(),
            1,
            "standard must not wipe port scripts"
        );

        // Aggressive /24 rescan (Merge + runs_scripts) -> stale findings cleared.
        let aggr_subnet = ScanSemantics {
            port_strategy: PortMergeStrategy::Merge,
            os_scan: true,
            runs_scripts: true,
        };
        let mut aggr_inv = Inventory::default();
        aggr_inv
            .by_id
            .insert(seeded.device_id.clone(), seeded.clone());
        aggr_inv.merge(vec![clean], aggr_subnet);
        let after_aggr = aggr_inv.by_id.get("stable-id").unwrap();
        assert!(
            after_aggr.host_scripts.is_empty(),
            "aggressive rescan must clear stale host scripts"
        );
        assert!(
            after_aggr.open_ports[0].scripts.is_empty(),
            "aggressive rescan must clear stale port scripts"
        );
    }

    #[test]
    fn attack_surface_change_resets_vuln_triaged() {
        let mut existing = device(
            "stable-id",
            "192.168.50.101",
            Some("AA:BB:CC:DD:EE:FF"),
            Some("VendorA"),
            Some("nodeA"),
            Some("Linux 6.x"),
            &[(22, "tcp")],
            "2026-06-01T00:00:00Z",
            "2026-06-01T00:00:00Z",
        );
        existing.vuln_triaged = true;

        let fresh = device(
            "new-id",
            "192.168.50.101",
            Some("AA:BB:CC:DD:EE:FF"),
            Some("VendorA"),
            Some("nodeA"),
            Some("Linux 6.x"),
            &[(22, "tcp"), (443, "tcp")],
            "2026-06-09T00:00:00Z",
            "2026-06-09T00:00:00Z",
        );

        let mut inventory = Inventory::default();
        inventory.by_id.insert(existing.device_id.clone(), existing);
        inventory.merge(
            vec![fresh],
            ScanSemantics::for_intensity(ScanIntensity::Aggressive),
        );

        let merged = inventory.by_id.get("stable-id").unwrap();
        assert!(!merged.vuln_triaged);
        assert!(merged.open_ports.iter().any(|p| p.port == 443));
    }
}
