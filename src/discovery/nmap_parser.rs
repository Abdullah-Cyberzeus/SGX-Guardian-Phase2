use crate::discovery::{
    connected_device::{ConnectedDevice, DeviceStatus, OpenPort, ScriptResult},
    error::{DiscoveryError, DiscoveryResult},
};
use chrono::Utc;
use quick_xml::de::from_str;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NmapRun {
    #[serde(rename = "host", default)]
    hosts: Vec<XHost>,
}

#[derive(Debug, Deserialize)]
struct XHost {
    #[serde(rename = "address", default)]
    addresses: Vec<XAddr>,
    hostnames: Option<XHostnames>,
    ports: Option<XPorts>,
    os: Option<XOs>,
    hostscript: Option<XHostScript>,
    status: XStatus,
}

/// `<hostscript>` wraps host-level NSE results (smb-os-discovery, broadcast-*, ...).
#[derive(Debug, Deserialize)]
struct XHostScript {
    #[serde(rename = "script", default)]
    scripts: Vec<XScript>,
}

/// A single `<script id="..." output="..."/>` element (port- or host-level).
#[derive(Debug, Deserialize)]
struct XScript {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@output", default)]
    output: String,
}

#[derive(Debug, Deserialize)]
struct XStatus {
    #[serde(rename = "@state")]
    state: String,
}

#[derive(Debug, Deserialize)]
struct XAddr {
    #[serde(rename = "@addr")]
    addr: String,
    #[serde(rename = "@addrtype")]
    addrtype: String,
    #[serde(rename = "@vendor", default)]
    vendor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct XHostnames {
    #[serde(rename = "hostname", default)]
    items: Vec<XHostname>,
}

#[derive(Debug, Deserialize)]
struct XHostname {
    #[serde(rename = "@name")]
    name: String,
}

#[derive(Debug, Deserialize)]
struct XPorts {
    #[serde(rename = "port", default)]
    ports: Vec<XPort>,
}

#[derive(Debug, Deserialize)]
struct XPort {
    #[serde(rename = "@portid")]
    portid: u16,
    #[serde(rename = "@protocol")]
    protocol: String,
    state: XPortState,
    service: Option<XService>,
    #[serde(rename = "script", default)]
    scripts: Vec<XScript>,
}

#[derive(Debug, Deserialize)]
struct XPortState {
    #[serde(rename = "@state")]
    state: String,
}

#[derive(Debug, Deserialize)]
struct XService {
    #[serde(rename = "@name", default)]
    name: Option<String>,
    #[serde(rename = "@product", default)]
    product: Option<String>,
    #[serde(rename = "@version", default)]
    version: Option<String>,
    #[serde(rename = "cpe", default)]
    cpe: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct XOs {
    #[serde(rename = "osmatch", default)]
    matches: Vec<XOsMatch>,
}

#[derive(Debug, Deserialize)]
struct XOsMatch {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "osclass", default)]
    osclass: Vec<XOsClass>,
}

/// `<osclass>` carries the OS CPE under the matched `<osmatch>`.
#[derive(Debug, Deserialize)]
struct XOsClass {
    #[serde(rename = "cpe", default)]
    cpe: Vec<String>,
}

fn to_script_result(s: XScript) -> ScriptResult {
    ScriptResult {
        id: s.id,
        output: s.output,
    }
}

pub fn parse(xml: &str) -> DiscoveryResult<Vec<ConnectedDevice>> {
    let run: NmapRun = from_str(xml).map_err(|e| DiscoveryError::XmlParse(e.to_string()))?;
    let now = Utc::now().to_rfc3339();
    let mut out = Vec::with_capacity(run.hosts.len());

    for h in run.hosts {
        if h.status.state != "up" {
            continue;
        }

        let mut ip = None;
        let mut mac = None;
        let mut vendor = None;
        for a in &h.addresses {
            match a.addrtype.as_str() {
                "ipv4" => ip = Some(a.addr.clone()),
                "mac" => {
                    mac = Some(a.addr.clone());
                    vendor = a.vendor.clone();
                }
                _ => {}
            }
        }
        let ip = match ip {
            Some(v) => v,
            None => continue,
        };

        let hostname = h
            .hostnames
            .and_then(|x| x.items.into_iter().next())
            .map(|n| n.name);

        // Keep the best OS match's name *and* its CPE(s) together.
        let (os, os_cpe) = match h.os.and_then(|o| o.matches.into_iter().next()) {
            Some(m) => {
                let cpe = m.osclass.into_iter().flat_map(|c| c.cpe).collect();
                (Some(m.name), cpe)
            }
            None => (None, Vec::new()),
        };

        // Host-level NSE script output (`<hostscript>`).
        let host_scripts = h
            .hostscript
            .map(|hs| hs.scripts.into_iter().map(to_script_result).collect())
            .unwrap_or_default();

        let open_ports = h
            .ports
            .map(|p| {
                p.ports
                    .into_iter()
                    .filter(|x| x.state.state == "open")
                    .map(|x| OpenPort {
                        port: x.portid,
                        protocol: x.protocol,
                        service: x.service.as_ref().and_then(|s| s.name.clone()),
                        product_version: x.service.as_ref().and_then(|s| {
                            match (&s.product, &s.version) {
                                (Some(p), Some(v)) => Some(format!("{} {}", p, v)),
                                (Some(p), None) => Some(p.clone()),
                                _ => None,
                            }
                        }),
                        cpe: x
                            .service
                            .as_ref()
                            .map(|s| s.cpe.clone())
                            .unwrap_or_default(),
                        scripts: x.scripts.into_iter().map(to_script_result).collect(),
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let device_id = ConnectedDevice::compute_id(&ip, mac.as_deref());

        out.push(ConnectedDevice {
            device_id,
            ip,
            mac,
            vendor,
            hostname,
            os_fingerprint: os,
            os_cpe,
            open_ports,
            host_scripts,
            status: DeviceStatus::Unauthorized, // whitelist pass will set Approved
            first_seen: now.clone(),
            last_seen: now.clone(),
            vuln_triaged: false,
            last_scan_intensity: None, // set by the caller after merge
        });
    }

    // === FIX #4: MAC-aliasing dedup ===
    // NMAP reports the GATEWAY MAC for off-link IPs (anything not on the scanner's
    // direct L2 segment). This produces "same MAC on many IPs", which downstream
    // fools the whitelist matcher. Resolution: when a MAC appears on >1 device in
    // this scan, KEEP the MAC only on the device whose IP is in the local subnet
    // (heuristic: the first device that has both MAC + non-loopback + matches the
    // majority /24). For other duplicates, set mac = None and stamp `vendor =
    // Some("(mac_aliased)")` so the operator can see why.
    dedup_aliased_macs(&mut out);

    Ok(out)
}

/// Strip MAC from devices that share a MAC with another device in the same scan.
/// The "primary" of the group keeps the MAC; all others lose it.
///
/// Primary-pick policy (in order):
/// 1. The device whose IP shares the most-common /24 prefix in the scan (lowest count
///    = least likely to be a gateway alias).
/// 2. If tied, the one with the lowest IP (ascending stable order).
///
/// We also recompute `device_id` after stripping, so the inventory key flips from
/// `SHA(mac||ip)` to `SHA(ip)` for the demoted entries.
fn dedup_aliased_macs(devices: &mut [ConnectedDevice]) {
    use std::collections::HashMap;

    let mut by_mac: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, d) in devices.iter().enumerate() {
        if let Some(m) = &d.mac {
            by_mac.entry(m.trim().to_uppercase()).or_default().push(i);
        }
    }

    let mut per24_count: HashMap<String, usize> = HashMap::new();
    for d in devices.iter() {
        if let Some(prefix) = ipv4_24_prefix(&d.ip) {
            *per24_count.entry(prefix).or_default() += 1;
        }
    }

    for (mac, idxs) in by_mac.iter().filter(|(_, v)| v.len() > 1) {
        let mut scored: Vec<(usize, usize, String)> = idxs
            .iter()
            .map(|&i| {
                let pfx = ipv4_24_prefix(&devices[i].ip).unwrap_or_default();
                let count = per24_count.get(&pfx).copied().unwrap_or(usize::MAX);
                (i, count, devices[i].ip.clone())
            })
            .collect();
        scored.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));

        for (i, _, _) in scored.iter().skip(1) {
            let d = &mut devices[*i];
            d.mac = None;
            d.vendor = Some(format!("(mac_aliased to {})", mac));
            d.device_id = ConnectedDevice::compute_id(&d.ip, None);
        }
    }
}

fn ipv4_24_prefix(ip: &str) -> Option<String> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    Some(format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]))
}
