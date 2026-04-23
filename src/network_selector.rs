use crate::cot::types::TransportType;
use anyhow::Result;
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::RwLock;

#[derive(Debug, Clone, Copy, Default)]
pub struct LiveNetworkMetrics {
    pub is_up: bool,
    pub latency_ms: u64,
    pub bandwidth_kbps: u64,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_probed: i64,
}

#[derive(Debug, Clone, Default)]
pub struct SelectionPolicy {
    pub allowed_interfaces: Option<HashSet<String>>,
    pub prefer_live_metrics: bool,
    pub require_live_metrics: bool,
    pub require_reachable: bool,
    pub require_live_up: bool,
    pub max_consecutive_failures: Option<u32>,
}

static LIVE_METRICS_BY_IFACE: Lazy<RwLock<HashMap<String, LiveNetworkMetrics>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));
static SELECTED_INTERFACE: Lazy<RwLock<Option<String>>> = Lazy::new(|| RwLock::new(None));
const MAX_STABILITY_CREDITS: u32 = 3;

#[derive(Debug, Clone)]
pub struct NetworkCandidate {
    pub interface_name: String,
    pub ip: Ipv4Addr,
    pub transport_type: TransportType,
    pub default_priority: u8,
    pub oper_up: bool,
    pub carrier_up: bool,
    pub has_default_route: bool,
    pub route_metric: Option<u32>,
    pub estimated_latency_ms: u64,
    pub estimated_bandwidth_kbps: u64,
    pub observed_latency_ms: u64,
    pub observed_bandwidth_kbps: u64,
    pub observed_is_up: bool,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_probed: Option<i64>,
    pub using_live_metrics: bool,
    pub quality_score: i64,
}

impl NetworkCandidate {
    pub fn is_reachable(&self) -> bool {
        self.oper_up && self.carrier_up && self.has_default_route
    }
}

pub fn detect_candidates() -> Result<Vec<NetworkCandidate>> {
    let interfaces = NetworkInterface::show()?;
    let default_routes = default_routes_by_iface();
    let mut out = Vec::new();

    for iface in interfaces {
        if should_skip_interface(&iface.name) {
            continue;
        }

        let Some(transport_type) = classify_transport(&iface.name) else {
            continue;
        };

        let ipv4 = iface.addr.iter().find_map(|a| match a {
            Addr::V4(v4) if is_routable_ipv4(v4.ip) => Some(v4.ip),
            _ => None,
        });

        let Some(ip) = ipv4 else {
            continue;
        };

        let oper_up = read_oper_up(&iface.name);
        let carrier_up = read_carrier_up(&iface.name).unwrap_or(oper_up);
        let route_metric = default_routes.get(&iface.name).copied();
        let has_default_route = route_metric.is_some();
        let speed_mbps = read_link_speed_mbps(&iface.name);
        let estimated_bandwidth_kbps = estimate_bandwidth_kbps(transport_type, speed_mbps);
        let estimated_latency_ms = estimate_latency_ms(transport_type, route_metric);
        let default_priority = transport_type.default_priority();
        let quality_score = compute_quality_score(
            default_priority,
            estimated_latency_ms,
            estimated_bandwidth_kbps,
            has_default_route,
            route_metric,
            oper_up,
            carrier_up,
        );

        out.push(NetworkCandidate {
            interface_name: iface.name,
            ip,
            transport_type,
            default_priority,
            oper_up,
            carrier_up,
            has_default_route,
            route_metric,
            estimated_latency_ms,
            estimated_bandwidth_kbps,
            observed_latency_ms: estimated_latency_ms,
            observed_bandwidth_kbps: estimated_bandwidth_kbps,
            observed_is_up: oper_up && carrier_up,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_probed: None,
            using_live_metrics: false,
            quality_score,
        });
    }

    out.sort_by(|a, b| candidate_sort_key(a).cmp(&candidate_sort_key(b)));
    Ok(out)
}

pub fn best_candidate(candidates: &[NetworkCandidate]) -> Option<NetworkCandidate> {
    if let Some(selected_iface) = selected_interface() {
        let live_metrics = live_metrics_snapshot();
        if let Some(candidate) = candidates
            .iter()
            .find(|candidate| candidate.interface_name == selected_iface)
            .cloned()
        {
            return Some(apply_live_metrics(
                candidate,
                live_metrics.get(&selected_iface),
            ));
        }
    }

    best_candidate_with_live_metrics(
        candidates,
        &live_metrics_snapshot(),
        &SelectionPolicy {
            prefer_live_metrics: true,
            require_reachable: true,
            ..SelectionPolicy::default()
        },
    )
}

pub fn best_candidate_with_live_metrics(
    candidates: &[NetworkCandidate],
    live_metrics: &HashMap<String, LiveNetworkMetrics>,
    policy: &SelectionPolicy,
) -> Option<NetworkCandidate> {
    rank_candidates(candidates, live_metrics, policy)
        .into_iter()
        .next()
}

pub fn rank_candidates(
    candidates: &[NetworkCandidate],
    live_metrics: &HashMap<String, LiveNetworkMetrics>,
    policy: &SelectionPolicy,
) -> Vec<NetworkCandidate> {
    let mut ranked: Vec<NetworkCandidate> = candidates
        .iter()
        .filter(|candidate| {
            policy
                .allowed_interfaces
                .as_ref()
                .map(|allowed| allowed.contains(&candidate.interface_name))
                .unwrap_or(true)
        })
        .cloned()
        .map(|candidate| {
            let iface = candidate.interface_name.clone();
            apply_live_metrics(candidate, live_metrics.get(&iface))
        })
        .collect();

    let has_live_candidates = ranked.iter().any(|candidate| candidate.using_live_metrics);
    if policy.require_live_metrics || (policy.prefer_live_metrics && has_live_candidates) {
        ranked.retain(|candidate| candidate.using_live_metrics);
    }
    if policy.require_reachable {
        ranked.retain(NetworkCandidate::is_reachable);
    }
    if policy.require_live_up {
        ranked.retain(|candidate| candidate.observed_is_up);
    }
    if let Some(limit) = policy.max_consecutive_failures {
        ranked.retain(|candidate| candidate.consecutive_failures <= limit);
    }

    ranked.sort_by(|a, b| candidate_sort_key(a).cmp(&candidate_sort_key(b)));
    ranked
}

pub fn set_live_metrics(metrics: impl IntoIterator<Item = (String, LiveNetworkMetrics)>) {
    let mut state = LIVE_METRICS_BY_IFACE
        .write()
        .expect("live metrics lock poisoned");
    state.clear();
    state.extend(metrics);
}

pub fn live_metrics_snapshot() -> HashMap<String, LiveNetworkMetrics> {
    LIVE_METRICS_BY_IFACE
        .read()
        .expect("live metrics lock poisoned")
        .clone()
}

pub fn set_selected_interface(iface: Option<String>) {
    let mut selected = SELECTED_INTERFACE
        .write()
        .expect("selected interface lock poisoned");
    *selected = iface;
}

pub fn selected_interface() -> Option<String> {
    SELECTED_INTERFACE
        .read()
        .expect("selected interface lock poisoned")
        .clone()
}

pub fn classify_transport(name: &str) -> Option<TransportType> {
    let lower = name.to_lowercase();
    if lower.starts_with("sat") || lower.starts_with("ppp") {
        return Some(TransportType::Satellite);
    }
    if lower.starts_with("eth")
        || lower.starts_with("en")
        || lower.starts_with("eno")
        || lower.starts_with("enp")
    {
        return Some(TransportType::Ethernet);
    }
    if lower.starts_with("wlan") || lower.starts_with("wl") || lower.starts_with("wlp") {
        return Some(TransportType::WiFi);
    }
    if lower.starts_with("bnep") || lower.starts_with("bt") || lower.starts_with("hci") {
        return Some(TransportType::Bluetooth);
    }
    if lower.starts_with("wwan") || lower.starts_with("rmnet") || lower.starts_with("usb") {
        return Some(TransportType::Cellular);
    }
    None
}

fn should_skip_interface(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower == "lo"
        || lower.starts_with("lo")
        || lower.starts_with("nebula")
        || lower.starts_with("docker")
        || lower.starts_with("veth")
        || lower.starts_with("br-")
        || lower.starts_with("virbr")
        || lower.starts_with("vnet")
        || lower.starts_with("flannel")
        || lower.starts_with("cni")
        || lower.starts_with("cali")
        || lower.starts_with("defined")
        || lower.starts_with("armia")
}

fn is_routable_ipv4(ip: Ipv4Addr) -> bool {
    if ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() {
        return false;
    }
    let o = ip.octets();
    !(o[0] == 169 && o[1] == 254)
}

fn read_oper_up(iface: &str) -> bool {
    std::fs::read_to_string(format!("/sys/class/net/{}/operstate", iface))
        .map(|s| s.trim() == "up")
        .unwrap_or(false)
}

fn read_carrier_up(iface: &str) -> Option<bool> {
    std::fs::read_to_string(format!("/sys/class/net/{}/carrier", iface))
        .ok()
        .map(|s| s.trim() == "1")
}

fn read_link_speed_mbps(iface: &str) -> Option<u64> {
    let raw = std::fs::read_to_string(format!("/sys/class/net/{}/speed", iface)).ok()?;
    let parsed = raw.trim().parse::<i64>().ok()?;
    if parsed > 0 {
        Some(parsed as u64)
    } else {
        None
    }
}

fn default_routes_by_iface() -> HashMap<String, u32> {
    let mut out = HashMap::new();
    let Ok(content) = std::fs::read_to_string("/proc/net/route") else {
        return out;
    };
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 8 {
            continue;
        }
        let iface = cols[0];
        let destination = cols[1];
        let flags = u16::from_str_radix(cols[3], 16).unwrap_or(0);
        let metric = cols[6].parse::<u32>().unwrap_or(9999);
        let is_up = flags & 0x1 != 0;
        let is_gateway = flags & 0x2 != 0;
        if destination == "00000000" && is_up && is_gateway {
            out.insert(iface.to_string(), metric);
        }
    }
    out
}

fn estimate_bandwidth_kbps(tt: TransportType, speed_mbps: Option<u64>) -> u64 {
    if let Some(mbps) = speed_mbps {
        return mbps.saturating_mul(1000);
    }
    match tt {
        TransportType::Ethernet => 100_000,
        TransportType::WiFi => 60_000,
        TransportType::Cellular => 8_000,
        TransportType::Bluetooth => 1_500,
        TransportType::Satellite => 512,
    }
}

fn estimate_latency_ms(tt: TransportType, route_metric: Option<u32>) -> u64 {
    let base = match tt {
        TransportType::Ethernet => 3,
        TransportType::WiFi => 8,
        TransportType::Cellular => 30,
        TransportType::Bluetooth => 40,
        TransportType::Satellite => 700,
    };
    let metric_penalty = route_metric.unwrap_or(200) as u64 / 5;
    base + metric_penalty
}

pub fn compute_quality_score(
    default_priority: u8,
    latency_ms: u64,
    bandwidth_kbps: u64,
    has_default_route: bool,
    route_metric: Option<u32>,
    oper_up: bool,
    carrier_up: bool,
) -> i64 {
    let bw = bandwidth_kbps.max(1);
    let bw_penalty = (250_000u64.saturating_sub(bw.min(250_000)) / 1000) as i64;
    let mut score = 0i64;
    score += i64::from(default_priority) * 20;
    score += latency_ms as i64 * 3;
    score += bw_penalty;
    score += i64::from(route_metric.unwrap_or(150)) * 2;
    if !has_default_route {
        score += 400;
    }
    if !oper_up {
        score += 500;
    }
    if !carrier_up {
        score += 500;
    }
    score
}

fn apply_live_metrics(
    mut candidate: NetworkCandidate,
    live: Option<&LiveNetworkMetrics>,
) -> NetworkCandidate {
    if let Some(live) = live {
        let observed_latency = live.latency_ms.max(1);
        let observed_bandwidth = live.bandwidth_kbps.max(1);
        let mut score = compute_quality_score(
            candidate.default_priority,
            observed_latency,
            observed_bandwidth,
            candidate.has_default_route,
            candidate.route_metric,
            candidate.oper_up,
            candidate.carrier_up,
        );
        if !live.is_up {
            score += 2_000;
        }
        score += i64::from(live.consecutive_failures) * 200;
        score = score
            .saturating_sub(i64::from(live.consecutive_successes.min(MAX_STABILITY_CREDITS)) * 8);

        candidate.observed_latency_ms = observed_latency;
        candidate.observed_bandwidth_kbps = observed_bandwidth;
        candidate.observed_is_up = live.is_up;
        candidate.consecutive_failures = live.consecutive_failures;
        candidate.consecutive_successes = live.consecutive_successes;
        candidate.last_probed = Some(live.last_probed);
        candidate.using_live_metrics = true;
        candidate.quality_score = score;
        return candidate;
    }

    candidate
}

fn candidate_sort_key(candidate: &NetworkCandidate) -> (i64, bool, bool, u32, u8, String) {
    (
        candidate.quality_score,
        !candidate.observed_is_up,
        !candidate.has_default_route,
        candidate.route_metric.unwrap_or(u32::MAX),
        candidate.default_priority,
        candidate.interface_name.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    fn candidate(name: &str, route_metric: Option<u32>) -> NetworkCandidate {
        NetworkCandidate {
            interface_name: name.to_string(),
            ip: Ipv4Addr::new(192, 168, 1, if name == "ens33" { 10 } else { 11 }),
            transport_type: TransportType::Ethernet,
            default_priority: TransportType::Ethernet.default_priority(),
            oper_up: true,
            carrier_up: true,
            has_default_route: true,
            route_metric,
            estimated_latency_ms: 10,
            estimated_bandwidth_kbps: 100_000,
            observed_latency_ms: 10,
            observed_bandwidth_kbps: 100_000,
            observed_is_up: true,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_probed: None,
            using_live_metrics: false,
            quality_score: 0,
        }
    }

    #[test]
    fn live_metrics_override_static_route_bias() {
        set_selected_interface(None);
        let mut static_preferred = candidate("ens33", Some(10));
        static_preferred.quality_score = compute_quality_score(
            static_preferred.default_priority,
            static_preferred.estimated_latency_ms,
            static_preferred.estimated_bandwidth_kbps,
            static_preferred.has_default_route,
            static_preferred.route_metric,
            static_preferred.oper_up,
            static_preferred.carrier_up,
        );
        let mut live_preferred = candidate("ens37", Some(50));
        live_preferred.quality_score = compute_quality_score(
            live_preferred.default_priority,
            live_preferred.estimated_latency_ms,
            live_preferred.estimated_bandwidth_kbps,
            live_preferred.has_default_route,
            live_preferred.route_metric,
            live_preferred.oper_up,
            live_preferred.carrier_up,
        );

        let candidates = vec![static_preferred, live_preferred];
        let live = HashMap::from([
            (
                "ens33".to_string(),
                LiveNetworkMetrics {
                    is_up: true,
                    latency_ms: 45,
                    bandwidth_kbps: 100_000,
                    consecutive_failures: 0,
                    consecutive_successes: 5,
                    last_probed: 1,
                },
            ),
            (
                "ens37".to_string(),
                LiveNetworkMetrics {
                    is_up: true,
                    latency_ms: 4,
                    bandwidth_kbps: 100_000,
                    consecutive_failures: 0,
                    consecutive_successes: 5,
                    last_probed: 1,
                },
            ),
        ]);

        let best = best_candidate_with_live_metrics(
            &candidates,
            &live,
            &SelectionPolicy {
                prefer_live_metrics: true,
                require_reachable: true,
                ..SelectionPolicy::default()
            },
        )
        .expect("best candidate");

        assert_eq!(best.interface_name, "ens37");
        assert!(best.using_live_metrics);
        assert_eq!(best.observed_latency_ms, 4);
    }

    #[test]
    fn require_live_metrics_filters_unknown_interfaces() {
        set_selected_interface(None);
        let candidates = vec![candidate("ens33", Some(10)), candidate("ens37", Some(20))];
        let live = HashMap::from([(
            "ens37".to_string(),
            LiveNetworkMetrics {
                is_up: true,
                latency_ms: 8,
                bandwidth_kbps: 100_000,
                consecutive_failures: 0,
                consecutive_successes: 3,
                last_probed: 1,
            },
        )]);

        let best = best_candidate_with_live_metrics(
            &candidates,
            &live,
            &SelectionPolicy {
                prefer_live_metrics: true,
                require_live_metrics: true,
                require_reachable: true,
                allowed_interfaces: Some(HashSet::from(["ens33".to_string(), "ens37".to_string()])),
                ..SelectionPolicy::default()
            },
        )
        .expect("best candidate");

        assert_eq!(best.interface_name, "ens37");
    }
}
