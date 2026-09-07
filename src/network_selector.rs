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

    out.sort_by_key(candidate_sort_key);
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

    ranked.sort_by_key(candidate_sort_key);
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

pub fn candidate_for_interface(iface: &str) -> Option<NetworkCandidate> {
    let candidates = detect_candidates().ok()?;
    let live_metrics = live_metrics_snapshot();
    let candidate = candidates
        .into_iter()
        .find(|candidate| candidate.interface_name == iface)?;
    Some(apply_live_metrics(candidate, live_metrics.get(iface)))
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
        || lower.starts_with("uap")
        || lower.starts_with("wfd")
        || lower.starts_with("ap")
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

    fn candidate_with_transport(
        name: &str,
        transport_type: TransportType,
        route_metric: Option<u32>,
        oper_up: bool,
        carrier_up: bool,
        has_default_route: bool,
    ) -> NetworkCandidate {
        let estimated_latency_ms = estimate_latency_ms(transport_type, route_metric);
        let estimated_bandwidth_kbps = estimate_bandwidth_kbps(transport_type, None);
        let quality_score = compute_quality_score(
            transport_type.default_priority(),
            estimated_latency_ms,
            estimated_bandwidth_kbps,
            has_default_route,
            route_metric,
            oper_up,
            carrier_up,
        );

        NetworkCandidate {
            interface_name: name.to_string(),
            ip: Ipv4Addr::new(10, 0, 0, 1),
            transport_type,
            default_priority: transport_type.default_priority(),
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
        }
    }

    fn live(
        is_up: bool,
        latency_ms: u64,
        bandwidth_kbps: u64,
        consecutive_failures: u32,
        consecutive_successes: u32,
    ) -> LiveNetworkMetrics {
        LiveNetworkMetrics {
            is_up,
            latency_ms,
            bandwidth_kbps,
            consecutive_failures,
            consecutive_successes,
            last_probed: 123,
        }
    }

    #[test]
    fn classify_transport_covers_known_prefixes_and_unknown_names() {
        assert_eq!(classify_transport("sat0"), Some(TransportType::Satellite));
        assert_eq!(classify_transport("PPP0"), Some(TransportType::Satellite));
        assert_eq!(classify_transport("eth0"), Some(TransportType::Ethernet));
        assert_eq!(classify_transport("en0"), Some(TransportType::Ethernet));
        assert_eq!(classify_transport("eno1"), Some(TransportType::Ethernet));
        assert_eq!(classify_transport("enp3s0"), Some(TransportType::Ethernet));
        assert_eq!(classify_transport("wlan0"), Some(TransportType::WiFi));
        assert_eq!(classify_transport("wlx123"), Some(TransportType::WiFi));
        assert_eq!(classify_transport("wlp2s0"), Some(TransportType::WiFi));
        assert_eq!(classify_transport("bnep0"), Some(TransportType::Bluetooth));
        assert_eq!(classify_transport("bt-pan"), Some(TransportType::Bluetooth));
        assert_eq!(classify_transport("hci0"), Some(TransportType::Bluetooth));
        assert_eq!(classify_transport("wwan0"), Some(TransportType::Cellular));
        assert_eq!(
            classify_transport("rmnet_data0"),
            Some(TransportType::Cellular)
        );
        assert_eq!(classify_transport("usb0"), Some(TransportType::Cellular));
        assert_eq!(classify_transport("tun0"), None);
        assert_eq!(classify_transport(""), None);
    }

    #[test]
    fn should_skip_interface_covers_virtual_and_ap_prefixes() {
        for name in [
            "lo",
            "lo0",
            "nebula1",
            "docker0",
            "vethabcd",
            "br-test",
            "virbr0",
            "vnet0",
            "flannel.1",
            "cni0",
            "cali123",
            "defined0",
            "armia0",
            "uap0",
            "wfd0",
            "ap0",
        ] {
            assert!(should_skip_interface(name), "{name} should be skipped");
        }

        assert!(!should_skip_interface("eth0"));
        assert!(!should_skip_interface("wlan0"));
        assert!(!should_skip_interface("wwan0"));
    }

    #[test]
    fn is_routable_ipv4_filters_loopback_link_local_and_unspecified() {
        assert!(!is_routable_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_routable_ipv4(Ipv4Addr::new(169, 254, 1, 1)));
        assert!(!is_routable_ipv4(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(is_routable_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_routable_ipv4(Ipv4Addr::new(192, 168, 1, 10)));
    }

    #[test]
    fn estimate_bandwidth_uses_speed_when_available_and_static_fallbacks_otherwise() {
        assert_eq!(
            estimate_bandwidth_kbps(TransportType::Ethernet, Some(1)),
            1_000
        );
        assert_eq!(
            estimate_bandwidth_kbps(TransportType::WiFi, Some(u64::MAX)),
            u64::MAX
        );
        assert_eq!(
            estimate_bandwidth_kbps(TransportType::Ethernet, None),
            100_000
        );
        assert_eq!(estimate_bandwidth_kbps(TransportType::WiFi, None), 60_000);
        assert_eq!(
            estimate_bandwidth_kbps(TransportType::Cellular, None),
            8_000
        );
        assert_eq!(
            estimate_bandwidth_kbps(TransportType::Bluetooth, None),
            1_500
        );
        assert_eq!(estimate_bandwidth_kbps(TransportType::Satellite, None), 512);
    }

    #[test]
    fn estimate_latency_combines_transport_base_and_route_metric_penalty() {
        assert_eq!(estimate_latency_ms(TransportType::Ethernet, Some(0)), 3);
        assert_eq!(estimate_latency_ms(TransportType::WiFi, Some(25)), 13);
        assert_eq!(estimate_latency_ms(TransportType::Cellular, Some(50)), 40);
        assert_eq!(estimate_latency_ms(TransportType::Bluetooth, Some(100)), 60);
        assert_eq!(
            estimate_latency_ms(TransportType::Satellite, Some(500)),
            800
        );
        assert_eq!(estimate_latency_ms(TransportType::Ethernet, None), 43);
    }

    #[test]
    fn compute_quality_score_accounts_for_penalties_and_boundaries() {
        let baseline = compute_quality_score(10, 10, 100_000, true, Some(5), true, true);
        assert_eq!(baseline, 200 + 30 + 150 + 10);

        let missing_route_down = compute_quality_score(10, 10, 0, false, None, false, false);
        assert_eq!(missing_route_down, 200 + 30 + 249 + 300 + 400 + 500 + 500);

        let saturated_bandwidth = compute_quality_score(1, 1, 999_999, true, Some(0), true, true);
        assert_eq!(saturated_bandwidth, 20 + 3);
    }

    #[test]
    fn apply_live_metrics_clamps_zero_values_and_applies_health_penalties() {
        let base =
            candidate_with_transport("ens33", TransportType::Ethernet, Some(10), true, true, true);
        let live_metrics = live(false, 0, 0, 2, 99);
        let updated = apply_live_metrics(base.clone(), Some(&live_metrics));
        let mut expected_score = compute_quality_score(
            base.default_priority,
            1,
            1,
            base.has_default_route,
            base.route_metric,
            base.oper_up,
            base.carrier_up,
        );
        expected_score += 2_000;
        expected_score += 400;
        expected_score -= 24;

        assert!(updated.using_live_metrics);
        assert_eq!(updated.observed_latency_ms, 1);
        assert_eq!(updated.observed_bandwidth_kbps, 1);
        assert!(!updated.observed_is_up);
        assert_eq!(updated.consecutive_failures, 2);
        assert_eq!(updated.consecutive_successes, 99);
        assert_eq!(updated.last_probed, Some(123));
        assert_eq!(updated.quality_score, expected_score);

        let unchanged = apply_live_metrics(base.clone(), None);
        assert!(!unchanged.using_live_metrics);
        assert_eq!(unchanged.quality_score, base.quality_score);
    }

    #[test]
    fn network_candidate_reachability_requires_oper_carrier_and_default_route() {
        assert!(candidate_with_transport(
            "ens33",
            TransportType::Ethernet,
            Some(10),
            true,
            true,
            true
        )
        .is_reachable());
        assert!(!candidate_with_transport(
            "ens33",
            TransportType::Ethernet,
            Some(10),
            false,
            true,
            true
        )
        .is_reachable());
        assert!(!candidate_with_transport(
            "ens33",
            TransportType::Ethernet,
            Some(10),
            true,
            false,
            true
        )
        .is_reachable());
        assert!(!candidate_with_transport(
            "ens33",
            TransportType::Ethernet,
            None,
            true,
            true,
            false
        )
        .is_reachable());
    }

    #[test]
    fn rank_candidates_filters_allowed_reachable_live_up_and_failures() {
        let candidates = vec![
            candidate_with_transport("ens33", TransportType::Ethernet, Some(10), true, true, true),
            candidate_with_transport("wlan0", TransportType::WiFi, Some(20), true, true, true),
            candidate_with_transport("wwan0", TransportType::Cellular, Some(30), true, true, true),
            candidate_with_transport("bt0", TransportType::Bluetooth, Some(40), false, true, true),
        ];
        let live = HashMap::from([
            ("wlan0".to_string(), live(true, 5, 100_000, 1, 3)),
            ("wwan0".to_string(), live(false, 3, 200_000, 0, 3)),
            ("bt0".to_string(), live(true, 1, 200_000, 0, 3)),
        ]);

        let ranked = rank_candidates(
            &candidates,
            &live,
            &SelectionPolicy {
                allowed_interfaces: Some(HashSet::from([
                    "wlan0".to_string(),
                    "wwan0".to_string(),
                    "bt0".to_string(),
                ])),
                prefer_live_metrics: true,
                require_reachable: true,
                require_live_up: true,
                max_consecutive_failures: Some(1),
                ..SelectionPolicy::default()
            },
        );

        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].interface_name, "wlan0");
        assert!(ranked[0].using_live_metrics);
    }

    #[test]
    fn rank_candidates_prefer_live_metrics_only_when_live_candidates_exist() {
        let candidates = vec![
            candidate_with_transport("ens33", TransportType::Ethernet, Some(10), true, true, true),
            candidate_with_transport("wlan0", TransportType::WiFi, Some(20), true, true, true),
        ];

        let no_live_ranked = rank_candidates(
            &candidates,
            &HashMap::new(),
            &SelectionPolicy {
                prefer_live_metrics: true,
                require_reachable: true,
                ..SelectionPolicy::default()
            },
        );
        assert_eq!(no_live_ranked.len(), 2);
        assert!(no_live_ranked.iter().all(|c| !c.using_live_metrics));

        let live_ranked = rank_candidates(
            &candidates,
            &HashMap::from([("wlan0".to_string(), live(true, 1, 200_000, 0, 3))]),
            &SelectionPolicy {
                prefer_live_metrics: true,
                require_reachable: true,
                ..SelectionPolicy::default()
            },
        );
        assert_eq!(live_ranked.len(), 1);
        assert_eq!(live_ranked[0].interface_name, "wlan0");
    }

    #[test]
    fn rank_candidates_orders_by_score_health_route_priority_and_name() {
        let mut alpha =
            candidate_with_transport("alpha", TransportType::Ethernet, Some(30), true, true, true);
        let mut beta =
            candidate_with_transport("beta", TransportType::WiFi, Some(20), true, true, true);
        let mut gamma =
            candidate_with_transport("gamma", TransportType::Cellular, Some(10), true, true, true);

        alpha.quality_score = 100;
        beta.quality_score = 100;
        gamma.quality_score = 90;

        let ranked = rank_candidates(
            &[alpha.clone(), beta.clone(), gamma.clone()],
            &HashMap::new(),
            &SelectionPolicy::default(),
        );
        assert_eq!(ranked[0].interface_name, "gamma");

        alpha.quality_score = 100;
        beta.quality_score = 100;
        gamma.quality_score = 100;
        alpha.observed_is_up = false;
        beta.has_default_route = false;
        gamma.route_metric = Some(50);

        let ranked = rank_candidates(
            &[beta, gamma, alpha],
            &HashMap::new(),
            &SelectionPolicy::default(),
        );
        assert_eq!(
            ranked
                .iter()
                .map(|c| c.interface_name.as_str())
                .collect::<Vec<_>>(),
            vec!["gamma", "beta", "alpha"]
        );
    }

    #[test]
    fn best_candidate_handles_empty_inputs_and_selected_interface_override() {
        set_live_metrics([]);
        set_selected_interface(None);
        assert!(best_candidate(&[]).is_none());

        let ens33 =
            candidate_with_transport("ens33", TransportType::Ethernet, Some(10), true, true, true);
        let wlan0 =
            candidate_with_transport("wlan0", TransportType::WiFi, Some(20), true, true, true);
        set_selected_interface(Some("wlan0".to_string()));
        set_live_metrics([("wlan0".to_string(), live(true, 2, 150_000, 0, 3))]);

        let best = best_candidate(&[ens33, wlan0]).expect("selected interface should win");

        assert_eq!(best.interface_name, "wlan0");
        assert!(best.using_live_metrics);

        set_selected_interface(None);
        set_live_metrics([]);
    }

    #[test]
    fn selected_interface_override_ignores_missing_selected_name() {
        set_live_metrics([]);
        set_selected_interface(Some("missing0".to_string()));
        let ens33 =
            candidate_with_transport("ens33", TransportType::Ethernet, Some(10), true, true, true);

        let best = best_candidate(&[ens33]).expect("fallback candidate should be selected");

        assert_eq!(best.interface_name, "ens33");
        set_selected_interface(None);
    }

    #[test]
    fn live_metrics_store_replaces_previous_snapshot() {
        set_live_metrics([("ens33".to_string(), live(true, 10, 10_000, 0, 1))]);
        let first = live_metrics_snapshot();
        assert_eq!(first.len(), 1);
        assert!(first.contains_key("ens33"));

        set_live_metrics([("wlan0".to_string(), live(false, 20, 20_000, 3, 0))]);
        let second = live_metrics_snapshot();
        assert_eq!(second.len(), 1);
        assert!(!second.contains_key("ens33"));
        assert_eq!(second["wlan0"].consecutive_failures, 3);

        set_live_metrics([]);
    }

    #[test]
    fn best_candidate_with_live_metrics_returns_none_when_policy_filters_everything() {
        let candidates = vec![candidate_with_transport(
            "ens33",
            TransportType::Ethernet,
            Some(10),
            true,
            true,
            true,
        )];
        let ranked = best_candidate_with_live_metrics(
            &candidates,
            &HashMap::new(),
            &SelectionPolicy {
                allowed_interfaces: Some(HashSet::from(["wlan0".to_string()])),
                require_live_metrics: true,
                ..SelectionPolicy::default()
            },
        );

        assert!(ranked.is_none());
    }
}
