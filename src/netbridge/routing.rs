use crate::netbridge::types::NetbridgeError;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tracing::{error, info, warn};

const HOTSPOT_ROUTE_TABLE: &str = "200";
const HOTSPOT_RULE_PRIORITY: &str = "22000";
const UPLINK_SOURCE_RULE_PRIORITY: &str = "22001";
/// Wins over any other default route this board normally carries (DHCP-assigned
/// defaults are conventionally >=10; see board evidence of wwan0 at metric 10).
const FORCED_DEFAULT_METRIC: &str = "1";
static POLICY_ROUTING_UNSUPPORTED: AtomicBool = AtomicBool::new(false);
/// Interface currently holding Guardian's forced main-table default route, used
/// only when the kernel has no policy-routing (FIB rules) support. Tracked so
/// `remove_hotspot_uplink` can clean up exactly the route Guardian added.
static FORCED_DEFAULT_IFACE: Mutex<Option<String>> = Mutex::new(None);

fn parse_interface_cidr(output: &str) -> Option<(Ipv4Addr, u8)> {
    output.lines().find_map(|line| {
        let trimmed = line.trim_start();
        let cidr = trimmed.strip_prefix("inet ")?.split_whitespace().next()?;
        let (ip, prefix) = cidr.split_once('/')?;
        Some((ip.parse().ok()?, prefix.parse().ok()?))
    })
}

fn network_cidr(ip: Ipv4Addr, prefix: u8) -> Option<String> {
    if prefix > 32 {
        return None;
    }

    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = Ipv4Addr::from(u32::from(ip) & mask);
    Some(format!("{}/{}", network, prefix))
}

fn inferred_gateway(ip: Ipv4Addr, prefix: u8) -> Option<Ipv4Addr> {
    if prefix >= 31 {
        return None;
    }

    let network = network_cidr(ip, prefix)?
        .split('/')
        .next()?
        .parse::<Ipv4Addr>()
        .ok()?;
    Some(Ipv4Addr::from(u32::from(network) + 1))
}

pub struct RoutingManager;

impl RoutingManager {
    pub fn new() -> Self {
        RoutingManager {}
    }
}

impl Default for RoutingManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RoutingManager {
    /// Enables IPv4 kernel forwarding to allow traffic between interfaces.
    pub fn enable_forwarding(&self) -> Result<(), NetbridgeError> {
        info!("Enabling IPv4 kernel forwarding...");
        let path = "/proc/sys/net/ipv4/ip_forward";

        if Path::new(path).exists() {
            fs::write(path, "1\n").map_err(NetbridgeError::IoError)?;
            info!("IPv4 forwarding successfully enabled.");
            Ok(())
        } else {
            let err_msg =
                "IPv4 forwarding path does not exist in sysfs (/proc/sys/net/ipv4/ip_forward)";
            error!("{}", err_msg);
            Err(NetbridgeError::ValidationFailed(err_msg.to_string()))
        }
    }

    /// Validates if IPv4 forwarding is currently active.
    pub fn is_forwarding_enabled(&self) -> Result<bool, NetbridgeError> {
        let path = "/proc/sys/net/ipv4/ip_forward";

        if Path::new(path).exists() {
            let content = fs::read_to_string(path).map_err(NetbridgeError::IoError)?;
            Ok(content.trim() == "1")
        } else {
            Ok(false)
        }
    }

    /// Disables IPv4 kernel forwarding.
    pub fn disable_forwarding(&self) -> Result<(), NetbridgeError> {
        info!("Disabling IPv4 kernel forwarding...");
        let path = "/proc/sys/net/ipv4/ip_forward";

        if Path::new(path).exists() {
            fs::write(path, "0\n").map_err(NetbridgeError::IoError)?;
            info!("IPv4 forwarding successfully disabled.");
            Ok(())
        } else {
            let err_msg =
                "IPv4 forwarding path does not exist in sysfs (/proc/sys/net/ipv4/ip_forward)";
            error!("{}", err_msg);
            Err(NetbridgeError::ValidationFailed(err_msg.to_string()))
        }
    }

    /// Ensures a default route exists for the given interface via its gateway.
    /// The Wi-Fi default stays lower priority than wired management traffic. Source-policy
    /// routing still sends hotspot clients and wlan0-bound health probes through table 200.
    pub fn ensure_default_route_for_interface(iface: &str) {
        let current = Command::new("ip")
            .args(["-4", "route", "show", "default", "dev", iface])
            .output();
        let current_routes = current
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
            .unwrap_or_default();
        if !current_routes.trim().is_empty() {
            return;
        }

        // Recover the gateway from any remaining route, then fall back to the
        // conventional first host in the DHCP subnet.
        let gw_out = Command::new("ip")
            .args(["-4", "route", "show", "dev", iface])
            .output();
        let mut gateway = gw_out.ok().and_then(|o| {
            let s = String::from_utf8_lossy(&o.stdout);
            s.lines().find_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let pos = parts.iter().position(|&x| x == "via")?;
                parts.get(pos + 1).map(|value| value.to_string())
            })
        });

        if gateway.is_none() {
            gateway = Self::interface_ipv4_cidr(iface)
                .and_then(|(ip, prefix)| inferred_gateway(ip, prefix))
                .map(|ip| ip.to_string());
        }

        let Some(gateway) = gateway else {
            return;
        };

        tracing::info!(
            target: "sgx_guardian_client::netbridge",
            "Recovering missing default route via {} on {}",
            gateway, iface
        );
        let output = Command::new("ip")
            .args([
                "-4", "route", "replace", "default", "via", &gateway, "dev", iface, "metric", "600",
            ])
            .output();
        if let Ok(output) = output {
            if !output.status.success() {
                tracing::warn!(
                    target: "sgx_guardian_client::netbridge",
                    "Failed to normalize default route on {}: {}",
                    iface,
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
        }
    }

    fn configure_multihoming_sysctls() -> Result<(), NetbridgeError> {
        // eth0 and wlan0 can share the same upstream subnet. Loose reverse-path
        // filtering permits replies on the policy-routed Wi-Fi path, while the ARP
        // settings stop the board advertising eth0's management IP on wlan0.
        for (path, value) in [
            ("/proc/sys/net/ipv4/conf/all/rp_filter", "2\n"),
            ("/proc/sys/net/ipv4/conf/all/arp_ignore", "1\n"),
            ("/proc/sys/net/ipv4/conf/all/arp_announce", "2\n"),
        ] {
            fs::write(path, value).map_err(NetbridgeError::IoError)?;
        }
        Ok(())
    }

    /// Pins traffic originating from the hotspot subnet to the configured Wi-Fi uplink.
    ///
    /// The board commonly has eth0 and wlan0 in the same upstream subnet. Keeping the
    /// main table unchanged preserves eth0 SSH, while this dedicated table guarantees
    /// that forwarded hotspot traffic and wlan0-bound probes actually leave via wlan0.
    pub fn configure_hotspot_uplink(
        hotspot_cidr: &str,
        uplink_iface: &str,
    ) -> Result<(), NetbridgeError> {
        let (uplink_ip, prefix) = Self::interface_ipv4_cidr(uplink_iface).ok_or_else(|| {
            NetbridgeError::ValidationFailed(format!(
                "{} has no usable IPv4 address for policy routing",
                uplink_iface
            ))
        })?;
        let uplink_network = network_cidr(uplink_ip, prefix).ok_or_else(|| {
            NetbridgeError::ValidationFailed(format!(
                "invalid IPv4 prefix {} on {}",
                prefix, uplink_iface
            ))
        })?;
        let gateway = Self::gateway_for_interface(uplink_iface)
            .or_else(|| inferred_gateway(uplink_ip, prefix))
            .ok_or_else(|| {
                NetbridgeError::ValidationFailed(format!(
                    "could not determine gateway for {}",
                    uplink_iface
                ))
            })?;

        Self::configure_multihoming_sysctls()?;
        Self::remove_hotspot_uplink();

        let policy_result = (|| {
            Self::run_ip(&[
                "-4",
                "route",
                "replace",
                &uplink_network,
                "dev",
                uplink_iface,
                "src",
                &uplink_ip.to_string(),
                "table",
                HOTSPOT_ROUTE_TABLE,
            ])?;
            Self::run_ip(&[
                "-4",
                "route",
                "replace",
                "default",
                "via",
                &gateway.to_string(),
                "dev",
                uplink_iface,
                "table",
                HOTSPOT_ROUTE_TABLE,
            ])?;
            Self::run_ip(&[
                "-4",
                "rule",
                "add",
                "priority",
                HOTSPOT_RULE_PRIORITY,
                "from",
                hotspot_cidr,
                "lookup",
                HOTSPOT_ROUTE_TABLE,
            ])?;
            Self::run_ip(&[
                "-4",
                "rule",
                "add",
                "priority",
                UPLINK_SOURCE_RULE_PRIORITY,
                "from",
                &format!("{}/32", uplink_ip),
                "lookup",
                HOTSPOT_ROUTE_TABLE,
            ])
        })();

        if let Err(error) = policy_result {
            Self::remove_hotspot_uplink();
            if !Self::is_operation_not_supported(&error) {
                return Err(error);
            }

            POLICY_ROUTING_UNSUPPORTED.store(true, Ordering::SeqCst);
            warn!(
                "Kernel policy routing is unavailable on {}. Forcing it as the main-table default route instead, since forwarded traffic cannot be scoped by source without FIB rules.",
                uplink_iface
            );
            Self::force_main_table_default(uplink_iface, &gateway.to_string())?;
            return Ok(());
        }

        POLICY_ROUTING_UNSUPPORTED.store(false, Ordering::SeqCst);

        info!(
            "Hotspot policy route active: {} -> table {} -> {} via {}",
            hotspot_cidr, HOTSPOT_ROUTE_TABLE, uplink_iface, gateway
        );
        Ok(())
    }

    /// Replaces the main table's default route so `uplink_iface` always wins the
    /// kernel's routing decision, regardless of other default routes the board
    /// carries (cellular, other Wi-Fi radio, etc.) at higher metrics. Used only
    /// when the kernel has no policy-routing support, so per-source scoping to a
    /// dedicated table is unavailable — this is the fallback that still lets
    /// forwarded hotspot traffic (and the board's own traffic) reach the intended
    /// uplink deterministically instead of racing an arbitrary competing route.
    fn force_main_table_default(uplink_iface: &str, gateway: &str) -> Result<(), NetbridgeError> {
        Self::run_ip(&[
            "-4",
            "route",
            "replace",
            "default",
            "via",
            gateway,
            "dev",
            uplink_iface,
            "metric",
            FORCED_DEFAULT_METRIC,
        ])?;
        if let Ok(mut forced) = FORCED_DEFAULT_IFACE.lock() {
            *forced = Some(uplink_iface.to_string());
        }
        info!(
            "Forced main-table default route: default via {} dev {} metric {}",
            gateway, uplink_iface, FORCED_DEFAULT_METRIC
        );
        Ok(())
    }

    pub fn hotspot_uplink_is_configured(hotspot_cidr: &str, uplink_iface: &str) -> bool {
        if POLICY_ROUTING_UNSUPPORTED.load(Ordering::SeqCst) {
            let output = Command::new("ip")
                .args(["-4", "route", "show", "default", "dev", uplink_iface])
                .output();
            let routes = match output {
                Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
                _ => return false,
            };
            return routes
                .lines()
                .any(|line| line.contains(&format!("metric {}", FORCED_DEFAULT_METRIC)));
        }

        let Some((uplink_ip, prefix)) = Self::interface_ipv4_cidr(uplink_iface) else {
            return false;
        };
        let Some(uplink_network) = network_cidr(uplink_ip, prefix) else {
            return false;
        };
        let Some(gateway) = Self::gateway_for_interface(uplink_iface)
            .or_else(|| inferred_gateway(uplink_ip, prefix))
        else {
            return false;
        };

        let rules = Command::new("ip").args(["-4", "rule", "show"]).output();
        let routes = Command::new("ip")
            .args(["-4", "route", "show", "table", HOTSPOT_ROUTE_TABLE])
            .output();
        let rules = match rules {
            Ok(output) if output.status.success() => {
                String::from_utf8_lossy(&output.stdout).into_owned()
            }
            _ => String::new(),
        };
        let routes = match routes {
            Ok(output) if output.status.success() => {
                String::from_utf8_lossy(&output.stdout).into_owned()
            }
            _ => String::new(),
        };
        rules.contains(&format!(
            "from {} lookup {}",
            hotspot_cidr, HOTSPOT_ROUTE_TABLE
        )) && rules.contains(&format!(
            "from {} lookup {}",
            uplink_ip, HOTSPOT_ROUTE_TABLE
        )) && routes.lines().any(|line| {
            line.starts_with("default ")
                && line.contains(&format!("via {}", gateway))
                && line.contains(&format!("dev {}", uplink_iface))
        }) && routes.lines().any(|line| {
            line.starts_with(&uplink_network)
                && line.contains(&format!("dev {}", uplink_iface))
                && line.contains(&format!("src {}", uplink_ip))
        })
    }

    pub fn remove_hotspot_uplink() {
        for priority in [HOTSPOT_RULE_PRIORITY, UPLINK_SOURCE_RULE_PRIORITY] {
            // Remove duplicates too, including any left by an interrupted previous run.
            for _ in 0..8 {
                let Ok(output) = Command::new("ip")
                    .args(["-4", "rule", "del", "priority", priority])
                    .output()
                else {
                    break;
                };
                if !output.status.success() {
                    break;
                }
            }
        }
        let _ = Command::new("ip")
            .args(["-4", "route", "flush", "table", HOTSPOT_ROUTE_TABLE])
            .output();

        let forced_iface = FORCED_DEFAULT_IFACE
            .lock()
            .ok()
            .and_then(|mut forced| forced.take());
        if let Some(iface) = forced_iface {
            let _ = Command::new("ip")
                .args([
                    "-4",
                    "route",
                    "del",
                    "default",
                    "dev",
                    &iface,
                    "metric",
                    FORCED_DEFAULT_METRIC,
                ])
                .output();
        }
    }

    fn is_operation_not_supported(error: &NetbridgeError) -> bool {
        error.to_string().contains("Operation not supported")
    }

    fn interface_ipv4_cidr(iface: &str) -> Option<(Ipv4Addr, u8)> {
        let output = Command::new("ip")
            .args(["-4", "addr", "show", "dev", iface])
            .output()
            .ok()?;
        parse_interface_cidr(&String::from_utf8_lossy(&output.stdout))
    }

    fn gateway_for_interface(iface: &str) -> Option<Ipv4Addr> {
        let output = Command::new("ip")
            .args(["-4", "route", "show", "default", "dev", iface])
            .output()
            .ok()?;
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let pos = parts.iter().position(|part| *part == "via")?;
                parts.get(pos + 1)?.parse().ok()
            })
    }

    fn run_ip(args: &[&str]) -> Result<(), NetbridgeError> {
        let output = Command::new("ip")
            .args(args)
            .output()
            .map_err(NetbridgeError::IoError)?;
        if output.status.success() {
            return Ok(());
        }

        Err(NetbridgeError::ProcessExecutionFailed(format!(
            "ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{inferred_gateway, network_cidr, parse_interface_cidr, RoutingManager};
    use crate::netbridge::types::NetbridgeError;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_primary_interface_address() {
        let output = "5: wlan0: <UP>\n    inet 192.168.1.200/24 scope global wlan0\n";
        assert_eq!(
            parse_interface_cidr(output),
            Some((Ipv4Addr::new(192, 168, 1, 200), 24))
        );
    }

    #[test]
    fn calculates_network_and_fallback_gateway() {
        let ip = Ipv4Addr::new(192, 168, 1, 200);
        assert_eq!(network_cidr(ip, 24).as_deref(), Some("192.168.1.0/24"));
        assert_eq!(
            inferred_gateway(ip, 24),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn recognizes_kernel_without_policy_routing() {
        let error = NetbridgeError::ProcessExecutionFailed(
            "RTNETLINK answers: Operation not supported".to_string(),
        );
        assert!(RoutingManager::is_operation_not_supported(&error));
    }

    #[test]
    fn does_not_misclassify_unrelated_process_errors() {
        let error =
            NetbridgeError::ProcessExecutionFailed("ip route replace: File exists".to_string());
        assert!(!RoutingManager::is_operation_not_supported(&error));

        let io_error = NetbridgeError::ValidationFailed("missing interface".to_string());
        assert!(!RoutingManager::is_operation_not_supported(&io_error));
    }

    #[test]
    fn parse_interface_cidr_returns_none_without_an_inet_line() {
        let output = "5: wlan0: <UP>\n    inet6 fe80::1/64 scope link\n";
        assert_eq!(parse_interface_cidr(output), None);
        assert_eq!(parse_interface_cidr(""), None);
    }

    #[test]
    fn parse_interface_cidr_skips_malformed_lines_and_finds_the_first_valid_one() {
        // The first "inet " line is missing the CIDR prefix and must be skipped;
        // the parser should fall through to the next well-formed line.
        let output = "\
5: wlan0: <UP>
    inet 192.168.1.200 scope global wlan0
    inet 10.0.0.5/16 scope global secondary wlan0
";
        assert_eq!(
            parse_interface_cidr(output),
            Some((Ipv4Addr::new(10, 0, 0, 5), 16))
        );
    }

    #[test]
    fn network_cidr_handles_prefix_boundaries() {
        let ip = Ipv4Addr::new(192, 168, 1, 200);
        assert_eq!(network_cidr(ip, 0).as_deref(), Some("0.0.0.0/0"));
        assert_eq!(network_cidr(ip, 32).as_deref(), Some("192.168.1.200/32"));
        assert_eq!(network_cidr(ip, 33), None);
    }

    #[test]
    fn inferred_gateway_is_none_for_point_to_point_and_host_prefixes() {
        let ip = Ipv4Addr::new(192, 168, 1, 200);
        assert_eq!(inferred_gateway(ip, 31), None);
        assert_eq!(inferred_gateway(ip, 32), None);
        assert_eq!(
            inferred_gateway(ip, 30),
            Some(Ipv4Addr::new(192, 168, 1, 201))
        );
    }

    #[test]
    fn routing_manager_constructors_are_usable() {
        let _explicit = RoutingManager::new();
        let _default = RoutingManager;
    }
}

/// Tests that drive the real `ip` binary and the real sysctl paths.
///
/// Every mutating call in this file needs `CAP_NET_ADMIN` (or root), so under a
/// normal unprivileged test run each one fails deterministically — `ip route
/// add` answers `Operation not permitted`, `fs::write` to `/proc/sys/...`
/// answers `EACCES`. That is a real, reproducible outcome rather than a mock,
/// and it is the outcome this code actually has to survive on a board where
/// the daemon has been dropped from root. The read-only queries (`ip addr
/// show`, `ip route show`, `ip rule show`) succeed for real, so the parsing and
/// decision logic downstream of them runs against genuine kernel output.
///
/// The handful of assertions whose expected result differs under root are
/// gated on [`unprivileged`] and skip rather than assert the wrong thing.
#[cfg(test)]
mod live_ip_tests {
    use super::{
        RoutingManager, HOTSPOT_ROUTE_TABLE, POLICY_ROUTING_UNSUPPORTED,
        UPLINK_SOURCE_RULE_PRIORITY,
    };
    use crate::netbridge::types::NetbridgeError;
    use std::net::Ipv4Addr;
    use std::process::Command;
    use std::sync::atomic::Ordering;
    use std::sync::{Mutex, MutexGuard};

    const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
    const MISSING_IFACE: &str = "sgxtest-nodev0";

    /// `POLICY_ROUTING_UNSUPPORTED` is process-global, so the tests that read or
    /// write it must not interleave with each other.
    static POLICY_FLAG_LOCK: Mutex<()> = Mutex::new(());

    fn policy_flag_lock() -> MutexGuard<'static, ()> {
        POLICY_FLAG_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// True when this process cannot write the forwarding sysctl — i.e. the
    /// ordinary case, and the one whose failure paths these tests assert.
    fn unprivileged() -> bool {
        std::fs::OpenOptions::new()
            .write(true)
            .open(IP_FORWARD)
            .is_err()
    }

    fn have_ip() -> bool {
        Command::new("ip").arg("-V").output().is_ok()
    }

    /// The interface carrying this host's real default route, if any.
    fn default_route_interface() -> Option<String> {
        let output = Command::new("ip")
            .args(["-4", "route", "show", "default"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.lines().find_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let pos = parts.iter().position(|part| *part == "dev")?;
            parts.get(pos + 1).map(|value| value.to_string())
        })
    }

    #[test]
    fn enable_forwarding_surfaces_the_unprivileged_write_refusal() {
        if !unprivileged() {
            return;
        }
        let error = RoutingManager::new()
            .enable_forwarding()
            .expect_err("writing the forwarding sysctl must fail without privileges");
        // The path exists on every Linux host, so this is the IO branch rather
        // than the "sysfs entry missing" validation branch.
        assert!(
            matches!(error, NetbridgeError::IoError(_)),
            "expected an IO error, got {error:?}"
        );
    }

    #[test]
    fn disable_forwarding_surfaces_the_unprivileged_write_refusal() {
        if !unprivileged() {
            return;
        }
        let error = RoutingManager::new()
            .disable_forwarding()
            .expect_err("clearing the forwarding sysctl must fail without privileges");
        assert!(
            matches!(error, NetbridgeError::IoError(_)),
            "expected an IO error, got {error:?}"
        );
    }

    #[test]
    fn is_forwarding_enabled_reports_the_live_sysctl_value() {
        let live = std::fs::read_to_string(IP_FORWARD).expect("sysctl readable");
        assert_eq!(
            RoutingManager::new().is_forwarding_enabled().unwrap(),
            live.trim() == "1"
        );
    }

    #[test]
    fn interface_ipv4_cidr_parses_loopback_and_rejects_an_absent_interface() {
        if !have_ip() {
            return;
        }
        // `lo` always carries 127.0.0.1/8 as its first inet line.
        assert_eq!(
            RoutingManager::interface_ipv4_cidr("lo"),
            Some((Ipv4Addr::new(127, 0, 0, 1), 8))
        );
        // A missing device makes `ip` exit non-zero with empty stdout: the call
        // still succeeds, and the parse returns None.
        assert_eq!(RoutingManager::interface_ipv4_cidr(MISSING_IFACE), None);
    }

    #[test]
    fn gateway_for_interface_is_none_when_the_interface_has_no_default_route() {
        if !have_ip() {
            return;
        }
        assert_eq!(RoutingManager::gateway_for_interface("lo"), None);
        assert_eq!(RoutingManager::gateway_for_interface(MISSING_IFACE), None);
    }

    #[test]
    fn gateway_for_interface_reads_the_real_default_route() {
        let Some(iface) = default_route_interface() else {
            return; // no default route on this host
        };
        let gateway = RoutingManager::gateway_for_interface(&iface);
        // A default route printed with `via` must parse; one without (a
        // point-to-point link) legitimately yields None.
        let raw = Command::new("ip")
            .args(["-4", "route", "show", "default", "dev", &iface])
            .output()
            .expect("ip route show");
        let has_via = String::from_utf8_lossy(&raw.stdout).contains(" via ");
        assert_eq!(gateway.is_some(), has_via);
    }

    #[test]
    fn run_ip_distinguishes_a_read_only_query_from_a_refused_mutation() {
        if !have_ip() {
            return;
        }
        RoutingManager::run_ip(&["-4", "route", "show"]).expect("a read-only query must succeed");

        if !unprivileged() {
            return;
        }
        let error = RoutingManager::run_ip(&[
            "-4",
            "rule",
            "add",
            "priority",
            UPLINK_SOURCE_RULE_PRIORITY,
            "from",
            "10.255.254.0/24",
            "lookup",
            HOTSPOT_ROUTE_TABLE,
        ])
        .expect_err("adding a policy rule must be refused without CAP_NET_ADMIN");
        match error {
            NetbridgeError::ProcessExecutionFailed(message) => {
                assert!(
                    message.starts_with("ip -4 rule add"),
                    "the failure must name the exact argv: {message}"
                );
                assert!(
                    message.contains("not permitted") || message.contains("not supported"),
                    "expected the kernel's refusal in the message: {message}"
                );
            }
            other => panic!("expected a process failure, got {other:?}"),
        }
    }

    #[test]
    fn remove_hotspot_uplink_is_a_safe_no_op_without_privileges() {
        if !have_ip() {
            return;
        }
        // Both `rule del` calls are refused on the first iteration, so each
        // loop breaks immediately; the table flush is discarded either way.
        // Running it twice proves it is idempotent and never panics.
        RoutingManager::remove_hotspot_uplink();
        RoutingManager::remove_hotspot_uplink();
    }

    #[test]
    fn ensure_default_route_falls_back_to_the_inferred_gateway() {
        if !have_ip() || !unprivileged() {
            return;
        }
        // `lo` has no default route and no `via` on any of its routes, so the
        // gateway is inferred from 127.0.0.1/8 and the `route replace` that
        // follows is refused — exercising the whole recovery path plus its
        // failure-logging tail without changing this host's routing table.
        RoutingManager::ensure_default_route_for_interface("lo");

        // A device that does not exist yields no routes and no address, so the
        // function returns at the `let Some(gateway) else` guard.
        RoutingManager::ensure_default_route_for_interface(MISSING_IFACE);
    }

    #[test]
    fn ensure_default_route_returns_early_when_one_already_exists() {
        let Some(iface) = default_route_interface() else {
            return;
        };
        let before = Command::new("ip")
            .args(["-4", "route", "show", "default", "dev", &iface])
            .output()
            .expect("ip route show");
        RoutingManager::ensure_default_route_for_interface(&iface);
        let after = Command::new("ip")
            .args(["-4", "route", "show", "default", "dev", &iface])
            .output()
            .expect("ip route show");
        assert_eq!(
            before.stdout, after.stdout,
            "an interface that already has a default route must be left untouched"
        );
    }

    #[test]
    fn configure_hotspot_uplink_rejects_an_interface_without_an_address() {
        if !have_ip() {
            return;
        }
        let error = RoutingManager::configure_hotspot_uplink("10.42.0.0/24", MISSING_IFACE)
            .expect_err("an interface with no IPv4 address cannot be policy-routed");
        match error {
            NetbridgeError::ValidationFailed(message) => assert!(
                message.contains(MISSING_IFACE) && message.contains("no usable IPv4"),
                "unexpected validation message: {message}"
            ),
            other => panic!("expected a validation failure, got {other:?}"),
        }
    }

    #[test]
    fn configure_hotspot_uplink_stops_at_the_multihoming_sysctls_without_privileges() {
        if !have_ip() || !unprivileged() {
            return;
        }
        // `lo` resolves an address (127.0.0.1/8), a network (127.0.0.0/8) and
        // an inferred gateway (127.0.0.1), so the call gets as far as the
        // multihoming sysctls — which an unprivileged process cannot write.
        // Nothing is added to the routing table before that point.
        let error = RoutingManager::configure_hotspot_uplink("10.42.0.0/24", "lo")
            .expect_err("the rp_filter/arp sysctl writes must be refused");
        assert!(
            matches!(error, NetbridgeError::IoError(_)),
            "expected the sysctl write to fail with an IO error, got {error:?}"
        );
    }

    #[test]
    fn hotspot_uplink_is_configured_checks_for_the_forced_route_when_policy_routing_is_unsupported()
    {
        let _guard = policy_flag_lock();
        let previous = POLICY_ROUTING_UNSUPPORTED.load(Ordering::SeqCst);
        POLICY_ROUTING_UNSUPPORTED.store(true, Ordering::SeqCst);
        // On a kernel without policy routing, `configure_hotspot_uplink` instead
        // forces a metric-1 default route on the uplink interface (see
        // `force_main_table_default`), and this check verifies that route is
        // still present rather than trusting in-memory state alone (another
        // process could have replaced it). A nonexistent interface can never
        // carry such a route, so the honest answer here is false.
        assert!(!RoutingManager::hotspot_uplink_is_configured(
            "10.42.0.0/24",
            MISSING_IFACE
        ));
        POLICY_ROUTING_UNSUPPORTED.store(previous, Ordering::SeqCst);
    }

    #[test]
    fn hotspot_uplink_is_configured_is_false_without_the_rules_and_routes() {
        if !have_ip() {
            return;
        }
        let _guard = policy_flag_lock();
        let previous = POLICY_ROUTING_UNSUPPORTED.load(Ordering::SeqCst);
        POLICY_ROUTING_UNSUPPORTED.store(false, Ordering::SeqCst);

        // No address at all: fails at the first guard.
        assert!(!RoutingManager::hotspot_uplink_is_configured(
            "10.42.0.0/24",
            MISSING_IFACE
        ));
        // `lo` resolves an address, network and inferred gateway, so both `ip`
        // queries run for real; table 200 is empty here, so the rule and route
        // assertions all fail and the answer is false.
        assert!(!RoutingManager::hotspot_uplink_is_configured(
            "10.42.0.0/24",
            "lo"
        ));

        POLICY_ROUTING_UNSUPPORTED.store(previous, Ordering::SeqCst);
    }
}
