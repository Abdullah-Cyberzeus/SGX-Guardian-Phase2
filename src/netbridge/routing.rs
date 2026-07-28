use crate::netbridge::types::NetbridgeError;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{error, info};

const HOTSPOT_ROUTE_TABLE: &str = "200";
const HOTSPOT_RULE_PRIORITY: &str = "22000";
const UPLINK_SOURCE_RULE_PRIORITY: &str = "22001";
static POLICY_ROUTING_UNSUPPORTED: AtomicBool = AtomicBool::new(false);

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
            tracing::warn!(
                "Kernel policy routing is unavailable on {}. Preserving the main routing table; NAT will follow the active egress.",
                uplink_iface
            );
            return Ok(());
        }

        POLICY_ROUTING_UNSUPPORTED.store(false, Ordering::SeqCst);

        info!(
            "Hotspot policy route active: {} -> table {} -> {} via {}",
            hotspot_cidr, HOTSPOT_ROUTE_TABLE, uplink_iface, gateway
        );
        Ok(())
    }

    pub fn hotspot_uplink_is_configured(hotspot_cidr: &str, uplink_iface: &str) -> bool {
        if POLICY_ROUTING_UNSUPPORTED.load(Ordering::SeqCst) {
            return true;
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
}
