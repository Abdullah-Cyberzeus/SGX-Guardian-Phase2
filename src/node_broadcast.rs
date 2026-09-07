use crate::node_announcement::NodeAnnouncement;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

fn broadcast_port() -> u16 {
    std::env::var("SGX_BROADCAST_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9000)
}

fn subnet_broadcast(local_ip: &str) -> Ipv4Addr {
    let ip: Ipv4Addr = match local_ip.parse() {
        Ok(ip) => ip,
        Err(_) => return Ipv4Addr::BROADCAST,
    };

    let mask = read_netmask_for_ip(local_ip).unwrap_or(Ipv4Addr::new(255, 255, 255, 0));
    let ip_o = ip.octets();
    let mask_o = mask.octets();

    Ipv4Addr::new(
        ip_o[0] | !mask_o[0],
        ip_o[1] | !mask_o[1],
        ip_o[2] | !mask_o[2],
        ip_o[3] | !mask_o[3],
    )
}

fn read_netmask_for_ip(target_ip: &str) -> Option<Ipv4Addr> {
    use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};

    let interfaces = NetworkInterface::show().ok()?;
    for iface in interfaces {
        for addr in &iface.addr {
            if let Addr::V4(v4) = addr {
                if v4.ip.to_string() == target_ip {
                    return v4.netmask;
                }
            }
        }
    }
    None
}

pub fn broadcast_node(info: &NodeAnnouncement) {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Broadcast bind failed: {}", e);
            return;
        }
    };

    if let Err(e) = socket.set_broadcast(true) {
        eprintln!("set_broadcast failed: {}", e);
        return;
    }

    let data = match serde_json::to_string(info) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("JSON serialize failed: {}", e);
            return;
        }
    };

    let bytes = data.as_bytes();
    let port = broadcast_port();

    let bcast_ip = subnet_broadcast(&info.ip);
    let subnet_addr = SocketAddrV4::new(bcast_ip, port);
    match socket.send_to(bytes, subnet_addr) {
        Ok(n) => tracing::debug!("Broadcasted to {} ({} bytes)", subnet_addr, n),
        Err(e) => tracing::warn!("Broadcast send failed: {}", e),
    }

    let global_addr = SocketAddrV4::new(Ipv4Addr::BROADCAST, port);
    match socket.send_to(bytes, global_addr) {
        Ok(n) => tracing::debug!("Global broadcast to {} ({} bytes)", global_addr, n),
        Err(e) => tracing::warn!("Global broadcast send failed: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_broadcast_port_defaults_and_falls_back_on_unparseable_values() {
        let _lock = crate::test_support::blocking_env_lock();
        const KEY: &str = "SGX_BROADCAST_PORT";
        let previous = std::env::var_os(KEY);

        std::env::remove_var(KEY);
        assert_eq!(broadcast_port(), 9000);
        std::env::set_var(KEY, "9100");
        assert_eq!(broadcast_port(), 9100);
        for value in ["", "not-a-port", "70000", "-1"] {
            std::env::set_var(KEY, value);
            assert_eq!(broadcast_port(), 9000, "{value:?}");
        }

        match previous {
            Some(value) => std::env::set_var(KEY, value),
            None => std::env::remove_var(KEY),
        }
    }

    #[test]
    fn an_unparseable_local_address_falls_back_to_the_global_broadcast() {
        // Better to reach the whole link than to compute a bogus subnet
        // address that silently reaches nothing.
        assert_eq!(subnet_broadcast("not-an-ip"), Ipv4Addr::BROADCAST);
        assert_eq!(subnet_broadcast(""), Ipv4Addr::BROADCAST);
        assert_eq!(subnet_broadcast("::1"), Ipv4Addr::BROADCAST);
    }

    #[test]
    fn a_parseable_address_yields_its_subnet_broadcast() {
        // No interface in the test environment carries these addresses, so the
        // documented /24 default mask applies.
        assert_eq!(
            subnet_broadcast("192.168.1.20"),
            Ipv4Addr::new(192, 168, 1, 255)
        );
        assert_eq!(subnet_broadcast("10.4.3.2"), Ipv4Addr::new(10, 4, 3, 255));
    }

    #[test]
    fn no_netmask_is_found_for_an_address_this_host_does_not_hold() {
        assert!(read_netmask_for_ip("203.0.113.99").is_none());
        assert!(read_netmask_for_ip("not-an-ip").is_none());
    }

    #[test]
    fn broadcasting_an_announcement_completes_without_panicking() {
        // Sends on an ephemeral socket to the link broadcast address: send
        // failures are logged and swallowed, so this asserts the whole path
        // stays panic-free including the serialize and both send_to calls.
        let announcement = NodeAnnouncement::new_signed(
            "nodeB".to_string(),
            "nodeb.guardian".to_string(),
            "192.168.1.20".to_string(),
            50052,
            "peer-public-key".to_string(),
        );

        broadcast_node(&announcement);
    }

    #[test]
    fn broadcasting_tolerates_an_announcement_with_an_invalid_address() {
        let announcement = NodeAnnouncement::new_signed(
            "nodeC".to_string(),
            "nodec.guardian".to_string(),
            "not-an-ip".to_string(),
            50053,
            "peer-public-key".to_string(),
        );

        broadcast_node(&announcement);
    }
}
