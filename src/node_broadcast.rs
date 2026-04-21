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
        Ok(_) => {} // Silent — reduces UART flood on boards
        Err(e) => eprintln!("Subnet broadcast failed: {}", e),
    }

    let global_addr = SocketAddrV4::new(Ipv4Addr::BROADCAST, port);
    match socket.send_to(bytes, global_addr) {
        Ok(_) => {} // Silent — reduces UART flood on boards
        Err(e) => eprintln!("Global broadcast failed: {}", e),
    }
}
