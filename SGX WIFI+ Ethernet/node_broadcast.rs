// node_broadcast.rs — FIXED VERSION
// ================================================================
// Changes:
//   1. Broadcast address apni detected IP se calculate hoti hai
//      (hardcoded 192.168.0.255 hata diya)
//   2. Global broadcast 255.255.255.255 bhi bhejte hain (fallback)
//   3. Clear error messages
// ================================================================

use std::net::{UdpSocket, SocketAddrV4, Ipv4Addr};
use crate::node_announcement::NodeAnnouncement;

/// Node ki IP se subnet broadcast address calculate karo
/// Example: 192.168.0.142 → 192.168.0.255
///          10.0.1.5       → 10.0.1.255
fn subnet_broadcast(local_ip: &str) -> Ipv4Addr {
    if let Ok(ip) = local_ip.parse::<Ipv4Addr>() {
        let o = ip.octets();
        // /24 subnet assume karo (most home/office LANs)
        return Ipv4Addr::new(o[0], o[1], o[2], 255);
    }
    // Fallback — global broadcast
    Ipv4Addr::BROADCAST
}

pub fn broadcast_node(info: &NodeAnnouncement) {
    // Binding 0.0.0.0:0 — OS random ephemeral port assign karta hai
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Broadcast socket bind failed: {}", e);
            return;
        }
    };

    // SO_BROADCAST — SEND side par bhi zaroori hai
    if let Err(e) = socket.set_broadcast(true) {
        eprintln!("❌ set_broadcast failed: {}", e);
        return;
    }

    let data = match serde_json::to_string(info) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("❌ JSON serialize failed: {}", e);
            return;
        }
    };

    let bytes = data.as_bytes();

    // Target 1: Subnet broadcast (apni IP se calculate)
    let bcast_ip = subnet_broadcast(&info.ip);
    let subnet_addr = SocketAddrV4::new(bcast_ip, 9000);

    match socket.send_to(bytes, subnet_addr) {
        Ok(n) => println!("📡 Broadcasted to {} ({} bytes)", subnet_addr, n),
        Err(e) => eprintln!("❌ Subnet broadcast failed to {}: {}", subnet_addr, e),
    }

    // Target 2: Global broadcast (255.255.255.255) — VMware fallback
    let global_addr = SocketAddrV4::new(Ipv4Addr::BROADCAST, 9000);
    match socket.send_to(bytes, global_addr) {
        Ok(n) => println!("📡 Broadcasted to {} ({} bytes)", global_addr, n),
        Err(e) => eprintln!("⚠️  Global broadcast failed to {}: {}", global_addr, e),
    }
}