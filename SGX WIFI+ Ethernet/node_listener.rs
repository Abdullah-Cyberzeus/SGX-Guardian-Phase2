// node_listener.rs — FIXED VERSION
// ================================================================
// Problem: tokio::net::UdpSocket bind("0.0.0.0:9000") on Linux/VMware
// does NOT receive broadcast packets by default because:
//   1. SO_BROADCAST not set on receive socket
//   2. SO_REUSEADDR not set (only one process can bind)
//   3. Tokio wraps std socket but doesn't set these options
//
// Fix: Use std::net::UdpSocket with manual socket options,
//      then convert to tokio for async recv.
// ================================================================

use std::net::UdpSocket as StdUdpSocket;
use tokio::net::UdpSocket;
use crate::node_announcement::NodeAnnouncement;
use crate::dynamic_config;

pub async fn start_listener(local_node_id: String) {

    // Step 1: std socket banao — options set karne ke liye
    let std_socket = StdUdpSocket::bind("0.0.0.0:9000")
        .expect("❌ Port 9000 bind failed — already in use? Try: sudo ss -ulpn | grep 9000");

    // Step 2: SO_BROADCAST enable karo — broadcast receive ke liye ZAROORI hai
    std_socket.set_broadcast(true)
        .expect("set_broadcast failed");

    // Step 3: Non-blocking set karo — tokio ki requirement
    std_socket.set_nonblocking(true)
        .expect("set_nonblocking failed");

    // Step 4: std socket ko tokio socket mein convert karo
    let socket = UdpSocket::from_std(std_socket)
        .expect("tokio UdpSocket conversion failed");

    println!("📡 Listener ready on 0.0.0.0:9000 (SO_BROADCAST enabled)");

    // Buffer size 8KB — large public keys + JSON overhead ke liye
    let mut buf = [0u8; 8192];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((size, src)) => {

                // Raw bytes ko string mein convert karo
                let msg = match std::str::from_utf8(&buf[..size]) {
                    Ok(s) => s.trim().to_string(),
                    Err(e) => {
                        eprintln!("❌ UTF-8 decode error from {}: {}", src, e);
                        continue;
                    }
                };

                println!("📥 Packet from {} ({} bytes)", src, size);

                // JSON parse karo
                match serde_json::from_str::<NodeAnnouncement>(&msg) {
                    Ok(peer) => {

                        // Apna khud ka broadcast ignore karo
                        // trim() important hai — YAML se loaded strings mein
                        // kabhi kabhi trailing whitespace hoti hai
                        if peer.node_id.trim() == local_node_id.trim() {
                            println!("🔁 Own broadcast ignored ({})", peer.node_id);
                            continue;
                        }

                        // Non-routable IPs reject karo (0.0.0.0, 127.x, etc)
                        if !dynamic_config::is_routable_ip(&peer.ip) {
                            eprintln!(
                                "⚠️  Ignoring {} — non-routable IP: {}",
                                peer.node_id, peer.ip
                            );
                            continue;
                        }

                        println!(
                            "🌐 Peer discovered: {} @ {}:{}",
                            peer.node_id, peer.ip, peer.port
                        );

                        // File write blocking hai — spawn_blocking mein karo
                        // taake async runtime block na ho
                        let peer_clone = peer.clone();
                        tokio::task::spawn_blocking(move || {
                            dynamic_config::update_peer_config(
                                &peer_clone.node_id,
                                &peer_clone.hostname,
                                &peer_clone.ip,
                                peer_clone.port,
                                &peer_clone.public_key,
                            );
                        });
                    }

                    Err(e) => {
                        eprintln!("❌ JSON parse failed from {}: {}", src, e);
                        // Debug ke liye first 300 chars print karo
                        let preview: String = msg.chars().take(300).collect();
                        eprintln!("   Preview: {:?}", preview);
                    }
                }
            }

            Err(e) => {
                eprintln!("❌ recv_from error: {}", e);
                // Thoda wait karo — tight loop se CPU spike hoga
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }
        }
    }
}