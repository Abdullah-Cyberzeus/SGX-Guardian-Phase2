use crate::dynamic_config;
use crate::node_announcement::NodeAnnouncement;
use std::collections::HashMap;
use std::net::UdpSocket as StdUdpSocket;
use std::time::Instant;
use tokio::net::UdpSocket;

const RATE_LIMIT_PER_MINUTE: usize = 10;
const DEDUP_INTERVAL_SECS: u64 = 25;

fn listen_port() -> u16 {
    std::env::var("SGX_BROADCAST_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9000)
}

pub async fn start_listener(local_node_id: String) {
    let port = listen_port();
    let bind_addr = format!("0.0.0.0:{}", port);

    let std_socket = match StdUdpSocket::bind(&bind_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Port {} bind failed: {}", port, e);
            return;
        }
    };

    std_socket
        .set_broadcast(true)
        .expect("set_broadcast failed");
    std_socket
        .set_nonblocking(true)
        .expect("set_nonblocking failed");
    let socket = UdpSocket::from_std(std_socket).expect("tokio socket conversion failed");

    println!("Listener ready on {} (SO_BROADCAST enabled)", bind_addr);

    let mut buf = [0u8; 8192];
    let mut rate_map: HashMap<String, (usize, Instant)> = HashMap::new();
    let mut dedup_map: HashMap<String, Instant> = HashMap::new();

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((size, src)) => {
                let src_ip = src.ip().to_string();
                let now = Instant::now();

                let entry = rate_map.entry(src_ip.clone()).or_insert((0, now));
                if now.duration_since(entry.1).as_secs() > 60 {
                    *entry = (1, now);
                } else {
                    entry.0 += 1;
                    if entry.0 > RATE_LIMIT_PER_MINUTE {
                        continue;
                    }
                }

                let msg = match std::str::from_utf8(&buf[..size]) {
                    Ok(s) => s.trim().to_string(),
                    Err(_) => continue,
                };

                match serde_json::from_str::<NodeAnnouncement>(&msg) {
                    Ok(peer) => {
                        if peer.node_id.trim() == local_node_id.trim() {
                            continue;
                        }

                        if !peer.verify_integrity() {
                            eprintln!("Rejected {} integrity check failed", peer.node_id);
                            continue;
                        }

                        if !dynamic_config::is_routable_ip(&peer.ip) {
                            eprintln!("Ignoring {} non-routable IP: {}", peer.node_id, peer.ip);
                            continue;
                        }

                        let should_write = match dedup_map.get(&peer.node_id) {
                            Some(last) => now.duration_since(*last).as_secs() > DEDUP_INTERVAL_SECS,
                            None => true,
                        };

                        if should_write {
                            println!("Peer announcement received: {}", peer.node_id);
                            dedup_map.insert(peer.node_id.clone(), now);

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
                    }
                    Err(e) => eprintln!("JSON parse failed from {}: {}", src, e),
                }
            }
            Err(e) => {
                eprintln!("recv_from error: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }
        }
    }
}
