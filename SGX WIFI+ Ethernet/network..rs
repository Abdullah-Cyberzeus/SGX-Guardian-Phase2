use local_ip_address::local_ip;
use std::net::IpAddr;

/// Detect local machine IP dynamically
pub fn get_local_ip() -> IpAddr {
    match local_ip() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("⚠️ Failed to detect local IP, falling back to 127.0.0.1");
            "127.0.0.1".parse().unwrap()
        }
    }
}