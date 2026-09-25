//! CA-only LAN presence advertiser (P3.2). See the parent module doc for the
//! presence/proof split this relies on — nothing broadcast here is trusted
//! on its own.

use crate::mesh::ca::server;
use crate::mesh::discovery::{beacon_port, descriptor_port, CaBeacon};
use crate::mesh::profile::{MeshProfile, MeshRole};
use libmdns::Responder;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

const BEACON_INTERVAL: Duration = Duration::from_secs(5);

/// Runs for as long as this Guardian is a CA — call once, `tokio::spawn`ed,
/// after `activate_mesh` reaches `ONLINE`. Never returns in the CA case
/// (mirrors every other long-running task `activate_mesh` starts); returns
/// immediately for a `Member`, so it is safe to call unconditionally from
/// the call site and let this function decide whether it has anything to do.
///
/// mDNS registration deliberately stays a local variable in *this* same
/// function rather than being moved into a nested `tokio::spawn` — `libmdns`
/// gives no `Send` guarantee for `Responder`/`Service`, and every existing
/// caller of it in this codebase (`p2p_discovery.rs`) keeps it in the
/// enclosing async scope for the same reason. The beacon loop below runs in
/// this same scope for exactly that reason, not just convenience.
pub async fn run(profile: Arc<MeshProfile>, lan_ip: String) {
    if !matches!(profile.role, MeshRole::Ca) {
        return;
    }

    let descriptor_addr = format!("{}:{}", lan_ip, descriptor_port());

    // Best-effort: a LAN that blocks multicast (or a sandboxed/dev container
    // with no multicast-capable interface) still has to work via the
    // CaBeacon below, so a responder failure here is logged, not fatal.
    let _mdns_guard = match Responder::new() {
        Ok(responder) => {
            let service = responder.register(
                "_sgx-ca._tcp".to_string(),
                profile.circle_name.clone(),
                descriptor_port(),
                &[&format!("circle_id={}", profile.circle_id)],
            );
            println!(
                "✅ mDNS _sgx-ca._tcp registered for circle {} ({})",
                profile.circle_name, profile.circle_id
            );
            Some((responder, service))
        }
        Err(e) => {
            eprintln!(
                "⚠️ mDNS responder unavailable for CA advertising (continuing via CaBeacon only): {e}"
            );
            None
        }
    };

    let descriptor_profile = profile.clone();
    let descriptor_bind = descriptor_addr.clone();
    tokio::spawn(async move {
        if let Err(e) = server::serve_forever(descriptor_profile, descriptor_bind).await {
            eprintln!("⚠️ CA enrollment/descriptor listener stopped: {e}");
        }
    });

    run_beacon(profile, descriptor_addr).await;
    // Unreachable in practice (`run_beacon` loops forever), but keeps the
    // mDNS guard's lifetime tied to this function's, not to whichever branch
    // happened to run first.
    drop(_mdns_guard);
}

async fn run_beacon(profile: Arc<MeshProfile>, lan_endpoint: String) {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("⚠️ CaBeacon socket bind failed: {e}");
            return;
        }
    };
    if let Err(e) = socket.set_broadcast(true) {
        eprintln!("⚠️ CaBeacon set_broadcast failed: {e}");
        return;
    }

    let beacon = CaBeacon::new(
        profile.circle_id.clone(),
        profile.guardian_id.clone(),
        lan_endpoint,
    );
    let bytes = match serde_json::to_vec(&beacon) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("⚠️ CaBeacon serialize failed: {e}");
            return;
        }
    };
    let target = SocketAddrV4::new(Ipv4Addr::BROADCAST, beacon_port());

    loop {
        if let Err(e) = socket.send_to(&bytes, target).await {
            eprintln!("⚠️ CaBeacon send failed: {e}");
        }
        tokio::time::sleep(BEACON_INTERVAL).await;
    }
}
