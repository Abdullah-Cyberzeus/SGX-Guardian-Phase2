//! Joiner-side LAN scan (P3.3). See the parent module doc for why only the
//! `CaDescriptor` fetch-and-verify step (not the beacon that pointed at it)
//! determines [`DiscoveredCa::verified`].

use super::{beacon_port, fingerprint_words, CaBeacon, DiscoveredCa, CA_BEACON_MAGIC};
use crate::mesh::ca::descriptor::CaDescriptorBundle;
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::net::UdpSocket;

/// P3.3's own number: "5 s collection window."
pub const COLLECTION_WINDOW: Duration = Duration::from_secs(5);
const FETCH_TIMEOUT: Duration = Duration::from_secs(3);

/// Runs one full LAN scan: listens for `CaBeacon`s for [`COLLECTION_WINDOW`],
/// fetches and verifies each distinct advertised endpoint's descriptor in
/// parallel, dedupes by `(circle_id, fingerprint)` (P3.3) and returns
/// whatever verified or failed to verify — both kinds are returned, since
/// P3.6 renders unverified entries too (greyed out, unselectable), it just
/// doesn't drop them.
pub async fn scan() -> Vec<DiscoveredCa> {
    let candidates = collect_beacons(COLLECTION_WINDOW).await;
    let mut tasks = Vec::with_capacity(candidates.len());
    for endpoint in candidates {
        tasks.push(tokio::spawn(async move { fetch_and_verify(&endpoint).await }));
    }

    let mut by_key: HashMap<(String, String), DiscoveredCa> = HashMap::new();
    for task in tasks {
        if let Ok(Some(entry)) = task.await {
            let key = (entry.circle_id.clone(), entry.fingerprint.clone());
            by_key.entry(key).or_insert(entry);
        }
    }
    by_key.into_values().collect()
}

/// Manual entry (P3.4's `POST /api/v1/mesh/discovery/probe {host:port}`) —
/// fetches and verifies a single, operator-supplied endpoint directly,
/// bypassing beacon discovery entirely. For LANs that block UDP
/// broadcast/multicast but still route ordinary TCP, per P3.6's own
/// "Enter join code" fallback framing.
pub async fn probe(host_port: &str) -> Option<DiscoveredCa> {
    fetch_and_verify(host_port).await
}

async fn collect_beacons(window: Duration) -> Vec<String> {
    let socket = match UdpSocket::bind(("0.0.0.0", beacon_port())).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("⚠️ LAN scan: could not bind the beacon listener: {e}");
            return Vec::new();
        }
    };

    let mut endpoints: HashSet<String> = HashSet::new();
    let deadline = tokio::time::Instant::now() + window;
    let mut buf = [0u8; 2048];
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _from))) => {
                if let Ok(beacon) = serde_json::from_slice::<CaBeacon>(&buf[..len]) {
                    if beacon.magic == CA_BEACON_MAGIC {
                        endpoints.insert(beacon.lan_endpoint);
                    }
                }
            }
            // A read error or the window simply elapsing both just end
            // collection with whatever was gathered so far — a LAN scan
            // finding zero CAs is a legitimate, expected outcome (P3.6's
            // empty state), not a failure.
            Ok(Err(_)) | Err(_) => break,
        }
    }
    endpoints.into_iter().collect()
}

async fn fetch_and_verify(endpoint: &str) -> Option<DiscoveredCa> {
    let url = format!("http://{endpoint}/ca-descriptor");
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()
        .ok()?;
    let bundle: CaDescriptorBundle = client.get(&url).send().await.ok()?.json().await.ok()?;
    let verified = bundle
        .descriptor
        .verify_with_document(&bundle.ca_did_document, Utc::now())
        .is_ok();

    Some(DiscoveredCa {
        circle_id: bundle.descriptor.circle_id.clone(),
        circle_name: bundle.descriptor.circle_name.clone(),
        ca_guardian_id: bundle.descriptor.ca_guardian_id.clone(),
        fingerprint: bundle.descriptor.ca_fingerprint.clone(),
        fingerprint_words: fingerprint_words(&bundle.descriptor.ca_fingerprint),
        lan_endpoint: bundle.descriptor.lan_endpoint.clone(),
        verified,
        policy_summary: Some(bundle.descriptor.policy_summary.clone()),
    })
}
