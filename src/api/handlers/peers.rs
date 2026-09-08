use crate::api::{error::ApiError, state::AppState};
use axum::{extract::State, Json};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
pub struct Peer {
    #[serde(rename = "peerId")]
    pub peer_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    pub ip: String,
    pub status: String,
    #[serde(rename = "lastSeen")]
    pub last_seen: String,
    #[serde(rename = "callAvailable")]
    pub call_available: bool,
    #[serde(
        rename = "callUnavailableReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub call_unavailable_reason: Option<String>,
    pub online: bool,
}

#[derive(Serialize)]
pub struct PeersResponse {
    pub peers: Vec<Peer>,
    pub total: usize,
    pub timestamp: String,
}

/// Read-only peer state used by other authenticated API handlers. The DID and
/// node ID are both required to prevent one Guardian's state being reported
/// for another Guardian.c
#[derive(Debug, Clone)]
pub struct GuardianPeerState {
    pub online: Option<bool>,
    pub status: String,
}

pub async fn state_for_guardian(
    state: &AppState,
    guardian_did: &str,
    guardian_node_id: Option<&str>,
) -> Option<GuardianPeerState> {
    let filenames = [
        format!("trusted_peers_{}.json", state.node_id),
        "trusted_peers.json".to_string(),
    ];

    for filename in filenames {
        let text = match safe_read(&filename, &state.log_dir_primary).await {
            Some(text) => text,
            None => match safe_read(&filename, &state.log_dir_fallback).await {
                Some(text) => text,
                None => continue,
            },
        };
        let peers: Vec<serde_json::Value> = serde_json::from_str(&text).ok()?;
        if let Some(peer) = peers.into_iter().find(|peer| {
            peer.get("did")
                .and_then(|value| value.as_str())
                .is_some_and(|did| did.eq_ignore_ascii_case(guardian_did))
                && guardian_node_id.is_none_or(|node_id| {
                    peer.get("node_id")
                        .or_else(|| peer.get("nodeId"))
                        .or_else(|| peer.get("peer_id"))
                        .and_then(|value| value.as_str())
                        .is_some_and(|peer_node_id| peer_node_id.eq_ignore_ascii_case(node_id))
                })
        }) {
            return Some(GuardianPeerState {
                online: peer.get("online").and_then(|value| value.as_bool()),
                status: peer
                    .get("status")
                    .and_then(|value| value.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
            });
        }
    }

    None
}

async fn safe_read(filename: &str, base_dir: &str) -> Option<String> {
    let base = std::path::Path::new(base_dir).canonicalize().ok()?;
    let path = base.join(filename);
    let resolved = path.canonicalize().ok()?;
    if !resolved.starts_with(&base) {
        return None;
    }
    tokio::fs::read_to_string(resolved).await.ok()
}

async fn call_peer_online(ip: &str) -> bool {
    let signaling_port = std::env::var("SGX_CALL_SIGNALING_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(50065);
    let address = format!("{}:{}", ip, signaling_port);
    for attempt in 0..3 {
        let connected = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect(&address),
        )
        .await
        .is_ok_and(|result| result.is_ok());
        if connected {
            return true;
        }
        if attempt < 2 {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
    }
    false
}

pub async fn list(State(s): State<Arc<AppState>>) -> Result<Json<PeersResponse>, ApiError> {
    let text = match safe_read("trusted_peers.json", &s.log_dir_primary).await {
        Some(t) => t,
        None => safe_read("trusted_peers.json", &s.log_dir_fallback)
            .await
            .unwrap_or_else(|| "[]".into()),
    };
    let mut raw: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap_or_default();
    // The merged registry may omit DID metadata while the node-specific
    // registry retains it. Enrich matching trusted entries so API consumers
    // can safely correlate Circle membership DIDs with call peer IDs.
    let per_node_filename = format!("trusted_peers_{}.json", s.node_id);
    let per_node_text = match safe_read(&per_node_filename, &s.log_dir_primary).await {
        Some(text) => text,
        None => safe_read(&per_node_filename, &s.log_dir_fallback)
            .await
            .unwrap_or_else(|| "[]".into()),
    };
    let per_node_raw: Vec<serde_json::Value> =
        serde_json::from_str(&per_node_text).unwrap_or_default();
    let mut known_peer_ids = raw
        .iter()
        .filter_map(|peer| peer.get("peer_id").and_then(|value| value.as_str()))
        .map(|peer_id| peer_id.to_lowercase())
        .collect::<std::collections::BTreeSet<_>>();

    for peer in &per_node_raw {
        let Some(peer_id) = peer.get("peer_id").and_then(|value| value.as_str()) else {
            continue;
        };
        if known_peer_ids.insert(peer_id.to_lowercase()) {
            raw.push(peer.clone());
        }
    }

    for peer in &mut raw {
        if peer.get("did").and_then(|value| value.as_str()).is_some() {
            continue;
        }
        let peer_id = peer.get("peer_id").and_then(|value| value.as_str());
        let Some(peer_id) = peer_id else { continue };
        let did = per_node_raw.iter().find_map(|candidate| {
            // Case-insensitive: `peer_id` is a human-editable device label
            // (renamed from Guardian device settings) and the merged/
            // per-node registries can end up with it cased differently
            // between files, which previously made this backfill silently
            // no-op and left `did` unresolved for an otherwise-known peer.
            let same_peer = candidate
                .get("peer_id")
                .and_then(|value| value.as_str())
                .is_some_and(|value| value.eq_ignore_ascii_case(peer_id));
            same_peer
                .then(|| candidate.get("did").and_then(|value| value.as_str()))
                .flatten()
                .filter(|value| !value.trim().is_empty())
        });
        if let Some(did) = did {
            peer["did"] = serde_json::Value::String(did.to_string());
        }
    }
    let candidates: Vec<(serde_json::Value, String)> = raw
        .into_iter()
        .filter_map(|v| {
            let peer_id = v
                .get("peer_id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            (peer_id != s.node_id).then_some((v, peer_id))
        })
        .collect();
    let peers: Vec<Peer> =
        futures_util::future::join_all(candidates.into_iter().map(|(v, peer_id)| async move {
            let did = v
                .get("did")
                .and_then(|value| value.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string);
            let ip = v
                .get("ip")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let status = v
                .get("status")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown")
                .to_string();
            let has_virtual_id = v
                .get("virtual_id")
                .and_then(|x| x.as_str())
                .is_some_and(|value| !value.trim().is_empty());
            let trusted = matches!(status.as_str(), "verified" | "trusted" | "success");
            let valid_ip = ip.parse::<std::net::IpAddr>().is_ok();
            let online = if valid_ip && trusted && has_virtual_id {
                call_peer_online(&ip).await
            } else {
                false
            };
            let call_unavailable_reason = if !trusted {
                Some("Peer is not currently trusted".to_string())
            } else if !valid_ip {
                Some("Peer registry has no plain Nebula IP address".to_string())
            } else if !has_virtual_id {
                Some("Peer registry has no attested VirtualID".to_string())
            } else if !online {
                Some("Peer is offline on the Nebula call network".to_string())
            } else {
                None
            };
            Peer {
                peer_id,
                did,
                ip,
                status,
                last_seen: v
                    .get("timestamp")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                call_available: call_unavailable_reason.is_none(),
                call_unavailable_reason,
                online,
            }
        }))
        .await;
    let total = peers.len();
    Ok(Json(PeersResponse {
        peers,
        total,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use serde_json::json;
    use tempfile::TempDir;

    fn state_with_logs() -> (std::sync::Arc<AppState>, TempDir, TempDir) {
        let base = TempDir::new().expect("base tempdir");
        let config = TempDir::new().expect("config tempdir");
        let state = AppState::for_tests(
            base.path(),
            "nodeA",
            config.path().to_string_lossy().to_string(),
        );
        (state, base, config)
    }

    fn write_peers(state: &AppState, filename: &str, value: &serde_json::Value) {
        std::fs::write(
            std::path::Path::new(&state.log_dir_primary).join(filename),
            serde_json::to_vec(value).unwrap(),
        )
        .expect("write peers file");
    }

    #[tokio::test]
    async fn state_for_guardian_returns_none_when_no_files_exist() {
        let (state, _base, _config) = state_with_logs();
        assert!(state_for_guardian(&state, "did:guardian:x", None)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn state_for_guardian_finds_a_case_insensitive_match_by_did() {
        let (state, _base, _config) = state_with_logs();
        write_peers(
            &state,
            "trusted_peers.json",
            &json!([{ "did": "did:guardian:ABC", "online": true, "status": "verified" }]),
        );
        let found = state_for_guardian(&state, "did:guardian:abc", None)
            .await
            .expect("should find by case-insensitive did");
        assert_eq!(found.status, "verified");
        assert_eq!(found.online, Some(true));
    }

    #[tokio::test]
    async fn state_for_guardian_filters_by_node_id_when_provided() {
        let (state, _base, _config) = state_with_logs();
        write_peers(
            &state,
            "trusted_peers.json",
            &json!([{ "did": "did:guardian:abc", "node_id": "nodeB", "status": "verified" }]),
        );
        assert!(
            state_for_guardian(&state, "did:guardian:abc", Some("nodeC"))
                .await
                .is_none()
        );
        let found = state_for_guardian(&state, "did:guardian:abc", Some("nodeB"))
            .await
            .expect("matching node_id should be found");
        assert_eq!(found.status, "verified");
    }

    #[tokio::test]
    async fn state_for_guardian_defaults_status_to_unknown_when_absent() {
        let (state, _base, _config) = state_with_logs();
        write_peers(
            &state,
            "trusted_peers.json",
            &json!([{ "did": "did:guardian:abc" }]),
        );
        let found = state_for_guardian(&state, "did:guardian:abc", None)
            .await
            .expect("present");
        assert_eq!(found.status, "unknown");
        assert_eq!(found.online, None);
    }

    #[tokio::test]
    async fn state_for_guardian_returns_none_for_malformed_json() {
        let (state, _base, _config) = state_with_logs();
        std::fs::write(
            std::path::Path::new(&state.log_dir_primary).join("trusted_peers.json"),
            b"not json",
        )
        .expect("write malformed file");
        assert!(state_for_guardian(&state, "did:guardian:abc", None)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn state_for_guardian_falls_back_to_node_specific_file() {
        let (state, _base, _config) = state_with_logs();
        write_peers(
            &state,
            "trusted_peers_nodeA.json",
            &json!([{ "did": "did:guardian:abc", "status": "trusted" }]),
        );
        let found = state_for_guardian(&state, "did:guardian:abc", None)
            .await
            .expect("should fall back to node-specific file");
        assert_eq!(found.status, "trusted");
    }

    #[tokio::test]
    async fn list_returns_an_empty_response_when_no_registry_file_exists() {
        let (state, _base, _config) = state_with_logs();
        let response = list(State(state)).await.expect("list should not error");
        assert_eq!(response.0.total, 0);
        assert!(response.0.peers.is_empty());
    }

    #[tokio::test]
    async fn list_excludes_self_but_still_reports_peers_without_an_attested_virtual_id() {
        let (state, _base, _config) = state_with_logs();
        write_peers(
            &state,
            "trusted_peers.json",
            &json!([
                { "peer_id": "nodeA", "virtual_id": "vid-self", "status": "verified", "ip": "10.0.0.1" },
                { "peer_id": "nodeB", "status": "verified", "ip": "10.0.0.2" },
            ]),
        );
        let response = list(State(state)).await.expect("list should not error");

        // Only this node is dropped. A peer missing a VirtualID stays listed
        // and carries the reason it cannot be called — dropping it instead
        // would make the peer vanish from the UI with nothing to explain why.
        let peer_ids: Vec<&str> = response
            .0
            .peers
            .iter()
            .map(|peer| peer.peer_id.as_str())
            .collect();
        assert_eq!(peer_ids, vec!["nodeB"]);

        let peer = &response.0.peers[0];
        assert!(!peer.call_available);
        assert_eq!(
            peer.call_unavailable_reason.as_deref(),
            Some("Peer registry has no attested VirtualID")
        );
    }

    #[tokio::test]
    async fn list_reports_call_unavailable_reasons_for_untrusted_and_invalid_ip_peers() {
        let (state, _base, _config) = state_with_logs();
        write_peers(
            &state,
            "trusted_peers.json",
            &json!([
                { "peer_id": "nodeB", "virtual_id": "vid-b", "status": "unknown", "ip": "10.0.0.2" },
                { "peer_id": "nodeC", "virtual_id": "vid-c", "status": "verified", "ip": "not-an-ip" },
            ]),
        );
        let response = list(State(state)).await.expect("list should not error");
        assert_eq!(response.0.total, 2);
        let by_id = |id: &str| {
            response
                .0
                .peers
                .iter()
                .find(|p| p.peer_id == id)
                .unwrap_or_else(|| panic!("missing peer {id}"))
        };
        let untrusted = by_id("nodeB");
        assert!(!untrusted.call_available);
        assert_eq!(
            untrusted.call_unavailable_reason.as_deref(),
            Some("Peer is not currently trusted")
        );
        let bad_ip = by_id("nodeC");
        assert!(!bad_ip.call_available);
        assert_eq!(
            bad_ip.call_unavailable_reason.as_deref(),
            Some("Peer registry has no plain Nebula IP address")
        );
    }

    #[tokio::test]
    async fn list_reports_offline_when_the_signaling_port_is_unreachable() {
        // `SGX_CALL_SIGNALING_PORT` is process-global and the sibling
        // reachability tests point it at a port they really bind, so this
        // redirect has to be exclusive.
        let _env_lock = crate::test_support::async_env_lock().await;
        let (state, _base, _config) = state_with_logs();
        write_peers(
            &state,
            "trusted_peers.json",
            &json!([
                { "peer_id": "nodeB", "virtual_id": "vid-b", "status": "verified", "ip": "127.0.0.1" },
            ]),
        );
        std::env::set_var("SGX_CALL_SIGNALING_PORT", "1");
        let response = list(State(state)).await.expect("list should not error");
        std::env::remove_var("SGX_CALL_SIGNALING_PORT");
        let peer = &response.0.peers[0];
        assert!(!peer.online);
        assert!(!peer.call_available);
        assert_eq!(
            peer.call_unavailable_reason.as_deref(),
            Some("Peer is offline on the Nebula call network")
        );
    }

    #[tokio::test]
    async fn list_reports_online_when_the_signaling_port_is_reachable() {
        // `SGX_CALL_SIGNALING_PORT` is process-global and the sibling
        // reachability tests point it at a port they really bind, so this
        // redirect has to be exclusive.
        let _env_lock = crate::test_support::async_env_lock().await;
        let (state, _base, _config) = state_with_logs();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let port = listener.local_addr().expect("local addr").port();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });
        write_peers(
            &state,
            "trusted_peers.json",
            &json!([
                { "peer_id": "nodeB", "virtual_id": "vid-b", "status": "verified", "ip": "127.0.0.1" },
            ]),
        );
        std::env::set_var("SGX_CALL_SIGNALING_PORT", port.to_string());
        let response = list(State(state)).await.expect("list should not error");
        std::env::remove_var("SGX_CALL_SIGNALING_PORT");
        let peer = &response.0.peers[0];
        assert!(peer.online);
        assert!(peer.call_available);
        assert!(peer.call_unavailable_reason.is_none());
    }

    #[tokio::test]
    async fn list_enriches_a_did_less_merged_entry_from_the_per_node_registry() {
        let (state, _base, _config) = state_with_logs();
        write_peers(
            &state,
            "trusted_peers.json",
            &json!([
                { "peer_id": "nodeB", "virtual_id": "vid-b", "status": "unknown", "ip": "10.0.0.2" },
            ]),
        );
        write_peers(
            &state,
            "trusted_peers_nodeA.json",
            &json!([
                { "peer_id": "nodeB", "did": "did:guardian:node-b" },
            ]),
        );
        let response = list(State(state)).await.expect("list should not error");
        assert_eq!(
            response.0.peers[0].did.as_deref(),
            Some("did:guardian:node-b")
        );
    }

    #[tokio::test]
    async fn list_does_not_overwrite_a_did_already_present_in_the_merged_registry() {
        let (state, _base, _config) = state_with_logs();
        write_peers(
            &state,
            "trusted_peers.json",
            &json!([
                {
                    "peer_id": "nodeB",
                    "did": "did:guardian:already-present",
                    "virtual_id": "vid-b",
                    "status": "unknown",
                    "ip": "10.0.0.2",
                },
            ]),
        );
        write_peers(
            &state,
            "trusted_peers_nodeA.json",
            &json!([{ "peer_id": "nodeB", "did": "did:guardian:should-not-be-used" }]),
        );
        let response = list(State(state)).await.expect("list should not error");
        assert_eq!(
            response.0.peers[0].did.as_deref(),
            Some("did:guardian:already-present")
        );
    }

    #[tokio::test]
    async fn safe_read_rejects_a_path_that_escapes_the_base_dir() {
        let temp = TempDir::new().expect("tempdir");
        let base = temp.path().join("base");
        std::fs::create_dir_all(&base).expect("mkdir base");
        let outside = temp.path().join("outside.txt");
        std::fs::write(&outside, b"secret").expect("write outside file");
        // A symlink inside `base` pointing outside it must not be followed.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, base.join("escape.txt")).expect("symlink");
            let result = safe_read("escape.txt", base.to_str().expect("utf8 base")).await;
            assert!(
                result.is_none(),
                "must not read through a symlink escaping base_dir"
            );
        }
    }

    #[tokio::test]
    async fn safe_read_returns_none_when_the_base_dir_does_not_exist() {
        assert!(safe_read("whatever.json", "/does/not/exist")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn safe_read_returns_file_contents_when_present() {
        let temp = TempDir::new().expect("tempdir");
        std::fs::write(temp.path().join("data.json"), b"hello").expect("write");
        let result = safe_read("data.json", temp.path().to_str().expect("utf8 path")).await;
        assert_eq!(result.as_deref(), Some("hello"));
    }

    #[tokio::test]
    async fn call_peer_online_returns_false_for_an_unreachable_port() {
        // `SGX_CALL_SIGNALING_PORT` is process-global and the sibling
        // reachability tests point it at a port they really bind, so this
        // redirect has to be exclusive.
        let _env_lock = crate::test_support::async_env_lock().await;
        std::env::set_var("SGX_CALL_SIGNALING_PORT", "1");
        let online = call_peer_online("127.0.0.1").await;
        std::env::remove_var("SGX_CALL_SIGNALING_PORT");
        assert!(!online);
    }
}
