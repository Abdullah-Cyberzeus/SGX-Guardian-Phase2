// src/nebula/registry_sync.rs
// ============================================================
// Overlay Registry Sync — Multi-PC Support
// ============================================================

use crate::nebula::lighthouse::LighthouseRegistry;
use crate::nebula::overlay_registry::OverlayRegistry;
use crate::nebula::relay_registry::RelayRegistry;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

pub const REGISTRY_SYNC_PORT: u16 = 50062;
pub const REGISTRY_PATH: &str = "/var/lib/sgx-guardian/nebula/overlay_registry.json";
pub const LIGHTHOUSE_REGISTRY_PATH: &str = "/var/lib/sgx-guardian/nebula/lighthouse_registry.json";
pub const RELAY_REGISTRY_PATH: &str = "/var/lib/sgx-guardian/nebula/relay_registry.json";
pub const CACHE_PATH: &str = "/var/lib/sgx-guardian/nebula/local_ip_cache.json";

pub type SharedRegistry = Arc<RwLock<OverlayRegistry>>;
fn is_ca_node() -> bool {
    std::env::args().nth(1).unwrap_or_default() == "nodeA"
}

// ── Wire Messages ─────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryRequest {
    pub action: String, // "assign" | "query" | "list" | "snapshot" | "snapshot_lh" | "snapshot_relay" | "publish_did_doc" | "snapshot_did_doc" | "status_list_snapshot"
    pub node_name: String,
    pub pubkey_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_doc_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_list_body: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RegistryResponse {
    pub success: bool,
    pub ip_cidr: Option<String>,
    pub ip: Option<String>,
    pub error: Option<String>,
    pub registry_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_doc_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_doc_aggregate_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_list_body: Option<String>,
}

// ── Directory bootstrap ───────────────────────────────────────

/// Ensure all required nebula directories exist.
/// Call at startup before any file operation.
pub fn ensure_dirs() -> Result<(), String> {
    for dir in &[
        "/var/lib/sgx-guardian",
        "/var/lib/sgx-guardian/nebula",
        "/var/lib/sgx-guardian/nebula/ca",
        "/var/lib/sgx-guardian/nebula/nodes",
    ] {
        std::fs::create_dir_all(dir).map_err(|e| format!("Cannot create {}: {}", dir, e))?;
    }
    Ok(())
}

// ── Server (nodeA / CA) ───────────────────────────────────────

pub async fn start_registry_server(registry: SharedRegistry) {
    let addr = format!("0.0.0.0:{}", REGISTRY_SYNC_PORT);

    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => {
            println!("🗂️  Registry sync server listening on {}", addr);
            l
        }
        Err(e) => {
            eprintln!("❌ Registry sync server bind failed on {}: {}", addr, e);
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let reg = registry.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_registry_connection(stream, reg).await {
                        eprintln!("Registry conn error from {}: {}", peer_addr, e);
                    }
                });
            }
            Err(e) => eprintln!("Registry accept error: {}", e),
        }
    }
}

fn parse_snapshot_payload(raw: &str) -> Result<serde_json::Value, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty snapshot payload".to_string());
    }

    let value: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|e| format!("invalid JSON snapshot: {}", e))?;

    // Guard against writing control-plane error responses as data snapshots.
    if let Some(obj) = value.as_object() {
        if obj.get("success").is_some()
            && (obj.get("error").is_some()
                || obj.get("ip_cidr").is_some()
                || obj.get("registry_summary").is_some())
        {
            return Err("received control response instead of registry snapshot".to_string());
        }
    }

    Ok(value)
}

fn atomic_write(path: &str, content: &str) -> Result<(), String> {
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create parent {}: {}", parent.display(), e))?;
    }
    let tmp = format!("{}.tmp", path);
    std::fs::write(&tmp, content).map_err(|e| format!("write {}: {}", tmp, e))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename {} -> {}: {}", tmp, path, e))
}

pub fn apply_overlay_snapshot(raw: &str, path: &str) -> Result<(), String> {
    let value = parse_snapshot_payload(raw)?;
    let incoming: OverlayRegistry = serde_json::from_value(value.clone())
        .map_err(|e| format!("invalid overlay snapshot schema: {}", e))?;

    if !incoming.allocations.contains_key(&incoming.owner_node) {
        return Err(format!(
            "overlay snapshot missing owner allocation for {}",
            incoming.owner_node
        ));
    }

    if Path::new(path).exists() {
        if let Ok(existing) = OverlayRegistry::load(path) {
            if !incoming.allocations.contains_key(&existing.owner_node) {
                return Err(format!(
                    "overlay snapshot missing existing owner allocation for {}",
                    existing.owner_node
                ));
            }
        }
    }

    let normalized =
        serde_json::to_string_pretty(&incoming).map_err(|e| format!("serialize overlay: {}", e))?;
    atomic_write(path, &normalized)
}

pub fn apply_lighthouse_snapshot(raw: &str, path: &str) -> Result<(), String> {
    let value = parse_snapshot_payload(raw)?;
    let incoming: LighthouseRegistry = serde_json::from_value(value.clone())
        .map_err(|e| format!("invalid lighthouse snapshot schema: {}", e))?;

    let active_lh_total = incoming
        .lighthouses
        .iter()
        .filter(|l| l.is_lighthouse)
        .count();
    if active_lh_total == 0 {
        return Err("lighthouse snapshot contains no lighthouse entries".to_string());
    }

    if Path::new(path).exists() {
        if let Ok(existing) = LighthouseRegistry::load(path) {
            if !existing.lighthouses.is_empty() && incoming.lighthouses.is_empty() {
                return Err(
                    "refusing to overwrite non-empty lighthouse registry with empty snapshot"
                        .to_string(),
                );
            }
        }
    }

    let normalized = serde_json::to_string_pretty(&incoming)
        .map_err(|e| format!("serialize lighthouse: {}", e))?;
    atomic_write(path, &normalized)
}

pub fn apply_relay_snapshot(raw: &str, path: &str) -> Result<(), String> {
    let value = parse_snapshot_payload(raw)?;
    let incoming: RelayRegistry = serde_json::from_value(value.clone())
        .map_err(|e| format!("invalid relay snapshot schema: {}", e))?;

    if Path::new(path).exists() {
        if let Ok(existing) = RelayRegistry::load(path) {
            if !existing.relays.is_empty() && incoming.relays.is_empty() {
                return Err(
                    "refusing to overwrite non-empty relay registry with empty snapshot"
                        .to_string(),
                );
            }
        }
    }

    let normalized =
        serde_json::to_string_pretty(&incoming).map_err(|e| format!("serialize relay: {}", e))?;
    atomic_write(path, &normalized)
}

async fn handle_registry_connection(
    stream: TcpStream,
    registry: SharedRegistry,
) -> Result<(), Box<dyn std::error::Error>> {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    buf_reader.read_line(&mut line).await?;
    if line.len() > 8192 {
        let resp = RegistryResponse {
            success: false,
            error: Some("Request too large (>8192 bytes)".into()),
            ..Default::default()
        };
        let mut json = serde_json::to_string(&resp)?;
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
        return Ok(());
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    let request: RegistryRequest = match serde_json::from_str(trimmed) {
        Ok(r) => r,
        Err(e) => {
            let resp = RegistryResponse {
                success: false,
                error: Some(format!("Invalid JSON: {}", e)),
                ..Default::default()
            };
            let mut json = serde_json::to_string(&resp)?;
            json.push('\n');
            writer.write_all(json.as_bytes()).await?;
            return Ok(());
        }
    };

    if request.action == "snapshot"
        || request.action == "snapshot_lh"
        || request.action == "snapshot_relay"
        || request.action == "status_list_snapshot"
    {
        // ✅ Only CA serves registry snapshots
        if !is_ca_node() {
            let resp = RegistryResponse {
                success: false,
                error: Some("Only CA can serve registry snapshots".into()),
                ..Default::default()
            };
            let mut json = serde_json::to_string(&resp)?;
            json.push('\n');
            writer.write_all(json.as_bytes()).await?;
            return Ok(());
        }

        let path = if request.action == "snapshot_lh" {
            LIGHTHOUSE_REGISTRY_PATH
        } else if request.action == "snapshot_relay" {
            RELAY_REGISTRY_PATH
        } else if request.action == "status_list_snapshot" {
            match std::fs::read_to_string(crate::vc::persistence::status_list_path()) {
                Ok(content) => {
                    let resp = RegistryResponse {
                        success: true,
                        status_list_body: Some(content),
                        ..Default::default()
                    };
                    let mut json = serde_json::to_string(&resp)?;
                    json.push('\n');
                    writer.write_all(json.as_bytes()).await?;
                    return Ok(());
                }
                Err(e) => {
                    let resp = RegistryResponse {
                        success: false,
                        error: Some(e.to_string()),
                        ..Default::default()
                    };
                    let mut json = serde_json::to_string(&resp)?;
                    json.push('\n');
                    writer.write_all(json.as_bytes()).await?;
                    return Ok(());
                }
            }
        } else {
            REGISTRY_PATH
        };

        match std::fs::read_to_string(path) {
            Ok(content) => {
                let normalized = serde_json::from_str::<serde_json::Value>(&content)
                    .ok()
                    .and_then(|v| serde_json::to_string(&v).ok())
                    .unwrap_or(content);
                let mut line = normalized;
                if !line.ends_with('\n') {
                    line.push('\n');
                }
                writer.write_all(line.as_bytes()).await?;
                return Ok(());
            }
            Err(e) => {
                let resp = RegistryResponse {
                    success: false,
                    error: Some(e.to_string()),
                    ..Default::default()
                };
                let mut json = serde_json::to_string(&resp)?;
                json.push('\n');
                writer.write_all(json.as_bytes()).await?;
                return Ok(());
            }
        }
    }

    let response = match request.action.as_str() {
        "assign" => {
            if std::env::args().nth(1).unwrap_or_default() != "nodeA" {
                RegistryResponse {
                    success: false,
                    error: Some("Only CA can assign IPs".into()),
                    ..Default::default()
                }
            } else {
                let mut reg = registry.write().await;
                if let Some(ref prefix) = request.pubkey_prefix {
                    reg.set_pubkey_prefix(&request.node_name, prefix);
                }
                match reg.assign_ip(&request.node_name) {
                    Ok(ip_cidr) => {
                        let ip = ip_cidr.split('/').next().unwrap_or("").to_string();
                        if let Err(e) = reg.save(REGISTRY_PATH) {
                            eprintln!("⚠️  Registry save failed: {}", e);
                        }
                        println!("✅ Registry: {} → {}", request.node_name, ip_cidr);
                        RegistryResponse {
                            success: true,
                            ip_cidr: Some(ip_cidr),
                            ip: Some(ip),
                            registry_summary: Some(reg.summary()),
                            ..Default::default()
                        }
                    }
                    Err(e) => RegistryResponse {
                        success: false,
                        error: Some(e),
                        ..Default::default()
                    },
                }
            }
        }

        "query" => {
            let reg = registry.read().await;
            match reg.get_ip_cidr(&request.node_name) {
                Some(ip_cidr) => {
                    let ip = ip_cidr.split('/').next().unwrap_or("").to_string();
                    RegistryResponse {
                        success: true,
                        ip_cidr: Some(ip_cidr.to_string()),
                        ip: Some(ip),
                        ..Default::default()
                    }
                }
                None => RegistryResponse {
                    success: false,
                    error: Some(format!("{} not found in registry", request.node_name)),
                    ..Default::default()
                },
            }
        }

        "list" => {
            let reg = registry.read().await;
            RegistryResponse {
                success: true,
                registry_summary: Some(reg.summary()),
                ..Default::default()
            }
        }

        "publish_did_doc" => {
            if !is_ca_node() {
                RegistryResponse {
                    success: false,
                    error: Some("Only CA can ingest DID documents".into()),
                    ..Default::default()
                }
            } else {
                match request.did_doc_json.as_deref() {
                    None => RegistryResponse {
                        success: false,
                        error: Some("missing did_doc_json".into()),
                        ..Default::default()
                    },
                    Some(payload) => {
                        match crate::did::doc_distribution::ca_ingest_published(payload).await {
                            Ok(()) => RegistryResponse {
                                success: true,
                                ..Default::default()
                            },
                            Err(e) => RegistryResponse {
                                success: false,
                                error: Some(format!("did_doc reject: {}", e)),
                                ..Default::default()
                            },
                        }
                    }
                }
            }
        }

        "snapshot_did_doc" => {
            if !is_ca_node() {
                RegistryResponse {
                    success: false,
                    error: Some("Only CA can serve DID document snapshots".into()),
                    ..Default::default()
                }
            } else {
                match crate::did::doc_distribution::ca_export_aggregate().await {
                    Ok(json) => RegistryResponse {
                        success: true,
                        did_doc_aggregate_json: Some(json),
                        ..Default::default()
                    },
                    Err(e) => RegistryResponse {
                        success: false,
                        error: Some(format!("did_doc snapshot: {}", e)),
                        ..Default::default()
                    },
                }
            }
        }

        "resolve_did" => {
            if !is_ca_node() {
                RegistryResponse {
                    success: false,
                    error: Some("Only CA can serve DID document point lookups".into()),
                    ..Default::default()
                }
            } else {
                match request.did_query.as_deref() {
                    Some(raw) if !raw.trim().is_empty() => match crate::did::Did::parse(raw.trim())
                    {
                        Ok(did) => match crate::did::doc_persistence::load_peer(&did) {
                            Ok(Some(doc)) => RegistryResponse {
                                success: true,
                                did_doc_json: Some(serde_json::to_string(&doc)?),
                                ..Default::default()
                            },
                            Ok(None) => RegistryResponse {
                                success: false,
                                error: Some("not found".into()),
                                ..Default::default()
                            },
                            Err(e) => RegistryResponse {
                                success: false,
                                error: Some(format!("resolve_did load failed: {}", e)),
                                ..Default::default()
                            },
                        },
                        Err(e) => RegistryResponse {
                            success: false,
                            error: Some(format!("bad DID: {}", e)),
                            ..Default::default()
                        },
                    },
                    _ => RegistryResponse {
                        success: false,
                        error: Some("missing did_query".into()),
                        ..Default::default()
                    },
                }
            }
        }

        _ => RegistryResponse {
            success: false,
            error: Some(format!("Unknown action: {}", request.action)),
            ..Default::default()
        },
    };

    let mut json = serde_json::to_string(&response)?;
    json.push('\n');
    writer.write_all(json.as_bytes()).await?;
    Ok(())
}

// ── Client ────────────────────────────────────────────────────

pub async fn request_ip_from_ca(
    node_name: &str,
    ca_host: &str,
    pubkey_prefix: &str,
) -> Result<(String, String), String> {
    let addr = format!("{}:{}", ca_host, REGISTRY_SYNC_PORT);

    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| format!("Timeout connecting to {}", addr))?
    .map_err(|e| format!("Connect error to {}: {}", addr, e))?;

    let request = RegistryRequest {
        action: "assign".to_string(),
        node_name: node_name.to_string(),
        pubkey_prefix: Some(pubkey_prefix.to_string()),
        did_doc_json: None,
        did_query: None,
        status_list_body: None,
    };

    let mut json = serde_json::to_string(&request).map_err(|e| format!("Serialize: {}", e))?;
    json.push('\n');

    let (reader, mut writer) = stream.into_split();
    writer
        .write_all(json.as_bytes())
        .await
        .map_err(|e| format!("Write: {}", e))?;

    let mut buf_reader = BufReader::new(reader);
    let mut response_line = String::new();

    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        buf_reader.read_line(&mut response_line),
    )
    .await
    .map_err(|_| "Timeout reading response".to_string())?
    .map_err(|e| format!("Read: {}", e))?;

    let response: RegistryResponse = serde_json::from_str(response_line.trim())
        .map_err(|e| format!("Parse: {} (got: '{}')", e, response_line.trim()))?;

    if response.success {
        let ip_cidr = response.ip_cidr.ok_or("No ip_cidr in response")?;
        let ip = response.ip.ok_or("No ip in response")?;
        Ok((ip_cidr, ip))
    } else {
        Err(response
            .error
            .unwrap_or_else(|| "Unknown error".to_string()))
    }
}

pub async fn query_ip_from_ca(node_name: &str, ca_host: &str) -> Result<(String, String), String> {
    let addr = format!("{}:{}", ca_host, REGISTRY_SYNC_PORT);

    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| format!("Timeout connecting to {}", addr))?
    .map_err(|e| format!("Connect error to {}: {}", addr, e))?;

    let request = RegistryRequest {
        action: "query".to_string(),
        node_name: node_name.to_string(),
        pubkey_prefix: None,
        did_doc_json: None,
        did_query: None,
        status_list_body: None,
    };

    let mut json = serde_json::to_string(&request).map_err(|e| format!("Serialize: {}", e))?;
    json.push('\n');

    let (reader, mut writer) = stream.into_split();
    writer
        .write_all(json.as_bytes())
        .await
        .map_err(|e| format!("Write: {}", e))?;

    let mut buf_reader = BufReader::new(reader);
    let mut response_line = String::new();

    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        buf_reader.read_line(&mut response_line),
    )
    .await
    .map_err(|_| "Timeout reading response".to_string())?
    .map_err(|e| format!("Read: {}", e))?;

    let response: RegistryResponse = serde_json::from_str(response_line.trim())
        .map_err(|e| format!("Parse: {} (got: '{}')", e, response_line.trim()))?;

    if response.success {
        let ip_cidr = response.ip_cidr.ok_or("No ip_cidr in response")?;
        let ip = response.ip.ok_or("No ip in response")?;
        Ok((ip_cidr, ip))
    } else {
        Err(response
            .error
            .unwrap_or_else(|| "Unknown error".to_string()))
    }
}

pub async fn pull_registry_snapshot_from_ca(ca_host: &str) -> Result<String, String> {
    let addr = format!("{}:{}", ca_host, REGISTRY_SYNC_PORT);

    let stream = tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| format!("connect: {}", e))?;

    let request = RegistryRequest {
        action: "snapshot".to_string(),
        node_name: "".to_string(),
        pubkey_prefix: None,
        did_doc_json: None,
        did_query: None,
        status_list_body: None,
    };

    let mut json = serde_json::to_string(&request).map_err(|e| e.to_string())?;
    json.push('\n');

    let (reader, mut writer) = stream.into_split();
    writer
        .write_all(json.as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    let mut buf_reader = BufReader::new(reader);
    let mut response_line = String::new();
    buf_reader
        .read_line(&mut response_line)
        .await
        .map_err(|e| e.to_string())?;

    Ok(response_line)
}

pub async fn pull_lighthouse_snapshot_from_ca(ca_host: &str) -> Result<String, String> {
    let addr = format!("{}:{}", ca_host, REGISTRY_SYNC_PORT);

    let stream = tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| format!("connect: {}", e))?;

    let request = RegistryRequest {
        action: "snapshot_lh".to_string(),
        node_name: "".to_string(),
        pubkey_prefix: None,
        did_doc_json: None,
        did_query: None,
        status_list_body: None,
    };

    let mut json = serde_json::to_string(&request).map_err(|e| e.to_string())?;
    json.push('\n');

    let (reader, mut writer) = stream.into_split();
    writer
        .write_all(json.as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    let mut buf_reader = BufReader::new(reader);
    let mut response_line = String::new();
    buf_reader
        .read_line(&mut response_line)
        .await
        .map_err(|e| e.to_string())?;

    Ok(response_line)
}

pub async fn pull_relay_snapshot_from_ca(ca_host: &str) -> Result<String, String> {
    let addr = format!("{}:{}", ca_host, REGISTRY_SYNC_PORT);

    let stream = tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| format!("connect: {}", e))?;

    let request = RegistryRequest {
        action: "snapshot_relay".to_string(),
        node_name: "".to_string(),
        pubkey_prefix: None,
        did_doc_json: None,
        did_query: None,
        status_list_body: None,
    };

    let mut json = serde_json::to_string(&request).map_err(|e| e.to_string())?;
    json.push('\n');

    let (reader, mut writer) = stream.into_split();
    writer
        .write_all(json.as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    let mut buf_reader = BufReader::new(reader);
    let mut response_line = String::new();
    buf_reader
        .read_line(&mut response_line)
        .await
        .map_err(|e| e.to_string())?;

    Ok(response_line)
}

pub async fn pull_status_list_snapshot_from_ca(ca_host: &str) -> Result<RegistryResponse, String> {
    let addr = format!("{}:{}", ca_host, REGISTRY_SYNC_PORT);

    let stream = tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| format!("connect: {}", e))?;

    let request = RegistryRequest {
        action: "status_list_snapshot".to_string(),
        node_name: String::new(),
        pubkey_prefix: None,
        did_doc_json: None,
        did_query: None,
        status_list_body: None,
    };

    let mut json = serde_json::to_string(&request).map_err(|e| e.to_string())?;
    json.push('\n');

    let (reader, mut writer) = stream.into_split();
    writer
        .write_all(json.as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    let mut buf_reader = BufReader::new(reader);
    let mut response_line = String::new();
    buf_reader
        .read_line(&mut response_line)
        .await
        .map_err(|e| e.to_string())?;

    serde_json::from_str(response_line.trim()).map_err(|e| e.to_string())
}

async fn request_or_query_ip_from_registry(
    node_name: &str,
    ca_host: &str,
    pubkey_prefix: &str,
) -> Result<(String, String), String> {
    match request_ip_from_ca(node_name, ca_host, pubkey_prefix).await {
        Ok(v) => Ok(v),
        Err(e) if e.contains("Only CA can assign IPs") => {
            query_ip_from_ca(node_name, ca_host).await
        }
        Err(e) => Err(e),
    }
}

// ── Main resolver for member nodes ────────────────────────────

/// Call this from main.rs for any non-CA node.
/// Order: CA (authoritative) with retry loop until reachable.
pub async fn resolve_overlay_ip(node_name: &str, ca_host: &str, pubkey_prefix: &str) -> String {
    if let Err(e) = ensure_dirs() {
        eprintln!("⚠️  [OverlayIP] Dir setup failed: {}", e);
    }

    // 1. CA request first (authoritative source)
    println!(
        "📡 [OverlayIP] Requesting IP from CA {}:{}...",
        ca_host, REGISTRY_SYNC_PORT
    );
    match request_or_query_ip_from_registry(node_name, ca_host, pubkey_prefix).await {
        Ok((ip_cidr, _)) => {
            println!("✅ [OverlayIP] Assigned: {} → {}", node_name, ip_cidr);
            match save_local_ip_cache(node_name, &ip_cidr) {
                Ok(_) => println!("💾 [OverlayIP] Cache saved: {}", CACHE_PATH),
                Err(e) => eprintln!("⚠️  [OverlayIP] Cache save failed: {}", e),
            }
            ip_cidr
        }
        Err(e) => {
            eprintln!("❌ [OverlayIP] CA request failed: {}", e);
            eprintln!("   CA: {}:{}", ca_host, REGISTRY_SYNC_PORT);
            eprintln!("⏳ [OverlayIP] Retrying every 5s until CA is reachable...");

            let mut attempt = 0u32;
            loop {
                attempt += 1;
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                let fresh_ca_host = crate::dynamic_config::latest_known_ca_ip()
                    .unwrap_or_else(|| ca_host.to_string());

                match request_or_query_ip_from_registry(node_name, &fresh_ca_host, pubkey_prefix)
                    .await
                {
                    Ok((ip_cidr, _)) => {
                        println!(
                            "✅ [OverlayIP] Assigned after {} retries: {} → {}",
                            attempt, node_name, ip_cidr
                        );
                        // Do NOT cache fallback IPs — only CA-issued IPs are authoritative
                        return ip_cidr;
                    }
                    Err(e) if attempt.is_multiple_of(6) => {
                        eprintln!(
                            "⏳ [OverlayIP] Still waiting for CA ({}): {}",
                            fresh_ca_host, e
                        );
                    }
                    Err(_) => {}
                }
            }
        }
    }
}

// ── Cache helpers ─────────────────────────────────────────────

pub fn save_local_ip_cache(node_name: &str, ip_cidr: &str) -> Result<(), String> {
    for dir in &["/var/lib/sgx-guardian", "/var/lib/sgx-guardian/nebula"] {
        std::fs::create_dir_all(dir).map_err(|e| format!("Cannot create {}: {}", dir, e))?;
    }

    let mut cache: HashMap<String, String> = if std::path::Path::new(CACHE_PATH).exists() {
        std::fs::read_to_string(CACHE_PATH)
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_default()
    } else {
        HashMap::new()
    };

    cache.insert(node_name.to_string(), ip_cidr.to_string());

    let tmp = format!("{}.tmp", CACHE_PATH);
    let json = serde_json::to_string_pretty(&cache).map_err(|e| format!("Serialize: {}", e))?;

    std::fs::write(&tmp, &json).map_err(|e| format!("Write {}: {}", tmp, e))?;

    std::fs::rename(&tmp, CACHE_PATH).map_err(|e| format!("Rename: {}", e))?;

    Ok(())
}

pub fn load_local_ip_cache(node_name: &str) -> Option<String> {
    let content = std::fs::read_to_string(CACHE_PATH).ok()?;
    let cache: HashMap<String, String> = serde_json::from_str(&content).ok()?;
    cache.get(node_name).cloned()
}

pub fn clear_local_ip_cache(node_name: &str) -> Result<(), String> {
    if !std::path::Path::new(CACHE_PATH).exists() {
        return Ok(());
    }
    let content = std::fs::read_to_string(CACHE_PATH).map_err(|e| format!("Read: {}", e))?;
    let mut cache: HashMap<String, String> = serde_json::from_str(&content).unwrap_or_default();
    cache.remove(node_name);
    let json = serde_json::to_string_pretty(&cache).map_err(|e| format!("Serialize: {}", e))?;
    std::fs::write(CACHE_PATH, json).map_err(|e| format!("Write: {}", e))?;
    println!("🗑️  Cache cleared for {}", node_name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp_file(name: &str) -> String {
        let pid = std::process::id();
        format!("/tmp/{}_{}.json", name, pid)
    }

    #[test]
    fn test_apply_relay_snapshot_rejects_control_response() {
        let path = tmp_file("relay_snapshot_control");
        let payload = r#"{"success":false,"error":"Only CA can serve registry snapshots"}"#;
        let res = apply_relay_snapshot(payload, &path);
        assert!(res.is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_apply_relay_snapshot_refuses_empty_overwrite() {
        let path = tmp_file("relay_snapshot_empty_overwrite");
        let mut existing = RelayRegistry::new("guardian-circle-alpha");
        existing.add_relay("nodeA", "192.168.100.1", "10.0.0.1:4242", 5, 10, true);
        existing.save(&path).unwrap();

        let incoming_empty = RelayRegistry::new("guardian-circle-alpha");
        let payload = serde_json::to_string_pretty(&incoming_empty).unwrap();
        let res = apply_relay_snapshot(&payload, &path);
        assert!(res.is_err());

        let preserved = RelayRegistry::load(&path).unwrap();
        assert!(preserved.relays.contains_key("nodeA"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_apply_relay_snapshot_creates_parent_directories() {
        let td = TempDir::new().expect("tempdir");
        let path = td
            .path()
            .join("nested")
            .join("relay")
            .join("relay_registry.json");
        let mut incoming = RelayRegistry::new("guardian-circle-alpha");
        incoming.add_relay("nodeA", "192.168.100.1", "10.0.0.1:4242", 5, 10, true);
        let payload = serde_json::to_string_pretty(&incoming).expect("serialize relay registry");

        apply_relay_snapshot(&payload, path.to_str().expect("path")).expect("apply snapshot");

        let saved = RelayRegistry::load(path.to_str().expect("path")).expect("load snapshot");
        assert!(saved.relays.contains_key("nodeA"));
    }

    // ── parse_snapshot_payload ──────────────────────────────────

    #[test]
    fn test_parse_snapshot_payload_rejects_empty() {
        let err = parse_snapshot_payload("   ").unwrap_err();
        assert!(err.contains("empty snapshot payload"));
    }

    #[test]
    fn test_parse_snapshot_payload_rejects_invalid_json() {
        let err = parse_snapshot_payload("{not json").unwrap_err();
        assert!(err.contains("invalid JSON snapshot"));
    }

    #[test]
    fn test_parse_snapshot_payload_accepts_plain_object() {
        let value = parse_snapshot_payload(r#"{"circle_id":"alpha"}"#).unwrap();
        assert_eq!(value["circle_id"], "alpha");
    }

    #[test]
    fn test_parse_snapshot_payload_rejects_control_response_with_error() {
        let err = parse_snapshot_payload(r#"{"success":false,"error":"nope"}"#).unwrap_err();
        assert!(err.contains("control response"));
    }

    #[test]
    fn test_parse_snapshot_payload_rejects_control_response_with_ip_cidr() {
        let err =
            parse_snapshot_payload(r#"{"success":true,"ip_cidr":"10.0.0.1/24"}"#).unwrap_err();
        assert!(err.contains("control response"));
    }

    #[test]
    fn test_parse_snapshot_payload_rejects_control_response_with_summary() {
        let err = parse_snapshot_payload(r#"{"success":true,"registry_summary":"x"}"#).unwrap_err();
        assert!(err.contains("control response"));
    }

    #[test]
    fn test_parse_snapshot_payload_allows_success_only_field() {
        // "success" alone, without error/ip_cidr/registry_summary, is not
        // treated as a control response and passes through unchanged.
        let value = parse_snapshot_payload(r#"{"success":true}"#).unwrap();
        assert_eq!(value["success"], true);
    }

    // ── atomic_write ─────────────────────────────────────────────

    #[test]
    fn test_atomic_write_creates_parents_and_writes_content() {
        let td = TempDir::new().expect("tempdir");
        let path = td.path().join("a").join("b").join("out.json");
        atomic_write(path.to_str().unwrap(), "hello world").expect("atomic write");
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "hello world");
        // no leftover temp file
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[test]
    fn test_atomic_write_fails_when_parent_creation_blocked() {
        let td = TempDir::new().expect("tempdir");
        let blocker = td.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let bad_path = blocker.join("nested").join("out.json");
        let err = atomic_write(bad_path.to_str().unwrap(), "content").unwrap_err();
        assert!(err.contains("create parent"));
    }

    // ── is_ca_node ───────────────────────────────────────────────

    #[test]
    fn test_is_ca_node_runs_without_panic() {
        // Depends on real process argv; only exercised for coverage of the
        // branch, not for a specific truth value.
        let _ = is_ca_node();
    }

    // ── RegistryRequest / RegistryResponse serde ────────────────

    #[test]
    fn test_registry_response_default_omits_optional_fields() {
        let resp = RegistryResponse {
            success: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("did_doc_json"));
        assert!(!json.contains("did_doc_aggregate_json"));
        assert!(!json.contains("status_list_body"));
        assert!(json.contains("\"success\":true"));
    }

    #[test]
    fn test_registry_request_roundtrip_serialization() {
        let req = RegistryRequest {
            action: "assign".to_string(),
            node_name: "nodeB".to_string(),
            pubkey_prefix: Some("abcd1234".to_string()),
            did_doc_json: None,
            did_query: None,
            status_list_body: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: RegistryRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.action, "assign");
        assert_eq!(back.node_name, "nodeB");
        assert_eq!(back.pubkey_prefix.as_deref(), Some("abcd1234"));
    }

    // ── apply_overlay_snapshot ───────────────────────────────────

    #[test]
    fn test_apply_overlay_snapshot_rejects_invalid_json() {
        let path = tmp_file("overlay_invalid_json");
        let err = apply_overlay_snapshot("{bad", &path).unwrap_err();
        assert!(err.contains("invalid JSON snapshot"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_apply_overlay_snapshot_rejects_invalid_schema() {
        let path = tmp_file("overlay_invalid_schema");
        let err = apply_overlay_snapshot(r#"{"foo":"bar"}"#, &path).unwrap_err();
        assert!(err.contains("invalid overlay snapshot schema"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_apply_overlay_snapshot_rejects_missing_owner_allocation() {
        let path = tmp_file("overlay_missing_owner");
        let mut incoming = OverlayRegistry::new("alpha", "192.168.100", "nodeA");
        incoming.allocations.remove("nodeA");
        let payload = serde_json::to_string_pretty(&incoming).unwrap();
        let err = apply_overlay_snapshot(&payload, &path).unwrap_err();
        assert!(err.contains("missing owner allocation"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_apply_overlay_snapshot_rejects_when_existing_owner_dropped() {
        let path = tmp_file("overlay_existing_owner_dropped");
        let existing = OverlayRegistry::new("alpha", "192.168.100", "nodeX");
        existing.save(&path).unwrap();

        // Incoming snapshot is internally consistent (has its own owner)
        // but does not carry an allocation for the *existing* owner nodeX.
        let incoming = OverlayRegistry::new("alpha", "192.168.100", "nodeA");
        let payload = serde_json::to_string_pretty(&incoming).unwrap();

        let err = apply_overlay_snapshot(&payload, &path).unwrap_err();
        assert!(err.contains("missing existing owner allocation"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_apply_overlay_snapshot_succeeds_and_normalizes_file() {
        let path = tmp_file("overlay_success");
        let mut incoming = OverlayRegistry::new("alpha", "192.168.100", "nodeA");
        incoming.assign_ip("nodeB").unwrap();
        let payload = serde_json::to_string_pretty(&incoming).unwrap();

        apply_overlay_snapshot(&payload, &path).expect("apply overlay snapshot");

        let saved = OverlayRegistry::load(&path).expect("load saved overlay");
        assert_eq!(saved.owner_node, "nodeA");
        assert!(saved.allocations.contains_key("nodeB"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_apply_overlay_snapshot_overwrites_existing_when_owner_present() {
        let path = tmp_file("overlay_overwrite_ok");
        let existing = OverlayRegistry::new("alpha", "192.168.100", "nodeA");
        existing.save(&path).unwrap();

        let mut incoming = OverlayRegistry::new("alpha", "192.168.100", "nodeA");
        incoming.assign_ip("nodeC").unwrap();
        let payload = serde_json::to_string_pretty(&incoming).unwrap();

        apply_overlay_snapshot(&payload, &path).expect("apply overlay snapshot");
        let saved = OverlayRegistry::load(&path).unwrap();
        assert!(saved.allocations.contains_key("nodeC"));
        let _ = std::fs::remove_file(&path);
    }

    // ── apply_lighthouse_snapshot ────────────────────────────────

    #[test]
    fn test_apply_lighthouse_snapshot_rejects_invalid_json() {
        let path = tmp_file("lh_invalid_json");
        let err = apply_lighthouse_snapshot("not json", &path).unwrap_err();
        assert!(err.contains("invalid JSON snapshot"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_apply_lighthouse_snapshot_rejects_invalid_schema() {
        let path = tmp_file("lh_invalid_schema");
        let err = apply_lighthouse_snapshot(r#"{"nope":true}"#, &path).unwrap_err();
        assert!(err.contains("invalid lighthouse snapshot schema"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_apply_lighthouse_snapshot_rejects_empty_lighthouse_list() {
        let path = tmp_file("lh_empty_list");
        let incoming = LighthouseRegistry {
            circle_id: "alpha".to_string(),
            lighthouses: vec![],
        };
        let payload = serde_json::to_string_pretty(&incoming).unwrap();
        let err = apply_lighthouse_snapshot(&payload, &path).unwrap_err();
        assert!(err.contains("no lighthouse entries"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_apply_lighthouse_snapshot_rejects_when_no_entry_is_lighthouse() {
        let path = tmp_file("lh_no_active_lighthouse");
        let mut incoming =
            LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "1.2.3.4:4242");
        // Demote the only entry so no lighthouse-role entries remain.
        incoming.lighthouses[0].is_lighthouse = false;
        let payload = serde_json::to_string_pretty(&incoming).unwrap();
        let err = apply_lighthouse_snapshot(&payload, &path).unwrap_err();
        assert!(err.contains("no lighthouse entries"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_apply_lighthouse_snapshot_succeeds_and_creates_parents() {
        let td = TempDir::new().expect("tempdir");
        let path = td.path().join("nested").join("lighthouse_registry.json");
        let incoming = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "1.2.3.4:4242");
        let payload = serde_json::to_string_pretty(&incoming).unwrap();

        apply_lighthouse_snapshot(&payload, path.to_str().unwrap()).expect("apply lh snapshot");

        let saved = LighthouseRegistry::load(path.to_str().unwrap()).unwrap();
        assert_eq!(saved.lighthouses.len(), 1);
        assert_eq!(saved.lighthouses[0].node_name, "nodeA");
    }

    #[test]
    fn test_apply_lighthouse_snapshot_overwrites_existing_non_empty() {
        let path = tmp_file("lh_overwrite_ok");
        let existing = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "1.2.3.4:4242");
        existing.save(&path).unwrap();

        let mut incoming =
            LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "1.2.3.4:4242");
        incoming.add_secondary("nodeB", "192.168.100.2", "5.6.7.8:4242");
        let payload = serde_json::to_string_pretty(&incoming).unwrap();

        apply_lighthouse_snapshot(&payload, &path).expect("apply lh snapshot");
        let saved = LighthouseRegistry::load(&path).unwrap();
        assert_eq!(saved.lighthouses.len(), 2);
        let _ = std::fs::remove_file(&path);
    }

    // ── apply_relay_snapshot: additional coverage ────────────────

    #[test]
    fn test_apply_relay_snapshot_rejects_invalid_json() {
        let path = tmp_file("relay_invalid_json");
        let err = apply_relay_snapshot("{{{", &path).unwrap_err();
        assert!(err.contains("invalid JSON snapshot"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_apply_relay_snapshot_rejects_invalid_schema() {
        let path = tmp_file("relay_invalid_schema");
        // Missing required "circle_id" and wrong shape for "relays".
        let err = apply_relay_snapshot(r#"{"relays":123}"#, &path).unwrap_err();
        assert!(err.contains("invalid relay snapshot schema"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_apply_relay_snapshot_succeeds_on_fresh_path() {
        let path = tmp_file("relay_fresh_success");
        let mut incoming = RelayRegistry::new("guardian-circle-alpha");
        incoming.add_relay("nodeB", "192.168.100.2", "10.0.0.2:4242", 5, 10, true);
        let payload = serde_json::to_string_pretty(&incoming).unwrap();

        apply_relay_snapshot(&payload, &path).expect("apply relay snapshot");
        let saved = RelayRegistry::load(&path).unwrap();
        assert!(saved.relays.contains_key("nodeB"));
        let _ = std::fs::remove_file(&path);
    }

    // ── handle_registry_connection ────────────────────────────────
    //
    // These exercise the connection handler directly over a loopback
    // TcpStream pair (an OS-assigned ephemeral port via `bind("127.0.0.1:0")`),
    // rather than through `start_registry_server`, which itself binds the
    // fixed, hardcoded `REGISTRY_SYNC_PORT` and is not safely unit-testable
    // (no root, and a fixed port risks colliding with a real service or other
    // test runs). `is_ca_node()` reads the real process argv (`std::env::args()`),
    // which cannot be faked per-test, so under `cargo test` it is always false —
    // meaning only the "Only CA can ..." rejection branches of the CA-only
    // actions are reachable here; their true-CA success branches (which also
    // touch hardcoded `/var/lib/...` registry paths) are left uncovered.

    fn empty_registry() -> SharedRegistry {
        Arc::new(RwLock::new(OverlayRegistry::new(
            "alpha",
            "192.168.100",
            "nodeA",
        )))
    }

    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("local addr");
        let client = TcpStream::connect(addr).await.expect("connect loopback");
        let (server, _) = listener.accept().await.expect("accept loopback");
        (server, client)
    }

    async fn roundtrip(registry: SharedRegistry, request_line: &str) -> RegistryResponse {
        let (server, mut client) = connected_pair().await;

        client
            .write_all(request_line.as_bytes())
            .await
            .expect("write request");
        client.write_all(b"\n").await.expect("write newline");

        handle_registry_connection(server, registry)
            .await
            .expect("handle connection");

        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read response");
        serde_json::from_str(line.trim()).expect("parse response json")
    }

    #[tokio::test]
    async fn test_handle_registry_connection_request_too_large() {
        let (server, mut client) = connected_pair().await;

        let mut oversized = "a".repeat(9000);
        oversized.push('\n');
        client
            .write_all(oversized.as_bytes())
            .await
            .expect("write oversized request");

        handle_registry_connection(server, empty_registry())
            .await
            .expect("handle connection");

        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read response");
        let resp: RegistryResponse = serde_json::from_str(line.trim()).unwrap();
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("Request too large"));
    }

    #[tokio::test]
    async fn test_handle_registry_connection_invalid_json() {
        let resp = roundtrip(empty_registry(), "not valid json").await;
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("Invalid JSON"));
    }

    #[tokio::test]
    async fn test_handle_registry_connection_empty_line_closes_without_response() {
        let (server, mut client) = connected_pair().await;

        client.write_all(b"\n").await.expect("write empty line");

        handle_registry_connection(server, empty_registry())
            .await
            .expect("handle connection");

        let mut reader = BufReader::new(client);
        let mut line = String::new();
        let n = reader.read_line(&mut line).await.expect("read eof");
        assert_eq!(n, 0, "expected EOF with no response written");
    }

    #[tokio::test]
    async fn test_handle_registry_connection_unknown_action() {
        let req = r#"{"action":"bogus","node_name":"nodeB"}"#;
        let resp = roundtrip(empty_registry(), req).await;
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("Unknown action: bogus"));
    }

    #[tokio::test]
    async fn test_handle_registry_connection_query_hit() {
        let registry = empty_registry();
        {
            let mut reg = registry.write().await;
            reg.assign_ip("nodeB").expect("assign ip");
        }
        let req = r#"{"action":"query","node_name":"nodeB"}"#;
        let resp = roundtrip(registry, req).await;
        assert!(resp.success);
        assert!(resp.ip_cidr.is_some());
        assert!(resp.ip.is_some());
    }

    #[tokio::test]
    async fn test_handle_registry_connection_query_miss() {
        let req = r#"{"action":"query","node_name":"ghost"}"#;
        let resp = roundtrip(empty_registry(), req).await;
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("not found in registry"));
    }

    #[tokio::test]
    async fn test_handle_registry_connection_list() {
        let req = r#"{"action":"list","node_name":""}"#;
        let resp = roundtrip(empty_registry(), req).await;
        assert!(resp.success);
        assert!(resp.registry_summary.is_some());
    }

    #[tokio::test]
    async fn test_handle_registry_connection_assign_rejected_when_not_ca() {
        let req = r#"{"action":"assign","node_name":"nodeB"}"#;
        let resp = roundtrip(empty_registry(), req).await;
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("Only CA can assign IPs"));
    }

    #[tokio::test]
    async fn test_handle_registry_connection_publish_did_doc_rejected_when_not_ca() {
        let req = r#"{"action":"publish_did_doc","node_name":"nodeB","did_doc_json":"{}"}"#;
        let resp = roundtrip(empty_registry(), req).await;
        assert!(!resp.success);
        assert!(resp
            .error
            .unwrap()
            .contains("Only CA can ingest DID documents"));
    }

    #[tokio::test]
    async fn test_handle_registry_connection_snapshot_did_doc_rejected_when_not_ca() {
        let req = r#"{"action":"snapshot_did_doc","node_name":""}"#;
        let resp = roundtrip(empty_registry(), req).await;
        assert!(!resp.success);
        assert!(resp
            .error
            .unwrap()
            .contains("Only CA can serve DID document snapshots"));
    }

    #[tokio::test]
    async fn test_handle_registry_connection_resolve_did_rejected_when_not_ca() {
        let req = r#"{"action":"resolve_did","node_name":"","did_query":"did:example:123"}"#;
        let resp = roundtrip(empty_registry(), req).await;
        assert!(!resp.success);
        assert!(resp
            .error
            .unwrap()
            .contains("Only CA can serve DID document point lookups"));
    }

    #[tokio::test]
    async fn test_handle_registry_connection_snapshot_rejected_when_not_ca() {
        let req = r#"{"action":"snapshot","node_name":""}"#;
        let resp = roundtrip(empty_registry(), req).await;
        assert!(!resp.success);
        assert!(resp
            .error
            .unwrap()
            .contains("Only CA can serve registry snapshots"));
    }

    #[tokio::test]
    async fn test_handle_registry_connection_snapshot_lh_rejected_when_not_ca() {
        let req = r#"{"action":"snapshot_lh","node_name":""}"#;
        let resp = roundtrip(empty_registry(), req).await;
        assert!(!resp.success);
        assert!(resp
            .error
            .unwrap()
            .contains("Only CA can serve registry snapshots"));
    }

    #[tokio::test]
    async fn test_handle_registry_connection_snapshot_relay_rejected_when_not_ca() {
        let req = r#"{"action":"snapshot_relay","node_name":""}"#;
        let resp = roundtrip(empty_registry(), req).await;
        assert!(!resp.success);
        assert!(resp
            .error
            .unwrap()
            .contains("Only CA can serve registry snapshots"));
    }

    #[tokio::test]
    async fn test_handle_registry_connection_status_list_snapshot_rejected_when_not_ca() {
        let req = r#"{"action":"status_list_snapshot","node_name":""}"#;
        let resp = roundtrip(empty_registry(), req).await;
        assert!(!resp.success);
        assert!(resp
            .error
            .unwrap()
            .contains("Only CA can serve registry snapshots"));
    }

    // ── local ip cache round trip (env-overridable path) ─────────
    //
    // `CACHE_PATH` itself is a hardcoded `/var/lib/...` constant with no
    // env-var override in this file (unlike e.g. `src/did/doc_persistence.rs`'s
    // `..._PATH_ENV` constants), and `save_local_ip_cache` additionally tries
    // to `create_dir_all("/var/lib/sgx-guardian")`, which is not writable by
    // an unprivileged test process. So `save_local_ip_cache`,
    // `load_local_ip_cache`, `clear_local_ip_cache`, and `ensure_dirs` are not
    // exercised here — they are left uncovered for that reason.

    // ── client functions (pull_*_from_ca / request_ip_from_ca /
    // query_ip_from_ca / resolve_overlay_ip) ──────────────────────
    //
    // Unlike `handle_registry_connection`, these hardcode
    // `format!("{ca_host}:{REGISTRY_SYNC_PORT}")` with no port override, so
    // there is no ephemeral-port seam available — the ONLY way to exercise
    // them against a real socket is to bind the real, fixed
    // `REGISTRY_SYNC_PORT` (50062) on loopback. A process-wide async mutex
    // serializes every test below so at most one of them ever holds that
    // port at a time, regardless of test-runner thread count. A fake
    // responder (not the real `start_registry_server`/`handle_registry_connection`,
    // which are already covered above via the ephemeral-port `roundtrip`
    // helper) gives full control over the response for each case.
    // The lock now lives in `crate::test_support` so the other suites that
    // bind this same fixed port (`did::tests::resolver_tests`, `api::tests`)
    // serialize against it too.
    use crate::test_support::registry_port_lock;

    async fn fake_ca_responder(response_line: String) -> tokio::task::JoinHandle<Vec<u8>> {
        let listener = TcpListener::bind(("127.0.0.1", REGISTRY_SYNC_PORT))
            .await
            .expect("bind fixed registry port (held by REGISTRY_PORT_LOCK)");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut request_line = String::new();
            reader
                .read_line(&mut request_line)
                .await
                .expect("read request");
            writer
                .write_all(response_line.as_bytes())
                .await
                .expect("write response");
            request_line.into_bytes()
        })
    }

    #[tokio::test]
    async fn pull_registry_snapshot_from_ca_returns_the_raw_response_line() {
        let _guard = registry_port_lock().await;
        let server = fake_ca_responder("{\"nodes\":{}}\n".to_string()).await;
        let result = pull_registry_snapshot_from_ca("127.0.0.1").await;
        assert_eq!(result.as_deref(), Ok("{\"nodes\":{}}\n"));
        let request = server.await.expect("server task joined");
        let request: RegistryRequest =
            serde_json::from_slice(&request).expect("parse request sent by client");
        assert_eq!(request.action, "snapshot");
    }

    #[tokio::test]
    async fn pull_lighthouse_snapshot_from_ca_returns_the_raw_response_line() {
        let _guard = registry_port_lock().await;
        let server = fake_ca_responder("{\"lighthouses\":[]}\n".to_string()).await;
        let result = pull_lighthouse_snapshot_from_ca("127.0.0.1").await;
        assert_eq!(result.as_deref(), Ok("{\"lighthouses\":[]}\n"));
        let request: RegistryRequest =
            serde_json::from_slice(&server.await.expect("server joined")).expect("parse request");
        assert_eq!(request.action, "snapshot_lh");
    }

    #[tokio::test]
    async fn pull_relay_snapshot_from_ca_returns_the_raw_response_line() {
        let _guard = registry_port_lock().await;
        let server = fake_ca_responder("{\"relays\":{}}\n".to_string()).await;
        let result = pull_relay_snapshot_from_ca("127.0.0.1").await;
        assert_eq!(result.as_deref(), Ok("{\"relays\":{}}\n"));
        let request: RegistryRequest =
            serde_json::from_slice(&server.await.expect("server joined")).expect("parse request");
        assert_eq!(request.action, "snapshot_relay");
    }

    #[tokio::test]
    async fn pull_status_list_snapshot_from_ca_parses_a_registry_response() {
        let _guard = registry_port_lock().await;
        let response = RegistryResponse {
            success: true,
            status_list_body: Some("status-list-body".to_string()),
            ..Default::default()
        };
        let mut line = serde_json::to_string(&response).expect("serialize response");
        line.push('\n');
        let server = fake_ca_responder(line).await;
        let result = pull_status_list_snapshot_from_ca("127.0.0.1")
            .await
            .expect("parse response");
        assert!(result.success);
        assert_eq!(result.status_list_body.as_deref(), Some("status-list-body"));
        let request: RegistryRequest =
            serde_json::from_slice(&server.await.expect("server joined")).expect("parse request");
        assert_eq!(request.action, "status_list_snapshot");
    }

    #[tokio::test]
    async fn request_ip_from_ca_succeeds_and_reports_the_assigned_ip() {
        let _guard = registry_port_lock().await;
        let response = RegistryResponse {
            success: true,
            ip_cidr: Some("192.168.100.7/24".to_string()),
            ip: Some("192.168.100.7".to_string()),
            ..Default::default()
        };
        let mut line = serde_json::to_string(&response).expect("serialize");
        line.push('\n');
        let server = fake_ca_responder(line).await;
        let (ip_cidr, ip) = request_ip_from_ca("nodeB", "127.0.0.1", "aabbcc")
            .await
            .expect("assign should succeed");
        assert_eq!(ip_cidr, "192.168.100.7/24");
        assert_eq!(ip, "192.168.100.7");
        let request: RegistryRequest =
            serde_json::from_slice(&server.await.expect("server joined")).expect("parse request");
        assert_eq!(request.action, "assign");
        assert_eq!(request.node_name, "nodeB");
    }

    #[tokio::test]
    async fn request_ip_from_ca_surfaces_a_server_side_error() {
        let _guard = registry_port_lock().await;
        let response = RegistryResponse {
            success: false,
            error: Some("Only CA can assign IPs".to_string()),
            ..Default::default()
        };
        let mut line = serde_json::to_string(&response).expect("serialize");
        line.push('\n');
        let _server = fake_ca_responder(line).await;
        let error = request_ip_from_ca("nodeB", "127.0.0.1", "aabbcc")
            .await
            .expect_err("server error must surface");
        assert_eq!(error, "Only CA can assign IPs");
    }

    #[tokio::test]
    async fn query_ip_from_ca_succeeds_and_reports_the_known_ip() {
        let _guard = registry_port_lock().await;
        let response = RegistryResponse {
            success: true,
            ip_cidr: Some("192.168.100.9/24".to_string()),
            ip: Some("192.168.100.9".to_string()),
            ..Default::default()
        };
        let mut line = serde_json::to_string(&response).expect("serialize");
        line.push('\n');
        let server = fake_ca_responder(line).await;
        let (ip_cidr, ip) = query_ip_from_ca("nodeC", "127.0.0.1")
            .await
            .expect("query should succeed");
        assert_eq!(ip_cidr, "192.168.100.9/24");
        assert_eq!(ip, "192.168.100.9");
        let request: RegistryRequest =
            serde_json::from_slice(&server.await.expect("server joined")).expect("parse request");
        assert_eq!(request.action, "query");
    }

    #[tokio::test]
    async fn resolve_overlay_ip_returns_the_ca_assigned_ip_on_first_attempt() {
        let _guard = registry_port_lock().await;
        let response = RegistryResponse {
            success: true,
            ip_cidr: Some("192.168.100.5/24".to_string()),
            ip: Some("192.168.100.5".to_string()),
            ..Default::default()
        };
        let mut line = serde_json::to_string(&response).expect("serialize");
        line.push('\n');
        let _server = fake_ca_responder(line).await;
        // `ensure_dirs`/`save_local_ip_cache` hit the real unwritable
        // `/var/lib/sgx-guardian` path, but both failures are caught and
        // only logged — the function still returns the CA-assigned IP.
        let ip_cidr = resolve_overlay_ip("node-resolve-test", "127.0.0.1", "aabbcc").await;
        assert_eq!(ip_cidr, "192.168.100.5/24");
    }
}
