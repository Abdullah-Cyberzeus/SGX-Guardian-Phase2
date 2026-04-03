// src/nebula/registry_sync.rs
// ============================================================
// Overlay Registry Sync — Multi-PC Support
// ============================================================

use crate::nebula::overlay_registry::OverlayRegistry;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

pub const REGISTRY_SYNC_PORT: u16 = 50062;
pub const REGISTRY_PATH: &str = "/var/lib/sgx-guardian/nebula/overlay_registry.json";
pub const CACHE_PATH: &str = "/var/lib/sgx-guardian/nebula/local_ip_cache.json";

pub type SharedRegistry = Arc<RwLock<OverlayRegistry>>;

// ── Wire Messages ─────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryRequest {
    pub action: String, // "assign" | "query" | "list"
    pub node_name: String,
    pub pubkey_prefix: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryResponse {
    pub success: bool,
    pub ip_cidr: Option<String>,
    pub ip: Option<String>,
    pub error: Option<String>,
    pub registry_summary: Option<String>,
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
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("Cannot create {}: {}", dir, e))?;
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

async fn handle_registry_connection(
    stream: TcpStream,
    registry: SharedRegistry,
) -> Result<(), Box<dyn std::error::Error>> {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    buf_reader.read_line(&mut line).await?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    let request: RegistryRequest = match serde_json::from_str(trimmed) {
        Ok(r) => r,
        Err(e) => {
            let resp = RegistryResponse {
                success: false,
                ip_cidr: None,
                ip: None,
                error: Some(format!("Invalid JSON: {}", e)),
                registry_summary: None,
            };
            let mut json = serde_json::to_string(&resp)?;
            json.push('\n');
            writer.write_all(json.as_bytes()).await?;
            return Ok(());
        }
    };

    let response = match request.action.as_str() {
        "assign" => {
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
                        error: None,
                        registry_summary: Some(reg.summary()),
                    }
                }
                Err(e) => RegistryResponse {
                    success: false,
                    ip_cidr: None,
                    ip: None,
                    error: Some(e),
                    registry_summary: None,
                },
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
                        error: None,
                        registry_summary: None,
                    }
                }
                None => RegistryResponse {
                    success: false,
                    ip_cidr: None,
                    ip: None,
                    error: Some(format!("{} not found in registry", request.node_name)),
                    registry_summary: None,
                },
            }
        }

        "list" => {
            let reg = registry.read().await;
            RegistryResponse {
                success: true,
                ip_cidr: None,
                ip: None,
                error: None,
                registry_summary: Some(reg.summary()),
            }
        }

        _ => RegistryResponse {
            success: false,
            ip_cidr: None,
            ip: None,
            error: Some(format!("Unknown action: {}", request.action)),
            registry_summary: None,
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
    };

    let mut json = serde_json::to_string(&request)
        .map_err(|e| format!("Serialize: {}", e))?;
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
        Err(response.error.unwrap_or_else(|| "Unknown error".to_string()))
    }
}

// ── Main resolver for member nodes ────────────────────────────

/// Call this from main.rs for any non-CA node.
/// Order: cache → CA → deterministic fallback
pub async fn resolve_overlay_ip(
    node_name: &str,
    ca_host: &str,
    pubkey_prefix: &str,
) -> String {
    if let Err(e) = ensure_dirs() {
        eprintln!("⚠️  [OverlayIP] Dir setup failed: {}", e);
    }

    // 1. Cache
    if let Some(cached) = load_local_ip_cache(node_name) {
        println!("✅ [OverlayIP] Cache hit: {} → {}", node_name, cached);
        return cached;
    }

    println!("📡 [OverlayIP] Requesting IP from CA {}:{}...", ca_host, REGISTRY_SYNC_PORT);

    // 2. CA request
    match request_ip_from_ca(node_name, ca_host, pubkey_prefix).await {
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
            eprintln!("   Fix checklist:");
            eprintln!("     1. nodeA running? (cargo run -- nodeA)");
            eprintln!("     2. Port open? (nc -zv {} {})", ca_host, REGISTRY_SYNC_PORT);
            eprintln!("     3. nodeA.yaml correct IP?");
            eprintln!("     4. Firewall: sudo ufw allow {}/tcp", REGISTRY_SYNC_PORT);

            // 3. Deterministic fallback
            let host: u8 = match node_name {
                "nodeB" => 2,
                "nodeC" => 3,
                "nodeD" => 4,
                _ => {
                    let sum: u32 = node_name.bytes().map(|b| b as u32).sum();
                    ((sum % 250) + 5) as u8
                }
            };
            let fallback = format!("192.168.100.{}/24", host);
            eprintln!("⚠️  [OverlayIP] Fallback: {} (temporary — connect CA for permanent)", fallback);
            let _ = save_local_ip_cache(node_name, &fallback);
            fallback
        }
    }
}

// ── Cache helpers ─────────────────────────────────────────────

pub fn save_local_ip_cache(node_name: &str, ip_cidr: &str) -> Result<(), String> {
    for dir in &["/var/lib/sgx-guardian", "/var/lib/sgx-guardian/nebula"] {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("Cannot create {}: {}", dir, e))?;
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
    let json = serde_json::to_string_pretty(&cache)
        .map_err(|e| format!("Serialize: {}", e))?;

    std::fs::write(&tmp, &json)
        .map_err(|e| format!("Write {}: {}", tmp, e))?;

    std::fs::rename(&tmp, CACHE_PATH)
        .map_err(|e| format!("Rename: {}", e))?;

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
    let content = std::fs::read_to_string(CACHE_PATH)
        .map_err(|e| format!("Read: {}", e))?;
    let mut cache: HashMap<String, String> =
        serde_json::from_str(&content).unwrap_or_default();
    cache.remove(node_name);
    let json = serde_json::to_string_pretty(&cache)
        .map_err(|e| format!("Serialize: {}", e))?;
    std::fs::write(CACHE_PATH, json)
        .map_err(|e| format!("Write: {}", e))?;
    println!("🗑️  Cache cleared for {}", node_name);
    Ok(())
}