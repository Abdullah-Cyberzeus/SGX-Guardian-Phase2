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
pub const LIGHTHOUSE_REGISTRY_PATH: &str = "/var/lib/sgx-guardian/nebula/lighthouse_registry.json";
pub const CACHE_PATH: &str = "/var/lib/sgx-guardian/nebula/local_ip_cache.json";

pub type SharedRegistry = Arc<RwLock<OverlayRegistry>>;

// ── Wire Messages ─────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryRequest {
    pub action: String, // "assign" | "query" | "list" | "snapshot" | "snapshot_lh"
    pub node_name: String,
    pub pubkey_prefix: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
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

    if request.action == "snapshot" || request.action == "snapshot_lh" {
        let path = if request.action == "snapshot_lh" {
            LIGHTHOUSE_REGISTRY_PATH
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
                    ip_cidr: None,
                    ip: None,
                    error: Some(e.to_string()),
                    registry_summary: None,
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
                        let _ = save_local_ip_cache(node_name, &ip_cidr);
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
