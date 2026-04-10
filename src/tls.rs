use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use anyhow::{Context, Result};
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig};
use std::fs;
use std::sync::Arc;

pub struct TlsConfig {
    pub server: ServerConfig,
    pub client: ClientConfig,
}
/// Load PEM private key (safe, rustls-pemfile removed)
pub fn load_private_key(path: &str) -> Result<PrivateKey> {
    let pem_data = fs::read_to_string(path)
        .with_context(|| format!("Failed to read private key: {}", path))?;

    let blocks =
        pem::parse_many(&pem_data).map_err(|e| anyhow::anyhow!("Failed to parse PEM: {}", e))?;

    for block in blocks {
        match block.tag() {
            "PRIVATE KEY" | "RSA PRIVATE KEY" => {
                return Ok(PrivateKey(block.contents().to_vec()));
            }
            "EC PRIVATE KEY" => {
                return Err(anyhow::anyhow!(
                    "EC PRIVATE KEY (SEC1) not supported; provide PKCS#8"
                ));
            }
            _ => continue,
        }
    }

    Err(anyhow::anyhow!("No valid private key found in PEM file"))
}
/// Load PEM certificates (safe, rustls-pemfile removed)
pub fn load_certificate(path: &str) -> Result<Vec<Certificate>> {
    let pem_data = fs::read_to_string(path)
        .with_context(|| format!("Failed to read certificate: {}", path))?;

    let blocks = pem::parse_many(&pem_data)
        .map_err(|e| anyhow::anyhow!("Failed to parse PEM certificates: {}", e))?;

    let certs: Vec<Certificate> = blocks
        .into_iter()
        .filter(|b| b.tag() == "CERTIFICATE")
        .map(|b| Certificate(b.contents().to_vec()))
        .collect();

    if certs.is_empty() {
        return Err(anyhow::anyhow!("No certificates found in PEM file"));
    }

    Ok(certs)
}
/// Build server-side TLS config (requires client certs)
pub fn build_server_config(
    server_cert: Vec<Certificate>,
    private_key: PrivateKey,
    client_ca: Vec<Certificate>,
) -> Result<ServerConfig> {
    let mut root = RootCertStore::empty();
    for ca in client_ca {
        root.add(&ca)?;
    }
    let client_verifier = AllowAnyAuthenticatedClient::new(root);
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(Arc::new(client_verifier))
        .with_single_cert(server_cert, private_key)?;

    Ok(config)
}
/// Build client-side TLS config
pub fn build_client_config(
    ca_certs: Vec<Certificate>,
    client_cert: Vec<Certificate>,
    private_key: PrivateKey,
) -> Result<ClientConfig> {
    let mut root = RootCertStore::empty();
    for ca in ca_certs {
        root.add(&ca)?;
    }
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root)
        .with_client_auth_cert(client_cert, private_key)?;
    Ok(config)
}
// Certificate-generation helper
use rcgen::{Certificate as RcgenCert, CertificateParams, DistinguishedName, DnType, KeyPair};
/// Ensures a DER certificate exists at `cert_path`.
/// If missing, it generates a self-signed cert using the existing private key (`key_path`).
pub fn ensure_node_certificate_or_generate(
    key_path: &str,
    cert_path: &str,
    subject_alt_names: &[&str],
) -> Result<Vec<u8>> {
    // If certificate already exists → load & return raw DER
    if std::path::Path::new(cert_path).exists() {
        let der = fs::read(cert_path)
            .with_context(|| format!("Failed to read existing certificate: {}", cert_path))?;

        let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());

        log_audit(
            &node_id,
            AuditCategory::Tls,
            AuditSeverity::Info,
            AuditAction::Succeeded,
            "TLS certificate loaded from disk",
        );

        return Ok(der);
    }
    // Load private key as raw DER
    let pkcs8_der = fs::read(key_path)
        .with_context(|| format!("Failed to read private key DER: {}", key_path))?;
    // Build rcgen KeyPair from private key
    let kp = KeyPair::from_der(&pkcs8_der)
        .map_err(|e| anyhow::anyhow!("Failed to create rcgen KeyPair: {:?}", e))?;
    // Build certificate params
    let mut params = CertificateParams::new(
        subject_alt_names
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<String>>(),
    );
    // Convert SAN input into DNS/IP entries and keep loopback available.
    let mut san_entries: Vec<rcgen::SanType> = Vec::new();
    for san in subject_alt_names {
        if let Ok(ip) = san.parse::<std::net::IpAddr>() {
            san_entries.push(rcgen::SanType::IpAddress(ip));
        } else {
            san_entries.push(rcgen::SanType::DnsName((*san).to_string()));
        }
    }
    let has_loopback = san_entries
        .iter()
        .any(|entry| matches!(entry, rcgen::SanType::IpAddress(ip) if ip.is_loopback()));
    if !has_loopback {
        san_entries.push(rcgen::SanType::IpAddress(
            "127.0.0.1".parse().expect("valid loopback IP"),
        ));
    }
    params.subject_alt_names = san_entries;
    // Add CN
    let mut dn = DistinguishedName::new();
    let cn = subject_alt_names.first().cloned().unwrap_or("sgx-node");
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;
    params.key_pair = Some(kp);
    // Create certificate
    let cert = RcgenCert::from_params(params).map_err(|e| {
        let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());

        log_audit(
            &node_id,
            AuditCategory::Tls,
            AuditSeverity::Critical,
            AuditAction::Failed,
            "TLS certificate generation failed",
        );

        anyhow::anyhow!("Failed to create rcgen certificate: {:?}", e)
    })?;
    // Convert to DER and persist
    let der = cert
        .serialize_der()
        .map_err(|e| anyhow::anyhow!("Failed to serialize DER: {:?}", e))?;
    fs::write(cert_path, &der)
        .with_context(|| format!("Failed to write certificate file {}", cert_path))?;

    let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());

    log_audit(
        &node_id,
        AuditCategory::Tls,
        AuditSeverity::Warning,
        AuditAction::Applied,
        "TLS certificate generated and written to disk",
    );

    Ok(der)
}
/// Convert DER bytes → PEM string for tonic TLS
pub fn der_to_pem(der: &[u8]) -> String {
    let pem = pem::Pem::new("CERTIFICATE", der.to_vec());
    pem::encode(&pem)
}
