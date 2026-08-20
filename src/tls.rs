use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use anyhow::{Context, Result};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::fs;
use std::sync::Arc;

pub struct TlsConfig {
    pub server: ServerConfig,
    pub client: ClientConfig,
}
/// Load PEM private key (safe, rustls-pemfile removed)
pub fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let pem_data = fs::read_to_string(path)
        .with_context(|| format!("Failed to read private key: {}", path))?;

    let blocks =
        pem::parse_many(&pem_data).map_err(|e| anyhow::anyhow!("Failed to parse PEM: {}", e))?;

    for block in blocks {
        match block.tag() {
            "PRIVATE KEY" | "RSA PRIVATE KEY" => {
                let key_bytes = block.contents().to_vec();
                return Ok(match block.tag() {
                    "PRIVATE KEY" => PrivatePkcs8KeyDer::from(key_bytes).into(),
                    "RSA PRIVATE KEY" => PrivatePkcs1KeyDer::from(key_bytes).into(),
                    _ => unreachable!(),
                });
            }
            "EC PRIVATE KEY" => {
                return Ok(PrivateSec1KeyDer::from(block.contents().to_vec()).into());
            }
            _ => continue,
        }
    }

    Err(anyhow::anyhow!("No valid private key found in PEM file"))
}
/// Load PEM certificates (safe, rustls-pemfile removed)
pub fn load_certificate(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let pem_data = fs::read_to_string(path)
        .with_context(|| format!("Failed to read certificate: {}", path))?;

    let blocks = pem::parse_many(&pem_data)
        .map_err(|e| anyhow::anyhow!("Failed to parse PEM certificates: {}", e))?;

    let certs: Vec<CertificateDer<'static>> = blocks
        .into_iter()
        .filter(|b| b.tag() == "CERTIFICATE")
        .map(|b| CertificateDer::from(b.contents().to_vec()))
        .collect();

    if certs.is_empty() {
        return Err(anyhow::anyhow!("No certificates found in PEM file"));
    }

    Ok(certs)
}
/// Build server-side TLS config (requires client certs)
pub fn build_server_config(
    server_cert: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    client_ca: Vec<CertificateDer<'static>>,
) -> Result<ServerConfig> {
    let mut root = RootCertStore::empty();
    for ca in client_ca {
        root.add(ca)?;
    }
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root)).build()?;
    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_cert, private_key)?;

    Ok(config)
}
/// Build client-side TLS config
pub fn build_client_config(
    ca_certs: Vec<CertificateDer<'static>>,
    client_cert: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<ClientConfig> {
    let mut root = RootCertStore::empty();
    for ca in ca_certs {
        root.add(ca)?;
    }
    let config = ClientConfig::builder()
        .with_root_certificates(root)
        .with_client_auth_cert(client_cert, private_key)?;
    Ok(config)
}
// Certificate-generation helper
use rcgen::{Certificate as RcgenCert, CertificateParams, DistinguishedName, DnType, KeyPair};
fn certificate_contains_required_dns_names(der: &[u8], subject_alt_names: &[&str]) -> bool {
    subject_alt_names
        .iter()
        .filter(|name| name.parse::<std::net::IpAddr>().is_err())
        .all(|name| der.windows(name.len()).any(|window| window == name.as_bytes()))
}

/// Ensures a DER certificate exists at `cert_path` and contains every requested
/// DNS SAN. A certificate from an older release is backed up and reissued with
/// the same private key when a required LAN name is missing.
pub fn ensure_node_certificate_or_generate(
    key_path: &str,
    cert_path: &str,
    subject_alt_names: &[&str],
) -> Result<Vec<u8>> {
    // Reuse an existing certificate only when it covers the current canonical
    // LAN name. DNS SAN values are IA5 strings in DER, so this check does not
    // require an additional X.509 parser on constrained board builds.
    if std::path::Path::new(cert_path).exists() {
        let der = fs::read(cert_path)
            .with_context(|| format!("Failed to read existing certificate: {}", cert_path))?;

        let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());

        if !certificate_contains_required_dns_names(&der, subject_alt_names) {
            let backup_path = format!("{}.pre-lan-name.bak", cert_path);
            if !std::path::Path::new(&backup_path).exists() {
                fs::copy(cert_path, &backup_path).with_context(|| {
                    format!("Failed to back up previous TLS certificate to {}", backup_path)
                })?;
            }
            log_audit(
                &node_id,
                AuditCategory::Tls,
                AuditSeverity::Warning,
                AuditAction::Applied,
                "TLS certificate missing canonical LAN DNS name; reissuing with existing key",
            );
        } else {
            log_audit(
                &node_id,
                AuditCategory::Tls,
                AuditSeverity::Info,
                AuditAction::Succeeded,
                "TLS certificate loaded from disk",
            );

            return Ok(der);
        }
    }
    // Load private key as raw DER
    let pkcs8_der = fs::read(key_path)
        .with_context(|| format!("Failed to read private key DER: {}", key_path))?;
    // Build rcgen KeyPair from private key
    let kp = KeyPair::from_der(&pkcs8_der)
        .map_err(|e| anyhow::anyhow!("Failed to create rcgen KeyPair: {:?}", e))?;
    // Build certificate params
    let mut params = CertificateParams::default();
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
