use anyhow::{Context, Result};
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig};
use std::fs;
use std::sync::Arc;
pub struct TlsConfig {
    pub server: ServerConfig,
    pub client: ClientConfig,
}
/// Load PEM private key
pub fn load_private_key(path: &str) -> Result<PrivateKey> {
    let key_bytes =
        fs::read(path).with_context(|| format!("Failed to read private key: {}", path))?;

    let key = rustls_pemfile::pkcs8_private_keys(&mut key_bytes.as_slice())
        .unwrap()
        .remove(0);

    Ok(PrivateKey(key))
}
/// Load PEM certificate
pub fn load_certificate(path: &str) -> Result<Vec<Certificate>> {
    let cert_bytes =
        fs::read(path).with_context(|| format!("Failed to read certificate: {}", path))?;

    let certs = rustls_pemfile::certs(&mut cert_bytes.as_slice())
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();

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
    // ----- AUTO SAN + CN FIX FOR EACH NODE -----
    // Determine node ID from CLI args (nodeA / nodeB / nodeC)
    let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());
    // Load config for this node
    let conf_path = format!("config/{}.yaml", node_id);
    let node_conf = crate::config_loader::load_config(&conf_path)
        .expect("Failed to load node config inside TLS generator");
    // Extract hostname + IP for SAN fields
    let san_dns = node_conf.hostname.clone(); // guardian-node-A etc
    let san_ip = node_conf.ip.clone(); // 127.0.0.1
                                       // Apply SAN entries to certificate params
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName(san_dns.clone()), // guardian-node-A
        rcgen::SanType::DnsName("127.0.0.1".into()), // ← REQUIRED
        rcgen::SanType::IpAddress(san_ip.parse().unwrap()), // 127.0.0.1
    ];
    // Add CN
    let mut dn = DistinguishedName::new();
    let cn = subject_alt_names.first().cloned().unwrap_or("sgx-node");
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;
    params.key_pair = Some(kp);
    // Create certificate
    let cert = RcgenCert::from_params(params)
        .map_err(|e| anyhow::anyhow!("Failed to create rcgen certificate: {:?}", e))?;
    // Convert to DER and persist
    let der = cert
        .serialize_der()
        .map_err(|e| anyhow::anyhow!("Failed to serialize DER: {:?}", e))?;
    fs::write(cert_path, &der)
        .with_context(|| format!("Failed to write certificate file {}", cert_path))?;
    Ok(der)
}
/// Convert DER bytes → PEM string for tonic TLS
pub fn der_to_pem(der: &[u8]) -> String {
    let pem = pem::Pem {
        tag: "CERTIFICATE".to_string(),
        contents: der.to_vec(),
    };
    pem::encode(&pem)
}
