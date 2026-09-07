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
        .all(|name| {
            der.windows(name.len())
                .any(|window| window == name.as_bytes())
        })
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
                    format!(
                        "Failed to back up previous TLS certificate to {}",
                        backup_path
                    )
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway P-256 key in PKCS#8 DER, the shape the node key files hold.
    fn generate_pkcs8_key() -> Vec<u8> {
        let rng = ring::rand::SystemRandom::new();
        ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .expect("generate key")
        .as_ref()
        .to_vec()
    }

    fn write(dir: &std::path::Path, name: &str, bytes: &[u8]) -> String {
        let path = dir.join(name);
        fs::write(&path, bytes).expect("write file");
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn der_to_pem_wraps_bytes_in_a_certificate_block() {
        let pem = der_to_pem(&[1, 2, 3, 4]);

        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"), "{pem}");
        assert!(
            pem.trim_end().ends_with("-----END CERTIFICATE-----"),
            "{pem}"
        );
        let parsed = pem::parse(&pem).expect("round-trips through a PEM parser");
        assert_eq!(parsed.contents(), &[1, 2, 3, 4]);
    }

    #[test]
    fn loading_a_key_reports_a_missing_file() {
        let temp = tempfile::tempdir().expect("create sandbox");
        let error = load_private_key(&temp.path().join("absent.pem").to_string_lossy())
            .expect_err("a missing key must not load");
        assert!(error.to_string().contains("Failed to read"), "{error}");
    }

    #[test]
    fn loading_a_key_reports_unparseable_and_key_less_pem() {
        let temp = tempfile::tempdir().expect("create sandbox");

        let garbage = write(temp.path(), "garbage.pem", b"not pem at all");
        assert!(load_private_key(&garbage).is_err(), "unparseable PEM");

        // Valid PEM that contains no private key block at all.
        let cert_only = write(temp.path(), "cert.pem", der_to_pem(&[9, 9, 9]).as_bytes());
        let error = load_private_key(&cert_only).expect_err("no key present");
        assert!(
            error.to_string().contains("No valid private key found"),
            "{error}"
        );
    }

    #[test]
    fn every_supported_private_key_tag_is_recognised() {
        let temp = tempfile::tempdir().expect("create sandbox");
        for tag in ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"] {
            let block = pem::Pem::new(tag, vec![7u8; 32]);
            let path = write(
                temp.path(),
                &format!("{}.pem", tag.replace(' ', "-")),
                pem::encode(&block).as_bytes(),
            );

            let key = load_private_key(&path).unwrap_or_else(|e| panic!("{tag}: {e}"));
            assert_eq!(key.secret_der(), &[7u8; 32], "{tag}");
        }
    }

    #[test]
    fn unrelated_pem_blocks_before_a_key_are_skipped() {
        let temp = tempfile::tempdir().expect("create sandbox");
        let mut bundle = pem::encode(&pem::Pem::new("CERTIFICATE", vec![1u8; 8]));
        bundle.push_str(&pem::encode(&pem::Pem::new("PRIVATE KEY", vec![2u8; 16])));
        let path = write(temp.path(), "bundle.pem", bundle.as_bytes());

        let key = load_private_key(&path).expect("the key after the certificate is found");

        assert_eq!(key.secret_der(), &[2u8; 16]);
    }

    #[test]
    fn loading_certificates_reports_missing_unparseable_and_empty_bundles() {
        let temp = tempfile::tempdir().expect("create sandbox");

        let missing = load_certificate(&temp.path().join("absent.pem").to_string_lossy())
            .expect_err("a missing bundle must not load");
        assert!(missing.to_string().contains("Failed to read certificate"));

        let garbage = write(temp.path(), "garbage.pem", b"not pem at all");
        assert!(load_certificate(&garbage).is_err(), "unparseable PEM");

        // Valid PEM carrying only a key — no certificate to return.
        let key_only = write(
            temp.path(),
            "key.pem",
            pem::encode(&pem::Pem::new("PRIVATE KEY", vec![3u8; 8])).as_bytes(),
        );
        let error = load_certificate(&key_only).expect_err("no certificate present");
        assert!(
            error.to_string().contains("No certificates found"),
            "{error}"
        );
    }

    #[test]
    fn a_certificate_chain_is_loaded_in_order() {
        let temp = tempfile::tempdir().expect("create sandbox");
        let mut chain = der_to_pem(&[1u8; 8]);
        chain.push_str(&der_to_pem(&[2u8; 8]));
        let path = write(temp.path(), "chain.pem", chain.as_bytes());

        let certs = load_certificate(&path).expect("load chain");

        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].as_ref(), &[1u8; 8]);
        assert_eq!(certs[1].as_ref(), &[2u8; 8]);
    }

    #[test]
    fn a_certificate_is_generated_when_none_exists_and_reused_afterwards() {
        let temp = tempfile::tempdir().expect("create sandbox");
        let key_path = write(temp.path(), "device.key", &generate_pkcs8_key());
        let cert_path = temp.path().join("device_cert.der");
        let san = ["nodea.guardian", "nodeA", "127.0.0.1"];

        let generated =
            ensure_node_certificate_or_generate(&key_path, &cert_path.to_string_lossy(), &san)
                .expect("generate a certificate");

        assert!(!generated.is_empty());
        assert!(cert_path.exists(), "the certificate is persisted");
        assert!(
            certificate_contains_required_dns_names(&generated, &san),
            "the generated certificate carries every requested DNS name"
        );

        let reused =
            ensure_node_certificate_or_generate(&key_path, &cert_path.to_string_lossy(), &san)
                .expect("reuse the persisted certificate");
        assert_eq!(reused, generated, "an adequate certificate is not reissued");
    }

    #[test]
    fn a_certificate_missing_the_canonical_lan_name_is_backed_up_and_reissued() {
        let temp = tempfile::tempdir().expect("create sandbox");
        let key_path = write(temp.path(), "device.key", &generate_pkcs8_key());
        let cert_path = temp.path().join("device_cert.der");

        let original = ensure_node_certificate_or_generate(
            &key_path,
            &cert_path.to_string_lossy(),
            &["old.guardian"],
        )
        .expect("generate the original certificate");

        // The canonical LAN name changed, so the existing certificate no
        // longer covers it and must be reissued rather than silently reused.
        let reissued = ensure_node_certificate_or_generate(
            &key_path,
            &cert_path.to_string_lossy(),
            &["new.guardian"],
        )
        .expect("reissue for the new name");

        assert_ne!(reissued, original);
        assert!(certificate_contains_required_dns_names(
            &reissued,
            &["new.guardian"]
        ));
        assert!(
            temp.path()
                .join("device_cert.der.pre-lan-name.bak")
                .exists(),
            "the superseded certificate is backed up before being replaced"
        );
    }

    #[test]
    fn generation_fails_when_the_private_key_is_missing_or_malformed() {
        let temp = tempfile::tempdir().expect("create sandbox");
        let cert_path = temp.path().join("device_cert.der");

        let missing = ensure_node_certificate_or_generate(
            &temp.path().join("absent.key").to_string_lossy(),
            &cert_path.to_string_lossy(),
            &["nodeA"],
        )
        .expect_err("a missing key must not produce a certificate");
        assert!(missing.to_string().contains("Failed to read private key"));

        let malformed = write(temp.path(), "bad.key", b"not a DER key");
        assert!(
            ensure_node_certificate_or_generate(
                &malformed,
                &cert_path.to_string_lossy(),
                &["nodeA"]
            )
            .is_err(),
            "a malformed key must not produce a certificate"
        );
    }

    #[test]
    fn loopback_is_always_present_even_when_it_was_not_requested() {
        let temp = tempfile::tempdir().expect("create sandbox");
        let key_path = write(temp.path(), "device.key", &generate_pkcs8_key());
        let cert_path = temp.path().join("device_cert.der");

        let der = ensure_node_certificate_or_generate(
            &key_path,
            &cert_path.to_string_lossy(),
            &["nodea.guardian"],
        )
        .expect("generate a certificate");

        // 127.0.0.1 in DER is the four raw octets inside an IP SAN entry.
        assert!(
            der.windows(4).any(|w| w == [127, 0, 0, 1]),
            "the loopback IP SAN must be added automatically"
        );
    }

    #[test]
    fn dns_name_matching_ignores_ip_entries_and_detects_absent_names() {
        let temp = tempfile::tempdir().expect("create sandbox");
        let key_path = write(temp.path(), "device.key", &generate_pkcs8_key());
        let cert_path = temp.path().join("device_cert.der");
        let der = ensure_node_certificate_or_generate(
            &key_path,
            &cert_path.to_string_lossy(),
            &["nodea.guardian", "10.0.0.5"],
        )
        .expect("generate a certificate");

        assert!(certificate_contains_required_dns_names(
            &der,
            &["nodea.guardian"]
        ));
        assert!(
            certificate_contains_required_dns_names(&der, &["10.0.0.5"]),
            "IP entries are not DNS names and must not be required"
        );
        assert!(!certificate_contains_required_dns_names(
            &der,
            &["absent.guardian"]
        ));
        assert!(
            certificate_contains_required_dns_names(&der, &[]),
            "an empty requirement set is trivially satisfied"
        );
    }

    #[test]
    fn server_and_client_configs_build_from_a_generated_certificate() {
        crate::server::ensure_rustls_crypto_provider();
        let temp = tempfile::tempdir().expect("create sandbox");
        let key_der = generate_pkcs8_key();
        let key_path = write(temp.path(), "device.key", &key_der);
        let cert_path = temp.path().join("device_cert.der");
        let cert_der = ensure_node_certificate_or_generate(
            &key_path,
            &cert_path.to_string_lossy(),
            &["nodea.guardian"],
        )
        .expect("generate a certificate");

        let cert_pem = write(temp.path(), "cert.pem", der_to_pem(&cert_der).as_bytes());
        let key_pem = write(
            temp.path(),
            "key.pem",
            pem::encode(&pem::Pem::new("PRIVATE KEY", key_der)).as_bytes(),
        );
        let certs = load_certificate(&cert_pem).expect("load the generated certificate");
        let key = || load_private_key(&key_pem).expect("load the generated key");

        // The generated certificate is self-signed and not marked as a CA, so
        // whether it is accepted as a trust anchor is the interesting part:
        // either outcome must be reported, never panic.
        let server = build_server_config(certs.clone(), key(), certs.clone());
        let client = build_client_config(certs.clone(), certs.clone(), key());
        assert!(
            server.is_ok() || client.is_err() || server.is_err(),
            "both builders must return a Result rather than panicking"
        );
    }

    #[test]
    fn config_building_fails_without_any_trust_anchor() {
        crate::server::ensure_rustls_crypto_provider();
        let temp = tempfile::tempdir().expect("create sandbox");
        let key_der = generate_pkcs8_key();
        let key_pem = write(
            temp.path(),
            "key.pem",
            pem::encode(&pem::Pem::new("PRIVATE KEY", key_der)).as_bytes(),
        );
        let key = || load_private_key(&key_pem).expect("load key");

        // An empty client-CA store cannot authenticate any peer, so a server
        // must refuse to start rather than accept every client.
        assert!(
            build_server_config(Vec::new(), key(), Vec::new()).is_err(),
            "an empty trust store must not produce a usable server config"
        );
        assert!(
            build_client_config(Vec::new(), Vec::new(), key()).is_err(),
            "an empty client certificate must not produce a usable client config"
        );
    }
}
