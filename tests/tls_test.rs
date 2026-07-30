// tests/tls_test.rs
// Integration tests for src/tls.rs

use sgx_guardian_client::tls::{
    build_client_config, build_server_config, der_to_pem, ensure_node_certificate_or_generate,
    load_certificate, load_private_key,
};
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;

#[test]
fn test_pem_conversion() {
    let der = vec![1, 2, 3, 4];
    let pem = der_to_pem(&der);
    assert!(pem.contains("-----BEGIN CERTIFICATE-----"));
    assert!(pem.contains("-----END CERTIFICATE-----"));
}

#[test]
fn test_tls_generation_and_loading_flow() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("device.key");
    let cert_path = temp_dir.path().join("device.crt");

    // 1. Generate a mock keypair using rcgen and save it
    let rc_keypair = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let pkcs8_der = rc_keypair.serialize_der();
    fs::write(&key_path, &pkcs8_der).unwrap();

    // 2. Test certificate generation
    let san = vec!["127.0.0.1", "localhost"];
    let cert_der = ensure_node_certificate_or_generate(
        key_path.to_str().unwrap(),
        cert_path.to_str().unwrap(),
        &san,
    )
    .unwrap();
    assert!(!cert_der.is_empty());

    // 3. Test idempotency (loading existing cert)
    let cert_der_cached = ensure_node_certificate_or_generate(
        key_path.to_str().unwrap(),
        cert_path.to_str().unwrap(),
        &san,
    )
    .unwrap();
    assert_eq!(cert_der, cert_der_cached);

    // 4. Convert PKCS8 DER private key to PEM to test load_private_key
    let key_pem_content = pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8_der.clone()));
    let key_pem_path = temp_dir.path().join("device_key.pem");
    fs::write(&key_pem_path, key_pem_content).unwrap();

    let loaded_key = load_private_key(key_pem_path.to_str().unwrap()).unwrap();

    // 5. Convert cert DER to PEM to test load_certificate
    let cert_pem_content = pem::encode(&pem::Pem::new("CERTIFICATE", cert_der.clone()));
    let cert_pem_path = temp_dir.path().join("device_cert.pem");
    fs::write(&cert_pem_path, cert_pem_content).unwrap();

    let loaded_certs = load_certificate(cert_pem_path.to_str().unwrap()).unwrap();
    assert_eq!(loaded_certs.len(), 1);

    // 6. Test build_server_config and build_client_config
    let client_ca = loaded_certs.clone();
    let server_config = build_server_config(loaded_certs.clone(), loaded_key, client_ca);
    assert!(server_config.is_ok());

    // Re-load key because loaded_key was consumed (moved)
    let loaded_key_for_client = load_private_key(key_pem_path.to_str().unwrap()).unwrap();
    let client_config =
        build_client_config(loaded_certs.clone(), loaded_certs, loaded_key_for_client);
    assert!(client_config.is_ok());

    // 7. Verify handshake using in-memory ClientConnection and ServerConnection
    let client_config_arc = Arc::new(client_config.unwrap());
    let server_config_arc = Arc::new(server_config.unwrap());

    let mut client_conn = rustls::ClientConnection::new(
        client_config_arc,
        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();

    let mut server_conn = rustls::ServerConnection::new(server_config_arc).unwrap();

    // Complete TLS Handshake in memory
    let mut loop_count = 0;
    while (client_conn.is_handshaking() || server_conn.is_handshaking()) && loop_count < 100 {
        loop_count += 1;

        // Client -> Server
        if client_conn.wants_write() {
            let mut buf = Vec::new();
            client_conn.write_tls(&mut buf).unwrap();

            let mut read_slice = &buf[..];
            server_conn.read_tls(&mut read_slice).unwrap();
            server_conn.process_new_packets().unwrap();
        }

        // Server -> Client
        if server_conn.wants_write() {
            let mut buf = Vec::new();
            server_conn.write_tls(&mut buf).unwrap();

            let mut read_slice = &buf[..];
            client_conn.read_tls(&mut read_slice).unwrap();
            client_conn.process_new_packets().unwrap();
        }
    }

    assert!(!client_conn.is_handshaking());
    assert!(!server_conn.is_handshaking());
}
