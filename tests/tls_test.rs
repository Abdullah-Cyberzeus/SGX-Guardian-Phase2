use rcgen::generate_simple_self_signed;
use rustls::{Certificate, PrivateKey};
use sgx_guardian_client::tls;
#[test]
fn test_tls_certificate_loading() {
    // === 1. Generate a valid ECDSA-P256 keypair + certificate ===
    let subject_alt_names = vec!["localhost".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names)
        .expect("failed to generate self-signed certificate");
    // rcgen gives DER cert + DER key
    let cert_der = cert.serialize_der().expect("serialize cert failed");
    let key_der = cert.serialize_private_key_der();
    let certificate = Certificate(cert_der.clone());
    let private_key = PrivateKey(key_der.clone());
    let cert_chain = vec![certificate.clone()];
    let ca_chain = vec![certificate];
    // === 2. Test server TLS config ===
    let server_cfg =
        tls::build_server_config(cert_chain.clone(), private_key.clone(), ca_chain.clone());
    if let Err(e) = &server_cfg {
        println!("❌ Server TLS config error: {:?}", e);
    }
    assert!(server_cfg.is_ok());
    // === 3. Test client TLS config ===
    let client_cfg = tls::build_client_config(ca_chain, cert_chain, private_key);
    if let Err(e) = &client_cfg {
        println!("❌ Client TLS config error: {:?}", e);
    }
    assert!(client_cfg.is_ok());
}
