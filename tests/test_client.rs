use rcgen::generate_simple_self_signed;
use sgx_guardian_client::client::send_ping;
use tonic::transport::{Certificate, Identity};
#[tokio::test]
async fn test_send_ping_with_identity() {
    // 1. Create a temporary certificate + key
    let cert =
        generate_simple_self_signed(vec!["localhost".into()]).expect("Failed to generate cert");
    let cert_pem = cert.serialize_pem().unwrap();
    let key_pem = cert.serialize_private_key_pem();
    // 2. Build Identity + CA
    let identity = Identity::from_pem(cert_pem.clone(), key_pem.clone());
    let ca_cert = Certificate::from_pem(cert_pem.clone());
    // 3. Call send_ping with 4 arguments
    let result = send_ping(
        "127.0.0.1:50051".to_string(),
        "test-node".to_string(),
        identity,
        ca_cert,
    )
    .await;
    assert!(result.is_err());
}
