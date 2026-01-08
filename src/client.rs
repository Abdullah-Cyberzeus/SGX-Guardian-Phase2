use crate::logging::log_event;
use crate::proto::sgx::ping_service_client::PingServiceClient;
use tonic::transport::{Channel, ClientTlsConfig};
/// Sends a gRPC ping request to a remote SG-X node and logs the response.
/// Uses mTLS via rustls client config passed in.
pub async fn send_ping(
    addr: String,
    from_id: String,
    identity: tonic::transport::Identity,
    ca_cert: tonic::transport::Certificate,
) -> Result<(), Box<dyn std::error::Error>> {
    // Extract peer-node name based on port
    let peer_label = match addr.split(':').next_back() {
        Some("50052") => "nodeB",
        Some("50053") => "nodeC",
        _ => "unknown-peer",
    };
    let endpoint = Channel::from_shared(format!("https://{}", addr))?.tls_config(
        ClientTlsConfig::new()
            .identity(identity.clone())
            .ca_certificate(ca_cert.clone())
            .domain_name("127.0.0.1"),
    )?;
    let channel = endpoint.connect().await?;
    let mut client = PingServiceClient::new(channel);
    let request = tonic::Request::new(crate::proto::sgx::PingRequest {
        from: from_id.clone(),
    });
    let response = client.ping(request).await?;
    let message = response.into_inner().message;
    println!(
        "🎉 gRPC Ping over TLS SUCCESSFUL (from {}) → {}",
        peer_label, message
    );
    log_event(
        &from_id,
        &format!("Ping response from {}: {}", peer_label, message),
    );
    Ok(())
}
