use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::logging::log_event;
use crate::proto::sgx::ping_service_client::PingServiceClient;
use anyhow::Error;
use tonic::transport::{Channel, ClientTlsConfig};

/// Sends a gRPC ping request to a remote SG-X node and logs the response.
/// Uses mTLS via rustls client config passed in.
pub async fn send_ping(
    addr: String,
    from_id: String,
    identity: tonic::transport::Identity,
    ca_cert: tonic::transport::Certificate,
) -> Result<(), Box<dyn std::error::Error>> {
    log_audit(
        &from_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Started,
        &format!("Outbound TLS ping attempt to {}", addr),
    );

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
            // .domain_name("127.0.0.1"),
            .domain_name(peer_label)
    )?;
    let channel = match endpoint.connect().await {
        Ok(ch) => ch,
        Err(e) => {
            log_audit(
                &from_id,
                AuditCategory::Network,
                AuditSeverity::Warning,
                AuditAction::Failed,
                &format!("TLS connection failed to {}: {}", addr, e),
            );
            return Err(Error::msg(e.to_string()).into());
        }
    };
    let mut client = PingServiceClient::new(channel);
    let request = tonic::Request::new(crate::proto::sgx::PingRequest {
        from: from_id.clone(),
    });
    let response = match client.ping(request).await {
        Ok(resp) => resp,
        Err(e) => {
            log_audit(
                &from_id,
                AuditCategory::Network,
                AuditSeverity::Warning,
                AuditAction::Failed,
                &format!("Secure ping failed to {}: {}", peer_label, e),
            );
            return Err(Error::msg(e.to_string()).into());
        }
    };
    let message = response.into_inner().message;
    println!(
        "🎉 gRPC Ping over TLS SUCCESSFUL (from {}) → {}",
        peer_label, message
    );
    log_audit(
        &from_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        &format!("Secure ping succeeded to {}", peer_label),
    );
    log_event(
        &from_id,
        &format!("Ping response from {}: {}", peer_label, message),
    );
    Ok(())
}
