use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::cert_service::MyCertService;
use crate::logging::log_event;
use crate::metrics::Metrics;
use crate::proto::sgx::cert_service_server::CertServiceServer;
use crate::proto::sgx::ping_service_server::{PingService, PingServiceServer};
use crate::proto::sgx::{PingRequest, PingResponse};
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::transport::ServerTlsConfig;
use tonic::{transport::Server, Request, Response, Status};

fn ensure_rustls_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // Explicitly select ring to avoid runtime panic when both rustls crypto
        // backends are present in the dependency graph.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

/// Basic gRPC Ping service used for inter-node liveness checks.
/// Implements the `PingService` trait generated from the SG-X protobuf schema.
pub struct MyPingService {
    pub metrics: Arc<Mutex<Metrics>>,
}
#[tonic::async_trait]
impl PingService for MyPingService {
    /// Handles an incoming gRPC ping request from another SG-X node.
    /// Logs the source node ID and returns a simple Pong response.
    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        let from = request.get_ref().from.clone();
        println!("📡gRPC Ping request RECEIVED from {}", from);
        log_event(&from, &format!("Received ping from: {}", from));

        log_audit(
            &from,
            AuditCategory::Network,
            AuditSeverity::Info,
            AuditAction::Succeeded,
            "Secure gRPC ping received",
        );
        {
            let mut m = self.metrics.lock().await;
            m.record_connection();
        }
        println!("📨Sending Pong response to {}", from);
        let reply = PingResponse {
            message: format!("Pong to {}", from),
        };
        Ok(Response::new(reply))
    }
}
/// Starts the SG-X gRPC server on the specified address,
/// registers the Ping service, and begins handling requests asynchronously.
/// NOTE: Now accepts an Arc<rustls::ServerConfig> for mTLS.
pub async fn start_server(
    addr: String,
    identity: tonic::transport::Identity,
    ca_cert: tonic::transport::Certificate,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_rustls_crypto_provider();

    use crate::metrics::Metrics;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    let service = MyPingService {
        metrics: Arc::new(Mutex::new(Metrics::default())),
    };
    println!("🔥gRPC TLS Server is initializing at {}", addr);
    let tls = ServerTlsConfig::new()
        .identity(identity.clone())
        .client_ca_root(ca_cert.clone());
    println!("🔐 TLS Identity + CA loaded successfully. Starting secure gRPC server...");
    let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());

    Server::builder()
        .tls_config(tls)
        .inspect_err(|_e| {
            log_audit(
                &node_id,
                AuditCategory::Network,
                AuditSeverity::Critical,
                AuditAction::Failed,
                "Failed to configure TLS for gRPC server",
            );
        })?
        .add_service(PingServiceServer::new(service))
        .serve(addr.parse()?)
        .await
        .inspect_err(|_e| {
            log_audit(
                &node_id,
                AuditCategory::Network,
                AuditSeverity::Critical,
                AuditAction::Failed,
                "Secure gRPC server failed to start",
            );
        })?;
    println!("🚀gRPC TLS Server is now LIVE at {}", addr);
    log_event("server", &format!("Server listening on {}", addr));

    let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());

    log_audit(
        &node_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        "Secure gRPC server started with mTLS",
    );
    Ok(())
}

/// Starts a plaintext gRPC server for CertService ONLY (bootstrap endpoint).
/// No TLS — used for initial certificate requests before nodes have trusted certs.
/// Runs on nodeA only, on a dedicated port (e.g., 50061).
pub async fn start_cert_bootstrap_server(addr: String) -> Result<(), Box<dyn std::error::Error>> {
    let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());

    println!(
        "🔐 CertService bootstrap server starting on {} (plaintext)",
        addr
    );

    log_audit(
        &node_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Started,
        &format!("CertService bootstrap server starting on {}", addr),
    );

    Server::builder()
        .add_service(CertServiceServer::new(MyCertService))
        .serve(addr.parse()?)
        .await
        .inspect_err(|_e| {
            log_audit(
                &node_id,
                AuditCategory::Network,
                AuditSeverity::Critical,
                AuditAction::Failed,
                "CertService bootstrap server failed to start",
            );
        })?;

    Ok(())
}
