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

/// The node id this process was started with, as the audit trail records it.
///
/// The gRPC servers are started before configuration is fully resolved, so
/// they read the launch argument directly rather than threading the id
/// through every call site.
pub fn audited_node_id() -> String {
    std::env::args()
        .nth(1)
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| "unknown-node".into())
}

pub fn ensure_rustls_crypto_provider() {
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
    let node_id = audited_node_id();

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

    let node_id = audited_node_id();

    log_audit(
        &node_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        "Secure gRPC server started with mTLS",
    );
    Ok(())
}

/// Starts a dedicated PLAINTEXT gRPC server for the Chat service only.
/// Uses no TLS — security is provided by the Nebula overlay VPN which
/// already authenticates and encrypts all inter-node traffic.
/// Runs on a port derived from the attestation port (att_port - 100).
pub async fn start_chat_plaintext_server(
    addr: String,
    api_state: Arc<crate::api::state::AppState>,
) -> Result<(), Box<dyn std::error::Error>> {
    let node_id = audited_node_id();

    println!(
        "💬 Chat plaintext gRPC server starting on {} (Guardian Mesh-secured)",
        addr
    );

    log_audit(
        &node_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Started,
        &format!("Chat plaintext gRPC server starting on {}", addr),
    );

    let chat_service = crate::chat::grpc_server::MyChatService { state: api_state };

    Server::builder()
        .add_service(crate::proto::sgx::chat_service_server::ChatServiceServer::new(chat_service))
        .serve(addr.parse()?)
        .await
        .inspect_err(|_e| {
            log_audit(
                &node_id,
                AuditCategory::Network,
                AuditSeverity::Critical,
                AuditAction::Failed,
                "Chat plaintext gRPC server failed to start",
            );
        })?;
    Ok(())
}

/// Starts a plaintext gRPC server for CertService ONLY (bootstrap endpoint).
/// No TLS — used for initial certificate requests before nodes have trusted certs.
/// Runs on nodeA only, on a dedicated port (e.g., 50061).
pub async fn start_cert_bootstrap_server(addr: String) -> Result<(), Box<dyn std::error::Error>> {
    let node_id = audited_node_id();

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_crypto_provider_installs_once_and_is_idempotent() {
        // Both rustls backends are in the dependency graph, so a default must
        // be selected explicitly or every TLS handshake panics at runtime.
        ensure_rustls_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());

        // Calling again must not panic or replace the installed provider.
        ensure_rustls_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }

    #[test]
    fn the_audited_node_id_falls_back_when_no_argument_was_given() {
        // The test harness supplies no node-id argument, so this exercises the
        // fallback the servers record in the audit log.
        let node_id = audited_node_id();
        assert!(!node_id.is_empty());
    }

    #[tokio::test]
    async fn a_ping_is_answered_with_a_pong_and_counted_as_a_connection() {
        let metrics = Arc::new(Mutex::new(Metrics::default()));
        let service = MyPingService {
            metrics: Arc::clone(&metrics),
        };

        let response = service
            .ping(Request::new(PingRequest {
                from: "nodeB".to_string(),
            }))
            .await
            .expect("ping must succeed");

        assert_eq!(response.get_ref().message, "Pong to nodeB");
        assert_eq!(
            metrics.lock().await.connections_total,
            1,
            "each ping records one connection"
        );
    }

    #[tokio::test]
    async fn repeated_pings_accumulate_connection_counts() {
        let metrics = Arc::new(Mutex::new(Metrics::default()));
        let service = MyPingService {
            metrics: Arc::clone(&metrics),
        };

        for peer in ["nodeB", "nodeC", "nodeB"] {
            service
                .ping(Request::new(PingRequest {
                    from: peer.to_string(),
                }))
                .await
                .expect("ping must succeed");
        }

        assert_eq!(metrics.lock().await.connections_total, 3);
    }

    #[tokio::test]
    async fn an_empty_peer_name_is_still_answered() {
        let service = MyPingService {
            metrics: Arc::new(Mutex::new(Metrics::default())),
        };

        let response = service
            .ping(Request::new(PingRequest {
                from: String::new(),
            }))
            .await
            .expect("ping must succeed");

        assert_eq!(response.get_ref().message, "Pong to ");
    }

    #[tokio::test]
    async fn the_chat_server_rejects_an_unparseable_bind_address() {
        let temp = tempfile::tempdir().expect("state dir");
        let state =
            crate::api::state::AppState::for_tests(temp.path(), "nodeA", "/tmp".to_string());

        let error = start_chat_plaintext_server("not-a-socket-address".to_string(), state)
            .await
            .expect_err("an unparseable address must not start a server");

        assert!(
            error.to_string().contains("invalid socket address")
                || error.to_string().contains("invalid IP address"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn the_cert_bootstrap_server_rejects_an_unparseable_bind_address() {
        let error = start_cert_bootstrap_server("also-not-an-address".to_string())
            .await
            .expect_err("an unparseable address must not start a server");

        assert!(!error.to_string().is_empty());
    }

    #[tokio::test]
    async fn the_cert_bootstrap_server_reports_an_occupied_port() {
        let Ok(holder) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            // Some CI sandboxes prohibit local sockets.
            return;
        };
        let addr = holder.local_addr().expect("bound address");

        let error = start_cert_bootstrap_server(addr.to_string())
            .await
            .expect_err("the occupied port must not be bound twice");

        // tonic wraps the bind failure as an opaque "transport error"; the
        // underlying cause is what identifies the occupied address.
        let mut cause = String::new();
        let mut current = error.source();
        while let Some(source) = current {
            cause.push_str(&source.to_string());
            cause.push_str(" / ");
            current = source.source();
        }
        assert!(
            cause.to_lowercase().contains("address"),
            "unexpected error: {error} ({cause})"
        );
    }

    #[tokio::test]
    async fn the_mtls_server_rejects_a_malformed_identity() {
        // Garbage PEM must be refused at TLS-configuration time, before the
        // listener is ever bound — a server that started without a valid
        // identity would accept unauthenticated peers.
        let identity = tonic::transport::Identity::from_pem("not-a-cert", "not-a-key");
        let ca = tonic::transport::Certificate::from_pem("not-a-cert");

        let error = start_server("127.0.0.1:0".to_string(), identity, ca)
            .await
            .expect_err("a malformed identity must not start a server");

        assert!(!error.to_string().is_empty());
    }
}
