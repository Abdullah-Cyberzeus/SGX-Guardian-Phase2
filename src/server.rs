use crate::logging::log_event;
use crate::metrics::Metrics;
use crate::proto::sgx::ping_service_server::{PingService, PingServiceServer};
use crate::proto::sgx::{PingRequest, PingResponse};
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::transport::ServerTlsConfig;
use tonic::{transport::Server, Request, Response, Status};
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
/// Starts the SG-X gRPC server on the specified address,
/// registers the Ping service, and begins handling requests asynchronously.
/// NOTE: Now accepts an Arc<rustls::ServerConfig> for mTLS.
pub async fn start_server(
    addr: String,
    identity: tonic::transport::Identity,
    ca_cert: tonic::transport::Certificate,
) -> Result<(), Box<dyn std::error::Error>> {
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
    Server::builder()
        .tls_config(tls)?
        .add_service(PingServiceServer::new(service))
        .serve(addr.parse()?)
        .await?;
    println!("🚀gRPC TLS Server is now LIVE at {}", addr);
    log_event("server", &format!("Server listening on {}", addr));
    Ok(())
}
