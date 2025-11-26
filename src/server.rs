use crate::logging::log_event;
use crate::proto::sgx::ping_service_server::{PingService, PingServiceServer};
use crate::proto::sgx::{PingRequest, PingResponse};
use tonic::{transport::Server, Request, Response, Status};

/// Basic gRPC Ping service used for inter-node liveness checks.
/// Implements the `PingService` trait generated from the SG-X protobuf schema.
#[derive(Default)]
pub struct MyPingService;
#[tonic::async_trait]
impl PingService for MyPingService {
    /// Handles an incoming gRPC ping request from another SG-X node.
    /// Logs the source node ID and returns a simple Pong response.
    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        let from = request.get_ref().from.clone();
        log_event(&from, &format!("Received ping from: {}", from));

        let reply = PingResponse {
            message: format!("Pong to {}", from),
        };
        Ok(Response::new(reply))
    }
}
/// Starts the SG-X gRPC server on the specified address,
/// registers the Ping service, and begins handling requests asynchronously.
pub async fn start_server(addr: String) -> Result<(), Box<dyn std::error::Error>> {
    let service = MyPingService;
    log_event("server", &format!("Server listening on {}", addr));
    Server::builder()
        .add_service(PingServiceServer::new(service))
        .serve(addr.parse()?)
        .await?;
    Ok(())
}
