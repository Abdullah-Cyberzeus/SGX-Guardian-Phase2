use crate::proto::sgx::ping_service_server::{PingService, PingServiceServer};
use crate::proto::sgx::{PingRequest, PingResponse};
use tonic::{transport::Server, Request, Response, Status};
#[derive(Default)]
pub struct MyPingService;
#[tonic::async_trait]
impl PingService for MyPingService {
    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        let from = request.get_ref().from.clone();
        println!("Received ping from: {}", from);

        let reply = PingResponse {
            message: format!("Pong to {}", from),
        };
        Ok(Response::new(reply))
    }
}
pub async fn start_server(addr: String) -> Result<(), Box<dyn std::error::Error>> {
    let service = MyPingService;
    println!("Server listening on {}", addr);
    Server::builder()
        .add_service(PingServiceServer::new(service))
        .serve(addr.parse()?)
        .await?;
    Ok(())
}
