use crate::logging::log_event;
use crate::proto::sgx::ping_service_client::PingServiceClient;
use crate::proto::sgx::PingRequest;

pub async fn send_ping(addr: String, from_id: String) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = PingServiceClient::connect(format!("http://{}", addr)).await?;
    let request = tonic::Request::new(PingRequest {
        from: from_id.clone(),
    });
    let response = client.ping(request).await?;
    let msg = response.into_inner().message;
    log_event(&from_id, &format!("Ping response: {}", msg));
    Ok(())
}
