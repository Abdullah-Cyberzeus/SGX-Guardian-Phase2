use crate::proto::sgx::ping_service_client::PingServiceClient;
use crate::proto::sgx::PingRequest;
pub async fn send_ping(addr: String, from_id: String) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = PingServiceClient::connect(format!("http://{}", addr)).await?;
    let request = tonic::Request::new(PingRequest { from: from_id });
    let response = client.ping(request).await?;
    println!("Response: {}", response.into_inner().message);
    Ok(())
}
