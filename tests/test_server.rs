use sgx_guardian_client::proto::sgx::ping_service_server::PingService;
use sgx_guardian_client::proto::sgx::PingRequest;
use sgx_guardian_client::server::MyPingService;

use tonic::Request;

#[tokio::test]
async fn test_ping_handler_success() {
    // Create service instance
    let service = MyPingService;

    // Build a request
    let req = Request::new(PingRequest {
        from: "clientA".into(),
    });

    // Call handler
    let response = service.ping(req).await.expect("Ping should succeed");

    let reply = response.into_inner();

    assert_eq!(reply.message, "Pong to clientA");
}
