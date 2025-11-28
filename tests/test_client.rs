// tests/test_client.rs

use sgx_guardian_client::client::send_ping;
use sgx_guardian_client::proto::sgx::ping_service_server::PingServiceServer;
use sgx_guardian_client::server::MyPingService;

use tokio::runtime::Runtime;
use tonic::transport::Server;

#[test]
fn test_send_ping_success() {
    let rt = Runtime::new().unwrap();

    rt.block_on(async {
        // 1. Bind to port 0 to let OS give a free port
        let temp_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind test port");

        let addr = temp_listener.local_addr().unwrap();

        // 2. Drop the listener so tonic can bind the same port
        drop(temp_listener);

        // 3. Spawn tonic gRPC server on that same address
        tokio::spawn({
            let addr_clone = addr;
            async move {
                Server::builder()
                    .add_service(PingServiceServer::new(MyPingService))
                    .serve(addr_clone)
                    .await
                    .unwrap();
            }
        });

        // 4. Call the client function under test
        let result = send_ping(addr.to_string(), "test-node".to_string()).await;

        assert!(result.is_ok(), "send_ping should succeed");
    });
}
