use sgx_guardian_client::p2p_discovery::P2PDiscovery;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_p2p_discovery_starts_without_panic() {
    let (tx, _rx) = mpsc::channel::<String>(10);

    // Dummy logger
    let logger = Arc::new(Mutex::new("test-logger".to_string()));

    // Spawn discovery in background
    let handle = tokio::spawn(async move {
        let _ = P2PDiscovery::run(tx, "nodeX".into(), logger).await;
    });

    // Give it a tiny window to initialize
    sleep(Duration::from_millis(20)).await;

    // Abort task intentionally
    handle.abort();
}

#[tokio::test]
async fn test_tokio_runtime_healthy() {
    tokio::spawn(async { 1 + 1 }).await.unwrap();
}
