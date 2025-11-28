use sgx_guardian_client::p2p_discovery::P2PDiscovery;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn test_p2p_discovery_starts_without_panic() {
    // Create dummy channel
    let (tx, _rx) = mpsc::channel::<String>(10);

    // Dummy shared logger string
    let logger = Arc::new(Mutex::new("test-logger".to_string()));

    // The real run() never returns. We must timeout it.
    // If run() INITIALLY starts correctly → test passes.
    let result = timeout(
        Duration::from_millis(50),
        P2PDiscovery::run(tx, "nodeX".into(), logger),
    )
    .await;

    // If timeout occurs = GOOD (because the loop is infinite)
    match result {
        Err(_) => {
            // Timed out = expected behavior
            return;
        }
        Ok(inner) => {
            // If it returned early, still treat as pass as long as no panic
            assert!(inner.is_ok(), "Discovery should start cleanly");
        }
    }
}
