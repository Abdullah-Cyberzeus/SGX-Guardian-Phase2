use sgx_guardian_client::call::{CallState, MediaType, SessionManager};
use sgx_guardian_client::key_manager::KeyManager;
use std::time::Instant;
use tempfile::tempdir;

#[tokio::test]
async fn benchmark_call_setup_latency() {
    let temp = tempdir().expect("create temp dir");
    let key_path = temp.path().join("bench_key.pk8");
    let _key_manager = KeyManager::load_or_generate(key_path.to_str().unwrap()).expect("load key");

    let manager = SessionManager::new();
    let mut elapsed_total = 0u128;
    let iterations = 20;

    for i in 0..iterations {
        let start = Instant::now();
        let session_id = manager
            .create_session(
                format!("bench-initiator-{}", i),
                format!("bench-virtual-{}", i),
                format!("bench-receiver-{}", i),
                format!("bench-virtual-receiver-{}", i),
                vec![MediaType::Audio, MediaType::Video],
                format!("nonce-bench-{}", i),
            )
            .await
            .expect("create session");
        manager
            .update_session_state(
                &session_id,
                CallState::LocalPolicyCheck,
                "bench local policy".to_string(),
            )
            .await
            .expect("update local policy");
        manager
            .update_session_state(&session_id, CallState::OfferSent, "bench offer".to_string())
            .await
            .expect("update offer sent");
        manager
            .update_session_state(
                &session_id,
                CallState::Verifying,
                "bench verifying".to_string(),
            )
            .await
            .expect("update verifying");
        manager
            .update_session_state(
                &session_id,
                CallState::Authorizing,
                "bench authorizing".to_string(),
            )
            .await
            .expect("update authorizing");
        manager
            .update_session_state(
                &session_id,
                CallState::Accepted,
                "bench accepted".to_string(),
            )
            .await
            .expect("update accepted");
        elapsed_total += start.elapsed().as_millis();
    }

    let average_ms = elapsed_total / iterations as u128;
    assert!(
        average_ms < 500,
        "Average call setup latency too high: {}ms",
        average_ms
    );
}
