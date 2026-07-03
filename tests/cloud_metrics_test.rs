use sgx_guardian_client::cloud::client::send_heartbeat;
use sgx_guardian_client::metrics::Metrics;
use sgx_guardian_client::metrics_server::start_metrics_server;
use std::sync::Arc;
use tokio::sync::Mutex;

// ─── Cloud Heartbeat ─────────────────────────────────────────

#[tokio::test]
async fn test_send_heartbeat_connection_refused() {
    // Sending to a dead endpoint should return Ok(()) gracefully, not panic
    let result = send_heartbeat("test-node", "http://127.0.0.2:19999/heartbeat").await;
    assert!(result.is_ok(), "heartbeat should return Ok even on failure");
}

#[tokio::test]
async fn test_send_heartbeat_bad_url() {
    let result = send_heartbeat("test-node", "http://[::1]:invalid_port/heartbeat").await;
    // May succeed or fail, but should not panic
    let _ = result;
}

// ─── Metrics Server ──────────────────────────────────────────

#[tokio::test]
async fn test_metrics_server_get_metrics() {
    let metrics = Arc::new(Mutex::new(Metrics::default()));

    // Populate some metrics
    {
        let mut m = metrics.lock().await;
        m.connections_total = 42;
        m.errors_total = 7;
        m.relay_active_peers = 3;
    }

    // Bind on ephemeral port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let metrics_clone = metrics.clone();
    tokio::spawn(async move {
        start_metrics_server(metrics_clone, ([127, 0, 0, 1], port)).await;
    });

    // Wait for server to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // GET /metrics
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/metrics", port))
        .send()
        .await
        .expect("GET /metrics should succeed");

    assert!(resp.status().is_success(), "Expected 200 OK, got {}", resp.status());

    let content_type = resp.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("text/plain"),
        "Expected text/plain content type, got: {}",
        content_type
    );

    let body = resp.text().await.expect("response body");
    assert!(body.contains("sgx_connections_total"), "body should contain connections counter");
    assert!(body.contains("sgx_errors_total"), "body should contain errors counter");
    assert!(body.contains("sgx_relay_active_peers"), "body should contain relay peers");
    assert!(body.contains("42"), "body should contain connections count 42");
    assert!(body.contains("7"), "body should contain error count 7");
}

#[tokio::test]
async fn test_metrics_server_content_type() {
    let metrics = Arc::new(Mutex::new(Metrics::default()));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let metrics_clone = metrics.clone();
    tokio::spawn(async move {
        start_metrics_server(metrics_clone, ([127, 0, 0, 1], port)).await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/metrics", port))
        .send()
        .await
        .expect("GET /metrics");

    let content_type = resp.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(
        content_type.contains("text/plain") && content_type.contains("0.0.4"),
        "Expected text/plain; version=0.0.4, got: {}",
        content_type
    );
}

// ─── MetricsSnapshot / to_prometheus ─────────────────────────

#[test]
fn test_metrics_snapshot_prometheus_format() {
    let mut m = Metrics::default();
    m.connections_total = 10;
    m.errors_total = 2;
    m.relay_active_peers = 5;
    m.relay_bytes_total = 100_000;
    m.update_relay_stats(5, 100_000, 1.5, 3, 2);
    m.set_cot_transport_state("eth0", "Ethernet", true, 10, 1000);
    m.set_cot_active_transport("Ethernet");
    m.record_cot_switch("WiFi", "Ethernet");

    let snap = m.snapshot();
    let prom = snap.to_prometheus();

    assert!(prom.contains("sgx_connections_total 10"));
    assert!(prom.contains("sgx_errors_total 2"));
    assert!(prom.contains("sgx_relay_active_peers 5"));
    assert!(prom.contains("sgx_relay_bytes_total 100000"));
    assert!(prom.contains("sgx_relay_current_mbps 1.50"));
    assert!(prom.contains("sgx_cot_transport_up{interface=\"eth0\",transport=\"ethernet\"} 1"));
    assert!(prom.contains("sgx_cot_active_transport_info{transport=\"ethernet\"} 1"));
    assert!(prom.contains("sgx_cot_transport_switches_total{from=\"wifi\",to=\"ethernet\"} 1"));
}

#[test]
fn test_metrics_snapshot_policy_active() {
    let mut m = Metrics::default();
    m.set_policy_active(true);

    let snap = m.snapshot();
    let prom = snap.to_prometheus();
    assert!(prom.contains("sgx_policy_active 1"));
}

#[test]
fn test_metrics_relay_limit_breach() {
    let mut m = Metrics::default();
    m.record_relay_limit_breach();
    m.record_relay_limit_breach();

    let snap = m.snapshot();
    assert_eq!(snap.relay_limit_breaches_total, 2);
    let prom = snap.to_prometheus();
    assert!(prom.contains("sgx_relay_limit_breaches_total 2"));
}
