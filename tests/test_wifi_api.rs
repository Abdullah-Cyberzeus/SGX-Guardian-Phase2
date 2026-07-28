use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::Value;
use sgx_guardian_client::runtime::event_bus::EventBus;
use sgx_guardian_client::runtime::runtime_manager::RuntimeManager;
use sgx_guardian_client::runtime::server::build_wifi_router;
use sgx_guardian_client::runtime::state_machine::StateMachine;
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
async fn test_wifi_api_clients_endpoint() {
    let event_bus = Arc::new(EventBus::new());
    let state_machine = Arc::new(StateMachine::new(event_bus.clone()));
    let manager = Arc::new(RuntimeManager::new(state_machine.clone()));

    let app = build_wifi_router(manager, event_bus);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/clients")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: Value = serde_json::from_slice(&body).unwrap();

    // Verify it returns the JSON schema we expect
    assert!(body_json.get("clients").is_some());
    let clients = body_json.get("clients").unwrap().as_array().unwrap();

    // We don't assert the exact size because it reads from /tmp/netbridge/dnsmasq.leases
    // which may or may not exist on the testing machine. The important part is it doesn't crash
    // and returns the proper JSON structure.
    println!("Parsed clients: {:?}", clients);
}

#[tokio::test]
async fn test_wifi_api_get_mode() {
    let event_bus = Arc::new(EventBus::new());
    let state_machine = Arc::new(StateMachine::new(event_bus.clone()));
    let manager = Arc::new(RuntimeManager::new(state_machine.clone()));

    let app = build_wifi_router(manager, event_bus);

    let response = app
        .oneshot(Request::builder().uri("/mode").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: Value = serde_json::from_slice(&body).unwrap();

    // The default state for a newly initialized RuntimeManager is Idle
    assert_eq!(
        body_json
            .get("status")
            .unwrap()
            .get("state")
            .unwrap()
            .as_str()
            .unwrap(),
        "Idle"
    );
}
