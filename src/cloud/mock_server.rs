use axum::{routing::post, Json, Router};
use serde_json::Value;
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub async fn run_mock_cloud(addr: ([u8; 4], u16)) {
    let app = Router::new().route("/uplink", post(handle_uplink));

    println!(
        "[MOCK CLOUD] Listening on http://{}:{}",
        addr.0
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join("."),
        addr.1
    );

    let listener = TcpListener::bind(SocketAddr::from(addr))
        .await
        .expect("bind mock cloud listener");

    axum::serve(listener, app)
        .await
        .expect("mock cloud server failed");
}

async fn handle_uplink(Json(body): Json<Value>) -> Json<Value> {
    println!("[MOCK CLOUD] Received uplink payload:\n{}", body);
    Json(serde_json::json!({
        "status": "ok"
    }))
}
