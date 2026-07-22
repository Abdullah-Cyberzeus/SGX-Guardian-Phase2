use serde_json::Value;
use warp::Filter;

pub async fn run_mock_cloud(addr: ([u8; 4], u16)) {
    let route = warp::post()
        .and(warp::path("uplink"))
        .and(warp::body::json())
        .map(|body: Value| {
            println!("[MOCK CLOUD] Received uplink payload:\n{}", body);
            warp::reply::json(&serde_json::json!({
                "status": "ok"
            }))
        });

    println!(
        "[MOCK CLOUD] Listening on http://{}.{}",
        addr.0
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join("."),
        addr.1
    );

    warp::serve(route).run(addr).await;
}
