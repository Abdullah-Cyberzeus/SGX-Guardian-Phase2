use serde_json::{json, Value};
use sgx_guardian_client::homeassistant::circuit_breaker::{
    CircuitBreaker, CircuitBreakerError, CircuitState,
};
use sgx_guardian_client::homeassistant::events::{EventBus, HaEvent};
use sgx_guardian_client::homeassistant::rest::{HaRestClient, RetryPolicy};
use sgx_guardian_client::homeassistant::HomeAssistantConfig;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct HaEnv {
    original_url: Option<String>,
    original_token: Option<String>,
    _lock: MutexGuard<'static, ()>,
}

impl HaEnv {
    fn set(url: &str, token: &str) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let original_url = std::env::var("HA_URL").ok();
        let original_token = std::env::var("HA_TOKEN").ok();
        std::env::set_var("HA_URL", url);
        std::env::set_var("HA_TOKEN", token);
        Self {
            original_url,
            original_token,
            _lock: lock,
        }
    }
}

impl Drop for HaEnv {
    fn drop(&mut self) {
        match &self.original_url {
            Some(value) => std::env::set_var("HA_URL", value),
            None => std::env::remove_var("HA_URL"),
        }
        match &self.original_token {
            Some(value) => std::env::set_var("HA_TOKEN", value),
            None => std::env::remove_var("HA_TOKEN"),
        }
    }
}

async fn http_once(status: &str, body: &str) -> (String, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let status = status.to_string();
    let body = body.to_string();
    let (request_tx, request_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n") else {
                continue;
            };
            let header_end = header_end + 4;
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            if request.len() >= header_end + content_length {
                break;
            }
        }
        let request = String::from_utf8_lossy(&request).into_owned();
        let _ = request_tx.send(request);
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    (format!("http://{address}"), request_rx)
}

#[tokio::test]
async fn circuit_breaker_opens_fast_fails_half_opens_and_recovers() {
    let breaker = CircuitBreaker::new(2, Duration::from_millis(20));
    assert_eq!(breaker.current_state().await, CircuitState::Closed);
    assert!(breaker.can_execute().await.is_ok());
    breaker.on_failure().await;
    assert_eq!(breaker.current_state().await, CircuitState::Closed);
    breaker.on_failure().await;
    assert!(matches!(
        breaker.current_state().await,
        CircuitState::Open { .. }
    ));
    let error = breaker.can_execute().await.unwrap_err();
    assert!(error.to_string().contains("Circuit breaker is OPEN"));

    tokio::time::sleep(Duration::from_millis(25)).await;
    breaker.can_execute().await.unwrap();
    assert_eq!(breaker.current_state().await, CircuitState::HalfOpen);
    assert!(breaker.can_execute().await.is_ok());
    breaker.on_success().await;
    assert_eq!(breaker.current_state().await, CircuitState::Closed);
}

#[tokio::test]
async fn circuit_breaker_clones_share_state_and_success_resets_failures() {
    let breaker = CircuitBreaker::new(1, Duration::from_secs(10));
    let clone = breaker.clone();
    clone.on_failure().await;
    assert!(matches!(
        breaker.current_state().await,
        CircuitState::Open { .. }
    ));
    breaker.on_success().await;
    assert_eq!(clone.current_state().await, CircuitState::Closed);
    clone.on_failure().await;
    assert!(matches!(
        breaker.current_state().await,
        CircuitState::Open { .. }
    ));

    let default = CircuitBreaker::default();
    assert_eq!(default.current_state().await, CircuitState::Closed);
    let error = CircuitBreakerError::CircuitOpen("blocked".into());
    assert_eq!(error.to_string(), "blocked");
    assert_eq!(RetryPolicy::Idempotent, RetryPolicy::Idempotent);
    assert_ne!(RetryPolicy::Idempotent, RetryPolicy::NonIdempotent);
}

#[tokio::test]
async fn event_bus_delivers_every_event_variant_and_ignores_no_subscribers() {
    let unused = EventBus::new();
    unused.publish(HaEvent::Unknown(json!({"ignored": true})));

    let bus = EventBus::new();
    let mut first = bus.subscribe();
    let mut second = bus.subscribe();
    let events = [
        HaEvent::StateChanged(json!({"entity_id": "light.office"})),
        HaEvent::DeviceRegistryUpdated(json!({"device_id": "dev-1"})),
        HaEvent::EntityRegistryUpdated(json!({"entity_id": "sensor.temp"})),
        HaEvent::NotificationCreated {
            id: "notice-1".into(),
            title: "Warning".into(),
            message: "Door open".into(),
            severity: "high".into(),
        },
        HaEvent::Unknown(json!({"event_type": "custom"})),
    ];
    for event in events {
        bus.publish(event);
    }
    for receiver in [&mut first, &mut second] {
        match receiver.recv().await.unwrap() {
            HaEvent::StateChanged(value) => assert_eq!(value["entity_id"], "light.office"),
            other => panic!("unexpected event: {other:?}"),
        }
        match receiver.recv().await.unwrap() {
            HaEvent::DeviceRegistryUpdated(value) => assert_eq!(value["device_id"], "dev-1"),
            other => panic!("unexpected event: {other:?}"),
        }
        match receiver.recv().await.unwrap() {
            HaEvent::EntityRegistryUpdated(value) => assert_eq!(value["entity_id"], "sensor.temp"),
            other => panic!("unexpected event: {other:?}"),
        }
        match receiver.recv().await.unwrap() {
            HaEvent::NotificationCreated {
                id,
                title,
                message,
                severity,
            } => {
                assert_eq!((id.as_str(), title.as_str()), ("notice-1", "Warning"));
                assert_eq!((message.as_str(), severity.as_str()), ("Door open", "high"));
            }
            other => panic!("unexpected event: {other:?}"),
        }
        match receiver.recv().await.unwrap() {
            HaEvent::Unknown(value) => assert_eq!(value["event_type"], "custom"),
            other => panic!("unexpected event: {other:?}"),
        }
    }
}

#[test]
fn homeassistant_config_reads_environment_and_trims_trailing_slashes() {
    let _env = HaEnv::set("http://ha.local:8123///", "secret-token");
    let config = HomeAssistantConfig::from_env().unwrap();
    assert_eq!(config.url, "http://ha.local:8123");
    assert_eq!(config.token, "secret-token");
    let cloned = config.clone();
    assert_eq!(cloned.url, config.url);
    assert!(format!("{config:?}").contains("ha.local"));
}

#[tokio::test]
async fn rest_status_and_states_cover_success_and_http_failure() {
    let (url, request) = http_once("200 OK", r#"{"message":"API running"}"#).await;
    let client = HaRestClient::new(HomeAssistantConfig {
        url,
        token: "token-a".into(),
    });
    assert!(client.check_api_status().await.unwrap());
    let request = request.await.unwrap();
    assert!(request.starts_with("GET /api/ HTTP/1.1"));
    assert!(request
        .to_ascii_lowercase()
        .contains("authorization: bearer token-a"));

    let (url, _) = http_once(
        "200 OK",
        r#"[{"entity_id":"light.one"},{"entity_id":"sensor.two"}]"#,
    )
    .await;
    let client = HaRestClient::new(HomeAssistantConfig {
        url,
        token: "t".into(),
    });
    let states = client.get_states().await.unwrap();
    assert_eq!(states.len(), 2);
    assert_eq!(states[0]["entity_id"], "light.one");

    let (url, _) = http_once("503 Service Unavailable", r#"{"error":"offline"}"#).await;
    let client = HaRestClient::new(HomeAssistantConfig {
        url,
        token: "t".into(),
    });
    let error = client.get_states().await.unwrap_err();
    assert!(error.contains("Failed to get states: HTTP 503"));
}

#[tokio::test]
async fn rest_entity_and_config_cover_json_success_parse_and_status_errors() {
    let (url, request) = http_once(
        "200 OK",
        r#"{"state":"on","attributes":{"friendly_name":"Desk"}}"#,
    )
    .await;
    let client = HaRestClient::new(HomeAssistantConfig {
        url,
        token: "t".into(),
    });
    let state = client.get_state("light.desk").await.unwrap();
    assert_eq!(state["attributes"]["friendly_name"], "Desk");
    assert!(request
        .await
        .unwrap()
        .starts_with("GET /api/states/light.desk HTTP/1.1"));

    let (url, _) = http_once("404 Not Found", "{}").await;
    let client = HaRestClient::new(HomeAssistantConfig {
        url,
        token: "t".into(),
    });
    assert!(client
        .get_state("missing")
        .await
        .unwrap_err()
        .contains("HTTP 404"));

    let (url, _) = http_once("200 OK", r#"{"unit_system":{"temperature":"°C"}}"#).await;
    let client = HaRestClient::new(HomeAssistantConfig {
        url,
        token: "t".into(),
    });
    assert_eq!(
        client.get_config().await.unwrap()["unit_system"]["temperature"],
        "°C"
    );

    let (url, _) = http_once("200 OK", "not-json").await;
    let client = HaRestClient::new(HomeAssistantConfig {
        url,
        token: "t".into(),
    });
    assert!(!client.get_config().await.unwrap_err().is_empty());

    let (url, _) = http_once("500 Internal Server Error", "{}").await;
    let client = HaRestClient::new(HomeAssistantConfig {
        url,
        token: "t".into(),
    });
    assert!(client.get_config().await.unwrap_err().contains("HTTP 500"));
}

#[tokio::test]
async fn rest_service_calls_merge_object_payload_and_replace_non_object_payload() {
    let (url, request) = http_once("200 OK", "[]").await;
    let client = HaRestClient::new(HomeAssistantConfig {
        url,
        token: "service-token".into(),
    });
    client
        .call_service(
            "light",
            "turn_on",
            "light.office",
            Some(json!({"brightness": 120})),
        )
        .await
        .unwrap();
    let request = request.await.unwrap();
    assert!(request.starts_with("POST /api/services/light/turn_on HTTP/1.1"));
    let body = request.split("\r\n\r\n").nth(1).unwrap();
    let body: Value = serde_json::from_str(body).unwrap();
    assert_eq!(body["entity_id"], "light.office");
    assert_eq!(body["brightness"], 120);

    let (url, request) = http_once("200 OK", "[]").await;
    let client = HaRestClient::new(HomeAssistantConfig {
        url,
        token: "t".into(),
    });
    client
        .call_service("lock", "lock", "lock.front", Some(json!(["ignored"])))
        .await
        .unwrap();
    let request = request.await.unwrap();
    let body: Value = serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(body, json!({"entity_id": "lock.front"}));

    let (url, _) = http_once("400 Bad Request", "invalid target").await;
    let client = HaRestClient::new(HomeAssistantConfig {
        url,
        token: "t".into(),
    });
    let error = client
        .call_service("cover", "open_cover", "cover.garage", None)
        .await
        .unwrap_err();
    assert!(error.contains("Failed to call service cover.open_cover: HTTP 400"));
    assert!(error.contains("invalid target"));
}
