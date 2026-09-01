use sgx_guardian_client::homeassistant::events::EventBus;
use sgx_guardian_client::homeassistant::websocket::start_websocket_client;
use sgx_guardian_client::homeassistant::HomeAssistantConfig;

fn config(url: &str) -> HomeAssistantConfig {
    HomeAssistantConfig {
        url: url.into(),
        token: "token".into(),
    }
}

#[tokio::test]
async fn start_websocket_client_returns_after_spawn() {
    start_websocket_client(config("ws://127.0.0.1:9"), EventBus::new()).await;
}

macro_rules! config_shape_tests {
    ($($name:ident => $url:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            let cfg = config($url);
            assert_eq!(cfg.url, $url);
            assert_eq!(cfg.token, "token");
        }
    )+};
}

config_shape_tests! {
    websocket_config_http_url => "http://localhost:8123",
    websocket_config_https_url => "https://localhost:8123",
    websocket_config_ws_url => "ws://localhost:8123",
    websocket_config_wss_url => "wss://localhost:8123",
    websocket_config_empty_url => "",
    websocket_config_path_url => "http://localhost/base",
    websocket_config_trailing_slash => "http://localhost/",
    websocket_config_ipv4 => "http://127.0.0.1:8123",
    websocket_config_ipv6 => "http://[::1]:8123",
    websocket_config_dns => "http://homeassistant.local:8123",
    websocket_config_uppercase => "HTTP://localhost",
    websocket_config_query => "http://localhost?x=1",
    websocket_config_fragment => "http://localhost/#x",
    websocket_config_subpath => "http://localhost/api",
    websocket_config_port_443 => "https://localhost:443",
    websocket_config_port_80 => "http://localhost:80",
    websocket_config_no_scheme => "localhost:8123",
    websocket_config_spaces => " http://localhost ",
    websocket_config_localhost => "http://localhost",
    websocket_config_loopback_no_port => "http://127.0.0.1",
    websocket_config_wildcard_like => "http://0.0.0.0:8123",
    websocket_config_nested_path => "http://localhost/a/b",
    websocket_config_dash_host => "http://ha-test.local",
    websocket_config_numeric_host => "http://10.0.0.2:8123",
}

#[tokio::test]
async fn start_websocket_client_accepts_empty_token_without_panic() {
    start_websocket_client(
        HomeAssistantConfig {
            url: "ws://127.0.0.1:9".into(),
            token: "".into(),
        },
        EventBus::new(),
    )
    .await;
}
