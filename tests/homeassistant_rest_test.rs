use sgx_guardian_client::homeassistant::rest::{HaRestClient, RetryPolicy};
use sgx_guardian_client::homeassistant::HomeAssistantConfig;

fn config(url: &str, token: &str) -> HomeAssistantConfig {
    HomeAssistantConfig {
        url: url.into(),
        token: token.into(),
    }
}

#[test]
fn retry_policy_idempotent_is_clone_copy_equal() {
    let policy = RetryPolicy::Idempotent;
    assert_eq!(policy, policy.clone());
}

#[test]
fn retry_policy_non_idempotent_is_clone_copy_equal() {
    let policy = RetryPolicy::NonIdempotent;
    assert_eq!(policy, policy.clone());
}

#[test]
fn retry_policies_are_distinct() {
    assert_ne!(RetryPolicy::Idempotent, RetryPolicy::NonIdempotent);
}

#[test]
fn retry_policy_debug_names_variants() {
    assert!(format!("{:?}", RetryPolicy::Idempotent).contains("Idempotent"));
    assert!(format!("{:?}", RetryPolicy::NonIdempotent).contains("NonIdempotent"));
}

macro_rules! client_new_tests {
    ($($name:ident => $url:expr, $token:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            let client = HaRestClient::new(config($url, $token));
            let cloned = client.clone();
            drop(cloned);
        }
    )+};
}

client_new_tests! {
    client_new_http_url => "http://localhost:8123", "token",
    client_new_https_url => "https://ha.local", "token",
    client_new_empty_url => "", "token",
    client_new_empty_token => "http://localhost", "",
    client_new_url_with_trailing_slash => "http://localhost/", "token",
    client_new_url_with_path => "http://localhost/base", "token",
    client_new_ipv4_url => "http://127.0.0.1:8123", "token",
    client_new_ipv6_url => "http://[::1]:8123", "token",
    client_new_long_token => "http://localhost", "abcdefghijklmnopqrstuvwxyz0123456789",
    client_new_symbol_token => "http://localhost", "tok.en-with_symbols",
    client_new_bearer_like_token => "http://localhost", "Bearer abc",
    client_new_url_without_scheme => "localhost:8123", "token",
    client_new_url_with_query => "http://localhost?x=1", "token",
    client_new_url_with_fragment => "http://localhost/#x", "token",
    client_new_uppercase_scheme => "HTTP://localhost", "token",
    client_new_space_token => "http://localhost", " ",
    client_new_unicode_token => "http://localhost", "token-check",
    client_new_localhost_https_port => "https://localhost:443", "token",
    client_new_private_ip => "http://192.168.1.10:8123", "token",
    client_new_dns_name => "http://homeassistant.local:8123", "token",
    client_new_subpath_and_port => "http://ha.local:8123/api", "token",
}

#[test]
fn homeassistant_config_clone_preserves_values() {
    let cfg = config("http://ha", "token");
    let cloned = cfg.clone();
    assert_eq!(cloned.url, "http://ha");
    assert_eq!(cloned.token, "token");
}

#[test]
fn homeassistant_config_debug_contains_url() {
    assert!(format!("{:?}", config("http://ha", "token")).contains("http://ha"));
}
