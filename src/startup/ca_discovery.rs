//! Resolving the CA node's LAN address from the config files that the UDP
//! broadcast loop keeps up to date.
//!
//! Members boot before discovery has necessarily populated nodeA's address, so
//! this polls with a bounded retry. The retry count and delay are parameters
//! rather than constants so tests exercise the exhaustion path without waiting
//! the full production window.

use super::GuardianPaths;
use std::time::Duration;

/// How many times a member polls for the CA's address before giving up.
pub const DEFAULT_ATTEMPTS: u32 = 20;
/// Delay between polls.
pub const DEFAULT_RETRY_DELAY: Duration = Duration::from_secs(1);
/// Address used when discovery never produced one. Local-test only: a member
/// that falls back here cannot reach a real CA, and says so on stderr.
pub const LOCAL_FALLBACK: &str = "127.0.0.1";

/// Whether a configured address is usable as a CA endpoint.
///
/// The unspecified and loopback addresses are what an un-broadcast config
/// still holds, so treating them as resolved would point every member at
/// itself.
pub fn is_usable_ca_address(ip: &str) -> bool {
    !ip.is_empty() && ip != "0.0.0.0" && ip != LOCAL_FALLBACK
}

/// Reads the CA address from whichever config file already carries one.
pub fn ca_address_from_configs(paths: &GuardianPaths) -> Option<String> {
    for candidate in [
        paths.node_config("nodeA"),
        paths.node_config_mirror("nodeA"),
    ] {
        let Some(path) = candidate.to_str() else {
            continue;
        };
        if let Ok(config) = crate::config_loader::load_config(path) {
            if is_usable_ca_address(&config.ip) {
                return Some(config.ip);
            }
        }
    }
    None
}

/// Polls for the CA's LAN address, falling back to loopback once the attempts
/// are exhausted.
pub async fn resolve_ca_ip(paths: &GuardianPaths, attempts: u32, retry_delay: Duration) -> String {
    for attempt in 1..=attempts {
        if let Some(ip) = ca_address_from_configs(paths) {
            return ip;
        }
        if attempt == 1 {
            eprintln!("⏳ Waiting for nodeA LAN IP via discovery/config sync...");
        }
        if attempt < attempts {
            tokio::time::sleep(retry_delay).await;
        }
    }
    eprintln!(
        "⚠️  Could not find nodeA LAN IP from config files. \
         Is nodeA running and broadcasting? Falling back to {LOCAL_FALLBACK} (local test only)."
    );
    LOCAL_FALLBACK.to_string()
}

/// [`resolve_ca_ip`] with the production roots and retry window.
pub async fn resolve_ca_ip_from_config() -> String {
    resolve_ca_ip(
        &GuardianPaths::production(),
        DEFAULT_ATTEMPTS,
        DEFAULT_RETRY_DELAY,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox() -> (tempfile::TempDir, GuardianPaths) {
        let temp = tempfile::tempdir().expect("create sandbox");
        let paths = GuardianPaths::rooted_at(temp.path());
        std::fs::create_dir_all(paths.etc_root.join("config")).expect("create config dir");
        (temp, paths)
    }

    fn write_config(path: &std::path::Path, ip: &str) {
        std::fs::write(
            path,
            format!("node_id: nodeA\nhostname: ca\nip: {ip}\nport: 50051\npublic_key: k\n"),
        )
        .expect("write config");
    }

    #[test]
    fn placeholder_addresses_are_not_treated_as_resolved() {
        assert!(is_usable_ca_address("10.0.0.7"));
        assert!(is_usable_ca_address("192.168.1.20"));
        assert!(!is_usable_ca_address(""));
        assert!(!is_usable_ca_address("0.0.0.0"));
        assert!(!is_usable_ca_address("127.0.0.1"));
    }

    #[test]
    fn the_dynamic_config_is_preferred_over_the_mirror() {
        let (_temp, paths) = sandbox();
        write_config(&paths.node_config("nodeA"), "10.0.0.7");
        write_config(&paths.node_config_mirror("nodeA"), "10.0.0.8");

        assert_eq!(ca_address_from_configs(&paths).as_deref(), Some("10.0.0.7"));
    }

    #[test]
    fn the_mirror_is_used_when_the_dynamic_config_is_still_a_placeholder() {
        let (_temp, paths) = sandbox();
        write_config(&paths.node_config("nodeA"), "0.0.0.0");
        write_config(&paths.node_config_mirror("nodeA"), "10.0.0.8");

        assert_eq!(ca_address_from_configs(&paths).as_deref(), Some("10.0.0.8"));
    }

    #[test]
    fn no_config_and_only_placeholders_resolve_to_nothing() {
        let (_temp, paths) = sandbox();
        assert!(ca_address_from_configs(&paths).is_none());

        write_config(&paths.node_config("nodeA"), "0.0.0.0");
        write_config(&paths.node_config_mirror("nodeA"), "127.0.0.1");
        assert!(ca_address_from_configs(&paths).is_none());
    }

    #[tokio::test]
    async fn an_address_already_present_is_returned_on_the_first_attempt() {
        let (_temp, paths) = sandbox();
        write_config(&paths.node_config("nodeA"), "10.0.0.7");

        let started = std::time::Instant::now();
        let ip = resolve_ca_ip(&paths, DEFAULT_ATTEMPTS, Duration::from_secs(30)).await;

        assert_eq!(ip, "10.0.0.7");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "a resolved address must not wait out the retry delay"
        );
    }

    #[tokio::test]
    async fn exhausting_every_attempt_falls_back_to_loopback() {
        let (_temp, paths) = sandbox();

        let ip = resolve_ca_ip(&paths, 3, Duration::from_millis(1)).await;

        assert_eq!(ip, LOCAL_FALLBACK);
    }

    #[tokio::test]
    async fn an_address_that_appears_mid_poll_is_picked_up() {
        let (_temp, paths) = sandbox();
        let config_path = paths.node_config("nodeA");

        // Simulates the broadcast loop writing nodeA's address after boot.
        let writer_path = config_path.clone();
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            write_config(&writer_path, "10.0.0.9");
        });

        let ip = resolve_ca_ip(&paths, 50, Duration::from_millis(10)).await;
        writer.await.expect("writer task");

        assert_eq!(ip, "10.0.0.9");
    }

    #[tokio::test]
    async fn a_single_attempt_does_not_sleep_before_falling_back() {
        let (_temp, paths) = sandbox();

        let started = std::time::Instant::now();
        let ip = resolve_ca_ip(&paths, 1, Duration::from_secs(30)).await;

        assert_eq!(ip, LOCAL_FALLBACK);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the final attempt must not sleep before giving up"
        );
    }
}
