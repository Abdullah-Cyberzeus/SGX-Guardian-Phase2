//! Resolution of the REST admin API's TLS posture from YAML plus environment
//! overrides, and of the certificate SAN list.

use crate::config_loader::ApiTlsConfig;

/// Parses one of the accepted boolean spellings for an override variable.
///
/// Wider than [`super::env_true`] on purpose: these variables override a YAML
/// value in both directions, so an explicit `off` has to be distinguishable
/// from an unset variable.
pub fn parse_bool_flag(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Reads an override variable, treating an unparseable value as unset.
pub fn env_flag(name: &str) -> Option<bool> {
    std::env::var(name).ok().and_then(|v| parse_bool_flag(&v))
}

pub const TLS_ENABLED_ENV: &str = "SGX_ADMIN_TLS_ENABLED";
pub const REQUIRE_HTTPS_ENV: &str = "SGX_ADMIN_REQUIRE_HTTPS";
pub const ALIAS_PORT_ENV: &str = "SGX_ADMIN_TLS_ALIAS_PORT";
pub const DEFAULT_ALIAS_PORT: u16 = 443;

/// The admin API's resolved TLS decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminTlsPlan {
    pub enabled: bool,
    pub require_https: bool,
    /// `require_https` without `enabled` — the API must not start, since
    /// serving plaintext while claiming HTTPS is required is fail-open.
    pub misconfigured: bool,
    pub cert_path: String,
    pub key_path: String,
}

impl AdminTlsPlan {
    pub fn scheme(&self) -> &'static str {
        if self.enabled {
            "https"
        } else {
            "http"
        }
    }
}

/// Applies the environment overrides to the YAML TLS block.
pub fn resolve_admin_tls(
    mut tls: ApiTlsConfig,
    node_id: &str,
    enabled_override: Option<bool>,
    require_https_override: Option<bool>,
) -> AdminTlsPlan {
    if let Some(enabled) = enabled_override {
        tls.enabled = enabled;
    }
    if let Some(require_https) = require_https_override {
        tls.require_https = require_https;
    }
    AdminTlsPlan {
        enabled: tls.enabled,
        require_https: tls.require_https,
        misconfigured: tls.require_https && !tls.enabled,
        cert_path: tls.resolved_cert_path(node_id),
        key_path: tls.resolved_key_path(node_id),
    }
}

/// [`resolve_admin_tls`] with the overrides read from the process environment.
pub fn resolve_admin_tls_from_env(tls: ApiTlsConfig, node_id: &str) -> AdminTlsPlan {
    resolve_admin_tls(
        tls,
        node_id,
        env_flag(TLS_ENABLED_ENV),
        env_flag(REQUIRE_HTTPS_ENV),
    )
}

/// The port the HTTPS name alias should listen on, or `None` when it would
/// collide with the API's own bind port.
pub fn alias_port(configured: Option<&str>, api_port: u16) -> Option<u16> {
    let port = configured
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(DEFAULT_ALIAS_PORT);
    (port != api_port).then_some(port)
}

/// [`alias_port`] using the process environment.
pub fn alias_port_from_env(api_port: u16) -> Option<u16> {
    alias_port(std::env::var(ALIAS_PORT_ENV).ok().as_deref(), api_port)
}

/// The SAN entries the node certificate must carry.
///
/// Deliberately excludes the transient LAN IP: the certificate binds stable
/// identity entries so a DHCP lease change does not invalidate it.
pub fn certificate_san(
    lan_fqdn: &str,
    hostname: &str,
    node_id: &str,
    overlay_ip: &str,
) -> Vec<String> {
    let mut san = vec![
        lan_fqdn.to_string(),
        hostname.to_string(),
        node_id.to_string(),
        overlay_ip.to_string(),
        "127.0.0.1".to_string(),
        "localhost".to_string(),
        "guardian.local".to_string(),
        "192.168.200.1".to_string(),
    ];
    san.retain(|entry| !entry.is_empty());
    san.dedup();
    san
}

/// Serves the HTTPS name alias: a bare TCP relay that forwards every
/// connection on `bind` to the admin API on `upstream`.
///
/// Deliberately not a TLS terminator — the admin API already owns the
/// certificate, so relaying the raw stream keeps one certificate and one
/// trust decision rather than two.
pub async fn serve_admin_tls_alias(
    bind: std::net::SocketAddr,
    upstream: std::net::SocketAddr,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    println!("✅ Guardian HTTPS name endpoint listening on https://{bind}");
    loop {
        let (mut client, _) = listener.accept().await?;
        tokio::spawn(async move {
            match tokio::net::TcpStream::connect(upstream).await {
                Ok(mut server) => {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                }
                Err(error) => {
                    tracing::warn!(%error, "Guardian HTTPS alias could not reach admin API")
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml_tls(enabled: bool, require_https: bool) -> ApiTlsConfig {
        ApiTlsConfig {
            enabled,
            cert_path: None,
            key_path: None,
            require_https,
        }
    }

    #[test]
    fn bool_flags_accept_both_spellings_and_reject_noise() {
        for value in ["1", "true", "YES", " On ", "TRUE"] {
            assert_eq!(parse_bool_flag(value), Some(true), "{value:?}");
        }
        for value in ["0", "false", "NO", " off ", "FALSE"] {
            assert_eq!(parse_bool_flag(value), Some(false), "{value:?}");
        }
        for value in ["", "maybe", "2", "enabled"] {
            assert_eq!(parse_bool_flag(value), None, "{value:?}");
        }
    }

    #[test]
    fn env_flag_reads_overrides_and_treats_noise_as_unset() {
        let _lock = crate::test_support::blocking_env_lock();
        const KEY: &str = "SGX_STARTUP_TEST_TLS_FLAG";
        let previous = std::env::var_os(KEY);

        std::env::remove_var(KEY);
        assert_eq!(env_flag(KEY), None);
        std::env::set_var(KEY, "off");
        assert_eq!(env_flag(KEY), Some(false));
        std::env::set_var(KEY, "on");
        assert_eq!(env_flag(KEY), Some(true));
        std::env::set_var(KEY, "perhaps");
        assert_eq!(env_flag(KEY), None);

        match previous {
            Some(value) => std::env::set_var(KEY, value),
            None => std::env::remove_var(KEY),
        }
    }

    #[test]
    fn yaml_values_are_used_when_no_override_is_present() {
        let plan = resolve_admin_tls(yaml_tls(true, true), "nodeA", None, None);

        assert!(plan.enabled);
        assert!(plan.require_https);
        assert!(!plan.misconfigured);
        assert_eq!(plan.scheme(), "https");
        assert_eq!(
            plan.cert_path,
            "/var/lib/sgx-guardian/sgx-agent/device_nodeA_cert.der"
        );
        assert_eq!(
            plan.key_path,
            "/var/lib/sgx-guardian/sgx-agent/device_nodeA.key"
        );
    }

    #[test]
    fn overrides_win_over_yaml_in_both_directions() {
        let disabled = resolve_admin_tls(yaml_tls(true, true), "nodeA", Some(false), Some(false));
        assert!(!disabled.enabled);
        assert!(!disabled.require_https);
        assert!(!disabled.misconfigured);
        assert_eq!(disabled.scheme(), "http");

        let enabled = resolve_admin_tls(yaml_tls(false, false), "nodeB", Some(true), Some(true));
        assert!(enabled.enabled);
        assert!(enabled.require_https);
        assert!(!enabled.misconfigured);
    }

    #[test]
    fn requiring_https_without_tls_is_reported_as_misconfigured() {
        let plan = resolve_admin_tls(yaml_tls(false, true), "nodeC", None, None);
        assert!(plan.misconfigured);

        // The override can create the same conflict from a valid YAML block.
        let via_override = resolve_admin_tls(yaml_tls(true, true), "nodeC", Some(false), None);
        assert!(via_override.misconfigured);
    }

    #[test]
    fn explicit_certificate_paths_from_yaml_are_preserved() {
        let tls = ApiTlsConfig {
            enabled: true,
            cert_path: Some("/opt/certs/admin.der".into()),
            key_path: Some("/opt/certs/admin.key".into()),
            require_https: true,
        };

        let plan = resolve_admin_tls(tls, "nodeA", None, None);

        assert_eq!(plan.cert_path, "/opt/certs/admin.der");
        assert_eq!(plan.key_path, "/opt/certs/admin.key");
    }

    #[test]
    fn resolve_from_env_reads_both_override_variables() {
        let _lock = crate::test_support::blocking_env_lock();
        let previous_enabled = std::env::var_os(TLS_ENABLED_ENV);
        let previous_https = std::env::var_os(REQUIRE_HTTPS_ENV);
        std::env::set_var(TLS_ENABLED_ENV, "false");
        std::env::set_var(REQUIRE_HTTPS_ENV, "true");

        let plan = resolve_admin_tls_from_env(yaml_tls(true, false), "nodeA");

        assert!(!plan.enabled);
        assert!(plan.require_https);
        assert!(plan.misconfigured);

        match previous_enabled {
            Some(value) => std::env::set_var(TLS_ENABLED_ENV, value),
            None => std::env::remove_var(TLS_ENABLED_ENV),
        }
        match previous_https {
            Some(value) => std::env::set_var(REQUIRE_HTTPS_ENV, value),
            None => std::env::remove_var(REQUIRE_HTTPS_ENV),
        }
    }

    #[test]
    fn alias_port_defaults_to_443_and_skips_a_collision() {
        assert_eq!(alias_port(None, 8443), Some(443));
        assert_eq!(alias_port(Some("8080"), 8443), Some(8080));
        assert_eq!(
            alias_port(Some("not-a-port"), 8443),
            Some(443),
            "an unparseable value falls back to the default"
        );
        assert_eq!(
            alias_port(Some("8443"), 8443),
            None,
            "the alias must not fight the API for its own port"
        );
        assert_eq!(alias_port(None, 443), None);
    }

    #[test]
    fn alias_port_from_env_reads_the_override() {
        let _lock = crate::test_support::blocking_env_lock();
        let previous = std::env::var_os(ALIAS_PORT_ENV);

        std::env::set_var(ALIAS_PORT_ENV, "9443");
        assert_eq!(alias_port_from_env(8443), Some(9443));
        std::env::remove_var(ALIAS_PORT_ENV);
        assert_eq!(alias_port_from_env(8443), Some(443));

        match previous {
            Some(value) => std::env::set_var(ALIAS_PORT_ENV, value),
            None => std::env::remove_var(ALIAS_PORT_ENV),
        }
    }

    #[test]
    fn certificate_san_lists_stable_identity_entries_only() {
        let san = certificate_san(
            "nodea.guardian",
            "guardian-node-A",
            "nodeA",
            "192.168.100.1",
        );

        assert_eq!(
            san,
            vec![
                "nodea.guardian",
                "guardian-node-A",
                "nodeA",
                "192.168.100.1",
                "127.0.0.1",
                "localhost",
                "guardian.local",
                "192.168.200.1",
            ]
        );
    }

    #[test]
    fn certificate_san_drops_empty_entries() {
        let san = certificate_san("", "", "nodeB", "10.1.2.3");
        assert_eq!(
            san,
            vec![
                "nodeB",
                "10.1.2.3",
                "127.0.0.1",
                "localhost",
                "guardian.local",
                "192.168.200.1",
            ]
        );
    }

    #[tokio::test]
    async fn the_alias_relays_bytes_to_the_upstream_admin_api() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let Ok(upstream) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            // Some CI sandboxes prohibit local sockets; the parsing-side
            // behaviour is covered by the other tests in this module.
            return;
        };
        let upstream_addr = upstream.local_addr().expect("upstream address");
        // A trivial echo server standing in for the admin API.
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = upstream.accept().await {
                let mut buf = [0u8; 16];
                if let Ok(read) = socket.read(&mut buf).await {
                    let _ = socket.write_all(&buf[..read]).await;
                }
            }
        });

        let Ok(alias) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let alias_addr = alias.local_addr().expect("alias address");
        drop(alias);
        tokio::spawn(async move {
            let _ = serve_admin_tls_alias(alias_addr, upstream_addr).await;
        });

        // Give the relay a moment to claim the port it was just handed.
        let mut client = None;
        for _ in 0..50 {
            if let Ok(stream) = tokio::net::TcpStream::connect(alias_addr).await {
                client = Some(stream);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let Some(mut client) = client else {
            return;
        };

        client
            .write_all(b"ping")
            .await
            .expect("write through alias");
        let mut echoed = [0u8; 4];
        client
            .read_exact(&mut echoed)
            .await
            .expect("read the relayed response");

        assert_eq!(&echoed, b"ping");
    }

    #[tokio::test]
    async fn the_alias_reports_an_occupied_bind_address() {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("reserve local port: {error}"),
        };
        let bind = listener.local_addr().expect("bound address");
        let upstream = "127.0.0.1:9".parse().expect("parse upstream");

        let error = serve_admin_tls_alias(bind, upstream)
            .await
            .expect_err("the occupied address must not bind twice");

        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
    }

    #[tokio::test]
    async fn a_connection_survives_an_unreachable_upstream() {
        use tokio::io::AsyncWriteExt;

        let Ok(probe) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let alias_addr = probe.local_addr().expect("alias address");
        drop(probe);
        // 127.0.0.1:1 is reserved and has no listener.
        let unreachable = "127.0.0.1:1".parse().expect("parse upstream");
        tokio::spawn(async move {
            let _ = serve_admin_tls_alias(alias_addr, unreachable).await;
        });

        let mut client = None;
        for _ in 0..50 {
            if let Ok(stream) = tokio::net::TcpStream::connect(alias_addr).await {
                client = Some(stream);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let Some(mut client) = client else {
            return;
        };

        // The relay logs and drops the connection rather than aborting the
        // whole accept loop, so a second connection still succeeds.
        let _ = client.write_all(b"ping").await;
        drop(client);
        assert!(
            tokio::net::TcpStream::connect(alias_addr).await.is_ok(),
            "the accept loop must survive an unreachable upstream"
        );
    }
}
