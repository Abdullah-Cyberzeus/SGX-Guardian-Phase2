#[cfg(unix)]
use anyhow::bail;
use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct AdminTls {
    pub cert_path: String,
    pub key_path: String,
}

#[cfg(unix)]
pub fn validate_key_permissions(key_path: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let meta =
        std::fs::metadata(key_path).with_context(|| format!("cannot stat key {}", key_path))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "insecure key permissions {:o} on {} (require 0600)",
            mode,
            key_path
        );
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn validate_key_permissions(_key_path: &str) -> Result<()> {
    Ok(())
}

pub fn build_admin_server_config(
    cert_der_path: &str,
    key_der_path: &str,
) -> Result<Arc<ServerConfig>> {
    crate::server::ensure_rustls_crypto_provider();
    validate_key_permissions(key_der_path)?;

    let cert_der = std::fs::read(cert_der_path)
        .with_context(|| format!("read admin TLS cert {}", cert_der_path))?;
    let key_der = std::fs::read(key_der_path)
        .with_context(|| format!("read admin TLS key {}", key_der_path))?;

    let certs = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid admin TLS cert/key")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, SanType};
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    fn write_test_cert(dir: &Path) -> (PathBuf, PathBuf) {
        let cert_path = dir.join("device_nodeA_cert.der");
        let key_path = dir.join("device_nodeA.key");
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "nodeA");
        params
            .subject_alt_names
            .push(SanType::IpAddress("127.0.0.1".parse().expect("loopback")));
        let cert = rcgen::Certificate::from_params(params).expect("build cert");
        std::fs::write(&cert_path, cert.serialize_der().expect("serialize cert"))
            .expect("write cert");
        std::fs::write(&key_path, cert.serialize_private_key_der()).expect("write key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod key");
        }
        (cert_path, key_path)
    }

    #[test]
    fn missing_cert_fails_closed() {
        let td = TempDir::new().expect("tempdir");
        let missing_cert = td.path().join("missing.der");
        let key_path = td.path().join("device_nodeA.key");
        std::fs::write(&key_path, b"not-a-key").expect("write key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod key");
        }

        let err = build_admin_server_config(
            missing_cert.to_str().expect("cert path"),
            key_path.to_str().expect("key path"),
        )
        .expect_err("missing cert should fail");

        assert!(err.to_string().contains("read admin TLS cert"));
    }

    #[test]
    fn invalid_cert_or_key_fails_closed() {
        let td = TempDir::new().expect("tempdir");
        let cert_path = td.path().join("device_nodeA_cert.der");
        let key_path = td.path().join("device_nodeA.key");
        std::fs::write(&cert_path, b"garbage-cert").expect("write cert");
        std::fs::write(&key_path, b"garbage-key").expect("write key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod key");
        }

        let err = build_admin_server_config(
            cert_path.to_str().expect("cert path"),
            key_path.to_str().expect("key path"),
        )
        .expect_err("invalid cert/key should fail");

        assert!(err.to_string().contains("invalid admin TLS cert/key"));
    }

    #[cfg(unix)]
    #[test]
    fn insecure_key_permissions_are_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let td = TempDir::new().expect("tempdir");
        let (_cert_path, key_path) = write_test_cert(td.path());
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))
            .expect("chmod key");

        let err = validate_key_permissions(key_path.to_str().expect("key path"))
            .expect_err("0644 key should be rejected");

        assert!(err.to_string().contains("require 0600"));
    }
}
