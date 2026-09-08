use chrono::{Duration, Utc};
use sgx_guardian_client::integration::manager::IntegrationManager;
use sgx_guardian_client::integration::provider::{
    IntegrationStatus, OAuthCredentials, VendorProvider,
};

fn with_data_dir<T>(f: impl FnOnce() -> T) -> T {
    let dir = tempfile::tempdir().unwrap();
    let previous = std::env::var_os("SGX_DATA_DIR");
    std::env::set_var("SGX_DATA_DIR", dir.path());
    let out = f();
    if let Some(value) = previous {
        std::env::set_var("SGX_DATA_DIR", value);
    } else {
        std::env::remove_var("SGX_DATA_DIR");
    }
    out
}

fn creds(token: &str) -> OAuthCredentials {
    OAuthCredentials {
        access_token: token.into(),
        refresh_token: Some("refresh".into()),
        expires_at: Some(Utc::now() + Duration::hours(1)),
        token_type: "Bearer".into(),
        scope: Some("scope".into()),
    }
}

#[test]
fn new_manager_creates_default_provider_records() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            assert_eq!(
                IntegrationManager::new("i.json")
                    .list_integrations()
                    .await
                    .len(),
                2
            );
        })
    });
}

#[test]
fn get_google_nest_default_record() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let meta = IntegrationManager::new("i.json")
                .get_integration(VendorProvider::GoogleNest)
                .await
                .unwrap();
            assert_eq!(meta.name, "Google Nest");
            assert_eq!(meta.status, IntegrationStatus::Disconnected);
        })
    });
}

#[test]
fn get_kasa_default_record() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let meta = IntegrationManager::new("i.json")
                .get_integration(VendorProvider::TpLinkKasa)
                .await
                .unwrap();
            assert_eq!(meta.name, "TP-Link Kasa Smart Home");
            assert_eq!(meta.status, IntegrationStatus::Disconnected);
        })
    });
}

#[test]
fn connect_integration_marks_connected() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let manager = IntegrationManager::new("i.json");
            manager
                .connect_integration(VendorProvider::GoogleNest, creds("a"))
                .await
                .unwrap();
            assert_eq!(
                manager
                    .get_integration(VendorProvider::GoogleNest)
                    .await
                    .unwrap()
                    .status,
                IntegrationStatus::Connected
            );
        })
    });
}

#[test]
fn connect_integration_stores_credentials() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let manager = IntegrationManager::new("i.json");
            manager
                .connect_integration(VendorProvider::GoogleNest, creds("a"))
                .await
                .unwrap();
            assert_eq!(
                manager
                    .get_integration(VendorProvider::GoogleNest)
                    .await
                    .unwrap()
                    .credentials
                    .unwrap()
                    .access_token,
                "a"
            );
        })
    });
}

#[test]
fn connect_integration_clears_error_message() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let manager = IntegrationManager::new("i.json");
            manager
                .update_integration_status(
                    VendorProvider::GoogleNest,
                    IntegrationStatus::Error("bad".into()),
                    Some("bad".into()),
                )
                .await
                .unwrap();
            manager
                .connect_integration(VendorProvider::GoogleNest, creds("a"))
                .await
                .unwrap();
            assert!(manager
                .get_integration(VendorProvider::GoogleNest)
                .await
                .unwrap()
                .error_message
                .is_none());
        })
    });
}

#[test]
fn set_credentials_updates_existing_credentials() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let manager = IntegrationManager::new("i.json");
            manager
                .set_credentials(VendorProvider::GoogleNest, creds("b"))
                .await
                .unwrap();
            assert_eq!(
                manager
                    .get_integration(VendorProvider::GoogleNest)
                    .await
                    .unwrap()
                    .credentials
                    .unwrap()
                    .access_token,
                "b"
            );
        })
    });
}

#[test]
fn update_status_sets_error() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let manager = IntegrationManager::new("i.json");
            manager
                .update_integration_status(
                    VendorProvider::GoogleNest,
                    IntegrationStatus::Error("x".into()),
                    Some("x".into()),
                )
                .await
                .unwrap();
            let meta = manager
                .get_integration(VendorProvider::GoogleNest)
                .await
                .unwrap();
            assert_eq!(meta.status, IntegrationStatus::Error("x".into()));
            assert_eq!(meta.error_message.as_deref(), Some("x"));
        })
    });
}

#[test]
fn update_status_can_clear_error() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let manager = IntegrationManager::new("i.json");
            manager
                .update_integration_status(
                    VendorProvider::GoogleNest,
                    IntegrationStatus::Connected,
                    None,
                )
                .await
                .unwrap();
            assert!(manager
                .get_integration(VendorProvider::GoogleNest)
                .await
                .unwrap()
                .error_message
                .is_none());
        })
    });
}

#[test]
fn disconnect_clears_oauth_credentials() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let manager = IntegrationManager::new("i.json");
            manager
                .connect_integration(VendorProvider::GoogleNest, creds("a"))
                .await
                .unwrap();
            assert_eq!(
                manager
                    .disconnect_integration(VendorProvider::GoogleNest, None, None, None)
                    .await
                    .unwrap(),
                0
            );
            assert!(manager
                .get_integration(VendorProvider::GoogleNest)
                .await
                .unwrap()
                .credentials
                .is_none());
        })
    });
}

#[test]
fn disconnect_marks_disconnected() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let manager = IntegrationManager::new("i.json");
            manager
                .connect_integration(VendorProvider::GoogleNest, creds("a"))
                .await
                .unwrap();
            manager
                .disconnect_integration(VendorProvider::GoogleNest, None, None, None)
                .await
                .unwrap();
            assert_eq!(
                manager
                    .get_integration(VendorProvider::GoogleNest)
                    .await
                    .unwrap()
                    .status,
                IntegrationStatus::Disconnected
            );
        })
    });
}

#[test]
fn status_summary_has_two_providers() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            assert_eq!(
                IntegrationManager::new("i.json").get_status_summary().await["total_integrations"],
                2
            );
        })
    });
}

#[test]
fn status_summary_reflects_credentials() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let manager = IntegrationManager::new("i.json");
            manager
                .set_credentials(VendorProvider::GoogleNest, creds("a"))
                .await
                .unwrap();
            assert_eq!(
                manager.get_status_summary().await["providers"]["google_nest"]["has_credentials"],
                true
            );
        })
    });
}

#[test]
fn manager_persists_connected_status() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let manager = IntegrationManager::new("i.json");
            manager
                .connect_integration(VendorProvider::GoogleNest, creds("a"))
                .await
                .unwrap();
            assert_eq!(
                IntegrationManager::new("i.json")
                    .get_integration(VendorProvider::GoogleNest)
                    .await
                    .unwrap()
                    .status,
                IntegrationStatus::Connected
            );
        })
    });
}

macro_rules! status_tests {
    ($($name:ident => $status:expr, $text:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            with_data_dir(|| {
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    let manager = IntegrationManager::new("i.json");
                    manager.update_integration_status(VendorProvider::GoogleNest, $status, None).await.unwrap();
                    assert_eq!(manager.get_status_summary().await["providers"]["google_nest"]["status"], $text);
                })
            });
        }
    )+};
}

status_tests! {
    summary_connected_status => IntegrationStatus::Connected, "connected",
    summary_disconnected_status => IntegrationStatus::Disconnected, "disconnected",
    summary_expired_status => IntegrationStatus::Expired, "expired",
    summary_error_status => IntegrationStatus::Error("bad".into()), "error",
}

#[test]
fn connect_kasa_without_flow_connects_and_discovers_zero() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let manager = IntegrationManager::new("i.json");
            let creds =
                sgx_guardian_client::kasa::KasaCredentials::new(Some("local".into()), None, None);
            assert_eq!(manager.connect_kasa(creds, None, None).await.unwrap(), 0);
            assert_eq!(
                manager
                    .get_integration(VendorProvider::TpLinkKasa)
                    .await
                    .unwrap()
                    .status,
                IntegrationStatus::Connected
            );
        })
    });
}

#[test]
fn update_nest_credentials_saves_status() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let manager = IntegrationManager::new("i.json");
            let creds = sgx_guardian_client::nest::NestCredentials::new(
                Some("client".into()),
                Some("secret".into()),
                Some("project".into()),
                Some("access".into()),
                Some("refresh".into()),
            );
            manager.update_nest_credentials(creds).await.unwrap();
            assert_eq!(
                manager
                    .get_integration(VendorProvider::GoogleNest)
                    .await
                    .unwrap()
                    .status,
                IntegrationStatus::Connected
            );
        })
    });
}

#[test]
fn separate_data_files_are_isolated() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            IntegrationManager::new("a.json")
                .connect_integration(VendorProvider::GoogleNest, creds("a"))
                .await
                .unwrap();
            assert!(IntegrationManager::new("b.json")
                .get_integration(VendorProvider::GoogleNest)
                .await
                .unwrap()
                .credentials
                .is_none());
        })
    });
}

#[test]
fn list_integrations_returns_clones() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let manager = IntegrationManager::new("i.json");
            let mut list = manager.list_integrations().await;
            list.clear();
            assert_eq!(manager.list_integrations().await.len(), 2);
        })
    });
}

#[test]
fn kasa_status_summary_reflects_connected_state() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let manager = IntegrationManager::new("i.json");
            manager
                .update_integration_status(
                    VendorProvider::TpLinkKasa,
                    IntegrationStatus::Connected,
                    None,
                )
                .await
                .unwrap();
            assert_eq!(
                manager.get_status_summary().await["providers"]["tp_link_kasa"]["status"],
                "connected"
            );
        })
    });
}

#[test]
fn disconnect_kasa_without_managers_returns_zero() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let manager = IntegrationManager::new("i.json");
            manager
                .update_integration_status(
                    VendorProvider::TpLinkKasa,
                    IntegrationStatus::Connected,
                    None,
                )
                .await
                .unwrap();
            assert_eq!(
                manager
                    .disconnect_integration(VendorProvider::TpLinkKasa, None, None, None)
                    .await
                    .unwrap(),
                0
            );
            assert_eq!(
                manager
                    .get_integration(VendorProvider::TpLinkKasa)
                    .await
                    .unwrap()
                    .status,
                IntegrationStatus::Disconnected
            );
        })
    });
}

#[test]
fn persisted_status_survives_manager_recreation() {
    with_data_dir(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            IntegrationManager::new("i.json")
                .connect_integration(VendorProvider::GoogleNest, creds("persisted"))
                .await
                .unwrap();
            let loaded = IntegrationManager::new("i.json")
                .get_integration(VendorProvider::GoogleNest)
                .await
                .unwrap();
            assert_eq!(loaded.status, IntegrationStatus::Connected);
        })
    });
}
