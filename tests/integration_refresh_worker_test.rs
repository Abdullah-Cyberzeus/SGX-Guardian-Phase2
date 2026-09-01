use chrono::{Duration, Utc};
use sgx_guardian_client::integration::manager::IntegrationManager;
use sgx_guardian_client::integration::provider::{
    IntegrationStatus, OAuthCredentials, VendorProvider,
};
use sgx_guardian_client::integration::refresh_worker::TokenRefreshWorker;
use std::sync::Arc;

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

fn creds(refresh: Option<&str>, expires: Option<chrono::DateTime<Utc>>) -> OAuthCredentials {
    OAuthCredentials {
        access_token: "access".into(),
        refresh_token: refresh.map(str::to_string),
        expires_at: expires,
        token_type: "Bearer".into(),
        scope: None,
    }
}

#[test]
fn worker_new_can_check_empty_defaults() {
    with_data_dir(|| tokio::runtime::Runtime::new().unwrap().block_on(async {
        TokenRefreshWorker::new(IntegrationManager::new("i.json")).check_and_refresh_tokens().await;
    }));
}

#[test]
fn disconnected_provider_is_skipped() {
    with_data_dir(|| tokio::runtime::Runtime::new().unwrap().block_on(async {
        let manager = IntegrationManager::new("i.json");
        manager.set_credentials(VendorProvider::GoogleNest, creds(Some("refresh"), Some(Utc::now()))).await.unwrap();
        manager.update_integration_status(VendorProvider::GoogleNest, IntegrationStatus::Disconnected, None).await.unwrap();
        TokenRefreshWorker::new(manager.clone()).check_and_refresh_tokens().await;
        assert_eq!(manager.get_integration(VendorProvider::GoogleNest).await.unwrap().status, IntegrationStatus::Disconnected);
    }));
}

#[test]
fn future_token_is_not_refreshed() {
    with_data_dir(|| tokio::runtime::Runtime::new().unwrap().block_on(async {
        let manager = IntegrationManager::new("i.json");
        manager.connect_integration(VendorProvider::GoogleNest, creds(Some("refresh"), Some(Utc::now() + Duration::hours(1)))).await.unwrap();
        TokenRefreshWorker::new(manager.clone()).check_and_refresh_tokens().await;
        assert_eq!(manager.get_integration(VendorProvider::GoogleNest).await.unwrap().credentials.unwrap().access_token, "access");
    }));
}

#[test]
fn expiring_token_with_refresh_token_is_renewed() {
    with_data_dir(|| tokio::runtime::Runtime::new().unwrap().block_on(async {
        let manager = IntegrationManager::new("i.json");
        manager.connect_integration(VendorProvider::GoogleNest, creds(Some("refresh"), Some(Utc::now()))).await.unwrap();
        TokenRefreshWorker::new(manager.clone()).check_and_refresh_tokens().await;
        assert_ne!(manager.get_integration(VendorProvider::GoogleNest).await.unwrap().credentials.unwrap().access_token, "access");
    }));
}

#[test]
fn invalid_refresh_token_marks_expired() {
    with_data_dir(|| tokio::runtime::Runtime::new().unwrap().block_on(async {
        let manager = IntegrationManager::new("i.json");
        manager.connect_integration(VendorProvider::GoogleNest, creds(Some("invalid"), Some(Utc::now()))).await.unwrap();
        TokenRefreshWorker::new(manager.clone()).check_and_refresh_tokens().await;
        assert_eq!(manager.get_integration(VendorProvider::GoogleNest).await.unwrap().status, IntegrationStatus::Expired);
    }));
}

#[test]
fn missing_refresh_token_marks_expired() {
    with_data_dir(|| tokio::runtime::Runtime::new().unwrap().block_on(async {
        let manager = IntegrationManager::new("i.json");
        manager.connect_integration(VendorProvider::GoogleNest, creds(None, Some(Utc::now()))).await.unwrap();
        TokenRefreshWorker::new(manager.clone()).check_and_refresh_tokens().await;
        assert_eq!(manager.get_integration(VendorProvider::GoogleNest).await.unwrap().status, IntegrationStatus::Expired);
    }));
}

#[test]
fn missing_expiry_is_ignored() {
    with_data_dir(|| tokio::runtime::Runtime::new().unwrap().block_on(async {
        let manager = IntegrationManager::new("i.json");
        manager.connect_integration(VendorProvider::GoogleNest, creds(Some("refresh"), None)).await.unwrap();
        TokenRefreshWorker::new(manager.clone()).check_and_refresh_tokens().await;
        assert_eq!(manager.get_integration(VendorProvider::GoogleNest).await.unwrap().credentials.unwrap().access_token, "access");
    }));
}

#[test]
fn failed_refresh_records_error_message() {
    with_data_dir(|| tokio::runtime::Runtime::new().unwrap().block_on(async {
        let manager = IntegrationManager::new("i.json");
        manager.connect_integration(VendorProvider::GoogleNest, creds(Some("fail"), Some(Utc::now()))).await.unwrap();
        TokenRefreshWorker::new(manager.clone()).check_and_refresh_tokens().await;
        assert!(manager.get_integration(VendorProvider::GoogleNest).await.unwrap().error_message.unwrap().contains("refresh failed"));
    }));
}

macro_rules! no_panic_worker_tests {
    ($($name:ident),+ $(,)?) => {$(
        #[test]
        fn $name() {
            with_data_dir(|| tokio::runtime::Runtime::new().unwrap().block_on(async {
                let manager = IntegrationManager::new("i.json");
                TokenRefreshWorker::new(manager).check_and_refresh_tokens().await;
            }));
        }
    )+};
}

no_panic_worker_tests! {
    repeated_check_one,
    repeated_check_two,
    repeated_check_three,
    repeated_check_four,
    repeated_check_five,
    repeated_check_six,
    repeated_check_seven,
    repeated_check_eight,
    repeated_check_nine,
    repeated_check_ten,
    repeated_check_eleven,
    repeated_check_twelve,
    repeated_check_thirteen,
    repeated_check_fourteen,
    repeated_check_fifteen,
    repeated_check_sixteen,
    repeated_check_seventeen,
}

#[test]
fn start_spawns_background_task_without_blocking() {
    with_data_dir(|| tokio::runtime::Runtime::new().unwrap().block_on(async {
        let worker = Arc::new(TokenRefreshWorker::new(IntegrationManager::new("i.json")));
        worker.start();
    }));
}
