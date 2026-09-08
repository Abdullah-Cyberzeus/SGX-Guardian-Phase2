use sgx_guardian_client::integration::provider::{
    IntegrationMetadata, IntegrationStatus, OAuthCredentials, VendorProvider,
};
use sgx_guardian_client::integration::store::IntegrationStore;
use std::collections::HashMap;

fn path() -> (tempfile::NamedTempFile, String) {
    let file = tempfile::NamedTempFile::new().unwrap();
    let path = file.path().to_str().unwrap().to_string();
    (file, path)
}

fn meta(provider: VendorProvider, status: IntegrationStatus) -> IntegrationMetadata {
    IntegrationMetadata {
        provider,
        name: provider.display_name().into(),
        status,
        device_count: 0,
        last_synced: None,
        error_message: None,
        credentials: None,
        kasa_credentials: None,
        nest_credentials: None,
    }
}

#[test]
fn load_missing_or_empty_file_returns_empty_map() {
    let dir = tempfile::tempdir().unwrap();
    let store = IntegrationStore::new(dir.path().join("missing.json").to_str().unwrap());
    assert!(store.load().is_empty());

    let (_file, path) = path();
    assert!(IntegrationStore::new(&path).load().is_empty());
}

#[test]
fn load_malformed_json_returns_empty_map() {
    let (_file, path) = path();
    std::fs::write(&path, "{bad").unwrap();
    assert!(IntegrationStore::new(&path).load().is_empty());
}

#[test]
fn save_empty_map_writes_empty_integrations_object() {
    let (_file, path) = path();
    let store = IntegrationStore::new(&path);
    store.save(&HashMap::new()).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(value["integrations"], serde_json::json!({}));
    assert!(store.load().is_empty());
}

#[test]
fn save_and_load_metadata_without_credentials() {
    let (_file, path) = path();
    let store = IntegrationStore::new(&path);
    let mut map = HashMap::new();
    map.insert(
        VendorProvider::GoogleNest,
        IntegrationMetadata {
            device_count: 4,
            error_message: Some("offline".into()),
            ..meta(
                VendorProvider::GoogleNest,
                IntegrationStatus::Error("offline".into()),
            )
        },
    );
    store.save(&map).unwrap();
    let loaded = store.load();
    let nest = loaded.get(&VendorProvider::GoogleNest).unwrap();
    assert_eq!(nest.device_count, 4);
    assert_eq!(nest.error_message.as_deref(), Some("offline"));
    assert_eq!(nest.status, IntegrationStatus::Error("offline".into()));
    assert!(nest.credentials.is_none());
}

#[test]
fn oauth_shaped_google_nest_credentials_are_loaded_by_nest_parser_first() {
    let (_file, path) = path();
    let store = IntegrationStore::new(&path);
    let mut map = HashMap::new();
    map.insert(
        VendorProvider::GoogleNest,
        IntegrationMetadata {
            credentials: Some(OAuthCredentials {
                access_token: "access".into(),
                refresh_token: Some("refresh".into()),
                expires_at: Some(chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap()),
                token_type: "Bearer".into(),
                scope: Some("scope".into()),
            }),
            ..meta(VendorProvider::GoogleNest, IntegrationStatus::Connected)
        },
    );
    store.save(&map).unwrap();
    let loaded = store.load();
    let nest_creds = loaded
        .get(&VendorProvider::GoogleNest)
        .unwrap()
        .nest_credentials
        .as_ref()
        .unwrap();
    assert_eq!(nest_creds.access_token.as_deref(), Some("access"));
    assert_eq!(nest_creds.refresh_token.as_deref(), Some("refresh"));
    assert!(loaded
        .get(&VendorProvider::GoogleNest)
        .unwrap()
        .credentials
        .is_none());
}

#[test]
fn nest_credentials_round_trip_for_google_nest() {
    let (_file, path) = path();
    let store = IntegrationStore::new(&path);
    let mut map = HashMap::new();
    map.insert(
        VendorProvider::GoogleNest,
        IntegrationMetadata {
            nest_credentials: Some(sgx_guardian_client::nest::NestCredentials::new(
                Some("client".into()),
                Some("secret".into()),
                Some("project".into()),
                Some("access".into()),
                Some("refresh".into()),
            )),
            ..meta(VendorProvider::GoogleNest, IntegrationStatus::Connected)
        },
    );
    store.save(&map).unwrap();
    let loaded = store.load();
    let creds = loaded
        .get(&VendorProvider::GoogleNest)
        .unwrap()
        .nest_credentials
        .as_ref()
        .unwrap();
    assert_eq!(creds.client_id.as_deref(), Some("client"));
    assert_eq!(creds.access_token.as_deref(), Some("access"));
}

#[test]
fn kasa_credentials_round_trip_for_kasa_provider() {
    let (_file, path) = path();
    let store = IntegrationStore::new(&path);
    let mut map = HashMap::new();
    map.insert(
        VendorProvider::TpLinkKasa,
        IntegrationMetadata {
            kasa_credentials: Some(sgx_guardian_client::kasa::KasaCredentials::new(
                Some("cloud".into()),
                Some("user@example.com".into()),
                Some("password".into()),
            )),
            ..meta(VendorProvider::TpLinkKasa, IntegrationStatus::Connected)
        },
    );
    store.save(&map).unwrap();
    let loaded = store.load();
    let creds = loaded
        .get(&VendorProvider::TpLinkKasa)
        .unwrap()
        .kasa_credentials
        .as_ref()
        .unwrap();
    assert_eq!(creds.username.as_deref(), Some("user@example.com"));
}

#[test]
fn save_loads_multiple_providers() {
    let (_file, path) = path();
    let store = IntegrationStore::new(&path);
    let mut map = HashMap::new();
    map.insert(
        VendorProvider::GoogleNest,
        meta(VendorProvider::GoogleNest, IntegrationStatus::Expired),
    );
    map.insert(
        VendorProvider::TpLinkKasa,
        meta(VendorProvider::TpLinkKasa, IntegrationStatus::Disconnected),
    );
    store.save(&map).unwrap();
    let loaded = store.load();
    assert_eq!(loaded.len(), 2);
    assert_eq!(
        loaded[&VendorProvider::GoogleNest].status,
        IntegrationStatus::Expired
    );
    assert_eq!(
        loaded[&VendorProvider::TpLinkKasa].status,
        IntegrationStatus::Disconnected
    );
}

#[test]
fn save_overwrites_previous_file_contents() {
    let (_file, path) = path();
    let store = IntegrationStore::new(&path);
    let mut first = HashMap::new();
    first.insert(
        VendorProvider::GoogleNest,
        meta(VendorProvider::GoogleNest, IntegrationStatus::Connected),
    );
    store.save(&first).unwrap();

    let mut second = HashMap::new();
    second.insert(
        VendorProvider::TpLinkKasa,
        meta(VendorProvider::TpLinkKasa, IntegrationStatus::Expired),
    );
    store.save(&second).unwrap();
    let loaded = store.load();
    assert!(!loaded.contains_key(&VendorProvider::GoogleNest));
    assert!(loaded.contains_key(&VendorProvider::TpLinkKasa));
}

#[test]
fn encrypted_credentials_are_not_written_in_plaintext() {
    let (_file, path) = path();
    let store = IntegrationStore::new(&path);
    let mut map = HashMap::new();
    map.insert(
        VendorProvider::GoogleNest,
        IntegrationMetadata {
            credentials: Some(OAuthCredentials {
                access_token: "super-secret-access-token".into(),
                refresh_token: None,
                expires_at: None,
                token_type: "Bearer".into(),
                scope: None,
            }),
            ..meta(VendorProvider::GoogleNest, IntegrationStatus::Connected)
        },
    );
    store.save(&map).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("super-secret-access-token"));
    assert!(text.contains("encrypted_credentials"));
}

#[test]
fn invalid_encrypted_credentials_are_ignored_but_metadata_loads() {
    let (_file, path) = path();
    std::fs::write(
        &path,
        r#"{"integrations":{"google_nest":{"provider":"google_nest","name":"Nest","status":"connected","device_count":1,"last_synced":null,"error_message":null,"encrypted_credentials":[1,2,3]}}}"#,
    )
    .unwrap();
    let loaded = IntegrationStore::new(&path).load();
    let nest = loaded.get(&VendorProvider::GoogleNest).unwrap();
    assert_eq!(nest.device_count, 1);
    assert!(nest.credentials.is_none());
    assert!(nest.nest_credentials.is_none());
}

#[test]
fn invalid_provider_in_file_makes_load_return_empty_map() {
    let (_file, path) = path();
    std::fs::write(
        &path,
        r#"{"integrations":{"bad":{"provider":"bad","name":"Bad","status":"connected","device_count":1,"last_synced":null,"error_message":null,"encrypted_credentials":null}}}"#,
    )
    .unwrap();
    assert!(IntegrationStore::new(&path).load().is_empty());
}

#[test]
fn last_synced_round_trips() {
    let (_file, path) = path();
    let store = IntegrationStore::new(&path);
    let synced = chrono::DateTime::from_timestamp(1_700_000_123, 0).unwrap();
    let mut map = HashMap::new();
    map.insert(
        VendorProvider::GoogleNest,
        IntegrationMetadata {
            last_synced: Some(synced),
            ..meta(VendorProvider::GoogleNest, IntegrationStatus::Connected)
        },
    );
    store.save(&map).unwrap();
    assert_eq!(
        store.load()[&VendorProvider::GoogleNest].last_synced,
        Some(synced)
    );
}

#[test]
fn save_returns_error_when_nested_parent_is_missing_before_lock_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested").join("integrations.json");
    let store = IntegrationStore::new(path.to_str().unwrap());
    let err = store.save(&HashMap::new()).unwrap_err();
    assert!(err.contains("Atomic write error"));
    assert!(!path.exists());
}

#[test]
fn existing_file_permissions_are_restricted_on_unix() {
    let (_file, path) = path();
    std::fs::write(&path, "{}").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let store = IntegrationStore::new(&path);
        store.save(&HashMap::new()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn kasa_provider_with_oauth_credentials_does_not_parse_them_as_kasa_credentials() {
    let (_file, path) = path();
    let store = IntegrationStore::new(&path);
    let mut map = HashMap::new();
    map.insert(
        VendorProvider::TpLinkKasa,
        IntegrationMetadata {
            credentials: Some(OAuthCredentials {
                access_token: "access".into(),
                refresh_token: None,
                expires_at: None,
                token_type: "Bearer".into(),
                scope: None,
            }),
            ..meta(VendorProvider::TpLinkKasa, IntegrationStatus::Connected)
        },
    );
    store.save(&map).unwrap();
    let loaded = store.load();
    let kasa = loaded.get(&VendorProvider::TpLinkKasa).unwrap();
    assert!(kasa.credentials.is_none());
    assert!(kasa.kasa_credentials.is_none());
}
