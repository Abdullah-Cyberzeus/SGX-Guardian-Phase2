use sgx_guardian_client::integration::provider::{
    IntegrationMetadata, IntegrationStatus, OAuthCredentials, VendorProvider,
};

#[test]
fn default_provider_is_google_nest() {
    assert_eq!(VendorProvider::default(), VendorProvider::GoogleNest);
}

#[test]
fn provider_as_str_returns_stable_keys() {
    assert_eq!(VendorProvider::GoogleNest.as_str(), "google_nest");
    assert_eq!(VendorProvider::TpLinkKasa.as_str(), "tp_link_kasa");
}

#[test]
fn provider_display_name_returns_user_facing_names() {
    assert_eq!(VendorProvider::GoogleNest.display_name(), "Google Nest");
    assert_eq!(
        VendorProvider::TpLinkKasa.display_name(),
        "TP-Link Kasa Smart Home"
    );
}

#[test]
fn provider_from_str_accepts_google_aliases_case_insensitively() {
    assert_eq!(
        VendorProvider::from_str("GOOGLE_NEST"),
        Some(VendorProvider::GoogleNest)
    );
    assert_eq!(VendorProvider::from_str("Nest"), Some(VendorProvider::GoogleNest));
}

#[test]
fn provider_from_str_accepts_kasa_aliases_case_insensitively() {
    assert_eq!(
        VendorProvider::from_str("TP_LINK_KASA"),
        Some(VendorProvider::TpLinkKasa)
    );
    assert_eq!(VendorProvider::from_str("KASA"), Some(VendorProvider::TpLinkKasa));
    assert_eq!(VendorProvider::from_str("tplink"), Some(VendorProvider::TpLinkKasa));
}

#[test]
fn provider_from_str_rejects_empty_whitespace_and_unknown_values() {
    for raw in ["", " ", "google-nest", "tp-link-kasa", "unknown"] {
        assert_eq!(VendorProvider::from_str(raw), None, "{raw:?}");
    }
}

#[test]
fn provider_serializes_as_snake_case() {
    assert_eq!(
        serde_json::to_value(VendorProvider::GoogleNest).unwrap(),
        serde_json::json!("google_nest")
    );
    assert_eq!(
        serde_json::to_value(VendorProvider::TpLinkKasa).unwrap(),
        serde_json::json!("tp_link_kasa")
    );
}

#[test]
fn provider_deserializes_from_snake_case() {
    assert_eq!(
        serde_json::from_str::<VendorProvider>(r#""google_nest""#).unwrap(),
        VendorProvider::GoogleNest
    );
    assert_eq!(
        serde_json::from_str::<VendorProvider>(r#""tp_link_kasa""#).unwrap(),
        VendorProvider::TpLinkKasa
    );
}

#[test]
fn provider_deserialize_rejects_unknown_value() {
    assert!(serde_json::from_str::<VendorProvider>(r#""nest""#).is_err());
}

#[test]
fn default_status_is_disconnected() {
    assert_eq!(IntegrationStatus::default(), IntegrationStatus::Disconnected);
}

#[test]
fn status_as_str_returns_stable_values() {
    assert_eq!(IntegrationStatus::Connected.as_str(), "connected");
    assert_eq!(IntegrationStatus::Disconnected.as_str(), "disconnected");
    assert_eq!(IntegrationStatus::Expired.as_str(), "expired");
    assert_eq!(IntegrationStatus::Error("boom".into()).as_str(), "error");
}

#[test]
fn status_serializes_known_variants_as_snake_case() {
    assert_eq!(
        serde_json::to_value(IntegrationStatus::Connected).unwrap(),
        serde_json::json!("connected")
    );
    assert_eq!(
        serde_json::to_value(IntegrationStatus::Expired).unwrap(),
        serde_json::json!("expired")
    );
}

#[test]
fn status_error_variant_round_trips_message() {
    let status = IntegrationStatus::Error("token expired".into());
    let json = serde_json::to_string(&status).unwrap();
    let decoded: IntegrationStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, status);
    assert_eq!(decoded.as_str(), "error");
}

#[test]
fn oauth_credentials_round_trip_with_optional_fields() {
    let creds = OAuthCredentials {
        access_token: "access".into(),
        refresh_token: Some("refresh".into()),
        expires_at: Some(chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap()),
        token_type: "Bearer".into(),
        scope: Some("read write".into()),
    };
    let json = serde_json::to_string(&creds).unwrap();
    let decoded: OAuthCredentials = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.access_token, "access");
    assert_eq!(decoded.refresh_token.as_deref(), Some("refresh"));
    assert_eq!(decoded.token_type, "Bearer");
    assert_eq!(decoded.scope.as_deref(), Some("read write"));
}

#[test]
fn integration_metadata_serializes_without_credentials() {
    let meta = IntegrationMetadata {
        provider: VendorProvider::GoogleNest,
        name: "Nest".into(),
        status: IntegrationStatus::Disconnected,
        device_count: 0,
        last_synced: None,
        error_message: None,
        credentials: None,
        kasa_credentials: None,
        nest_credentials: None,
    };
    let value = serde_json::to_value(&meta).unwrap();
    assert_eq!(value["provider"], "google_nest");
    assert_eq!(value["device_count"], 0);
    assert!(value["credentials"].is_null());
}

#[test]
fn integration_metadata_round_trips_error_status_and_timestamp() {
    let synced = chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap();
    let meta = IntegrationMetadata {
        provider: VendorProvider::TpLinkKasa,
        name: "Kasa".into(),
        status: IntegrationStatus::Error("bad auth".into()),
        device_count: 7,
        last_synced: Some(synced),
        error_message: Some("bad auth".into()),
        credentials: None,
        kasa_credentials: None,
        nest_credentials: None,
    };
    let json = serde_json::to_string(&meta).unwrap();
    let decoded: IntegrationMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.provider, VendorProvider::TpLinkKasa);
    assert_eq!(decoded.status, IntegrationStatus::Error("bad auth".into()));
    assert_eq!(decoded.last_synced, Some(synced));
    assert_eq!(decoded.error_message.as_deref(), Some("bad auth"));
}
