use serde::{Deserialize, Serialize};

/// Supported Vendor Integration Providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VendorProvider {
    #[default]
    GoogleNest,
    TpLinkKasa,
}

impl VendorProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            VendorProvider::GoogleNest => "google_nest",
            VendorProvider::TpLinkKasa => "tp_link_kasa",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            VendorProvider::GoogleNest => "Google Nest",
            VendorProvider::TpLinkKasa => "TP-Link Kasa Smart Home",
        }
    }

    #[allow(clippy::should_implement_trait)]
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "google_nest" | "nest" => Some(VendorProvider::GoogleNest),
            "tp_link_kasa" | "kasa" | "tplink" => Some(VendorProvider::TpLinkKasa),
            _ => None,
        }
    }
}

/// Lifecycle Status of a Vendor Integration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationStatus {
    #[default]
    Disconnected,
    Connected,
    Expired,
    Error(String),
}

impl IntegrationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            IntegrationStatus::Connected => "connected",
            IntegrationStatus::Disconnected => "disconnected",
            IntegrationStatus::Expired => "expired",
            IntegrationStatus::Error(_) => "error",
        }
    }
}

/// OAuth Credential Payload (stored encrypted at rest)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCredentials {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub token_type: String,
    pub scope: Option<String>,
}

/// Integration Metadata Record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationMetadata {
    pub provider: VendorProvider,
    pub name: String,
    pub status: IntegrationStatus,
    pub device_count: usize,
    pub last_synced: Option<chrono::DateTime<chrono::Utc>>,
    pub error_message: Option<String>,
    pub credentials: Option<OAuthCredentials>,
    pub kasa_credentials: Option<crate::kasa::KasaCredentials>,
    pub nest_credentials: Option<crate::nest::NestCredentials>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vendor_provider_conversion() {
        assert_eq!(
            VendorProvider::from_str("google_nest"),
            Some(VendorProvider::GoogleNest)
        );
        assert_eq!(
            VendorProvider::from_str("kasa"),
            Some(VendorProvider::TpLinkKasa)
        );
        assert_eq!(VendorProvider::from_str("unknown"), None);
    }
}
