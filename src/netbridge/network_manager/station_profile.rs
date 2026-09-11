use std::collections::HashMap;
use std::fmt;

use sha2::{Digest, Sha256};
use uuid::Uuid;
use zbus::zvariant::{OwnedValue, Str, Value};

use crate::netbridge::backend::{require_nm_uplink, NetworkBackendError};
use crate::runtime::models::SavedWifi;

pub type NmSettings = HashMap<String, HashMap<String, OwnedValue>>;

const CONNECTION_TYPE_WIFI: &str = "802-11-wireless";
const WIFI_SECURITY_SETTING: &str = "802-11-wireless-security";
const NM_SETTINGS_ADD_CONNECTION2_IN_MEMORY: u32 = 0x2;
const NM_SETTINGS_ADD_CONNECTION2_BLOCK_AUTOCONNECT: u32 = 0x20;
const NM_SETTING_SECRET_FLAG_NONE: u32 = 0x0;
const NM_SETTING_WIRELESS_POWERSAVE_DISABLE: u32 = 0x2;
const DEFAULT_ROUTE_METRIC: i64 = 600;
const FIRST_AUTOCONNECT_PRIORITY: i32 = 999;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StationProfileError {
    #[error("E_WIFI_PROFILE_SSID: SSID must be 1-32 bytes and contain no newline or NUL")]
    InvalidSsid,
    #[error(
        "E_WIFI_PROFILE_PASSWORD: WPA passphrase must be 8-63 bytes and contain no newline or NUL"
    )]
    InvalidPassword,
    #[error("E_WIFI_PROFILE_BSSID: invalid BSSID format")]
    InvalidBssid,
    #[error("E_WIFI_PROFILE_VALUE: could not encode NetworkManager setting: {0}")]
    Encoding(String),
    #[error(transparent)]
    Backend(#[from] NetworkBackendError),
}

/// A complete station profile that has not been sent to NetworkManager.
pub struct StationProfile {
    id: String,
    uuid: String,
    interface: String,
    settings: NmSettings,
    contains_secret: bool,
}

impl StationProfile {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    pub fn settings(&self) -> &NmSettings {
        &self.settings
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    pub fn is_guardian_owned(&self) -> bool {
        self.id.starts_with("sgx-guardian-station-")
    }

    /// Flags for Settings.AddConnection2: keep the profile in memory and prevent
    /// it racing our explicit first activation. NetworkManager clears the block
    /// after manual activation, so the profile can subsequently auto-reconnect.
    pub fn add_connection2_flags(&self) -> u32 {
        NM_SETTINGS_ADD_CONNECTION2_IN_MEMORY | NM_SETTINGS_ADD_CONNECTION2_BLOCK_AUTOCONNECT
    }
}

impl fmt::Debug for StationProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StationProfile")
            .field("id", &self.id)
            .field("uuid", &self.uuid)
            .field("interface", &self.interface)
            .field("contains_secret", &self.contains_secret)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

pub struct StationProfileBuilder {
    interface: String,
    route_metric: i64,
    autoconnect: bool,
}

impl StationProfileBuilder {
    pub fn new(interface: impl Into<String>) -> Result<Self, StationProfileError> {
        let interface = interface.into();
        require_nm_uplink(&interface)?;
        Ok(Self {
            interface,
            route_metric: DEFAULT_ROUTE_METRIC,
            autoconnect: true,
        })
    }

    pub fn with_autoconnect(mut self, autoconnect: bool) -> Self {
        self.autoconnect = autoconnect;
        self
    }

    pub fn build(
        &self,
        network: &SavedWifi,
        saved_network_index: usize,
    ) -> Result<StationProfile, StationProfileError> {
        validate_ssid(&network.ssid)?;
        let password = network
            .password
            .as_deref()
            .filter(|password| !password.trim().is_empty());
        if let Some(password) = password {
            validate_password(password)?;
        }
        let bssid = network
            .bssid
            .as_deref()
            .filter(|bssid| !bssid.trim().is_empty())
            .map(parse_bssid)
            .transpose()?;

        let uuid = deterministic_uuid(&self.interface, network);
        let id = format!("sgx-guardian-station-{}", uuid.simple());
        let mut settings = NmSettings::new();

        let mut connection = HashMap::new();
        insert_string(&mut connection, "id", &id);
        insert_string(&mut connection, "uuid", &uuid.to_string());
        insert_string(&mut connection, "type", CONNECTION_TYPE_WIFI);
        insert_string(&mut connection, "interface-name", &self.interface);
        connection.insert("autoconnect".to_owned(), OwnedValue::from(self.autoconnect));
        connection.insert(
            "autoconnect-priority".to_owned(),
            OwnedValue::from(autoconnect_priority(saved_network_index)),
        );
        settings.insert("connection".to_owned(), connection);

        let mut wireless = HashMap::new();
        wireless.insert("ssid".to_owned(), owned_array(network.ssid.as_bytes())?);
        insert_string(&mut wireless, "mode", "infrastructure");
        wireless.insert(
            "mac-address-randomization".to_owned(),
            OwnedValue::from(1_u32),
        );
        wireless.insert(
            "powersave".to_owned(),
            OwnedValue::from(NM_SETTING_WIRELESS_POWERSAVE_DISABLE),
        );
        if let Some(bssid) = bssid {
            wireless.insert("bssid".to_owned(), owned_array(&bssid)?);
        }
        if password.is_some() {
            insert_string(&mut wireless, "security", WIFI_SECURITY_SETTING);
        }
        settings.insert(CONNECTION_TYPE_WIFI.to_owned(), wireless);

        if let Some(password) = password {
            let mut security = HashMap::new();
            insert_string(&mut security, "key-mgmt", "wpa-psk");
            insert_string(&mut security, "psk", password);
            security.insert(
                "psk-flags".to_owned(),
                OwnedValue::from(NM_SETTING_SECRET_FLAG_NONE),
            );
            settings.insert(WIFI_SECURITY_SETTING.to_owned(), security);
        }

        let mut ipv4 = HashMap::new();
        insert_string(&mut ipv4, "method", "auto");
        ipv4.insert(
            "route-metric".to_owned(),
            OwnedValue::from(self.route_metric),
        );
        settings.insert("ipv4".to_owned(), ipv4);

        let mut ipv6 = HashMap::new();
        insert_string(&mut ipv6, "method", "disabled");
        settings.insert("ipv6".to_owned(), ipv6);

        Ok(StationProfile {
            id,
            uuid: uuid.to_string(),
            interface: self.interface.clone(),
            settings,
            contains_secret: password.is_some(),
        })
    }
}

fn validate_ssid(ssid: &str) -> Result<(), StationProfileError> {
    if ssid.is_empty() || ssid.len() > 32 || ssid.contains(['\n', '\r', '\0']) {
        Err(StationProfileError::InvalidSsid)
    } else {
        Ok(())
    }
}

fn validate_password(password: &str) -> Result<(), StationProfileError> {
    if !(8..=63).contains(&password.len()) || password.contains(['\n', '\r', '\0']) {
        Err(StationProfileError::InvalidPassword)
    } else {
        Ok(())
    }
}

fn parse_bssid(bssid: &str) -> Result<[u8; 6], StationProfileError> {
    let parts: Vec<_> = bssid.split(':').collect();
    if parts.len() != 6 || parts.iter().any(|part| part.len() != 2) {
        return Err(StationProfileError::InvalidBssid);
    }

    let mut bytes = [0_u8; 6];
    for (index, part) in parts.into_iter().enumerate() {
        bytes[index] =
            u8::from_str_radix(part, 16).map_err(|_| StationProfileError::InvalidBssid)?;
    }
    Ok(bytes)
}

fn deterministic_uuid(interface: &str, network: &SavedWifi) -> Uuid {
    let mut hash = Sha256::new();
    hash.update(b"sgx-guardian-station\0");
    hash.update(interface.as_bytes());
    hash.update(b"\0");
    hash.update(network.ssid.as_bytes());
    hash.update(b"\0");
    if let Some(bssid) = &network.bssid {
        hash.update(bssid.to_ascii_lowercase().as_bytes());
    }
    let digest = hash.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // RFC 9562 UUIDv8: deterministic application-defined payload.
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn autoconnect_priority(saved_network_index: usize) -> i32 {
    FIRST_AUTOCONNECT_PRIORITY
        .saturating_sub(i32::try_from(saved_network_index).unwrap_or(i32::MAX))
}

fn insert_string(group: &mut HashMap<String, OwnedValue>, key: &str, value: &str) {
    group.insert(
        key.to_owned(),
        OwnedValue::from(Str::from(value.to_owned())),
    );
}

fn owned_array(bytes: &[u8]) -> Result<OwnedValue, StationProfileError> {
    OwnedValue::try_from(Value::new(bytes.to_vec()))
        .map_err(|error| StationProfileError::Encoding(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saved(ssid: &str, password: Option<&str>, bssid: Option<&str>) -> SavedWifi {
        SavedWifi {
            ssid: ssid.to_owned(),
            password: password.map(str::to_owned),
            bssid: bssid.map(str::to_owned),
        }
    }

    fn string(settings: &NmSettings, group: &str, key: &str) -> String {
        settings[group][key]
            .try_clone()
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn u32_value(settings: &NmSettings, group: &str, key: &str) -> u32 {
        settings[group][key]
            .try_clone()
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn i32_value(settings: &NmSettings, group: &str, key: &str) -> i32 {
        settings[group][key]
            .try_clone()
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn bool_value(settings: &NmSettings, group: &str, key: &str) -> bool {
        settings[group][key]
            .try_clone()
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn i64_value(settings: &NmSettings, group: &str, key: &str) -> i64 {
        settings[group][key]
            .try_clone()
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn bytes(settings: &NmSettings, group: &str, key: &str) -> Vec<u8> {
        settings[group][key]
            .try_clone()
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn builds_open_dhcp_profile_bound_to_wlan1() {
        let profile = StationProfileBuilder::new("wlan1")
            .unwrap()
            .build(&saved("Cafe", None, None), 0)
            .unwrap();
        let settings = profile.settings();

        assert_eq!(string(settings, "connection", "type"), CONNECTION_TYPE_WIFI);
        assert_eq!(string(settings, "connection", "interface-name"), "wlan1");
        assert!(bool_value(settings, "connection", "autoconnect"));
        assert_eq!(bytes(settings, CONNECTION_TYPE_WIFI, "ssid"), b"Cafe");
        assert_eq!(
            string(settings, CONNECTION_TYPE_WIFI, "mode"),
            "infrastructure"
        );
        assert_eq!(
            u32_value(settings, CONNECTION_TYPE_WIFI, "mac-address-randomization"),
            1
        );
        assert!(!settings.contains_key(WIFI_SECURITY_SETTING));
        assert_eq!(string(settings, "ipv4", "method"), "auto");
        assert_eq!(i64_value(settings, "ipv4", "route-metric"), 600);
        assert_eq!(string(settings, "ipv6", "method"), "disabled");
        assert_eq!(profile.add_connection2_flags(), 0x22);
    }

    #[test]
    fn builds_wpa_profile_with_in_memory_secret_and_binary_bssid() {
        let password = "correct horse battery staple";
        let profile = StationProfileBuilder::new("wlan1")
            .unwrap()
            .build(
                &saved("Office", Some(password), Some("AA:bb:CC:dd:EE:ff")),
                3,
            )
            .unwrap();
        let settings = profile.settings();

        assert_eq!(
            string(settings, CONNECTION_TYPE_WIFI, "security"),
            WIFI_SECURITY_SETTING
        );
        assert_eq!(
            string(settings, WIFI_SECURITY_SETTING, "key-mgmt"),
            "wpa-psk"
        );
        assert_eq!(string(settings, WIFI_SECURITY_SETTING, "psk"), password);
        assert_eq!(u32_value(settings, WIFI_SECURITY_SETTING, "psk-flags"), 0);
        assert_eq!(
            bytes(settings, CONNECTION_TYPE_WIFI, "bssid"),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert_eq!(u32_value(settings, CONNECTION_TYPE_WIFI, "powersave"), 2);
        assert_eq!(
            i32_value(settings, "connection", "autoconnect-priority"),
            996
        );
    }

    #[test]
    fn identity_is_deterministic_and_password_independent() {
        let builder = StationProfileBuilder::new("wlan1").unwrap();
        let first = builder
            .build(&saved("Office", Some("password-one"), None), 0)
            .unwrap();
        let second = builder
            .build(&saved("Office", Some("password-two"), None), 0)
            .unwrap();

        assert_eq!(first.id(), second.id());
        assert_eq!(first.uuid(), second.uuid());
        assert!(first.id().starts_with("sgx-guardian-station-"));
    }

    #[test]
    fn debug_output_never_contains_psk() {
        let password = "do-not-log-this-password";
        let profile = StationProfileBuilder::new("wlan1")
            .unwrap()
            .build(&saved("Office", Some(password), None), 0)
            .unwrap();
        let diagnostic = format!("{profile:?}");

        assert!(!diagnostic.contains(password));
        assert!(diagnostic.contains("[REDACTED]"));
    }

    #[test]
    fn rejects_invalid_ssid_password_bssid_and_interface() {
        let builder = StationProfileBuilder::new("wlan1").unwrap();
        assert_eq!(
            builder.build(&saved("", None, None), 0).unwrap_err(),
            StationProfileError::InvalidSsid
        );
        assert_eq!(
            builder
                .build(&saved("Office", Some("short"), None), 0)
                .unwrap_err(),
            StationProfileError::InvalidPassword
        );
        assert_eq!(
            builder
                .build(&saved("Office", None, Some("not-a-mac")), 0)
                .unwrap_err(),
            StationProfileError::InvalidBssid
        );
        assert!(matches!(
            StationProfileBuilder::new("uap0"),
            Err(StationProfileError::Backend(
                NetworkBackendError::InterfaceDenied(_)
            ))
        ));
    }

    #[test]
    fn saved_network_order_sets_descending_autoconnect_priority() {
        let builder = StationProfileBuilder::new("wlan1").unwrap();
        let first = builder.build(&saved("First", None, None), 0).unwrap();
        let second = builder.build(&saved("Second", None, None), 1).unwrap();

        assert!(
            i32_value(first.settings(), "connection", "autoconnect-priority")
                > i32_value(second.settings(), "connection", "autoconnect-priority")
        );
    }
}
