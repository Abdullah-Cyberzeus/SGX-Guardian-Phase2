use std::collections::HashMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::time::timeout;
use zbus::proxy::{Builder as ProxyBuilder, CacheProperties};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Str};
use zbus::{Connection, Proxy};

use crate::netbridge::backend::{
    require_nm_uplink, NetworkBackend, NetworkBackendError, NetworkDevice, NetworkDeviceKind,
    NetworkManagerPreflight,
};
use crate::netbridge::types::WifiNetwork;
use station_profile::StationProfile;

pub mod station_profile;

const NM_DESTINATION: &str = "org.freedesktop.NetworkManager";
const NM_PATH: &str = "/org/freedesktop/NetworkManager";
const NM_MANAGER_INTERFACE: &str = "org.freedesktop.NetworkManager";
const NM_DEVICE_INTERFACE: &str = "org.freedesktop.NetworkManager.Device";
const NM_WIRELESS_INTERFACE: &str = "org.freedesktop.NetworkManager.Device.Wireless";
const NM_ACCESS_POINT_INTERFACE: &str = "org.freedesktop.NetworkManager.AccessPoint";
const NM_SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";
const NM_SETTINGS_INTERFACE: &str = "org.freedesktop.NetworkManager.Settings";
const NM_SETTINGS_CONNECTION_INTERFACE: &str = "org.freedesktop.NetworkManager.Settings.Connection";
const NM_ACTIVE_CONNECTION_INTERFACE: &str = "org.freedesktop.NetworkManager.Connection.Active";

const AP_FLAG_PRIVACY: u32 = 0x1;
const AP_SEC_KEY_MGMT_PSK: u32 = 0x100;
const AP_SEC_KEY_MGMT_SAE: u32 = 0x400;
const AP_SEC_KEY_MGMT_OWE: u32 = 0x800;

/// Read-only NetworkManager D-Bus transport used by the first migration milestone.
pub struct NetworkManagerBackend {
    connection: Connection,
    call_timeout: Duration,
    scan_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileValidationReport {
    pub id: String,
    pub uuid: String,
    pub was_unsaved: bool,
    pub was_activated: bool,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StationSession {
    settings_path: OwnedObjectPath,
    active_path: OwnedObjectPath,
    pub profile_id: String,
    pub addresses: Vec<String>,
    pub gateway: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleValidationReport {
    pub addresses: Vec<String>,
    pub gateway: Option<String>,
    pub deactivated: bool,
    pub deleted: bool,
}

impl NetworkManagerBackend {
    pub async fn system(call_timeout: Duration) -> Result<Self, NetworkBackendError> {
        let connection = timeout(call_timeout, Connection::system())
            .await
            .map_err(|_| NetworkBackendError::Timeout)?
            .map_err(|error| NetworkBackendError::Unavailable(error.to_string()))?;
        Ok(Self {
            connection,
            call_timeout,
            scan_timeout: Duration::from_secs(20),
        })
    }

    pub fn from_connection(connection: Connection, call_timeout: Duration) -> Self {
        Self {
            connection,
            call_timeout,
            scan_timeout: Duration::from_secs(20),
        }
    }

    pub fn with_scan_timeout(mut self, scan_timeout: Duration) -> Self {
        self.scan_timeout = scan_timeout;
        self
    }

    async fn manager_proxy(&self) -> Result<Proxy<'_>, NetworkBackendError> {
        ProxyBuilder::<Proxy<'_>>::new(&self.connection)
            .destination(NM_DESTINATION)
            .map_err(unavailable)?
            .path(NM_PATH)
            .map_err(unavailable)?
            .interface(NM_MANAGER_INTERFACE)
            .map_err(unavailable)?
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(unavailable)
    }

    async fn device_from_path(
        &self,
        path: &OwnedObjectPath,
    ) -> Result<NetworkDevice, NetworkBackendError> {
        let proxy = ProxyBuilder::<Proxy<'_>>::new(&self.connection)
            .destination(NM_DESTINATION)
            .map_err(unavailable)?
            .path(path.clone())
            .map_err(unavailable)?
            .interface(NM_DEVICE_INTERFACE)
            .map_err(unavailable)?
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(unavailable)?;

        let read = async {
            let interface: String = proxy.get_property("Interface").await?;
            let device_type: u32 = proxy.get_property("DeviceType").await?;
            let state: u32 = proxy.get_property("State").await?;
            let managed: bool = proxy.get_property("Managed").await?;
            Ok::<_, zbus::Error>((interface, device_type, state, managed))
        };
        let (interface, device_type, state, managed) = timeout(self.call_timeout, read)
            .await
            .map_err(|_| NetworkBackendError::Timeout)?
            .map_err(unavailable)?;

        Ok(NetworkDevice {
            object_path: path.to_string(),
            interface,
            kind: NetworkDeviceKind::from(device_type),
            state,
            managed,
        })
    }

    /// Best-effort: tells NetworkManager to cancel whatever it is doing on
    /// `interface` right now (activating, activated, or idle). Errors are
    /// swallowed — this exists purely to clear stuck state before a fresh
    /// activation attempt, and "already disconnected" is a normal outcome.
    async fn disconnect_device(&self, interface: &str) {
        let Ok(devices) = self.devices().await else {
            return;
        };
        let Some(device) = devices.into_iter().find(|d| d.interface == interface) else {
            return;
        };
        let Ok(device_path) = OwnedObjectPath::try_from(device.object_path) else {
            return;
        };
        let Ok(proxy) = self.interface_proxy(device_path, NM_DEVICE_INTERFACE).await else {
            return;
        };
        let _ = timeout(self.call_timeout, proxy.call::<_, _, ()>("Disconnect", &())).await;
    }

    async fn manager_identity(&self) -> Result<(String, u32), NetworkBackendError> {
        let proxy = self.manager_proxy().await?;
        timeout(self.call_timeout, async {
            let version: String = proxy.get_property("Version").await?;
            let state: u32 = proxy.get_property("State").await?;
            Ok::<_, zbus::Error>((version, state))
        })
        .await
        .map_err(|_| NetworkBackendError::Timeout)?
        .map_err(unavailable)
    }

    async fn interface_proxy<'a>(
        &'a self,
        path: OwnedObjectPath,
        interface: &'static str,
    ) -> Result<Proxy<'a>, NetworkBackendError> {
        ProxyBuilder::<Proxy<'_>>::new(&self.connection)
            .destination(NM_DESTINATION)
            .map_err(unavailable)?
            .path(path)
            .map_err(unavailable)?
            .interface(interface)
            .map_err(unavailable)?
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(unavailable)
    }

    async fn read_access_point(
        &self,
        path: OwnedObjectPath,
    ) -> Result<RawAccessPoint, NetworkBackendError> {
        let proxy = self
            .interface_proxy(path, NM_ACCESS_POINT_INTERFACE)
            .await?;
        timeout(self.call_timeout, async {
            let ssid: Vec<u8> = proxy.get_property("Ssid").await?;
            let bssid: String = proxy.get_property("HwAddress").await?;
            let strength: u8 = proxy.get_property("Strength").await?;
            let frequency: u32 = proxy.get_property("Frequency").await?;
            let flags: u32 = proxy.get_property("Flags").await?;
            let wpa_flags: u32 = proxy.get_property("WpaFlags").await?;
            let rsn_flags: u32 = proxy.get_property("RsnFlags").await?;
            Ok::<_, zbus::Error>(RawAccessPoint {
                ssid,
                bssid,
                strength,
                frequency,
                flags,
                wpa_flags,
                rsn_flags,
            })
        })
        .await
        .map_err(|_| NetworkBackendError::Timeout)?
        .map_err(|error| NetworkBackendError::ScanFailed(error.to_string()))
    }

    /// Temporarily adds an in-memory station profile, validates it, and removes it.
    /// This method never asks NetworkManager to activate a connection.
    pub async fn validate_station_profile(
        &self,
        profile: &StationProfile,
    ) -> Result<ProfileValidationReport, NetworkBackendError> {
        if !profile.is_guardian_owned() {
            return Err(NetworkBackendError::ProfileOperation(
                "refused profile without Guardian identity".to_owned(),
            ));
        }
        self.cleanup_matching_guardian_profile(profile).await?;

        let connection_path = self
            .add_in_memory_profile(profile.settings(), profile.add_connection2_flags())
            .await?;

        let validation = self
            .inspect_added_profile(profile, connection_path.clone())
            .await;
        let deletion = self.delete_added_profile(connection_path.clone()).await;

        // Cleanup errors take precedence because they may require operator action.
        deletion?;
        let (was_unsaved, was_activated) = validation?;
        Ok(ProfileValidationReport {
            id: profile.id().to_owned(),
            uuid: profile.uuid().to_owned(),
            was_unsaved,
            was_activated,
            deleted: true,
        })
    }

    pub async fn activate_station(
        &self,
        profile: &StationProfile,
        activation_timeout: Duration,
    ) -> Result<StationSession, NetworkBackendError> {
        if !profile.is_guardian_owned() {
            return Err(NetworkBackendError::ProfileOperation(
                "refused profile without Guardian identity".to_owned(),
            ));
        }
        let interface = profile.interface();

        // A previous attempt on this device may have been abandoned mid-flight
        // (e.g. its Rust task was aborted by a newer mode-switch request before
        // ActivateConnection resolved). Aborting our side never told NetworkManager
        // to cancel that operation, so the device can still be mid-activation here
        // with nothing in our own state pointing at it. Force a clean slate on the
        // device itself before touching profiles, rather than relying on Guardian's
        // own bookkeeping (which has nothing to clean up in that scenario).
        self.disconnect_device(interface).await;

        self.cleanup_matching_guardian_profile(profile).await?;
        let preflight = self.preflight(interface).await?;
        let device_path = OwnedObjectPath::try_from(preflight.uplink.object_path)
            .map_err(|_| NetworkBackendError::ActivationFailed("invalid device path".to_owned()))?;
        let settings_path = self
            .add_in_memory_profile(profile.settings(), profile.add_connection2_flags())
            .await?;

        match self
            .activate_added_profile(
                profile.id(),
                settings_path.clone(),
                device_path,
                activation_timeout,
            )
            .await
        {
            Ok(session) => {
                // Reinforce the profile setting at driver level for NXP radios.
                let _ = tokio::process::Command::new("iw")
                    .args(["dev", interface, "set", "power_save", "off"])
                    .output()
                    .await;
                Ok(session)
            }
            Err(error) => {
                let _ = self.delete_added_profile(settings_path).await;
                Err(error)
            }
        }
    }

    pub async fn deactivate_station(
        &self,
        session: &StationSession,
    ) -> Result<(), NetworkBackendError> {
        self.deactivate_active_path(&session.active_path).await?;
        self.delete_added_profile(session.settings_path.clone())
            .await
    }

    /// Returns true while NetworkManager still owns an activating or activated
    /// connection. A disappeared/deactivated object tells the runtime to
    /// rebuild the volatile profile and reconnect.
    pub async fn station_session_is_viable(
        &self,
        session: &StationSession,
    ) -> Result<bool, NetworkBackendError> {
        let active = self
            .interface_proxy(session.active_path.clone(), NM_ACTIVE_CONNECTION_INTERFACE)
            .await?;
        match timeout(self.call_timeout, active.get_property::<u32>("State")).await {
            Ok(Ok(state)) => Ok(is_viable_active_state(state)),
            Ok(Err(_)) => Ok(false),
            Err(_) => Err(NetworkBackendError::Timeout),
        }
    }

    /// Exercises the same D-Bus lifecycle on the lab's veth named wlan1.
    pub async fn validate_lab_ethernet_lifecycle(
        &self,
    ) -> Result<LifecycleValidationReport, NetworkBackendError> {
        require_nm_uplink("wlan1")?;
        let device = self
            .devices()
            .await?
            .into_iter()
            .find(|device| device.interface == "wlan1")
            .ok_or_else(|| NetworkBackendError::DeviceNotFound("wlan1".to_owned()))?;
        let device_path = OwnedObjectPath::try_from(device.object_path)
            .map_err(|_| NetworkBackendError::ActivationFailed("invalid device path".to_owned()))?;
        let profile_id = "sgx-guardian-lab-ethernet";
        let profile = lab_ethernet_profile(profile_id);
        // Keep the lab profile in memory and block autoactivation until the
        // explicit ActivateConnection call below, matching station semantics.
        let settings_path = self.add_in_memory_profile(&profile, 0x22).await?;
        let session = match self
            .activate_added_profile(
                profile_id,
                settings_path.clone(),
                device_path,
                Duration::from_secs(20),
            )
            .await
        {
            Ok(session) => session,
            Err(error) => {
                let _ = self.delete_added_profile(settings_path).await;
                return Err(error);
            }
        };
        let addresses = session.addresses.clone();
        let gateway = session.gateway.clone();
        self.deactivate_station(&session).await?;
        Ok(LifecycleValidationReport {
            addresses,
            gateway,
            deactivated: true,
            deleted: true,
        })
    }

    async fn add_in_memory_profile(
        &self,
        profile: &station_profile::NmSettings,
        flags: u32,
    ) -> Result<OwnedObjectPath, NetworkBackendError> {
        let settings = self
            .interface_proxy(
                OwnedObjectPath::try_from(NM_SETTINGS_PATH).map_err(unavailable)?,
                NM_SETTINGS_INTERFACE,
            )
            .await?;
        let arguments = HashMap::<String, OwnedValue>::new();
        let (path, _result): (OwnedObjectPath, HashMap<String, OwnedValue>) = timeout(
            self.call_timeout,
            settings.call("AddConnection2", &(profile, flags, arguments)),
        )
        .await
        .map_err(|_| NetworkBackendError::Timeout)?
        .map_err(|_| {
            NetworkBackendError::ProfileOperation(
                "NetworkManager rejected the in-memory station profile".to_owned(),
            )
        })?;
        Ok(path)
    }

    async fn cleanup_matching_guardian_profile(
        &self,
        profile: &StationProfile,
    ) -> Result<(), NetworkBackendError> {
        let settings = self
            .interface_proxy(
                OwnedObjectPath::try_from(NM_SETTINGS_PATH).map_err(unavailable)?,
                NM_SETTINGS_INTERFACE,
            )
            .await?;
        let paths: Vec<OwnedObjectPath> =
            timeout(self.call_timeout, settings.call("ListConnections", &()))
                .await
                .map_err(|_| NetworkBackendError::Timeout)?
                .map_err(unavailable)?;

        for path in paths {
            let connection = self
                .interface_proxy(path.clone(), NM_SETTINGS_CONNECTION_INTERFACE)
                .await?;
            let accepted: station_profile::NmSettings =
                match timeout(self.call_timeout, connection.call("GetSettings", &())).await {
                    Ok(Ok(settings)) => settings,
                    _ => continue,
                };
            let group = match accepted.get("connection") {
                Some(group) => group,
                None => continue,
            };
            let id = setting_string(group, "id");
            let uuid = setting_string(group, "uuid");
            let interface = setting_string(group, "interface-name");
            if id.as_deref() == Some(profile.id())
                && uuid.as_deref() == Some(profile.uuid())
                && interface.as_deref() == Some(profile.interface())
            {
                self.deactivate_connections_for_settings(&path).await?;
                self.delete_added_profile(path).await?;
            }
        }
        Ok(())
    }

    async fn deactivate_connections_for_settings(
        &self,
        settings_path: &OwnedObjectPath,
    ) -> Result<(), NetworkBackendError> {
        let manager = self.manager_proxy().await?;
        let active_paths: Vec<OwnedObjectPath> =
            timeout(self.call_timeout, manager.get_property("ActiveConnections"))
                .await
                .map_err(|_| NetworkBackendError::Timeout)?
                .map_err(unavailable)?;
        for active_path in active_paths {
            let active = self
                .interface_proxy(active_path.clone(), NM_ACTIVE_CONNECTION_INTERFACE)
                .await?;
            let connection_path: OwnedObjectPath =
                timeout(self.call_timeout, active.get_property("Connection"))
                    .await
                    .map_err(|_| NetworkBackendError::Timeout)?
                    .map_err(unavailable)?;
            if &connection_path == settings_path {
                self.deactivate_active_path(&active_path).await?;
            }
        }
        Ok(())
    }

    async fn deactivate_active_path(
        &self,
        active_path: &OwnedObjectPath,
    ) -> Result<(), NetworkBackendError> {
        let manager = self.manager_proxy().await?;

        // A device-level reset (firmware auth-timeout recovery, radio reset) can
        // tear the active connection down on its own before we get here. Treat an
        // already-gone active path as already deactivated instead of failing the
        // whole rebuild on a stale reference NetworkManager will never accept.
        let active: Vec<OwnedObjectPath> =
            timeout(self.call_timeout, manager.get_property("ActiveConnections"))
                .await
                .map_err(|_| NetworkBackendError::Timeout)?
                .map_err(unavailable)?;
        if !active.contains(active_path) {
            return Ok(());
        }

        if let Err(_) = timeout(
            self.call_timeout,
            manager.call::<_, _, ()>("DeactivateConnection", &(active_path.clone(),)),
        )
        .await
        .map_err(|_| NetworkBackendError::Timeout)?
        {
            // The call can fail simply because the connection disappeared between
            // our check above and the call itself; re-check before giving up.
            let active: Vec<OwnedObjectPath> =
                timeout(self.call_timeout, manager.get_property("ActiveConnections"))
                    .await
                    .map_err(|_| NetworkBackendError::Timeout)?
                    .map_err(unavailable)?;
            if !active.contains(active_path) {
                return Ok(());
            }
            return Err(NetworkBackendError::DeactivationFailed(
                "NetworkManager rejected deactivation".to_owned(),
            ));
        }

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let active: Vec<OwnedObjectPath> =
                timeout(self.call_timeout, manager.get_property("ActiveConnections"))
                    .await
                    .map_err(|_| NetworkBackendError::Timeout)?
                    .map_err(unavailable)?;
            if !active.contains(active_path) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(NetworkBackendError::DeactivationFailed(
                    "active connection did not disappear".to_owned(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    async fn activate_added_profile(
        &self,
        profile_id: &str,
        settings_path: OwnedObjectPath,
        device_path: OwnedObjectPath,
        activation_timeout: Duration,
    ) -> Result<StationSession, NetworkBackendError> {
        let manager = self.manager_proxy().await?;
        let root = OwnedObjectPath::try_from("/").map_err(unavailable)?;
        let active_path: OwnedObjectPath = timeout(
            self.call_timeout,
            manager.call(
                "ActivateConnection",
                &(settings_path.clone(), device_path.clone(), root),
            ),
        )
        .await
        .map_err(|_| NetworkBackendError::Timeout)?
        .map_err(|_| {
            NetworkBackendError::ActivationFailed("NetworkManager rejected activation".to_owned())
        })?;

        let deadline = Instant::now() + activation_timeout;
        let active = match self
            .interface_proxy(active_path.clone(), NM_ACTIVE_CONNECTION_INTERFACE)
            .await
        {
            Ok(active) => active,
            Err(error) => {
                let _ = self.deactivate_active_path(&active_path).await;
                return Err(error);
            }
        };
        loop {
            let state_res = timeout(self.call_timeout, active.get_property::<u32>("State")).await;
            let state: u32 = match state_res {
                Ok(Ok(s)) => s,
                Ok(Err(_)) => {
                    let failure = self
                        .inspect_activation_failure(&device_path, &active_path)
                        .await;
                    return self.fail_activation(&active_path, failure).await;
                }
                Err(_) => {
                    return self
                        .fail_activation(&active_path, NetworkBackendError::AssociationTimeout)
                        .await;
                }
            };

            if state == 2 {
                let ip_deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    match self.read_active_ipv4(&active).await {
                        Ok((addresses, gateway)) if !addresses.is_empty() => {
                            return Ok(StationSession {
                                settings_path,
                                active_path,
                                profile_id: profile_id.to_owned(),
                                addresses,
                                gateway,
                            });
                        }
                        _ if Instant::now() < ip_deadline => {
                            tokio::time::sleep(Duration::from_millis(250)).await;
                        }
                        Ok(_) => {
                            return self
                                .fail_activation(&active_path, NetworkBackendError::NoIpv4Address)
                                .await;
                        }
                        Err(error) => {
                            return self.fail_activation(&active_path, error).await;
                        }
                    }
                }
            }
            if state >= 4 {
                let failure = self
                    .inspect_activation_failure(&device_path, &active_path)
                    .await;
                return self.fail_activation(&active_path, failure).await;
            }
            if Instant::now() >= deadline {
                let failure = self
                    .inspect_activation_failure(&device_path, &active_path)
                    .await;
                if let NetworkBackendError::ActivationFailed(_) = failure {
                    return self
                        .fail_activation(&active_path, NetworkBackendError::Timeout)
                        .await;
                }
                return self.fail_activation(&active_path, failure).await;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    async fn fail_activation(
        &self,
        active_path: &OwnedObjectPath,
        error: NetworkBackendError,
    ) -> Result<StationSession, NetworkBackendError> {
        let _ = self.deactivate_active_path(active_path).await;
        Err(error)
    }

    async fn inspect_activation_failure(
        &self,
        device_path: &OwnedObjectPath,
        active_path: &OwnedObjectPath,
    ) -> NetworkBackendError {
        if let Ok(device) = self
            .interface_proxy(device_path.clone(), NM_DEVICE_INTERFACE)
            .await
        {
            if let Ok(Ok((dev_state, dev_reason))) = timeout(
                self.call_timeout,
                device.get_property::<(u32, u32)>("StateReason"),
            )
            .await
            {
                if let Some(err) = map_device_state_reason(dev_state, dev_reason) {
                    return err;
                }
                if dev_reason != 0 && dev_reason != 1 {
                    return NetworkBackendError::ActivationFailed(format!(
                        "device entered state {dev_state} with reason {dev_reason}"
                    ));
                }
            }

            if let Ok(Ok(dev_state)) =
                timeout(self.call_timeout, device.get_property::<u32>("State")).await
            {
                if dev_state == 120 {
                    return NetworkBackendError::ActivationFailed(
                        "Wi-Fi device entered failed state during association".to_owned(),
                    );
                }
            }
        }

        if let Ok(active) = self
            .interface_proxy(active_path.clone(), NM_ACTIVE_CONNECTION_INTERFACE)
            .await
        {
            if let Ok(Ok(active_reason)) =
                timeout(self.call_timeout, active.get_property::<u32>("StateReason")).await
            {
                if let Some(err) = map_active_connection_state_reason(active_reason) {
                    return err;
                }
            }
        }

        NetworkBackendError::ActivationFailed("activation failed (connection aborted)".to_owned())
    }

    async fn read_active_ipv4(
        &self,
        active: &Proxy<'_>,
    ) -> Result<(Vec<String>, Option<String>), NetworkBackendError> {
        let ip_path: OwnedObjectPath = timeout(self.call_timeout, active.get_property("Ip4Config"))
            .await
            .map_err(|_| NetworkBackendError::Timeout)?
            .map_err(unavailable)?;
        if ip_path.as_str() == "/" {
            return Err(NetworkBackendError::NoIpv4Address);
        }
        let ip = self
            .interface_proxy(ip_path, "org.freedesktop.NetworkManager.IP4Config")
            .await?;
        let address_data: Vec<HashMap<String, OwnedValue>> =
            timeout(self.call_timeout, ip.get_property("AddressData"))
                .await
                .map_err(|_| NetworkBackendError::Timeout)?
                .map_err(unavailable)?;
        let gateway: String = timeout(self.call_timeout, ip.get_property("Gateway"))
            .await
            .map_err(|_| NetworkBackendError::Timeout)?
            .map_err(unavailable)?;
        let addresses = address_data
            .into_iter()
            .filter_map(|entry| {
                let address: String = entry.get("address")?.try_clone().ok()?.try_into().ok()?;
                let prefix: u32 = entry.get("prefix")?.try_clone().ok()?.try_into().ok()?;
                Some(format!("{address}/{prefix}"))
            })
            .collect();
        Ok((addresses, (!gateway.is_empty()).then_some(gateway)))
    }

    async fn inspect_added_profile(
        &self,
        profile: &StationProfile,
        connection_path: OwnedObjectPath,
    ) -> Result<(bool, bool), NetworkBackendError> {
        let connection = self
            .interface_proxy(connection_path.clone(), NM_SETTINGS_CONNECTION_INTERFACE)
            .await?;
        let (accepted, was_unsaved): (station_profile::NmSettings, bool) =
            timeout(self.call_timeout, async {
                let accepted = connection.call("GetSettings", &()).await?;
                let unsaved = connection.get_property("Unsaved").await?;
                Ok::<_, zbus::Error>((accepted, unsaved))
            })
            .await
            .map_err(|_| NetworkBackendError::Timeout)?
            .map_err(|_| {
                NetworkBackendError::ProfileOperation(
                    "could not verify the added station profile".to_owned(),
                )
            })?;

        let accepted_id = accepted
            .get("connection")
            .and_then(|group| group.get("id"))
            .and_then(|value| value.try_clone().ok())
            .and_then(|value| String::try_from(value).ok());
        if accepted_id.as_deref() != Some(profile.id()) || !was_unsaved {
            return Err(NetworkBackendError::ProfileOperation(
                "NetworkManager did not preserve the expected in-memory profile identity"
                    .to_owned(),
            ));
        }

        // Give NetworkManager policy a brief opportunity to react, then prove the
        // newly added settings object is not referenced by an active connection.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let manager = self.manager_proxy().await?;
        let active_paths: Vec<OwnedObjectPath> =
            timeout(self.call_timeout, manager.get_property("ActiveConnections"))
                .await
                .map_err(|_| NetworkBackendError::Timeout)?
                .map_err(unavailable)?;

        for active_path in active_paths {
            let active = self
                .interface_proxy(active_path, NM_ACTIVE_CONNECTION_INTERFACE)
                .await?;
            let settings_path: OwnedObjectPath =
                timeout(self.call_timeout, active.get_property("Connection"))
                    .await
                    .map_err(|_| NetworkBackendError::Timeout)?
                    .map_err(unavailable)?;
            if settings_path == connection_path {
                return Ok((was_unsaved, true));
            }
        }

        Ok((was_unsaved, false))
    }

    async fn delete_added_profile(
        &self,
        connection_path: OwnedObjectPath,
    ) -> Result<(), NetworkBackendError> {
        let connection = self
            .interface_proxy(connection_path.clone(), NM_SETTINGS_CONNECTION_INTERFACE)
            .await?;
        timeout(
            self.call_timeout,
            connection.call::<_, _, ()>("Delete", &()),
        )
        .await
        .map_err(|_| NetworkBackendError::Timeout)?
        .map_err(|_| {
            NetworkBackendError::ProfileOperation(
                "failed to remove the temporary in-memory profile".to_owned(),
            )
        })?;

        let settings = self
            .interface_proxy(
                OwnedObjectPath::try_from(NM_SETTINGS_PATH).map_err(unavailable)?,
                NM_SETTINGS_INTERFACE,
            )
            .await?;
        let remaining: Vec<OwnedObjectPath> =
            timeout(self.call_timeout, settings.call("ListConnections", &()))
                .await
                .map_err(|_| NetworkBackendError::Timeout)?
                .map_err(unavailable)?;
        if remaining.contains(&connection_path) {
            return Err(NetworkBackendError::ProfileOperation(
                "temporary profile still exists after deletion".to_owned(),
            ));
        }
        Ok(())
    }
}

fn unavailable(error: impl std::fmt::Display) -> NetworkBackendError {
    NetworkBackendError::Unavailable(error.to_string())
}

fn setting_string(group: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    group.get(key)?.try_clone().ok()?.try_into().ok()
}

fn lab_ethernet_profile(profile_id: &str) -> station_profile::NmSettings {
    fn text(value: &str) -> OwnedValue {
        OwnedValue::from(Str::from(value.to_owned()))
    }

    let mut profile = station_profile::NmSettings::new();
    let mut connection = HashMap::new();
    connection.insert("id".to_owned(), text(profile_id));
    connection.insert(
        "uuid".to_owned(),
        text("76fcedd8-20d9-8d61-91d2-927f777999b8"),
    );
    connection.insert("type".to_owned(), text("802-3-ethernet"));
    connection.insert("interface-name".to_owned(), text("wlan1"));
    connection.insert("autoconnect".to_owned(), OwnedValue::from(false));
    profile.insert("connection".to_owned(), connection);
    profile.insert("802-3-ethernet".to_owned(), HashMap::new());

    let mut ipv4 = HashMap::new();
    ipv4.insert("method".to_owned(), text("auto"));
    ipv4.insert("route-metric".to_owned(), OwnedValue::from(600_i64));
    profile.insert("ipv4".to_owned(), ipv4);

    let mut ipv6 = HashMap::new();
    ipv6.insert("method".to_owned(), text("disabled"));
    profile.insert("ipv6".to_owned(), ipv6);
    profile
}

#[async_trait]
impl NetworkBackend for NetworkManagerBackend {
    async fn devices(&self) -> Result<Vec<NetworkDevice>, NetworkBackendError> {
        let proxy = self.manager_proxy().await?;
        let paths: Vec<OwnedObjectPath> = timeout(self.call_timeout, proxy.call("GetDevices", &()))
            .await
            .map_err(|_| NetworkBackendError::Timeout)?
            .map_err(unavailable)?;

        let mut devices = Vec::with_capacity(paths.len());
        for path in paths {
            devices.push(self.device_from_path(&path).await?);
        }
        devices.sort_by(|left, right| left.interface.cmp(&right.interface));
        Ok(devices)
    }

    async fn preflight(
        &self,
        interface: &str,
    ) -> Result<NetworkManagerPreflight, NetworkBackendError> {
        require_nm_uplink(interface)?;
        let (version, state) = self.manager_identity().await?;
        validate_preflight(version, state, self.devices().await?, interface)
    }

    async fn scan(&self, interface: &str) -> Result<Vec<WifiNetwork>, NetworkBackendError> {
        require_nm_uplink(interface)?;
        let report = self.preflight(interface).await?;
        let device_path = OwnedObjectPath::try_from(report.uplink.object_path)
            .map_err(|error| NetworkBackendError::ScanFailed(error.to_string()))?;
        let wireless = self
            .interface_proxy(device_path, NM_WIRELESS_INTERFACE)
            .await?;

        let previous_scan: i64 = timeout(self.call_timeout, wireless.get_property("LastScan"))
            .await
            .map_err(|_| NetworkBackendError::Timeout)?
            .map_err(|error| NetworkBackendError::ScanFailed(error.to_string()))?;

        let options = HashMap::<String, OwnedValue>::new();
        timeout(
            self.call_timeout,
            wireless.call::<_, _, ()>("RequestScan", &options),
        )
        .await
        .map_err(|_| NetworkBackendError::Timeout)?
        .map_err(|error| NetworkBackendError::ScanFailed(error.to_string()))?;

        let deadline = Instant::now() + self.scan_timeout;
        loop {
            let last_scan: i64 = timeout(self.call_timeout, wireless.get_property("LastScan"))
                .await
                .map_err(|_| NetworkBackendError::Timeout)?
                .map_err(|error| NetworkBackendError::ScanFailed(error.to_string()))?;
            if last_scan >= 0 && last_scan != previous_scan {
                break;
            }
            if Instant::now() >= deadline {
                return Err(NetworkBackendError::Timeout);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        let access_points: Vec<OwnedObjectPath> =
            timeout(self.call_timeout, wireless.call("GetAllAccessPoints", &()))
                .await
                .map_err(|_| NetworkBackendError::Timeout)?
                .map_err(|error| NetworkBackendError::ScanFailed(error.to_string()))?;

        let mut raw = Vec::with_capacity(access_points.len());
        for path in access_points {
            raw.push(self.read_access_point(path).await?);
        }
        Ok(map_access_points(raw))
    }
}

#[derive(Debug, Clone)]
struct RawAccessPoint {
    ssid: Vec<u8>,
    bssid: String,
    strength: u8,
    frequency: u32,
    flags: u32,
    wpa_flags: u32,
    rsn_flags: u32,
}

fn map_access_points(access_points: Vec<RawAccessPoint>) -> Vec<WifiNetwork> {
    let mut by_bssid = HashMap::<String, WifiNetwork>::new();
    for access_point in access_points {
        if access_point.ssid.is_empty() || access_point.bssid.trim().is_empty() {
            continue;
        }

        let bssid_key = access_point.bssid.to_ascii_lowercase();
        let network = WifiNetwork {
            ssid: String::from_utf8_lossy(&access_point.ssid).into_owned(),
            bssid: access_point.bssid,
            signal_percent: access_point.strength.min(100),
            signal_dbm: i32::from(access_point.strength.min(100)) / 2 - 100,
            band: frequency_to_band(access_point.frequency).to_owned(),
            security: security_name(
                access_point.flags,
                access_point.wpa_flags,
                access_point.rsn_flags,
            )
            .to_owned(),
        };

        match by_bssid.get(&bssid_key) {
            Some(existing) if existing.signal_percent >= network.signal_percent => {}
            _ => {
                by_bssid.insert(bssid_key, network);
            }
        }
    }

    let mut networks: Vec<_> = by_bssid.into_values().collect();
    networks.sort_by(|left, right| {
        right
            .signal_percent
            .cmp(&left.signal_percent)
            .then_with(|| left.ssid.cmp(&right.ssid))
            .then_with(|| left.bssid.cmp(&right.bssid))
    });
    networks
}

fn frequency_to_band(frequency: u32) -> &'static str {
    match frequency {
        2_400..=2_500 => "2.4GHz",
        4_900..=5_900 => "5GHz",
        5_925..=7_125 => "6GHz",
        _ => "Unknown",
    }
}

fn security_name(flags: u32, wpa_flags: u32, rsn_flags: u32) -> &'static str {
    if rsn_flags & AP_SEC_KEY_MGMT_SAE != 0 {
        "WPA3"
    } else if rsn_flags & AP_SEC_KEY_MGMT_OWE != 0 {
        "OWE"
    } else if rsn_flags & AP_SEC_KEY_MGMT_PSK != 0 || rsn_flags != 0 {
        "WPA2"
    } else if wpa_flags != 0 {
        "WPA"
    } else if flags & AP_FLAG_PRIVACY != 0 {
        "WEP"
    } else {
        "Open"
    }
}

fn is_viable_active_state(state: u32) -> bool {
    matches!(state, 1 | 2)
}

fn validate_preflight(
    version: String,
    state: u32,
    devices: Vec<NetworkDevice>,
    interface: &str,
) -> Result<NetworkManagerPreflight, NetworkBackendError> {
    require_nm_uplink(interface)?;
    let uplink = devices
        .into_iter()
        .find(|device| device.interface == interface)
        .ok_or_else(|| NetworkBackendError::DeviceNotFound(interface.to_owned()))?;

    if !uplink.managed {
        return Err(NetworkBackendError::DeviceUnmanaged(interface.to_owned()));
    }
    if uplink.kind != NetworkDeviceKind::Wifi {
        return Err(NetworkBackendError::DeviceNotWifi(interface.to_owned()));
    }

    Ok(NetworkManagerPreflight {
        version,
        state,
        uplink,
    })
}

pub fn map_device_state_reason(dev_state: u32, dev_reason: u32) -> Option<NetworkBackendError> {
    match dev_reason {
        // NM_DEVICE_STATE_REASON_NO_SECRETS (7), NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT (8),
        // NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED (9),
        // NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED (10).
        7 | 8 | 9 | 10 => Some(NetworkBackendError::AuthenticationFailed(format!(
            "Wi-Fi authentication failed (device state {dev_state}, reason {dev_reason})"
        ))),
        // NM_DEVICE_STATE_REASON_SSID_NOT_FOUND (53)
        53 => Some(NetworkBackendError::SsidNotFound(format!(
            "Wi-Fi network SSID was not found (device state {dev_state}, reason {dev_reason})"
        ))),
        // NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE (5), NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED (6),
        // NM_DEVICE_STATE_REASON_DHCP_START_FAILED (15), NM_DEVICE_STATE_REASON_DHCP_ERROR (16),
        // NM_DEVICE_STATE_REASON_DHCP_FAILED (17)
        5 | 6 | 15 | 16 | 17 => Some(NetworkBackendError::IpConfigFailed(format!(
            "DHCP/IP configuration failed (device state {dev_state}, reason {dev_reason})"
        ))),
        // NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT (11)
        11 => Some(NetworkBackendError::Timeout),
        0 | 1 => None,
        other => Some(NetworkBackendError::ActivationFailed(format!(
            "Device entered state {dev_state} with reason {other}"
        ))),
    }
}

pub fn map_active_connection_state_reason(reason: u32) -> Option<NetworkBackendError> {
    match reason {
        // NM_ACTIVE_CONNECTION_STATE_REASON_NO_SECRETS (9), NM_ACTIVE_CONNECTION_STATE_REASON_LOGIN_FAILED (10)
        9 | 10 => Some(NetworkBackendError::AuthenticationFailed(format!(
            "Active connection authentication failed (reason {reason})"
        ))),
        // NM_ACTIVE_CONNECTION_STATE_REASON_IP_CONFIG_INVALID (5)
        5 => Some(NetworkBackendError::IpConfigFailed(format!(
            "Active connection IP configuration invalid (reason {reason})"
        ))),
        // NM_ACTIVE_CONNECTION_STATE_REASON_CONNECT_TIMEOUT (6), NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT (7)
        6 | 7 => Some(NetworkBackendError::Timeout),
        0 | 1 => None,
        other => Some(NetworkBackendError::ActivationFailed(format!(
            "Active connection failed with reason {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_reason_mappings_distinguish_auth_ssid_and_dhcp_failures() {
        // Auth failures
        for reason in [7, 8, 9, 10] {
            let err = map_device_state_reason(120, reason).unwrap();
            assert_eq!(err.code(), "E_WIFI_AUTH_FAILED");
        }
        // 57 and 58 are modem state reasons, not Wi-Fi password failures.
        assert_eq!(
            map_device_state_reason(120, 57).unwrap().code(),
            "E_WIFI_ACTIVATION_FAILED"
        );
        assert_eq!(
            map_device_state_reason(120, 58).unwrap().code(),
            "E_WIFI_ACTIVATION_FAILED"
        );
        for reason in [9, 10] {
            let err = map_active_connection_state_reason(reason).unwrap();
            assert_eq!(err.code(), "E_WIFI_AUTH_FAILED");
        }

        // SSID not found
        let err = map_device_state_reason(30, 53).unwrap();
        assert_eq!(err.code(), "E_WIFI_SSID_NOT_FOUND");

        // DHCP / IP config failures
        for reason in [5, 6, 15, 16, 17] {
            let err = map_device_state_reason(120, reason).unwrap();
            assert_eq!(err.code(), "E_WIFI_IP_CONFIG_FAILED");
        }
        let err = map_active_connection_state_reason(5).unwrap();
        assert_eq!(err.code(), "E_WIFI_IP_CONFIG_FAILED");

        // Timeout
        let err = map_device_state_reason(120, 11).unwrap();
        assert_eq!(err.code(), "E_NM_TIMEOUT");
        let err = map_active_connection_state_reason(6).unwrap();
        assert_eq!(err.code(), "E_NM_TIMEOUT");

        // Benign / None
        assert!(map_device_state_reason(100, 0).is_none());
        assert!(map_device_state_reason(100, 1).is_none());
        assert!(map_active_connection_state_reason(0).is_none());
        assert!(map_active_connection_state_reason(1).is_none());
    }

    #[test]
    fn active_connection_health_accepts_activating_and_activated_only() {
        assert!(is_viable_active_state(1));
        assert!(is_viable_active_state(2));
        for state in [0, 3, 4, 99] {
            assert!(!is_viable_active_state(state));
        }
    }

    fn device(interface: &str, kind: NetworkDeviceKind, managed: bool) -> NetworkDevice {
        NetworkDevice {
            object_path: format!("/test/{interface}"),
            interface: interface.to_owned(),
            kind,
            state: 30,
            managed,
        }
    }

    #[tokio::test]
    async fn unavailable_system_bus_has_a_stable_error_code() {
        let result = zbus::connection::Builder::address("unix:path=/definitely/not/a/dbus/socket")
            .unwrap()
            .build()
            .await;
        let error = result.unwrap_err();
        let mapped = unavailable(error);
        assert_eq!(mapped.code(), "E_NM_UNAVAILABLE");
    }

    #[test]
    fn preflight_accepts_managed_wlan1_wifi() {
        let result = validate_preflight(
            "1.42.4".to_owned(),
            70,
            vec![device("wlan1", NetworkDeviceKind::Wifi, true)],
            "wlan1",
        )
        .unwrap();

        assert_eq!(result.version, "1.42.4");
        assert_eq!(result.uplink.interface, "wlan1");
    }

    #[test]
    fn preflight_reports_missing_unmanaged_and_non_wifi_devices() {
        let missing = validate_preflight("1.42.4".to_owned(), 70, vec![], "wlan1").unwrap_err();
        assert_eq!(missing.code(), "E_WIFI_DEVICE_NOT_FOUND");

        let unmanaged = validate_preflight(
            "1.42.4".to_owned(),
            70,
            vec![device("wlan1", NetworkDeviceKind::Wifi, false)],
            "wlan1",
        )
        .unwrap_err();
        assert_eq!(unmanaged.code(), "E_WIFI_DEVICE_UNMANAGED");

        let wrong_type = validate_preflight(
            "1.42.4".to_owned(),
            70,
            vec![device("wlan1", NetworkDeviceKind::Ethernet, true)],
            "wlan1",
        )
        .unwrap_err();
        assert_eq!(wrong_type.code(), "E_WIFI_DEVICE_NOT_WIFI");
    }

    #[test]
    fn preflight_rejects_non_station_target_before_device_selection() {
        let error = validate_preflight(
            "1.42.4".to_owned(),
            70,
            vec![device("uap0", NetworkDeviceKind::Wifi, true)],
            "uap0",
        )
        .unwrap_err();
        assert_eq!(error.code(), "E_WIFI_INTERFACE_DENIED");
    }

    fn access_point(
        ssid: &[u8],
        bssid: &str,
        strength: u8,
        frequency: u32,
        flags: u32,
        wpa_flags: u32,
        rsn_flags: u32,
    ) -> RawAccessPoint {
        RawAccessPoint {
            ssid: ssid.to_vec(),
            bssid: bssid.to_owned(),
            strength,
            frequency,
            flags,
            wpa_flags,
            rsn_flags,
        }
    }

    #[test]
    fn access_points_map_to_existing_wifi_network_shape() {
        let networks = map_access_points(vec![
            access_point(b"Cafe", "AA:BB:CC:DD:EE:01", 80, 2412, 0, 0, 0),
            access_point(
                b"Office",
                "AA:BB:CC:DD:EE:02",
                60,
                5180,
                AP_FLAG_PRIVACY,
                0,
                AP_SEC_KEY_MGMT_PSK,
            ),
            access_point(
                b"Secure",
                "AA:BB:CC:DD:EE:03",
                90,
                5955,
                AP_FLAG_PRIVACY,
                0,
                AP_SEC_KEY_MGMT_SAE,
            ),
        ]);

        assert_eq!(networks[0].ssid, "Secure");
        assert_eq!(networks[0].band, "6GHz");
        assert_eq!(networks[0].security, "WPA3");
        assert_eq!(networks[0].signal_percent, 90);
        assert_eq!(networks[1].ssid, "Cafe");
        assert_eq!(networks[1].security, "Open");
        assert_eq!(networks[2].band, "5GHz");
        assert_eq!(networks[2].security, "WPA2");
    }

    #[test]
    fn access_points_skip_hidden_and_deduplicate_bssid_case_insensitively() {
        let networks = map_access_points(vec![
            access_point(b"", "AA:BB:CC:DD:EE:01", 100, 2412, 0, 0, 0),
            access_point(b"Old", "AA:BB:CC:DD:EE:02", 20, 2412, 0, 0, 0),
            access_point(b"New", "aa:bb:cc:dd:ee:02", 80, 2412, 0, 0, 0),
        ]);

        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0].ssid, "New");
    }

    #[test]
    fn legacy_security_and_unknown_frequency_are_explicit() {
        assert_eq!(security_name(AP_FLAG_PRIVACY, 0, 0), "WEP");
        assert_eq!(security_name(AP_FLAG_PRIVACY, 1, 0), "WPA");
        assert_eq!(frequency_to_band(0), "Unknown");
    }

    #[test]
    fn access_point_strength_is_clamped_to_100_percent() {
        let networks = map_access_points(vec![access_point(
            b"Overdriven",
            "AA:BB:CC:DD:EE:04",
            255,
            2412,
            0,
            0,
            0,
        )]);
        assert_eq!(networks[0].signal_percent, 100);
    }
}
