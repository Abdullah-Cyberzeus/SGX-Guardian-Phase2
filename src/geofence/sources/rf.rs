use crate::geofence::errors::{GeofenceError, GeofenceResult};
use crate::geofence::model::{ApObservation, Fix, RfSignature};
use crate::geofence::sources::LocationSource;
use async_trait::async_trait;
use once_cell::sync::Lazy;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::process::Command;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::sleep;
use tokio::time::timeout;

const RF_INTERFACE_ENV: &str = "SGX_GEOFENCE_RF_INTERFACE";
const SCAN_TIMEOUT: Duration = Duration::from_secs(12);
const ENUMERATE_TIMEOUT: Duration = Duration::from_secs(3);
const LINK_TIMEOUT: Duration = Duration::from_secs(3);
const SCAN_MAX_ATTEMPTS: usize = 3;
const RETRY_BACKOFFS: [Duration; 2] = [Duration::from_millis(100), Duration::from_millis(250)];

static RF_SCAN_LOCK: Lazy<Arc<AsyncMutex<()>>> = Lazy::new(|| Arc::new(AsyncMutex::new(())));

pub fn shared_scan_lock() -> Arc<AsyncMutex<()>> {
    Arc::clone(&RF_SCAN_LOCK)
}

pub struct RfSource;

#[async_trait]
impl LocationSource for RfSource {
    fn id(&self) -> &'static str {
        "rf"
    }

    async fn current(&self) -> Option<Fix> {
        match scan().await {
            Ok(aps) => Some(Fix::RfSignature { aps }),
            Err(error) => {
                tracing::warn!(
                    "rf source unavailable during geofence evaluation: {}",
                    error
                );
                None
            }
        }
    }
}

pub async fn capture_signature() -> GeofenceResult<RfSignature> {
    let aps = scan().await?;
    Ok(RfSignature {
        aps,
        threshold: crate::geofence::model::default_rf_threshold(),
    })
}

async fn scan() -> GeofenceResult<Vec<ApObservation>> {
    scan_with(&SystemRfBackend).await
}

async fn scan_with(backend: &dyn RfBackend) -> GeofenceResult<Vec<ApObservation>> {
    let override_iface = std::env::var(RF_INTERFACE_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    tracing::debug!(?override_iface, "rf interface override configuration");

    let discovered = backend.discover_interfaces().await?;
    let default_route_iface = backend.default_route_interface().await?;
    tracing::debug!(
        ?default_route_iface,
        "rf default-route management interface"
    );

    let ssh_client_ip = ssh_client_ip_from_env();
    let ssh_iface = match ssh_client_ip.as_deref() {
        Some(client_ip) => backend.route_interface_for_ip(client_ip).await?,
        None => None,
    };
    tracing::debug!(?ssh_iface, "rf ssh management interface");

    let management_ifaces = management_interfaces(default_route_iface, ssh_iface);

    let candidates = select_candidates(&discovered, override_iface.as_deref(), &management_ifaces);
    tracing::debug!(
        candidates = ?candidates.iter().map(|candidate| &candidate.name).collect::<Vec<_>>(),
        "rf discovered scan candidates"
    );

    if candidates.is_empty() {
        let attempted = override_iface.into_iter().collect::<Vec<_>>();
        return Err(rf_unavailable(
            attempted,
            "no valid RF scan interfaces discovered",
        ));
    }

    let mut attempted = Vec::new();
    for candidate in candidates {
        attempted.push(candidate.name.clone());
        if candidate.is_down && !is_management_interface(&candidate.name, &management_ifaces) {
            tracing::debug!(interface = %candidate.name, "bringing spare rf interface up before scan");
            if let Err(error) = backend.bring_up(&candidate.name).await {
                tracing::warn!(
                    interface = %candidate.name,
                    error = %error,
                    "failed to bring rf interface up before scan"
                );
            }
        }

        match scan_candidate_with_retries(backend, &candidate.name).await {
            Ok(aps) if !aps.is_empty() => {
                tracing::debug!(
                    interface = %candidate.name,
                    ap_count = aps.len(),
                    "selected rf scan interface"
                );
                return Ok(aps);
            }
            Ok(_) => {
                tracing::debug!(interface = %candidate.name, "rf scan returned no AP observations");
            }
            Err(error) => {
                tracing::debug!(interface = %candidate.name, error = %error, "rf scan failure");
            }
        }
    }

    Err(rf_unavailable(
        attempted,
        "all RF scan interfaces failed or returned no AP observations",
    ))
}

async fn scan_candidate_with_retries(
    backend: &dyn RfBackend,
    iface: &str,
) -> GeofenceResult<Vec<ApObservation>> {
    let mut last_error: Option<GeofenceError> = None;
    for attempt in 1..=SCAN_MAX_ATTEMPTS {
        match locked_scan_once(backend, iface, attempt).await {
            Ok(aps) => return Ok(aps),
            Err(error) if is_retryable_scan_error(&error) && attempt < SCAN_MAX_ATTEMPTS => {
                let backoff = RETRY_BACKOFFS
                    .get(attempt - 1)
                    .copied()
                    .unwrap_or_else(|| Duration::from_millis(250));
                tracing::debug!(
                    interface = %iface,
                    attempt,
                    max_attempts = SCAN_MAX_ATTEMPTS,
                    backoff_ms = backoff.as_millis(),
                    error = %error,
                    "rf scan retry scheduled"
                );
                last_error = Some(error);
                sleep(backoff).await;
            }
            Err(error) => return Err(classify_scan_error(error)),
        }
    }

    Err(classify_scan_error(last_error.unwrap_or_else(|| {
        rf_unavailable(vec![iface.to_string()], "rf scan failed without an error")
    })))
}

async fn locked_scan_once(
    backend: &dyn RfBackend,
    iface: &str,
    attempt: usize,
) -> GeofenceResult<Vec<ApObservation>> {
    let lock = shared_scan_lock();
    let wait_start = Instant::now();
    tracing::trace!(
        interface = %iface,
        attempt,
        "rf scan waiting for shared lock"
    );
    let _guard = lock.lock().await;
    let waited = wait_start.elapsed();
    tracing::trace!(
        interface = %iface,
        attempt,
        wait_ms = waited.as_millis(),
        "rf scan lock acquired"
    );

    tracing::debug!(interface = %iface, attempt, "rf scan start");
    let scan_start = Instant::now();
    let result = backend.scan(iface).await;
    match &result {
        Ok(aps) => tracing::debug!(
            interface = %iface,
            attempt,
            ap_count = aps.len(),
            elapsed_ms = scan_start.elapsed().as_millis(),
            "rf scan success"
        ),
        Err(error) => tracing::debug!(
            interface = %iface,
            attempt,
            elapsed_ms = scan_start.elapsed().as_millis(),
            error = %error,
            "rf scan failure"
        ),
    }
    result
}

fn classify_scan_error(error: GeofenceError) -> GeofenceError {
    if is_busy_error(&error) {
        GeofenceError::RfScanBusy(error.to_string())
    } else {
        error
    }
}

fn is_retryable_scan_error(error: &GeofenceError) -> bool {
    is_busy_error(error) || is_timeout_error(error)
}

fn is_busy_error(error: &GeofenceError) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("device or resource busy") || message.contains("resource busy")
}

fn is_timeout_error(error: &GeofenceError) -> bool {
    error.to_string().to_ascii_lowercase().contains("timed out")
}

fn rf_unavailable(attempted: Vec<String>, reason: &str) -> GeofenceError {
    GeofenceError::RfUnavailable(format!(
        "{}; attempted interfaces: {}",
        reason,
        if attempted.is_empty() {
            "<none>".to_string()
        } else {
            attempted.join(", ")
        }
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WirelessInterface {
    name: String,
    iw_type: String,
    is_down: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CandidateInterface {
    name: String,
    is_down: bool,
}

trait RfBackend: Sync {
    fn discover_interfaces<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = GeofenceResult<Vec<WirelessInterface>>> + Send + 'a>>;

    fn default_route_interface<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = GeofenceResult<Option<String>>> + Send + 'a>>;

    fn route_interface_for_ip<'a>(
        &'a self,
        ip: &'a str,
    ) -> Pin<Box<dyn Future<Output = GeofenceResult<Option<String>>> + Send + 'a>>;

    fn bring_up<'a>(
        &'a self,
        iface: &'a str,
    ) -> Pin<Box<dyn Future<Output = GeofenceResult<()>> + Send + 'a>>;

    fn scan<'a>(
        &'a self,
        iface: &'a str,
    ) -> Pin<Box<dyn Future<Output = GeofenceResult<Vec<ApObservation>>> + Send + 'a>>;
}

struct SystemRfBackend;

impl RfBackend for SystemRfBackend {
    fn discover_interfaces<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = GeofenceResult<Vec<WirelessInterface>>> + Send + 'a>> {
        Box::pin(async move {
            let output = run_command("iw", &["dev"], ENUMERATE_TIMEOUT).await?;
            let mut interfaces = parse_iw_dev(&output);
            for interface in &mut interfaces {
                interface.is_down = interface_is_down(&interface.name).await.unwrap_or(false);
            }
            Ok(interfaces)
        })
    }

    fn default_route_interface<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = GeofenceResult<Option<String>>> + Send + 'a>> {
        Box::pin(async move {
            let output =
                run_command("ip", &["route", "show", "default"], ENUMERATE_TIMEOUT).await?;
            Ok(parse_default_route_interface(&output))
        })
    }

    fn route_interface_for_ip<'a>(
        &'a self,
        ip: &'a str,
    ) -> Pin<Box<dyn Future<Output = GeofenceResult<Option<String>>> + Send + 'a>> {
        Box::pin(async move {
            let output = run_command("ip", &["route", "get", ip], ENUMERATE_TIMEOUT).await?;
            Ok(parse_default_route_interface(&output))
        })
    }

    fn bring_up<'a>(
        &'a self,
        iface: &'a str,
    ) -> Pin<Box<dyn Future<Output = GeofenceResult<()>> + Send + 'a>> {
        Box::pin(async move {
            run_command("ip", &["link", "set", iface, "up"], LINK_TIMEOUT).await?;
            Ok(())
        })
    }

    fn scan<'a>(
        &'a self,
        iface: &'a str,
    ) -> Pin<Box<dyn Future<Output = GeofenceResult<Vec<ApObservation>>> + Send + 'a>> {
        Box::pin(async move {
            let output = run_command("iw", &["dev", iface, "scan"], SCAN_TIMEOUT).await?;
            Ok(parse_iw_scan(&output))
        })
    }
}

async fn run_command(command: &str, args: &[&str], duration: Duration) -> GeofenceResult<String> {
    let output = timeout(duration, Command::new(command).args(args).output())
        .await
        .map_err(|_| {
            GeofenceError::RfUnavailable(format!(
                "{} {} timed out after {:?}",
                command,
                args.join(" "),
                duration
            ))
        })??;

    if !output.status.success() {
        return Err(GeofenceError::RfUnavailable(format!(
            "{} {} failed: {}",
            command,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

async fn interface_is_down(iface: &str) -> GeofenceResult<bool> {
    let output = run_command("ip", &["link", "show", "dev", iface], LINK_TIMEOUT).await?;
    Ok(output.contains("state DOWN") || !output.contains("<UP"))
}

fn ssh_client_ip_from_env() -> Option<String> {
    let value = std::env::var("SSH_CONNECTION").ok()?;
    value
        .split_whitespace()
        .next()
        .filter(|ip| ip.parse::<std::net::IpAddr>().is_ok())
        .map(str::to_string)
}

fn management_interfaces(
    default_route_iface: Option<String>,
    ssh_iface: Option<String>,
) -> Vec<String> {
    let mut interfaces = Vec::new();
    for iface in [default_route_iface, ssh_iface].into_iter().flatten() {
        if !interfaces.contains(&iface) {
            interfaces.push(iface);
        }
    }
    interfaces
}

fn is_management_interface(iface: &str, management_ifaces: &[String]) -> bool {
    management_ifaces
        .iter()
        .any(|management_iface| management_iface == iface)
}

fn select_candidates(
    interfaces: &[WirelessInterface],
    override_iface: Option<&str>,
    management_ifaces: &[String],
) -> Vec<CandidateInterface> {
    if let Some(override_iface) = override_iface {
        tracing::debug!(interface = %override_iface, "using configured rf interface override");
        return vec![CandidateInterface {
            name: override_iface.to_string(),
            is_down: interfaces
                .iter()
                .find(|interface| interface.name == override_iface)
                .map(|interface| interface.is_down)
                .unwrap_or(false),
        }];
    }

    let mut candidates = Vec::new();
    for interface in interfaces {
        if let Some(reason) = rejection_reason(interface) {
            tracing::debug!(
                interface = %interface.name,
                iw_type = %interface.iw_type,
                reason,
                "rejected rf interface"
            );
            continue;
        }
        candidates.push(CandidateInterface {
            name: interface.name.clone(),
            is_down: interface.is_down,
        });
    }

    candidates.sort_by_key(|candidate| candidate_priority(candidate, management_ifaces));
    candidates
}

fn candidate_priority(
    candidate: &CandidateInterface,
    management_ifaces: &[String],
) -> (u8, u8, String) {
    (
        u8::from(is_management_interface(&candidate.name, management_ifaces)),
        u8::from(!candidate.name.starts_with("wlan")),
        candidate.name.clone(),
    )
}

fn rejection_reason(interface: &WirelessInterface) -> Option<&'static str> {
    let name = interface.name.as_str();
    if name.starts_with("wfd") {
        return Some("Wi-Fi Direct interface");
    }
    if name.starts_with("uap") {
        return Some("AP/uAP interface");
    }
    if name.starts_with("p2p") {
        return Some("P2P interface");
    }
    if interface.iw_type.eq_ignore_ascii_case("ap") {
        return Some("iw type AP");
    }
    if !interface.iw_type.eq_ignore_ascii_case("managed") {
        return Some("iw type is not managed");
    }
    None
}

fn parse_iw_dev(output: &str) -> Vec<WirelessInterface> {
    let mut interfaces = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_type: Option<String> = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("Interface ") {
            if let (Some(name), Some(iw_type)) = (current_name.take(), current_type.take()) {
                interfaces.push(WirelessInterface {
                    name,
                    iw_type,
                    is_down: false,
                });
            }
            current_name = Some(name.to_string());
            current_type = None;
        } else if let Some(iw_type) = trimmed.strip_prefix("type ") {
            current_type = Some(iw_type.to_string());
        }
    }

    if let (Some(name), Some(iw_type)) = (current_name, current_type) {
        interfaces.push(WirelessInterface {
            name,
            iw_type,
            is_down: false,
        });
    }

    interfaces
}

fn parse_default_route_interface(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        while let Some(word) = words.next() {
            if word == "dev" {
                return words.next().map(str::to_string);
            }
        }
        None
    })
}

fn parse_iw_scan(output: &str) -> Vec<ApObservation> {
    fn is_valid_bssid(value: &str) -> bool {
        let mut octets = value.split(':');
        (0..6).all(|_| {
            octets.next().is_some_and(|octet| {
                octet.len() == 2 && octet.chars().all(|ch| ch.is_ascii_hexdigit())
            })
        }) && octets.next().is_none()
    }

    let mut observations = Vec::new();
    let mut current_bssid: Option<String> = None;
    let mut current_signal: Option<i32> = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("BSS ") {
            let Some(bssid) = rest
                .split_whitespace()
                .next()
                .map(|bssid| bssid.trim_end_matches("(on"))
                .filter(|bssid| is_valid_bssid(bssid))
            else {
                continue;
            };
            push_observation(
                &mut observations,
                current_bssid.take(),
                current_signal.take(),
            );
            current_bssid = Some(bssid.to_string());
            current_signal = None;
        } else if let Some(rest) = trimmed.strip_prefix("signal:") {
            current_signal = parse_signal_dbm(rest);
        }
    }

    push_observation(&mut observations, current_bssid, current_signal);
    observations
}

fn push_observation(
    observations: &mut Vec<ApObservation>,
    bssid: Option<String>,
    signal_dbm: Option<i32>,
) {
    if let Some(bssid) = bssid.filter(|bssid| !bssid.is_empty()) {
        observations.push(ApObservation { bssid, signal_dbm });
    }
}

fn parse_signal_dbm(value: &str) -> Option<i32> {
    value
        .split_whitespace()
        .next()
        .and_then(|raw| raw.parse::<f64>().ok())
        .map(|signal| signal.round() as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::time::{sleep, Duration};

    type ScanResultQueue = Arc<Mutex<VecDeque<GeofenceResult<Vec<ApObservation>>>>>;

    #[derive(Default)]
    struct MockRfBackend {
        interfaces: Vec<WirelessInterface>,
        management_iface: Option<String>,
        ssh_iface: Option<String>,
        scans: HashMap<String, GeofenceResult<Vec<ApObservation>>>,
        scan_sequences: HashMap<String, ScanResultQueue>,
        scan_delay: Duration,
        calls: Arc<Mutex<Vec<String>>>,
        brought_up: Arc<Mutex<Vec<String>>>,
        active_scans: Arc<AtomicUsize>,
        max_concurrent_scans: Arc<AtomicUsize>,
    }

    impl MockRfBackend {
        fn with_interfaces(interfaces: Vec<WirelessInterface>) -> Self {
            Self {
                interfaces,
                ..Self::default()
            }
        }

        fn scan_result(mut self, iface: &str, result: GeofenceResult<Vec<ApObservation>>) -> Self {
            self.scans.insert(iface.to_string(), result);
            self
        }

        fn scan_sequence(
            mut self,
            iface: &str,
            results: Vec<GeofenceResult<Vec<ApObservation>>>,
        ) -> Self {
            self.scan_sequences.insert(
                iface.to_string(),
                Arc::new(Mutex::new(results.into_iter().collect())),
            );
            self
        }

        fn management(mut self, iface: &str) -> Self {
            self.management_iface = Some(iface.to_string());
            self
        }

        fn ssh_interface(mut self, iface: &str) -> Self {
            self.ssh_iface = Some(iface.to_string());
            self
        }

        fn scan_delay(mut self, delay: Duration) -> Self {
            self.scan_delay = delay;
            self
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().expect("calls lock poisoned").clone()
        }

        fn brought_up(&self) -> Vec<String> {
            self.brought_up
                .lock()
                .expect("brought_up lock poisoned")
                .clone()
        }

        fn max_concurrent_scans(&self) -> usize {
            self.max_concurrent_scans.load(Ordering::SeqCst)
        }
    }

    impl RfBackend for MockRfBackend {
        fn discover_interfaces<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = GeofenceResult<Vec<WirelessInterface>>> + Send + 'a>>
        {
            Box::pin(async move { Ok(self.interfaces.clone()) })
        }

        fn default_route_interface<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = GeofenceResult<Option<String>>> + Send + 'a>> {
            Box::pin(async move { Ok(self.management_iface.clone()) })
        }

        fn route_interface_for_ip<'a>(
            &'a self,
            _ip: &'a str,
        ) -> Pin<Box<dyn Future<Output = GeofenceResult<Option<String>>> + Send + 'a>> {
            Box::pin(async move { Ok(self.ssh_iface.clone()) })
        }

        fn bring_up<'a>(
            &'a self,
            iface: &'a str,
        ) -> Pin<Box<dyn Future<Output = GeofenceResult<()>> + Send + 'a>> {
            Box::pin(async move {
                self.brought_up
                    .lock()
                    .expect("brought_up lock poisoned")
                    .push(iface.to_string());
                Ok(())
            })
        }

        fn scan<'a>(
            &'a self,
            iface: &'a str,
        ) -> Pin<Box<dyn Future<Output = GeofenceResult<Vec<ApObservation>>> + Send + 'a>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .expect("calls lock poisoned")
                    .push(iface.to_string());
                let active = self.active_scans.fetch_add(1, Ordering::SeqCst) + 1;
                let mut max_seen = self.max_concurrent_scans.load(Ordering::SeqCst);
                while active > max_seen {
                    match self.max_concurrent_scans.compare_exchange(
                        max_seen,
                        active,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(_) => break,
                        Err(current) => max_seen = current,
                    }
                }
                if !self.scan_delay.is_zero() {
                    sleep(self.scan_delay).await;
                }
                self.active_scans.fetch_sub(1, Ordering::SeqCst);
                if let Some(sequence) = self.scan_sequences.get(iface) {
                    let mut results = sequence.lock().expect("scan sequence lock poisoned");
                    if let Some(result) = results.pop_front() {
                        return result.map_err(|error| rf_error(&error.to_string()));
                    }
                }
                match self.scans.get(iface) {
                    Some(Ok(aps)) => Ok(aps.clone()),
                    Some(Err(error)) => Err(rf_error(&error.to_string())),
                    None => Ok(Vec::new()),
                }
            })
        }
    }

    fn iface(name: &str, iw_type: &str) -> WirelessInterface {
        WirelessInterface {
            name: name.to_string(),
            iw_type: iw_type.to_string(),
            is_down: false,
        }
    }

    fn ap(bssid: &str) -> ApObservation {
        ApObservation {
            bssid: bssid.to_string(),
            signal_dbm: Some(-55),
        }
    }

    fn rf_error(message: &str) -> GeofenceError {
        GeofenceError::RfUnavailable(message.to_string())
    }

    struct EnvGuard {
        original: Vec<(&'static str, Option<String>)>,
        _lock: crate::test_support::EnvLockGuard,
    }

    impl EnvGuard {
        fn set_many(set: &[(&'static str, &str)], remove: &[&'static str]) -> Self {
            let lock = crate::test_support::env_lock();
            let mut keys = Vec::new();
            for (key, _) in set {
                if !keys.contains(key) {
                    keys.push(*key);
                }
            }
            for key in remove {
                if !keys.contains(key) {
                    keys.push(*key);
                }
            }

            let original = keys
                .into_iter()
                .map(|key| (key, std::env::var(key).ok()))
                .collect::<Vec<_>>();
            for (key, value) in set {
                std::env::set_var(key, value);
            }
            for key in remove {
                if !set.iter().any(|(set_key, _)| set_key == key) {
                    std::env::remove_var(key);
                }
            }
            Self {
                original,
                _lock: lock,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.original {
                if let Some(value) = value {
                    std::env::set_var(key, value);
                } else {
                    std::env::remove_var(key);
                }
            }
        }
    }

    #[test]
    fn wfd_before_wlan_selects_wlan() {
        let candidates = select_candidates(
            &[iface("wfd0", "managed"), iface("wlan1", "managed")],
            None,
            &[],
        );

        assert_eq!(candidates[0].name, "wlan1");
    }

    #[tokio::test]
    async fn wlan_management_deprioritized_when_spare_exists() {
        let _env = EnvGuard::set_many(&[], &[RF_INTERFACE_ENV, "SSH_CONNECTION"]);
        let backend = MockRfBackend::with_interfaces(vec![
            iface("wlan0", "managed"),
            iface("wlan1", "managed"),
        ])
        .management("wlan0")
        .scan_result("wlan0", Ok(vec![ap("aa:bb:cc:dd:ee:ff")]))
        .scan_result("wlan1", Ok(vec![ap("00:11:22:33:44:55")]));

        let aps = scan_with(&backend).await.expect("scan should succeed");

        assert_eq!(aps, vec![ap("00:11:22:33:44:55")]);
        assert_eq!(backend.calls(), vec!["wlan1"]);
    }

    #[tokio::test]
    async fn ssh_interface_deprioritized_even_when_default_route_is_elsewhere() {
        let _env = EnvGuard::set_many(
            &[("SSH_CONNECTION", "10.0.0.25 42318 10.0.0.10 22")],
            &[RF_INTERFACE_ENV],
        );
        let backend = MockRfBackend::with_interfaces(vec![
            iface("wlan0", "managed"),
            iface("wlan1", "managed"),
        ])
        .management("eth0")
        .ssh_interface("wlan0")
        .scan_result("wlan0", Ok(vec![ap("aa:bb:cc:dd:ee:ff")]))
        .scan_result("wlan1", Ok(vec![ap("00:11:22:33:44:55")]));

        let aps = scan_with(&backend).await.expect("scan should succeed");

        assert_eq!(aps, vec![ap("00:11:22:33:44:55")]);
        assert_eq!(backend.calls(), vec!["wlan1"]);
    }

    #[tokio::test]
    async fn no_ssh_connection_keeps_default_route_behavior() {
        let _env = EnvGuard::set_many(&[], &[RF_INTERFACE_ENV, "SSH_CONNECTION"]);
        let backend = MockRfBackend::with_interfaces(vec![
            iface("wlan0", "managed"),
            iface("wlan1", "managed"),
        ])
        .management("wlan0")
        .ssh_interface("wlan1")
        .scan_result("wlan0", Ok(vec![ap("aa:bb:cc:dd:ee:ff")]))
        .scan_result("wlan1", Ok(vec![ap("00:11:22:33:44:55")]));

        let aps = scan_with(&backend).await.expect("scan should succeed");

        assert_eq!(aps, vec![ap("00:11:22:33:44:55")]);
        assert_eq!(backend.calls(), vec!["wlan1"]);
    }

    #[tokio::test]
    async fn only_ssh_interface_available_is_final_fallback() {
        let _env = EnvGuard::set_many(
            &[("SSH_CONNECTION", "10.0.0.25 42318 10.0.0.10 22")],
            &[RF_INTERFACE_ENV],
        );
        let mut ssh = iface("wlan0", "managed");
        ssh.is_down = true;
        let backend = MockRfBackend::with_interfaces(vec![ssh])
            .management("eth0")
            .ssh_interface("wlan0")
            .scan_result("wlan0", Ok(vec![ap("aa:bb:cc:dd:ee:ff")]));

        let aps = scan_with(&backend).await.expect("scan should succeed");

        assert_eq!(aps, vec![ap("aa:bb:cc:dd:ee:ff")]);
        assert_eq!(backend.calls(), vec!["wlan0"]);
        assert!(backend.brought_up().is_empty());
    }

    #[tokio::test]
    async fn first_candidate_scan_fails_next_candidate_used() {
        let _env = EnvGuard::set_many(&[], &[RF_INTERFACE_ENV, "SSH_CONNECTION"]);
        let backend = MockRfBackend::with_interfaces(vec![
            iface("wlan1", "managed"),
            iface("wlan2", "managed"),
        ])
        .scan_result("wlan1", Err(rf_error("scan failed")))
        .scan_result("wlan2", Ok(vec![ap("00:11:22:33:44:55")]));

        let aps = scan_with(&backend).await.expect("scan should succeed");

        assert_eq!(aps, vec![ap("00:11:22:33:44:55")]);
        assert_eq!(backend.calls(), vec!["wlan1", "wlan2"]);
    }

    #[tokio::test]
    async fn concurrent_rf_scans_are_serialized_by_shared_lock() {
        let _env = EnvGuard::set_many(&[], &[RF_INTERFACE_ENV, "SSH_CONNECTION"]);
        let backend = Arc::new(
            MockRfBackend::with_interfaces(vec![iface("wlan1", "managed")])
                .scan_delay(Duration::from_millis(25))
                .scan_result("wlan1", Ok(vec![ap("00:11:22:33:44:55")])),
        );

        let mut tasks = Vec::new();
        for _ in 0..10 {
            let backend = Arc::clone(&backend);
            tasks.push(tokio::spawn(
                async move { scan_with(backend.as_ref()).await },
            ));
        }

        for task in tasks {
            let aps = task
                .await
                .expect("scan task should complete")
                .expect("scan");
            assert_eq!(aps, vec![ap("00:11:22:33:44:55")]);
        }

        assert_eq!(backend.calls().len(), 10);
        assert_eq!(backend.max_concurrent_scans(), 1);
    }

    #[tokio::test]
    async fn busy_scan_retries_and_recovers() {
        let _env = EnvGuard::set_many(&[], &[RF_INTERFACE_ENV, "SSH_CONNECTION"]);
        let backend = MockRfBackend::with_interfaces(vec![iface("wlan1", "managed")])
            .scan_sequence(
                "wlan1",
                vec![
                    Err(rf_error("Device or resource busy (-16)")),
                    Ok(vec![ap("00:11:22:33:44:55")]),
                ],
            );

        let aps = scan_with(&backend).await.expect("scan should recover");

        assert_eq!(aps, vec![ap("00:11:22:33:44:55")]);
        assert_eq!(backend.calls(), vec!["wlan1", "wlan1"]);
    }

    #[tokio::test]
    async fn explicit_environment_override_is_used() {
        let _env = EnvGuard::set_many(&[(RF_INTERFACE_ENV, "wlan9")], &["SSH_CONNECTION"]);
        let backend = MockRfBackend::with_interfaces(vec![iface("wlan1", "managed")])
            .scan_result("wlan9", Ok(vec![ap("66:77:88:99:aa:bb")]));

        let aps = scan_with(&backend)
            .await
            .expect("override scan should succeed");

        assert_eq!(aps, vec![ap("66:77:88:99:aa:bb")]);
        assert_eq!(backend.calls(), vec!["wlan9"]);
    }

    #[tokio::test]
    async fn all_candidates_fail_returns_clear_error() {
        let _env = EnvGuard::set_many(&[], &[RF_INTERFACE_ENV, "SSH_CONNECTION"]);
        let backend = MockRfBackend::with_interfaces(vec![
            iface("wlan1", "managed"),
            iface("wlan2", "managed"),
        ])
        .scan_result("wlan1", Err(rf_error("scan failed")))
        .scan_result("wlan2", Ok(Vec::new()));

        let error = scan_with(&backend).await.expect_err("scan should fail");
        let message = error.to_string();

        assert!(message.contains("rf source unavailable"));
        assert!(message.contains("all RF scan interfaces failed"));
        assert!(message.contains("wlan1, wlan2"));
    }

    #[tokio::test]
    async fn scan_remains_async_and_does_not_block_evaluation_loop() {
        let _env = EnvGuard::set_many(&[], &[RF_INTERFACE_ENV, "SSH_CONNECTION"]);
        let backend = MockRfBackend::with_interfaces(vec![iface("wlan1", "managed")])
            .scan_delay(Duration::from_millis(50))
            .scan_result("wlan1", Ok(vec![ap("00:11:22:33:44:55")]));

        let ticking = tokio::spawn(async {
            let mut count = 0;
            for _ in 0..3 {
                sleep(Duration::from_millis(10)).await;
                count += 1;
            }
            count
        });

        let aps = scan_with(&backend).await.expect("scan should succeed");
        let ticks = ticking.await.expect("ticker should finish");

        assert_eq!(aps.len(), 1);
        assert_eq!(ticks, 3);
    }

    #[test]
    fn parses_iw_scan_bssids_and_signals() {
        let aps = parse_iw_scan(
            r#"
BSS aa:bb:cc:dd:ee:ff(on wlan1)
	signal: -44.00 dBm
BSS 11:22:33:44:55:66(on wlan1)
	signal: -72.50 dBm
"#,
        );

        assert_eq!(
            aps,
            vec![
                ApObservation {
                    bssid: "aa:bb:cc:dd:ee:ff".to_string(),
                    signal_dbm: Some(-44),
                },
                ApObservation {
                    bssid: "11:22:33:44:55:66".to_string(),
                    signal_dbm: Some(-73),
                },
            ]
        );
    }

    #[test]
    fn ignores_bss_load_lines_in_iw_scan() {
        let aps = parse_iw_scan(
            r#"
BSS aa:bb:cc:dd:ee:ff(on wlan1)
	signal: -44.00 dBm
	BSS Load:
		station count: 4
BSS Load:
	station count: 1
BSS 11:22:33:44:55:66(on wlan1)
	signal: -72.50 dBm
"#,
        );

        assert_eq!(
            aps,
            vec![
                ApObservation {
                    bssid: "aa:bb:cc:dd:ee:ff".to_string(),
                    signal_dbm: Some(-44),
                },
                ApObservation {
                    bssid: "11:22:33:44:55:66".to_string(),
                    signal_dbm: Some(-73),
                },
            ]
        );
        assert!(!aps.iter().any(|ap| ap.bssid == "Load:"));
    }

    #[test]
    fn parses_iw_dev_interfaces() {
        let interfaces = parse_iw_dev(
            r#"
phy#0
	Interface wfd0
		type managed
	Interface wlan1
		type managed
	Interface uap0
		type AP
"#,
        );

        assert_eq!(
            interfaces
                .iter()
                .map(|interface| (interface.name.as_str(), interface.iw_type.as_str()))
                .collect::<Vec<_>>(),
            vec![("wfd0", "managed"), ("wlan1", "managed"), ("uap0", "AP")]
        );
    }

    #[test]
    fn parses_default_route_interface() {
        assert_eq!(
            parse_default_route_interface("default via 192.168.1.1 dev wlan0 proto dhcp"),
            Some("wlan0".to_string())
        );
    }
}
