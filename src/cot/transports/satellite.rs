use crate::cot::transport_trait::{Transport, TransportHealth, TransportMessage};
use crate::cot::types::{CotError, CotResult, InterfaceInfo, TransportPriority, TransportType};
use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SatelliteKind {
    Starlink,
    Iridium,
    Inmarsat,
    Generic,
}

impl SatelliteKind {
    fn from_interface_name(name: &str) -> Self {
        let lower = name.to_lowercase();
        if lower.starts_with("ppp") {
            return Self::Iridium;
        }
        if lower.starts_with("usb") {
            return Self::Inmarsat;
        }
        if lower.starts_with("eth") || lower.starts_with("en") {
            return Self::Starlink;
        }
        if lower.starts_with("sat") {
            return Self::Generic;
        }
        Self::Generic
    }

    fn from_env() -> Option<Self> {
        let kind = std::env::var("SGX_SAT_KIND").ok()?;
        match kind.to_lowercase().as_str() {
            "starlink" => Some(Self::Starlink),
            "iridium" => Some(Self::Iridium),
            "inmarsat" => Some(Self::Inmarsat),
            "generic" => Some(Self::Generic),
            _ => None,
        }
    }

    fn baseline(self) -> (u64, u64) {
        match self {
            Self::Starlink => (50, 100_000),
            Self::Iridium => (1500, 88),
            Self::Inmarsat => (700, 512),
            Self::Generic => (900, 256),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Starlink => "Starlink",
            Self::Iridium => "Iridium",
            Self::Inmarsat => "Inmarsat",
            Self::Generic => "Generic",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SatelliteTransport {
    interface: InterfaceInfo,
    kind: SatelliteKind,
}

impl SatelliteTransport {
    pub fn new(interface: InterfaceInfo) -> Self {
        let kind = SatelliteKind::from_env()
            .unwrap_or_else(|| SatelliteKind::from_interface_name(&interface.name));
        Self { interface, kind }
    }

    async fn latency_probe_ms(&self) -> Option<u64> {
        let gateway =
            std::env::var("SGX_SAT_GATEWAY_ADDR").unwrap_or_else(|_| "1.1.1.1:443".into());
        let timeout = Duration::from_secs(3);
        let start = Instant::now();
        let connected = tokio::time::timeout(timeout, TcpStream::connect(gateway))
            .await
            .ok()?
            .ok()?;
        drop(connected);
        Some(start.elapsed().as_millis().max(1) as u64)
    }
}

#[async_trait]
impl Transport for SatelliteTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Satellite
    }

    fn priority(&self) -> TransportPriority {
        self.interface.priority
    }

    fn interface_name(&self) -> &str {
        &self.interface.name
    }

    async fn is_available(&self) -> bool {
        if !self.interface.is_usable() {
            return false;
        }
        self.latency_probe_ms().await.is_some()
    }

    async fn send(&self, message: &TransportMessage) -> CotResult<()> {
        if !self.interface.is_usable() {
            return Err(CotError::TransportError(format!(
                "Satellite {} not available",
                self.interface.name
            )));
        }

        let mut stream = TcpStream::connect(&message.target_address)
            .await
            .map_err(|e| CotError::TransportError(format!("Satellite send failed: {}", e)))?;

        let len = (message.payload.len() as u32).to_be_bytes();
        stream.write_all(&len).await.map_err(|e| {
            CotError::TransportError(format!("Satellite write length failed: {}", e))
        })?;
        stream.write_all(&message.payload).await.map_err(|e| {
            CotError::TransportError(format!("Satellite write payload failed: {}", e))
        })?;
        stream
            .flush()
            .await
            .map_err(|e| CotError::TransportError(format!("Satellite flush failed: {}", e)))?;

        Ok(())
    }

    async fn health_check(&self) -> TransportHealth {
        if !self.interface.is_usable() {
            return TransportHealth::unhealthy("Satellite interface not usable");
        }

        let (baseline_latency, baseline_bw) = self.kind.baseline();
        match self.latency_probe_ms().await {
            Some(measured_latency) => {
                // Keep expected throughput by satellite family and report measured latency.
                let latency = measured_latency.max(baseline_latency.saturating_sub(20));
                TransportHealth::healthy(latency, baseline_bw)
            }
            None => TransportHealth::unhealthy("Satellite gateway probe failed"),
        }
    }

    fn display_name(&self) -> String {
        format!("Satellite({},{})", self.interface.name, self.kind.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cot::types::{InterfaceInfo, InterfaceStatus};

    fn make_sat(name: &str) -> InterfaceInfo {
        InterfaceInfo::new(
            name.to_string(),
            TransportType::Satellite,
            Some("100.64.1.2".parse().unwrap()),
            InterfaceStatus::Up,
        )
    }

    #[test]
    fn test_kind_detection_from_interface() {
        assert_eq!(
            SatelliteKind::from_interface_name("ppp0"),
            SatelliteKind::Iridium
        );
        assert_eq!(
            SatelliteKind::from_interface_name("usb0"),
            SatelliteKind::Inmarsat
        );
        assert_eq!(
            SatelliteKind::from_interface_name("eth0"),
            SatelliteKind::Starlink
        );
        assert_eq!(
            SatelliteKind::from_interface_name("sat0"),
            SatelliteKind::Generic
        );
    }

    #[test]
    fn test_display_name_no_stub_marker() {
        let t = SatelliteTransport::new(make_sat("sat0"));
        let name = t.display_name();
        assert!(name.contains("Satellite"));
        assert!(!name.contains("[STUB]"));
    }

    #[test]
    fn test_interface_name() {
        let t = SatelliteTransport::new(make_sat("sat1"));
        assert_eq!(t.interface_name(), "sat1");
    }

    fn sat_interface(status: InterfaceStatus, ip: Option<&str>) -> InterfaceInfo {
        InterfaceInfo::new(
            "sat0".into(),
            TransportType::Satellite,
            ip.map(|value| value.parse().expect("parse ip")),
            status,
        )
    }

    /// Points the gateway probe at a listener under the test's control, so
    /// the reachable and unreachable branches are both exercised offline.
    struct GatewayGuard(Option<std::ffi::OsString>);

    impl GatewayGuard {
        fn set(addr: &str) -> Self {
            let previous = std::env::var_os("SGX_SAT_GATEWAY_ADDR");
            std::env::set_var("SGX_SAT_GATEWAY_ADDR", addr);
            Self(previous)
        }
    }

    impl Drop for GatewayGuard {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => std::env::set_var("SGX_SAT_GATEWAY_ADDR", value),
                None => std::env::remove_var("SGX_SAT_GATEWAY_ADDR"),
            }
        }
    }

    #[tokio::test]
    async fn send_refuses_an_interface_that_is_not_usable() {
        let transport = SatelliteTransport::new(sat_interface(InterfaceStatus::Down, Some("100.64.1.2")));
        let error = transport
            .send(&TransportMessage::new(
                "device-a".into(),
                "device-b".into(),
                "127.0.0.1:9".into(),
                b"x".to_vec(),
            ))
            .await
            .expect_err("a downed interface must not dial");
        assert!(matches!(error, CotError::TransportError(msg) if msg.contains("not available")));
    }

    #[tokio::test]
    async fn send_delivers_a_length_prefixed_frame_over_the_link() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buffer = Vec::new();
            let _ = stream.read_to_end(&mut buffer).await;
            buffer
        });

        SatelliteTransport::new(sat_interface(InterfaceStatus::Up, Some("100.64.1.2")))
            .send(&TransportMessage::new(
                "device-a".into(),
                "device-b".into(),
                addr.to_string(),
                b"burst".to_vec(),
            ))
            .await
            .expect("send succeeds");
        let received = handle.await.expect("listener task");
        assert_eq!(&received[..4], &5u32.to_be_bytes());
        assert_eq!(&received[4..], b"burst");
    }

    #[tokio::test]
    async fn health_check_and_availability_follow_the_gateway_probe() {
        let unusable = SatelliteTransport::new(sat_interface(InterfaceStatus::Down, None));
        assert!(!unusable.is_available().await);
        let health = unusable.health_check().await;
        assert!(!health.is_healthy);
        assert!(health.status_message.contains("not usable"), "{health:?}");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind gateway stand-in");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });
        let _gateway = GatewayGuard::set(&addr.to_string());
        let transport = SatelliteTransport::new(sat_interface(InterfaceStatus::Up, Some("100.64.1.2")));
        assert!(transport.is_available().await);
        let health = transport.health_check().await;
        assert!(health.is_healthy, "{health:?}");
        assert!(health.bandwidth_kbps > 0);
    }

    #[tokio::test]
    async fn health_check_reports_a_failed_gateway_probe() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        let _gateway = GatewayGuard::set(&addr.to_string());
        let transport = SatelliteTransport::new(sat_interface(InterfaceStatus::Up, Some("100.64.1.2")));
        let health = transport.health_check().await;
        assert!(!health.is_healthy);
        assert!(health.status_message.contains("probe failed"), "{health:?}");
    }
}
