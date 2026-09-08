mod netbridge {
    pub mod types {
        #![allow(dead_code)]

        use std::io;

        #[derive(Debug)]
        pub enum NetbridgeError {
            IoError(io::Error),
            ValidationFailed(String),
            ConfigGenerationFailed(String),
            ProcessExecutionFailed(String),
            BootstrapFailed(String),
            MissingDependency(String),
            TemplateError(String),
            ConnectionFailed(String),
        }

        impl std::fmt::Display for NetbridgeError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::IoError(error) => write!(f, "I/O error: {error}"),
                    Self::ValidationFailed(message)
                    | Self::ConfigGenerationFailed(message)
                    | Self::ProcessExecutionFailed(message)
                    | Self::BootstrapFailed(message)
                    | Self::MissingDependency(message)
                    | Self::TemplateError(message)
                    | Self::ConnectionFailed(message) => write!(f, "{message}"),
                }
            }
        }
    }
}

mod routing_under_test {
    #![allow(dead_code)]

    include!("../src/netbridge/routing.rs");

    #[cfg(test)]
    mod extra_tests {
        use super::*;
        use crate::netbridge::types::NetbridgeError;
        use std::net::Ipv4Addr;

        #[test]
        fn new_and_default_construct_managers() {
            let _new = RoutingManager::new();
            let _default = RoutingManager;
        }

        #[test]
        fn parse_interface_cidr_reads_ipv4_line() {
            assert_eq!(
                parse_interface_cidr("2: wlan0\n    inet 192.168.1.20/24 scope global wlan0\n"),
                Some((Ipv4Addr::new(192, 168, 1, 20), 24))
            );
        }

        #[test]
        fn parse_interface_cidr_ignores_ipv6_lines() {
            assert_eq!(
                parse_interface_cidr("inet6 fe80::1/64\n inet 10.0.0.2/8 scope global"),
                Some((Ipv4Addr::new(10, 0, 0, 2), 8))
            );
        }

        #[test]
        fn parse_interface_cidr_returns_none_without_inet() {
            assert!(parse_interface_cidr("link/ether aa:bb").is_none());
        }

        #[test]
        fn parse_interface_cidr_rejects_bad_ip() {
            assert!(parse_interface_cidr("inet 999.1.1.1/24").is_none());
        }

        #[test]
        fn parse_interface_cidr_rejects_bad_prefix() {
            assert!(parse_interface_cidr("inet 192.168.1.1/bad").is_none());
        }

        #[test]
        fn parse_interface_cidr_requires_slash() {
            assert!(parse_interface_cidr("inet 192.168.1.1 scope global").is_none());
        }

        #[test]
        fn network_cidr_calculates_common_prefixes() {
            assert_eq!(
                network_cidr(Ipv4Addr::new(192, 168, 1, 200), 24).as_deref(),
                Some("192.168.1.0/24")
            );
            assert_eq!(
                network_cidr(Ipv4Addr::new(172, 16, 31, 99), 20).as_deref(),
                Some("172.16.16.0/20")
            );
        }

        #[test]
        fn network_cidr_handles_prefix_zero_and_thirty_two() {
            assert_eq!(
                network_cidr(Ipv4Addr::new(192, 168, 1, 200), 0).as_deref(),
                Some("0.0.0.0/0")
            );
            assert_eq!(
                network_cidr(Ipv4Addr::new(192, 168, 1, 200), 32).as_deref(),
                Some("192.168.1.200/32")
            );
        }

        #[test]
        fn network_cidr_rejects_prefix_above_thirty_two() {
            assert!(network_cidr(Ipv4Addr::new(192, 168, 1, 1), 33).is_none());
        }

        #[test]
        fn inferred_gateway_returns_first_host_for_routable_subnet() {
            assert_eq!(
                inferred_gateway(Ipv4Addr::new(192, 168, 1, 200), 24),
                Some(Ipv4Addr::new(192, 168, 1, 1))
            );
        }

        #[test]
        fn inferred_gateway_handles_prefix_zero() {
            assert_eq!(
                inferred_gateway(Ipv4Addr::new(10, 0, 0, 5), 0),
                Some(Ipv4Addr::new(0, 0, 0, 1))
            );
        }

        #[test]
        fn inferred_gateway_returns_none_for_point_to_point_prefixes() {
            assert!(inferred_gateway(Ipv4Addr::new(192, 168, 1, 1), 31).is_none());
            assert!(inferred_gateway(Ipv4Addr::new(192, 168, 1, 1), 32).is_none());
        }

        #[test]
        fn operation_not_supported_detection_matches_process_error_message() {
            let error = NetbridgeError::ProcessExecutionFailed(
                "RTNETLINK answers: Operation not supported".into(),
            );
            assert!(RoutingManager::is_operation_not_supported(&error));
        }

        #[test]
        fn operation_not_supported_detection_rejects_other_errors() {
            let error = NetbridgeError::ProcessExecutionFailed("permission denied".into());
            assert!(!RoutingManager::is_operation_not_supported(&error));
        }

        #[test]
        fn hotspot_configured_returns_false_for_missing_interface_when_supported() {
            POLICY_ROUTING_UNSUPPORTED.store(false, Ordering::SeqCst);
            assert!(!RoutingManager::hotspot_uplink_is_configured(
                "192.168.200.0/24",
                "definitely-not-an-interface"
            ));
        }
    }
}
