//! Recommendation generator for evaluated port-risk results.

use crate::port_security::PortSeverity;

pub fn generate(
    base: &str,
    service: &str,
    port: u16,
    internet_exposed: bool,
    authentication_enabled: bool,
    encryption_enabled: bool,
    risk: PortSeverity,
) -> String {
    let mut text = base
        .replace("{service}", service)
        .replace("{port}", &port.to_string());
    if risk >= PortSeverity::High && internet_exposed {
        text.push_str(
            " Public exposure makes this urgent: restrict it to VPN or approved source IPs.",
        );
    }
    if !authentication_enabled {
        text.push_str(" Enable strong authentication/MFA.");
    }
    if !encryption_enabled {
        text.push_str(" Enable TLS/encryption or replace the plaintext service.");
    }
    text
}
