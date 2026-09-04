//! Reading the overlay address out of a Nebula certificate.
//!
//! `nebula-cert print` is the only way to read a certificate's overlay IP, so
//! the process call is behind a [`CertPrinter`] trait: the parsing — which is
//! where the interesting behaviour lives — is tested against fixture output
//! with no external binary involved.

/// Runs `nebula-cert print -path <cert_path>` and returns its stdout.
///
/// `None` means the command could not be run or exited non-zero.
pub trait CertPrinter {
    fn print(&self, cert_path: &str) -> Option<String>;
}

/// The real `nebula-cert` binary, resolved from `PATH`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NebulaCertCommand;

impl CertPrinter for NebulaCertCommand {
    fn print(&self, cert_path: &str) -> Option<String> {
        let output = std::process::Command::new("nebula-cert")
            .args(["print", "-path", cert_path])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

/// Private overlay prefixes a Guardian mesh address may use.
const OVERLAY_PREFIXES: [&str; 3] = ["192.168.100.", "10.", "172.16."];

/// Extracts the first overlay address in CIDR form from `nebula-cert print`
/// output.
///
/// Only CIDR-shaped values are accepted: a bare address cannot be used to
/// configure the overlay interface and would silently produce a /32 route.
pub fn parse_overlay_ip(printed: &str) -> Option<String> {
    for line in printed.lines() {
        // Prefix order matters and is deliberate: the Guardian overlay range
        // is looked for first, so a `10.`-shaped substring elsewhere on the
        // line (a date, a version) cannot mask a real 192.168.100.x address.
        let Some(index) = line
            .find(OVERLAY_PREFIXES[0])
            .or_else(|| line.find(OVERLAY_PREFIXES[1]))
            .or_else(|| line.find(OVERLAY_PREFIXES[2]))
        else {
            continue;
        };
        let rest = &line[index..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.' && c != '/')
            .unwrap_or(rest.len());
        let candidate = rest[..end].trim();
        if candidate.contains('/')
            && OVERLAY_PREFIXES
                .iter()
                .any(|prefix| candidate.starts_with(prefix))
        {
            return Some(candidate.to_string());
        }
    }
    None
}

/// The overlay address recorded in `<base>/nodes/<node_id>.crt`.
pub fn read_ip_from_cert_with(
    printer: &impl CertPrinter,
    base: &str,
    node_id: &str,
) -> Option<String> {
    let cert_path = format!("{base}/nodes/{node_id}.crt");
    parse_overlay_ip(&printer.print(&cert_path)?)
}

/// [`read_ip_from_cert_with`] against the real `nebula-cert` binary.
pub fn read_ip_from_nebula_cert(base: &str, node_id: &str) -> Option<String> {
    read_ip_from_cert_with(&NebulaCertCommand, base, node_id)
}

/// Whether a certificate already carries `expected_ip_cidr`, used to decide
/// if the node needs a re-signed certificate after an overlay reassignment.
pub fn cert_matches_overlay_ip_with(
    printer: &impl CertPrinter,
    cert_path: &str,
    expected_ip_cidr: &str,
) -> bool {
    printer
        .print(cert_path)
        .map(|printed| printed.contains(expected_ip_cidr))
        .unwrap_or(false)
}

/// [`cert_matches_overlay_ip_with`] against the real `nebula-cert` binary.
pub fn cert_matches_overlay_ip(cert_path: &str, expected_ip_cidr: &str) -> bool {
    cert_matches_overlay_ip_with(&NebulaCertCommand, cert_path, expected_ip_cidr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Records the paths it was asked to print and replays fixture output.
    struct FakePrinter {
        output: Option<String>,
        seen: RefCell<Vec<String>>,
    }

    impl FakePrinter {
        fn printing(output: &str) -> Self {
            Self {
                output: Some(output.to_string()),
                seen: RefCell::new(Vec::new()),
            }
        }

        fn failing() -> Self {
            Self {
                output: None,
                seen: RefCell::new(Vec::new()),
            }
        }
    }

    impl CertPrinter for FakePrinter {
        fn print(&self, cert_path: &str) -> Option<String> {
            self.seen.borrow_mut().push(cert_path.to_string());
            self.output.clone()
        }
    }

    #[test]
    fn every_supported_overlay_prefix_is_recognised() {
        assert_eq!(
            parse_overlay_ip("Ips: 192.168.100.7/24").as_deref(),
            Some("192.168.100.7/24")
        );
        assert_eq!(
            parse_overlay_ip("overlay address 10.20.30.4/16, active").as_deref(),
            Some("10.20.30.4/16")
        );
        assert_eq!(
            parse_overlay_ip("overlay address 172.16.5.2/24; active").as_deref(),
            Some("172.16.5.2/24")
        );
    }

    #[test]
    fn an_address_without_a_prefix_length_is_rejected() {
        assert!(parse_overlay_ip("overlay address 10.20.30.4 without cidr").is_none());
        assert!(parse_overlay_ip("Ips: 192.168.100.7").is_none());
    }

    #[test]
    fn non_overlay_and_empty_output_yields_nothing() {
        assert!(parse_overlay_ip("").is_none());
        assert!(parse_overlay_ip("Name: nodeA\nGroups: []\n").is_none());
        assert!(
            parse_overlay_ip("Ips: 192.168.1.7/24").is_none(),
            "192.168.1.x is a LAN address, not a Guardian overlay address"
        );
    }

    #[test]
    fn the_first_overlay_address_in_the_output_wins() {
        let printed = "Details:\n\tName: nodeB\n\tIps:\n\t\t10.20.30.4/16\n\t\t172.16.5.2/24\n";
        assert_eq!(parse_overlay_ip(printed).as_deref(), Some("10.20.30.4/16"));
    }

    #[test]
    fn the_guardian_range_is_matched_ahead_of_a_bare_ten_dot_substring() {
        // "10." also occurs inside the date on this line; the Guardian range
        // is searched first so the real overlay address still wins.
        let printed = "\tNot before: 2026-01-10.  Ips: 192.168.100.9/24\n";
        assert_eq!(
            parse_overlay_ip(printed).as_deref(),
            Some("192.168.100.9/24")
        );
    }

    #[test]
    fn a_line_whose_first_prefix_match_is_not_a_cidr_yields_nothing_for_that_line() {
        // Documented limitation carried over from the original helper: only
        // the first prefix match on a line is examined, so a non-CIDR hit
        // ends that line's scan rather than falling through to a later match.
        let printed = "build 10.2 release, overlay 172.16.5.2/24\n";
        assert!(parse_overlay_ip(printed).is_none());
    }

    #[test]
    fn read_ip_builds_the_node_certificate_path() {
        let printer = FakePrinter::printing("Ips: 192.168.100.7/24");

        let ip = read_ip_from_cert_with(&printer, "/var/lib/sgx-guardian/nebula", "nodeA");

        assert_eq!(ip.as_deref(), Some("192.168.100.7/24"));
        assert_eq!(
            printer.seen.borrow().as_slice(),
            ["/var/lib/sgx-guardian/nebula/nodes/nodeA.crt"]
        );
    }

    #[test]
    fn a_failed_print_reports_no_address_and_no_match() {
        let printer = FakePrinter::failing();

        assert!(read_ip_from_cert_with(&printer, "base", "nodeA").is_none());
        assert!(!cert_matches_overlay_ip_with(
            &printer,
            "missing.crt",
            "10.20.30.4/16"
        ));
    }

    #[test]
    fn cert_match_is_a_substring_check_over_the_printed_certificate() {
        let printer = FakePrinter::printing("Details:\n\tIps:\n\t\t192.168.100.7/24\n");

        assert!(cert_matches_overlay_ip_with(
            &printer,
            "node.crt",
            "192.168.100.7/24"
        ));
        assert!(!cert_matches_overlay_ip_with(
            &printer,
            "node.crt",
            "192.168.100.8/24"
        ));
        assert_eq!(printer.seen.borrow().len(), 2);
    }

    #[test]
    fn the_real_command_reports_failure_when_nebula_cert_is_unavailable() {
        // `nebula-cert` is not installed in the test environment, so the real
        // adapter must degrade to "no address"/"no match" rather than panic.
        assert!(!cert_matches_overlay_ip(
            "/nonexistent/node.crt",
            "192.168.100.7/24"
        ));
        assert!(read_ip_from_nebula_cert("/nonexistent", "nodeA").is_none());
    }
}
