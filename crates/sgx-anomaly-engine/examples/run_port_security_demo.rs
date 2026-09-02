//! Open-port posture demo using the real Nmap-style inventory JSON.
//!
//! Examples:
//! cargo run --example run_port_security_demo -- ..\data_generate\inventory.json
//! cargo run --example run_port_security_demo -- ..\data_generate\inventory.json --ip 192.168.1.196 --port 22
//! cargo run --example run_port_security_demo -- --simulate-open 192.168.1.50 3389 rdp

use sgx_anomaly_engine::port_security::{
    finding_from_inventory, load_inventory, save_report, simulated_open_port, PortFinding,
    PortSecurityReport,
};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let simulate_at = args.iter().position(|arg| arg == "--simulate-open");

    let findings = if let Some(index) = simulate_at {
        let ip = args
            .get(index + 1)
            .ok_or_else(|| anyhow::anyhow!("--simulate-open needs: IP PORT SERVICE"))?;
        let port = args
            .get(index + 2)
            .ok_or_else(|| anyhow::anyhow!("--simulate-open needs: IP PORT SERVICE"))?
            .parse()?;
        let service = args
            .get(index + 3)
            .ok_or_else(|| anyhow::anyhow!("--simulate-open needs: IP PORT SERVICE"))?;
        vec![simulated_open_port(ip, port, service)]
    } else {
        let inventory_path = args
            .first()
            .map(String::as_str)
            .unwrap_or("../data_generate/inventory.json");
        let ip_filter = option_value(&args, "--ip");
        let port_filter = option_value(&args, "--port")
            .map(|value| value.parse::<u16>())
            .transpose()?;

        load_inventory(inventory_path)?
            .iter()
            .filter(|device| ip_filter.is_none_or(|ip| device.ip == ip))
            .flat_map(|device| {
                device
                    .open_ports
                    .iter()
                    .filter(move |port| port_filter.is_none_or(|number| port.port == number))
                    .map(move |port| finding_from_inventory(device, port))
            })
            .collect()
    };

    if findings.is_empty() {
        return Err(anyhow::anyhow!("no matching open ports found"));
    }

    print_findings(&findings);
    let report = PortSecurityReport {
        schema_version: 1,
        purpose: "Open-port exposure, severity, and recommendation report".to_string(),
        source_inventory: if simulate_at.is_some() {
            "simulated open-port scenario (no real network change)".to_string()
        } else {
            args.first()
                .cloned()
                .unwrap_or_else(|| "../data_generate/inventory.json".to_string())
        },
        findings,
    };
    let path = save_report(&report)?;
    println!("\nPort-security JSON: {}", path.display());
    Ok(())
}

fn option_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
}

fn print_findings(findings: &[PortFinding]) {
    println!("============================================================");
    println!("OPEN-PORT SECURITY CHECK");
    println!("============================================================");
    println!("+-----------------+----------+---------------+----------+------------+");
    println!("| Host            | Port     | Service       | CVSS     | Final      |");
    println!("+-----------------+----------+---------------+----------+------------+");
    for finding in findings {
        let cvss = finding
            .max_cvss
            .map(|score| format!("{score:.1}"))
            .unwrap_or_else(|| "-".to_string());
        let port_and_protocol = format!("{}/{}", finding.port, finding.protocol);
        println!(
            "| {:<15} | {:<8} | {:<13} | {:<8} | {:<10} |",
            finding.ip, port_and_protocol, finding.service, cvss, finding.severity
        );
    }
    println!("+-----------------+----------+---------------+----------+------------+");

    for finding in findings {
        println!("\n------------------------------------------------------------");
        println!(
            "{}:{}/{} ({})",
            finding.ip, finding.port, finding.protocol, finding.service
        );
        println!("Typical port label: {}", finding.typical_severity);
        println!(
            "Final posture: {} - {}",
            finding.severity, finding.severity_reason
        );
        println!("Asset context: exposure={}, transport={}, auth={}, patch={}, required={:?}, business_impact={}",
            finding.asset_context.network_exposure, finding.asset_context.transport_security,
            finding.asset_context.authentication, finding.asset_context.patch_status,
            finding.asset_context.service_required, finding.asset_context.business_impact);
        for adjustment in &finding.severity_adjustments {
            println!("Risk factor: {adjustment}");
        }
        println!("Recommendation: {}", finding.recommendation.message);
        println!(
            "Proposed action: {}",
            finding.recommendation.proposed_action
        );
    }
}
