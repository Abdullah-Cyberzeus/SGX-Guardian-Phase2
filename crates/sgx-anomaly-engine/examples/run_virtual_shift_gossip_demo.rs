//! VS15 demonstration: relay one persisted VS14 message across the configured
//! three-node topology. It simulates the transport only; VS16 verification
//! and VS17 application remain unavailable here.

use anyhow::Result;
use sgx_anomaly_engine::virtual_shift::{
    write_gossip_receipt, GossipTopology, GossipTransport, InMemoryGossipTransport, VShiftAlert,
};

fn flag(args: &[String], name: &str) -> Result<Option<String>> {
    let Some(index) = args.iter().position(|value| value == name) else {
        return Ok(None);
    };
    let value = args
        .get(index + 1)
        .ok_or_else(|| anyhow::anyhow!("{name} needs a value"))?
        .trim();
    if value.is_empty() {
        anyhow::bail!("{name} must not be empty");
    }
    Ok(Some(value.to_owned()))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let alert_path = args.first().ok_or_else(|| anyhow::anyhow!(
        "usage: cargo run --example run_virtual_shift_gossip_demo -- <vshift_alert.json> [--origin nodeA] [--offline nodeC]"
    ))?;
    let origin = flag(&args, "--origin")?.unwrap_or_else(|| "nodeA".into());
    let offline = flag(&args, "--offline")?;
    let alert: VShiftAlert = serde_json::from_str(&std::fs::read_to_string(alert_path)?)?;
    let topology = GossipTopology::from_path("config/circle_gossip_topology.json")?;
    let mut transport = InMemoryGossipTransport::new(topology)?;
    if let Some(node) = &offline {
        transport.set_online(node, false)?;
    }
    let receipt = transport.broadcast_vshift_alert(&origin, &alert)?;
    let receipt_path = write_gossip_receipt("data/virtual_shift/VS15_GOSSIP", &receipt)?;
    let delivered = if receipt.delivered.is_empty() {
        "none".to_owned()
    } else {
        receipt
            .delivered
            .iter()
            .map(|item| format!("{} ({} hop)", item.node_id, item.relay_hops))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let offline = if receipt.pending_offline_nodes.is_empty() {
        "none".to_owned()
    } else {
        receipt.pending_offline_nodes.join(", ")
    };

    println!("==========================================================================");
    println!("TASK 2 - VS15 GOSSIP RELAY DEMO");
    println!("==========================================================================");
    println!("Message type            : VSHIFT_ALERT");
    println!("Alert ID                : {}", receipt.alert_id);
    println!("Origin Guardian node    : {}", receipt.origin_node);
    println!("Circle                  : {}", receipt.circle_id);
    println!("Duplicate suppressed    : {}", receipt.duplicate_suppressed);
    println!("Delivered members       : {delivered}");
    println!("Offline queued members  : {offline}");
    println!("Receipt JSON            : {}", receipt_path.display());
    println!("Status                  : {}", receipt.status);
    println!("STOP: no member verification or policy apply occurs until VS16/VS17.");
    Ok(())
}
