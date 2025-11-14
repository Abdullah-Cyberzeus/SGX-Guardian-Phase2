use anyhow::Result;
use chrono::{DateTime, Utc};
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Table};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct TrustedPeer {
    peer_id: String,
    ip: String,
    status: String,
    timestamp: String,
}

pub fn run() -> Result<()> {
    let data = fs::read_to_string("../logs/trusted_peers.json")
        .or_else(|_| fs::read_to_string("logs/trusted_peers.json"))
        .unwrap_or_else(|_| "[]".to_string());

    let peers: Vec<TrustedPeer> = serde_json::from_str(&data).unwrap_or_else(|_| Vec::new());

    if peers.is_empty() {
        println!("No trusted peers found yet.");
        return Ok(());
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec!["Peer ID", "IP", "Status", "Last Seen"]);

    for p in peers {
        let ts: DateTime<Utc> = DateTime::parse_from_rfc3339(&p.timestamp)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        table.add_row(vec![
            p.peer_id,
            p.ip,
            p.status,
            ts.format("%H:%M:%S").to_string(),
        ]);
    }

    println!("{table}");
    Ok(())
}
