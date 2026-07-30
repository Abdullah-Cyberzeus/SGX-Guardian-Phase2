use anyhow::Result;
use clap::Args;
use comfy_table::{Attribute, Cell, Color, Table};
use std::fs;

#[derive(Args)]
#[command(about = "Inspect secure attestation history records")]
pub struct AttestationArgs {
    /// Filter by peer DID
    #[arg(long)]
    pub peer_did: Option<String>,

    /// Filter by result (success, failed)
    #[arg(long)]
    pub result: Option<String>,

    /// Limit the number of records displayed
    #[arg(long)]
    pub tail: Option<usize>,
}

pub fn run(args: AttestationArgs) -> Result<()> {
    let data = fs::read_to_string("../logs/last_attestation.json")
        .or_else(|_| fs::read_to_string("logs/last_attestation.json"))
        .unwrap_or_else(|_| "[]".to_string());

    if data.trim().is_empty() {
        println!("No attestation results recorded yet.");
        return Ok(());
    }

    let list: Vec<sgx_guardian_client::attestation_service::LastAttestation> =
        if let Ok(parsed_list) = serde_json::from_str(&data) {
            parsed_list
        } else if let Ok(single) =
            serde_json::from_str::<sgx_guardian_client::attestation_service::LastAttestation>(&data)
        {
            let mut migrated = single;
            migrated.count = 1;
            vec![migrated]
        } else {
            Vec::new()
        };

    if list.is_empty() {
        println!("No attestation results found.");
        return Ok(());
    }

    let mut filtered_list = Vec::new();
    for item in list {
        if let Some(ref peer_did_filter) = args.peer_did {
            match &item.peer_did {
                Some(did) => {
                    if !did.eq_ignore_ascii_case(peer_did_filter) {
                        continue;
                    }
                }
                None => continue,
            }
        }

        if let Some(ref result_filter) = args.result {
            if !item.result.eq_ignore_ascii_case(result_filter) {
                continue;
            }
        }

        filtered_list.push(item);
    }

    if filtered_list.is_empty() {
        println!("No attestation results match the specified filters.");
        return Ok(());
    }

    let len = filtered_list.len();
    let display_list = if let Some(t) = args.tail {
        let start = if len > t { len - t } else { 0 };
        &filtered_list[start..]
    } else {
        &filtered_list[..]
    };

    let mut table = Table::new();
    table.set_header(vec![
        Cell::new("Peer ID").add_attribute(Attribute::Bold),
        Cell::new("Peer DID").add_attribute(Attribute::Bold),
        Cell::new("Virtual ID").add_attribute(Attribute::Bold),
        Cell::new("Policy Digest").add_attribute(Attribute::Bold),
        Cell::new("DKP Fingerprint").add_attribute(Attribute::Bold),
        Cell::new("PCR Composite").add_attribute(Attribute::Bold),
        Cell::new("Result").add_attribute(Attribute::Bold),
        Cell::new("Count").add_attribute(Attribute::Bold),
        Cell::new("Timestamp").add_attribute(Attribute::Bold),
    ]);

    let format_digest = |val: &str| -> String {
        if val.len() > 10 {
            format!("{}..", &val[..10])
        } else {
            val.to_string()
        }
    };

    for item in display_list {
        let peer_did_str = item.peer_did.as_deref().unwrap_or("—");

        let vid_str = match &item.virtual_id {
            Some(vid) if vid.starts_with("vid:") && vid.len() > 14 => format!("{}..", &vid[..14]),
            Some(vid) => format_digest(vid),
            None => "—".to_string(),
        };

        let policy_disp = format_digest(&item.policy_digest);
        let dkp_disp = item
            .dkp_pubkey_sha256_b16
            .as_ref()
            .map(|d| format_digest(d))
            .unwrap_or_else(|| "—".to_string());
        let pcr_disp = item
            .pcr_composite_digest
            .as_ref()
            .map(|d| format_digest(d))
            .unwrap_or_else(|| "—".to_string());

        let mut result_cell = Cell::new(&item.result);
        match item.result.to_lowercase().as_str() {
            "success" => {
                result_cell = result_cell.fg(Color::Green);
            }
            "failed" => {
                result_cell = result_cell.fg(Color::Red).add_attribute(Attribute::Bold);
            }
            _ => {}
        }

        let time_cleaned = item
            .timestamp
            .chars()
            .take(19)
            .collect::<String>()
            .replace('T', " ");

        table.add_row(vec![
            Cell::new(&item.peer_id),
            Cell::new(peer_did_str),
            Cell::new(&vid_str),
            Cell::new(&policy_disp),
            Cell::new(&dkp_disp),
            Cell::new(&pcr_disp),
            result_cell,
            Cell::new(item.count.to_string()),
            Cell::new(time_cleaned),
        ]);
    }

    println!("{}", table);
    Ok(())
}
