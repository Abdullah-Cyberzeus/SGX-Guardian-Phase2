use clap::Args;
use comfy_table::{Attribute, Cell, Color, Table};
use serde_json::Value;
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Command-line arguments for viewing SG-X node logs, including
/// selecting the node ID and the number of recent log lines to display.
#[derive(Args)]
#[command(about = "Inspect recent JSON log activity for a selected SGX Guardian node")]
pub struct LogsArgs {
    /// Number of log lines to show from the end of file
    #[arg(long, default_value = "20")]
    pub tail: usize,

    /// Node ID to show logs for (e.g. nodeA)
    #[arg(long, default_value = "nodeA")]
    pub node: String,
}
/// Reads and displays the latest JSON log file for the specified SG-X node.
/// Automatically selects the newest log file matching the node name and prints
/// the last N entries based on the `--tail` argument.
pub fn run(args: LogsArgs) {
    use std::fs;
    use std::path::PathBuf;
    // Try to find the latest log file that starts with the node name (e.g. nodeA)
    let mut latest_file: Option<PathBuf> = None;
    let mut searched_paths = Vec::new();

    for dir in ["/var/log/sgx-guardian", "../logs", "logs"] {
        let logs_dir = PathBuf::from(dir);
        searched_paths.push(logs_dir.clone());
        if logs_dir.exists() {
            let mut candidates: Vec<_> = fs::read_dir(&logs_dir)
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    name.starts_with(&args.node)
                })
                .collect();

            // Sort by modification time so we pick the newest
            candidates.sort_by_key(|e| e.metadata().unwrap().modified().unwrap());
            if let Some(entry) = candidates.last() {
                latest_file = Some(entry.path());
                break;
            }
        }
    }

    if latest_file.is_none() {
        eprintln!(
            "❌ No log file found for node `{}` in searched locations: {:?}",
            args.node, searched_paths
        );
        eprintln!("Make sure node is running and logs directory exists.");
        std::process::exit(1);
    }
    let log_path = latest_file.unwrap();
    println!("Reading from latest log file: {:?}\n", log_path);
    let file = File::open(&log_path).expect("Could not open log file");
    let reader = BufReader::new(file);
    let lines: Vec<_> = reader.lines().map_while(Result::ok).collect();
    let start = if lines.len() > args.tail {
        lines.len() - args.tail
    } else {
        0
    };

    let mut table = Table::new();
    table.set_header(vec![
        Cell::new("Time").add_attribute(Attribute::Bold),
        Cell::new("Level").add_attribute(Attribute::Bold),
        Cell::new("Node").add_attribute(Attribute::Bold),
        Cell::new("Message").add_attribute(Attribute::Bold),
    ]);

    for line in &lines[start..] {
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            let time = v
                .get("time")
                .and_then(|x| x.as_str())
                .or_else(|| v.get("timestamp").and_then(|x| x.as_str()))
                .unwrap_or("")
                .chars()
                .take(19) // Truncate fractional seconds
                .collect::<String>();

            let raw_level = v.get("level").and_then(|x| x.as_str()).unwrap_or("INFO");
            let mut level_cell = Cell::new(raw_level);
            match raw_level.to_uppercase().as_str() {
                "ERROR" | "CRITICAL" => {
                    level_cell = level_cell.fg(Color::Red).add_attribute(Attribute::Bold);
                }
                "WARN" | "WARNING" => {
                    level_cell = level_cell.fg(Color::Yellow).add_attribute(Attribute::Bold);
                }
                "INFO" => {
                    level_cell = level_cell.fg(Color::Green);
                }
                _ => {}
            }

            let node = v.get("node").and_then(|x| x.as_str()).unwrap_or(&args.node);

            let message = v
                .get("fields")
                .and_then(|f| f.get("message"))
                .and_then(|x| x.as_str())
                .or_else(|| v.get("event").and_then(|x| x.as_str()))
                .or_else(|| v.get("message").and_then(|x| x.as_str()))
                .or_else(|| v.get("error").and_then(|x| x.as_str()))
                .unwrap_or(line);

            table.add_row(vec![
                Cell::new(time),
                level_cell,
                Cell::new(node),
                Cell::new(message),
            ]);
        } else {
            table.add_row(vec![
                Cell::new("—"),
                Cell::new("RAW").fg(Color::DarkCyan),
                Cell::new(&args.node),
                Cell::new(line),
            ]);
        }
    }

    println!("{}", table);
}

#[cfg(test)]
mod tests {
    use super::{run, LogsArgs};

    #[test]
    fn run_renders_real_pre_existing_workspace_logs() {
        // `../logs/test-log-node.log.*` are real, already-checked-in log files (this test
        // reads them, never writes), reachable because cargo runs this package's tests with
        // cwd = the sgx-pa-cli package directory, so "../logs" resolves to the workspace's
        // own `logs/` dir. This exercises the full parse/render path (multiple levels,
        // "event"/"error"/"message" field fallbacks) without seeding any tempdir.
        run(LogsArgs {
            tail: 5,
            node: "test-log-node".to_string(),
        });
    }
}
