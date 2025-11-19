use clap::Args;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Args)]
#[command(about = "View recent log entries for a specific node")]
pub struct LogsArgs {
    /// Number of log lines to show from the end of file
    #[arg(long, default_value = "20")]
    pub tail: usize,

    /// Node ID to show logs for (e.g. nodeA)
    #[arg(long, default_value = "nodeA")]
    pub node: String,
}
pub fn run(args: LogsArgs) {
    use std::fs;
    use std::path::PathBuf;
    let logs_dir = PathBuf::from("../logs");

    // Try to find the latest log file that starts with the node name (e.g. nodeA)
    let mut latest_file: Option<PathBuf> = None;
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
        }
    }

    if latest_file.is_none() {
        eprintln!(
            "❌ No log file found for node `{}` in {:?}",
            args.node, logs_dir
        );
        eprintln!("Make sure node is running and logs directory exists.");
        std::process::exit(1);
    }
    let log_path = latest_file.unwrap();
    println!("Reading from latest log file: {:?}\n", log_path);
    let file = File::open(&log_path).expect("Could not open log file");
    let reader = BufReader::new(file);
    let lines: Vec<_> = reader.lines().filter_map(Result::ok).collect();
    let start = if lines.len() > args.tail {
        lines.len() - args.tail
    } else {
        0
    };
    println!(
        "Showing last {} log entries for {}:\n",
        args.tail, args.node
    );
    for line in &lines[start..] {
        println!("{}", line);
    }
}
