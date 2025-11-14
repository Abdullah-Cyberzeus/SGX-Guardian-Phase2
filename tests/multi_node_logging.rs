use std::env;
use std::fs;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
#[test]
fn multi_node_logging() {
    let current_dir = env::current_dir().unwrap();
    let project_root = current_dir
        .ancestors()
        .find(|p| p.join("Cargo.toml").exists() && p.join("src").exists())
        .unwrap_or(&current_dir)
        .to_path_buf();
    let logs_path = project_root.join("logs");
    fs::create_dir_all(&logs_path).ok();
    let node_a_id = "nodeA";
    let node_b_id = "nodeB";

    // Remove old logs
    for e in fs::read_dir(&logs_path).unwrap().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name == "nodeA.log" || name == "nodeB.log" || name == "nodeC.log" {
            let _ = fs::remove_file(e.path());
        }
    }
    // Start Node A
    let mut node_a = Command::new("cargo")
        .args(["run", "--", node_a_id, "50051"])
        .current_dir(&project_root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start Node A");
    // Start Node B
    let mut node_b = Command::new("cargo")
        .args(["run", "--", node_b_id, "50052"])
        .current_dir(&project_root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start Node B");

    // Give them enough time to start, communicate, and write logs
    thread::sleep(Duration::from_secs(18));
    let _ = node_a.kill();
    let _ = node_b.kill();
    let _ = node_a.wait();
    let _ = node_b.wait();

    // Dynamically detect log files
    let node_a_log = fs::read_dir(&logs_path)
        .unwrap()
        .flatten()
        .find(|e| e.file_name().to_string_lossy().starts_with("nodeA.log"))
        .map(|e| e.path())
        .expect("nodeA log file not found");
    let node_b_log = fs::read_dir(&logs_path)
        .unwrap()
        .flatten()
        .find(|e| e.file_name().to_string_lossy().starts_with("nodeB.log"))
        .map(|e| e.path())
        .expect("nodeB log file not found");

    // Verify log files exist
    assert!(fs::metadata(&node_a_log).is_ok(), "nodeA log missing");
    assert!(fs::metadata(&node_b_log).is_ok(), "nodeB log missing");

    // Validate JSON structure
    let node_a_logs = fs::read_to_string(&node_a_log).expect("Failed to read nodeA log");
    assert!(
        node_a_logs.contains("\"level\":\"INFO\""),
        "nodeA log missing expected JSON structure"
    );
    println!("✅ Multi-node logging test passed successfully!");
}
