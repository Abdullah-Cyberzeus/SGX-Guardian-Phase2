/// Tests the `peers` CLI command by creating a temporary trusted_peers.json file,
/// running the command, and verifying that it executes successfully without errors.
#[test]
fn test_peers_table_format() {
    use std::fs;

    // ✅ ensure the logs directory exists before writing
    fs::create_dir_all("logs").unwrap();

    // Write a dummy peers file for the CLI to read
    fs::write(
        "logs/trusted_peers.json",
        r#"[{
            "peer_id":"nodeB",
            "ip":"127.0.0.1",
            "status":"verified",
            "timestamp":"2025-11-11T14:00:00Z"
        }]"#,
    )
    .unwrap();

    // Call the CLI command
    let result = sgx_pa_cli::commands::peers::run();

    // ✅ Assert that it executed successfully
    assert!(result.is_ok());
}
