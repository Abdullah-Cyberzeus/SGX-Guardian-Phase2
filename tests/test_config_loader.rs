//! Covers: valid config, invalid YAML, missing fields, invalid IP, port=0,
//! empty public_key, and file read errors.

use sgx_guardian_client::config_loader::load_config;
use std::fs;

/// Helper: write a temporary YAML file and return its path.
fn write_temp_config(name: &str, content: &str) -> String {
    let mut dir = std::env::temp_dir();
    dir.push(format!("{}_{}.yaml", name, std::process::id()));
    let path = dir.to_string_lossy().to_string();
    fs::write(&path, content).unwrap();
    path
}

#[test]
fn test_valid_config_loads_successfully() {
    let yaml = r#"
node_id: nodeA
hostname: localhost
ip: 127.0.0.1
port: 50051
public_key: "PUBKEY123"
"#;

    let p = write_temp_config("valid_cfg", yaml);
    let cfg = load_config(&p).expect("Valid config should load successfully");

    assert_eq!(cfg.node_id, "nodeA");
    assert_eq!(cfg.hostname, "localhost");
    assert_eq!(cfg.ip, "127.0.0.1");
    assert_eq!(cfg.port, 50051);
    assert_eq!(cfg.public_key, "PUBKEY123");

    let _ = fs::remove_file(&p);
}

#[test]
fn test_missing_file_fails() {
    let res = load_config("non_existing_config_12345.yaml");
    assert!(res.is_err(), "Loading missing file must return an error");
}

#[test]
fn test_invalid_yaml_fails() {
    let p = write_temp_config("bad_yaml", "this: : is: not: yaml:");
    let res = load_config(&p);
    assert!(res.is_err(), "Invalid YAML must cause failure");
    let _ = fs::remove_file(&p);
}

#[test]
fn test_empty_node_id_fails() {
    let yaml = r#"
node_id: ""
hostname: host
ip: 127.0.0.1
port: 50051
public_key: ABC
"#;

    let p = write_temp_config("empty_id", yaml);
    let res = load_config(&p);
    assert!(res.is_err(), "Empty node_id must cause validation failure");
    let _ = fs::remove_file(&p);
}

#[test]
fn test_empty_hostname_fails() {
    let yaml = r#"
node_id: nodeA
hostname: ""
ip: 127.0.0.1
port: 50051
public_key: ABC
"#;

    let p = write_temp_config("empty_host", yaml);
    let res = load_config(&p);
    assert!(res.is_err(), "Empty hostname must cause validation failure");
    let _ = fs::remove_file(&p);
}

#[test]
fn test_invalid_ip_fails() {
    let yaml = r#"
node_id: nodeA
hostname: host
ip: 999.999.999.999
port: 50051
public_key: ABC
"#;

    let p = write_temp_config("bad_ip", yaml);
    let res = load_config(&p);
    assert!(res.is_err(), "Invalid IP must cause validation failure");
    let _ = fs::remove_file(&p);
}

#[test]
fn test_zero_port_fails() {
    let yaml = r#"
node_id: nodeA
hostname: host
ip: 127.0.0.1
port: 0
public_key: ABC
"#;

    let p = write_temp_config("zero_port", yaml);
    let res = load_config(&p);
    assert!(res.is_err(), "Port=0 must cause validation failure");
    let _ = fs::remove_file(&p);
}

#[test]
fn test_empty_public_key_fails() {
    let yaml = r#"
node_id: nodeA
hostname: host
ip: 127.0.0.1
port: 50051
public_key: ""
"#;

    let p = write_temp_config("empty_pubkey", yaml);
    let res = load_config(&p);
    assert!(
        res.is_err(),
        "Empty public_key must cause validation failure"
    );
    let _ = fs::remove_file(&p);
}
