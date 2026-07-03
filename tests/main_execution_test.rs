use std::process::Command;

#[test]
fn test_main_execution() {
    let exe = env!("CARGO_BIN_EXE_sgx_guardian_client");
    let output = Command::new(exe)
        .arg("--help")
        .output()
        .expect("Failed to run binary");
    
    println!("{:?}", output);
}
