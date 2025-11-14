fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/ping.proto");
    println!("cargo:rerun-if-changed=proto/peer.proto");
    println!("cargo:rerun-if-changed=proto/policy.proto");
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile(
            &["proto/peer.proto", "proto/policy.proto", "proto/ping.proto"],
            &["proto"],
        )?;
    println!("✅ Protobufs compiled successfully with tonic 0.10!");
    Ok(())
}
