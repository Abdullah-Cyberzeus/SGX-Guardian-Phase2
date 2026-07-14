//! Build script for SG-X Guardian Client.
//! Watches protobuf files for changes and regenerates Rust gRPC bindings
//! using `tonic_build` during compilation.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/ping.proto");
    println!("cargo:rerun-if-changed=proto/cert.proto");
    println!("cargo:rerun-if-changed=proto/peer.proto");
    println!("cargo:rerun-if-changed=proto/policy.proto");
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(
            &[
                "proto/peer.proto",
                "proto/policy.proto",
                "proto/ping.proto",
                "proto/cert.proto",
            ],
            &["proto"],
        )?;
    println!("✅ Protobufs compiled successfully with tonic-prost-build.");
    Ok(())
}
