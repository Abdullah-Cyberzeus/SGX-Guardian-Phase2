//! Build script for SG-X Guardian Client.
//! Watches protobuf files for changes and regenerates Rust gRPC bindings
//! using `tonic_build` during compilation.

use std::fs;
use std::path::{Path, PathBuf};

fn frontend_mime(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("json") | Some("webmanifest") => "application/json; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn collect_frontend_files(directory: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_frontend_files(&path, files)?;
        } else {
            files.push(path);
        }
    }
    Ok(())
}

fn validate_frontend_entry(dist_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let index_path = dist_dir.join("index.html");
    let index = fs::read_to_string(&index_path)?;
    let module_tag = index
        .lines()
        .find(|line| {
            line.contains("<script") && line.contains("type=\"module\"") && line.contains("src=\"")
        })
        .ok_or("frontend index.html has no module entry script")?;
    let source = module_tag
        .split_once("src=\"")
        .and_then(|(_, rest)| rest.split_once('"').map(|(source, _)| source))
        .ok_or("frontend index.html has an invalid module script source")?;
    let entry_path = dist_dir.join(source.trim_start_matches('/'));
    let entry = fs::read(&entry_path).map_err(|error| {
        format!(
            "frontend module entry {} is missing: {}",
            entry_path.display(),
            error
        )
    })?;
    // The application entry contains the React DOM bootstrap. This prevents
    // accidentally embedding a lazy D3/vendor chunk as the page entry, which
    // otherwise returns HTTP 200 but renders a blank screen.
    if !entry
        .windows(b"createRoot".len())
        .any(|window| window == b"createRoot")
    {
        return Err(format!(
            "frontend module entry {} does not contain the React bootstrap",
            entry_path.display()
        )
        .into());
    }
    Ok(())
}

fn generate_embedded_frontend() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let dist_dir = manifest_dir.join("frontend/dist");
    let output_path = PathBuf::from(std::env::var("OUT_DIR")?).join("embedded_frontend.rs");

    println!("cargo:rerun-if-changed={}", dist_dir.display());

    if !dist_dir.join("index.html").is_file() {
        return Err(format!(
            "{} is missing; provide frontend/dist before Cargo build",
            dist_dir.join("index.html").display()
        )
        .into());
    }
    validate_frontend_entry(&dist_dir)?;

    let mut files = Vec::new();
    collect_frontend_files(&dist_dir, &mut files)?;
    files.sort();

    let mut generated = String::from(
        "pub fn embedded_file(path: &str) -> Option<(&'static [u8], &'static str)> {\n\
         match path {\n",
    );
    for file in files {
        let relative = file
            .strip_prefix(&dist_dir)?
            .to_string_lossy()
            .replace('\\', "/");
        let absolute = file.canonicalize()?.to_string_lossy().into_owned();
        generated.push_str(&format!(
            "        {:?} => Some((include_bytes!({:?}), {:?})),\n",
            relative,
            absolute,
            frontend_mime(&file)
        ));
    }
    generated.push_str("        _ => None,\n    }\n}\n");
    fs::write(output_path, generated)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    generate_embedded_frontend()?;

    println!("cargo:rerun-if-changed=proto/ping.proto");
    println!("cargo:rerun-if-changed=proto/cert.proto");
    println!("cargo:rerun-if-changed=proto/peer.proto");
    println!("cargo:rerun-if-changed=proto/policy.proto");
    println!("cargo:rerun-if-changed=proto/chat.proto");
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(
            &[
                "proto/peer.proto",
                "proto/policy.proto",
                "proto/ping.proto",
                "proto/cert.proto",
                "proto/chat.proto",
            ],
            &["proto"],
        )?;
    println!("✅ Protobufs compiled successfully with tonic-prost-build.");
    Ok(())
}
