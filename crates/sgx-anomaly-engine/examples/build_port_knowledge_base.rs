//! Build a JSON knowledge base directly from the supplied Markdown guide.
use sgx_anomaly_engine::port_knowledge::{parse_file, write_knowledge_base};
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let source = args
        .first()
        .map(String::as_str)
        .unwrap_or("..\\common_open_ports_security_guide.md");
    let output = args
        .get(1)
        .map(String::as_str)
        .unwrap_or("config\\generated_port_knowledge.json");
    let entries = parse_file(source)?;
    if entries.is_empty() {
        return Err(anyhow::anyhow!(
            "no Common Ports records parsed from {source}"
        ));
    }
    write_knowledge_base(output, &entries)?;
    println!("Parsed {} port records from {}", entries.len(), source);
    println!("Knowledge base written to {}", output);
    Ok(())
}
