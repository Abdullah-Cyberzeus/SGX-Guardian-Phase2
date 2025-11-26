use serde::Deserialize;
/// Represents a single UEP policy rule defining allowed or denied traffic.
/// Includes source, destination, protocol, and optional port matching.
#[derive(Debug, Deserialize)]
pub struct Rule {
    pub id: String,
    pub action: String,
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub port: Option<u16>,
}
/// Top-level UEP policy document containing a unique policy ID,
/// version metadata, and a list of traffic rules to enforce.
#[derive(Debug, Deserialize)]
pub struct Policy {
    pub policy_id: String,
    pub version: String,
    pub rules: Vec<Rule>,
}
/// Parses and validates a UEP policy YAML string into a strongly-typed `Policy` object.
/// Returns an error if the YAML format is invalid or missing required fields.
pub fn validate_policy(yaml_content: &str) -> Result<Policy, serde_yaml::Error> {
    serde_yaml::from_str::<Policy>(yaml_content)
}
