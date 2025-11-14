use serde::Deserialize;
#[derive(Debug, Deserialize)]
pub struct Rule {
    pub id: String,
    pub action: String,
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub port: Option<u16>,
}
#[derive(Debug, Deserialize)]
pub struct Policy {
    pub policy_id: String,
    pub version: String,
    pub rules: Vec<Rule>,
}
pub fn validate_policy(yaml_content: &str) -> Result<Policy, serde_yaml::Error> {
    serde_yaml::from_str::<Policy>(yaml_content)
}
