use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
/// Represents a single UEP policy rule defining allowed or denied traffic.
/// Includes source, destination, protocol, and optional port matching.
#[derive(Debug, Deserialize, Serialize, Clone)]
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
#[derive(Debug, Deserialize, Serialize, Clone)]
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

/// Produce deterministic canonical JSON for a Policy.
/// - Top-level keys sorted alphabetically
/// - Rule keys emitted in fixed order
/// - No whitespace
pub fn canonical_policy_bytes(policy: &Policy) -> Vec<u8> {
    let mut top = BTreeMap::new();
    top.insert(
        "policy_id",
        serde_json::Value::String(policy.policy_id.clone()),
    );
    top.insert("version", serde_json::Value::String(policy.version.clone()));

    let rules_json: Vec<serde_json::Value> = policy
        .rules
        .iter()
        .map(|r| {
            let mut m = serde_json::Map::new();
            m.insert(
                "action".to_string(),
                serde_json::Value::String(r.action.clone()),
            );
            m.insert("dst".to_string(), serde_json::Value::String(r.dst.clone()));
            m.insert("id".to_string(), serde_json::Value::String(r.id.clone()));
            m.insert(
                "port".to_string(),
                match r.port {
                    Some(p) => serde_json::Value::Number(p.into()),
                    None => serde_json::Value::Null,
                },
            );
            m.insert(
                "protocol".to_string(),
                serde_json::Value::String(r.protocol.clone()),
            );
            m.insert("src".to_string(), serde_json::Value::String(r.src.clone()));
            serde_json::Value::Object(m)
        })
        .collect();
    top.insert("rules", serde_json::Value::Array(rules_json));

    serde_json::to_vec(&top).unwrap_or_default()
}

pub fn canonical_policy_digest(policy: &Policy) -> String {
    use sha2::{Digest, Sha256};
    let bytes = canonical_policy_bytes(policy);
    hex::encode(Sha256::digest(&bytes))
}
use anyhow::Result;
use once_cell::sync::Lazy;
use std::sync::{Arc, RwLock};

#[allow(dead_code)]
static ACTIVE_POLICY_CACHE: Lazy<Arc<RwLock<Option<Policy>>>> =
    Lazy::new(|| Arc::new(RwLock::new(None)));

/// Load policy from YAML string and update runtime cache
#[allow(dead_code)]
pub fn load_policy_runtime(yaml: &str) -> Result<()> {
    let parsed = validate_policy(yaml)?;
    let mut guard = ACTIVE_POLICY_CACHE.write().unwrap();
    *guard = Some(parsed);
    Ok(())
}

/// Get currently active policy (if any)
#[allow(dead_code)]
pub fn get_active_policy() -> Option<Policy> {
    ACTIVE_POLICY_CACHE.read().unwrap().clone()
}
