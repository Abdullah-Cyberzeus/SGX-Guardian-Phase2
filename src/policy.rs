use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
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

pub const DEFAULT_POLICY_SCHEMA_PATH: &str = "/etc/sgx-guardian/schemas/uep_policy_v1.yaml";
pub const DEFAULT_EFFECTIVE_POLICY_YAML: &str = r#"---
policy_id: "123e4567-e89b-12d3-a456-426614174000"
version: "1.0.0"
description: "Default Guardian Edge Policy"
rules:
  - id: "rule-001"
    action: "ALLOW"
    src: "10.0.0.0/24"
    dst: "0.0.0.0/0"
    protocol: "TCP"
    port: 443
  - id: "rule-005"
    action: "DENY"
    src: "0.0.0.0/0"
    dst: "10.0.0.10"
    protocol: "UDP"
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePolicyMaterial {
    pub yaml: String,
    pub digest_hex: String,
    pub source: &'static str,
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

pub fn load_effective_policy_material() -> EffectivePolicyMaterial {
    let runtime_active = get_active_policy();
    load_effective_policy_material_from_sources(
        runtime_active.as_ref(),
        crate::policy_state::active_policy_file_path().as_path(),
        Path::new(DEFAULT_POLICY_SCHEMA_PATH),
    )
}

fn load_effective_policy_material_from_sources(
    runtime_active: Option<&Policy>,
    active_policy_path: &Path,
    schema_path: &Path,
) -> EffectivePolicyMaterial {
    if let Some(active) = runtime_active {
        return canonical_policy_material(active, "runtime-active-policy");
    }

    if let Some(material) = load_policy_material_from_path(active_policy_path, "active-policy-file")
    {
        return material;
    }

    if let Some(material) = load_policy_material_from_path(schema_path, "schema-canonical") {
        return material;
    }

    let parsed =
        validate_policy(DEFAULT_EFFECTIVE_POLICY_YAML).expect("default effective policy valid");
    canonical_policy_material(&parsed, "constant-default")
}

fn load_policy_material_from_path(
    path: &Path,
    source: &'static str,
) -> Option<EffectivePolicyMaterial> {
    let yaml = fs::read_to_string(path).ok()?;
    match validate_policy(&yaml) {
        Ok(parsed) => Some(canonical_policy_material(&parsed, source)),
        Err(err) => {
            tracing::error!(
                "Policy source {} at {} failed validation: {}",
                source,
                path.display(),
                err
            );
            None
        }
    }
}

fn canonical_policy_material(policy: &Policy, source: &'static str) -> EffectivePolicyMaterial {
    let bytes = canonical_policy_bytes(policy);
    let yaml = String::from_utf8_lossy(&bytes).to_string();
    let digest_hex = canonical_policy_digest(policy);
    EffectivePolicyMaterial {
        yaml,
        digest_hex,
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_policy() -> Policy {
        Policy {
            policy_id: "policy-1".into(),
            version: "1.2.3".into(),
            rules: vec![Rule {
                id: "rule-1".into(),
                action: "ALLOW".into(),
                src: "0.0.0.0/0".into(),
                dst: "10.0.0.10".into(),
                protocol: "TCP".into(),
                port: None,
            }],
        }
    }

    const ACTIVE_POLICY_YAML: &str = r#"
policy_id: "active-policy"
version: "2.0.0"
rules:
  - id: "allow-https"
    action: "ALLOW"
    src: "10.0.0.0/24"
    dst: "0.0.0.0/0"
    protocol: "TCP"
    port: 443
"#;

    const SCHEMA_POLICY_YAML: &str = r#"
policy_id: "schema-policy"
version: "1.0.0"
rules:
  - id: "deny-http"
    action: "DENY"
    src: "0.0.0.0/0"
    dst: "10.0.0.10"
    protocol: "TCP"
    port: 80
"#;

    #[test]
    fn canonical_policy_bytes_are_stable_and_digest_is_hex() {
        let policy = sample_policy();
        let canonical = String::from_utf8(canonical_policy_bytes(&policy))
            .expect("canonical policy bytes should be valid utf8");

        assert_eq!(
            canonical,
            r#"{"policy_id":"policy-1","rules":[{"action":"ALLOW","dst":"10.0.0.10","id":"rule-1","port":null,"protocol":"TCP","src":"0.0.0.0/0"}],"version":"1.2.3"}"#
        );

        let digest = canonical_policy_digest(&policy);
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn validate_policy_parses_valid_yaml_and_rejects_missing_version() {
        let valid = r#"
policy_id: "policy-1"
version: "1.2.3"
rules:
  - id: "rule-1"
    action: "ALLOW"
    src: "0.0.0.0/0"
    dst: "10.0.0.10"
    protocol: "TCP"
"#;
        let parsed = validate_policy(valid).expect("valid policy should parse");
        assert_eq!(parsed.policy_id, "policy-1");
        assert_eq!(parsed.rules.len(), 1);

        let invalid = r#"
policy_id: "policy-1"
rules:
  - id: "rule-1"
    action: "ALLOW"
    src: "0.0.0.0/0"
    dst: "10.0.0.10"
    protocol: "TCP"
"#;
        assert!(validate_policy(invalid).is_err());
    }

    #[test]
    fn effective_policy_material_prefers_active_policy_file() {
        let td = tempdir().expect("create temp dir");
        let active_path = td.path().join("active_policy.yaml");
        let schema_path = td.path().join("schema.yaml");
        fs::write(&active_path, ACTIVE_POLICY_YAML).expect("write active policy");
        fs::write(&schema_path, SCHEMA_POLICY_YAML).expect("write schema policy");

        let material =
            load_effective_policy_material_from_sources(None, &active_path, &schema_path);
        let parsed = validate_policy(ACTIVE_POLICY_YAML).expect("parse active policy");

        assert_eq!(material.source, "active-policy-file");
        assert_eq!(material.digest_hex, canonical_policy_digest(&parsed));
        assert_eq!(
            material.yaml,
            String::from_utf8(canonical_policy_bytes(&parsed)).expect("utf8 canonical policy")
        );
    }

    #[test]
    fn effective_policy_material_prefers_runtime_policy_over_disk() {
        let td = tempdir().expect("create temp dir");
        let active_path = td.path().join("active_policy.yaml");
        let schema_path = td.path().join("schema.yaml");
        fs::write(&active_path, ACTIVE_POLICY_YAML).expect("write active policy");
        fs::write(&schema_path, SCHEMA_POLICY_YAML).expect("write schema policy");

        let runtime_policy = validate_policy(SCHEMA_POLICY_YAML).expect("parse runtime policy");
        let material = load_effective_policy_material_from_sources(
            Some(&runtime_policy),
            &active_path,
            &schema_path,
        );

        assert_eq!(material.source, "runtime-active-policy");
        assert_eq!(
            material.digest_hex,
            canonical_policy_digest(&runtime_policy)
        );
    }
}
