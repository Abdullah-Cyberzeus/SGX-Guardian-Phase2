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
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

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

    fn clear_active_policy_cache() {
        *ACTIVE_POLICY_CACHE.write().unwrap() = None;
    }

    fn one_rule_policy() -> Policy {
        Policy {
            policy_id: "policy-a".to_string(),
            version: "1.2.3".to_string(),
            rules: vec![Rule {
                id: "rule-a".to_string(),
                action: "ALLOW".to_string(),
                src: "10.1.0.0/16".to_string(),
                dst: "192.168.1.10".to_string(),
                protocol: "TCP".to_string(),
                port: Some(443),
            }],
        }
    }

    #[test]
    fn validate_policy_accepts_required_fields_and_optional_port() {
        let yaml = r#"
policy_id: policy-with-optional-port
version: 2026.08
rules:
  - id: rule-with-port
    action: ALLOW
    src: 10.0.0.1
    dst: 10.0.0.2
    protocol: TCP
    port: 0
  - id: rule-without-port
    action: DENY
    src: 0.0.0.0/0
    dst: 10.0.0.3
    protocol: UDP
"#;

        let policy = validate_policy(yaml).expect("valid policy should parse");

        assert_eq!(policy.policy_id, "policy-with-optional-port");
        assert_eq!(policy.version, "2026.08");
        assert_eq!(policy.rules.len(), 2);
        assert_eq!(policy.rules[0].port, Some(0));
        assert_eq!(policy.rules[1].port, None);
    }

    #[test]
    fn validate_policy_accepts_u16_port_upper_boundary() {
        let yaml = r#"
policy_id: max-port
version: "1"
rules:
  - id: max
    action: ALLOW
    src: any
    dst: any
    protocol: TCP
    port: 65535
"#;

        let policy = validate_policy(yaml).expect("65535 is valid u16");

        assert_eq!(policy.rules[0].port, Some(u16::MAX));
    }

    #[test]
    fn validate_policy_rejects_malformed_yaml_missing_fields_and_bad_port_type() {
        assert!(validate_policy("policy_id: [not closed").is_err());

        let missing_rules = r#"
policy_id: missing-rules
version: "1"
"#;
        assert!(validate_policy(missing_rules).is_err());

        let missing_rule_field = r#"
policy_id: missing-rule-field
version: "1"
rules:
  - id: no-protocol
    action: ALLOW
    src: any
    dst: any
"#;
        assert!(validate_policy(missing_rule_field).is_err());

        let port_too_large = r#"
policy_id: bad-port
version: "1"
rules:
  - id: oversized
    action: ALLOW
    src: any
    dst: any
    protocol: TCP
    port: 65536
"#;
        assert!(validate_policy(port_too_large).is_err());

        let port_not_number = r#"
policy_id: bad-port-type
version: "1"
rules:
  - id: string-port
    action: ALLOW
    src: any
    dst: any
    protocol: TCP
    port: https
"#;
        assert!(validate_policy(port_not_number).is_err());
    }

    #[test]
    fn validate_policy_allows_empty_rules_and_ignores_unknown_fields() {
        let yaml = r#"
policy_id: empty-rules
version: "1"
description: ignored by typed policy
rules: []
"#;

        let policy = validate_policy(yaml).expect("empty rule list is structurally valid");

        assert_eq!(policy.policy_id, "empty-rules");
        assert!(policy.rules.is_empty());
    }

    #[test]
    fn canonical_policy_bytes_are_deterministic_and_use_fixed_field_order() {
        let policy = Policy {
            policy_id: "canonical".to_string(),
            version: "9".to_string(),
            rules: vec![
                Rule {
                    id: "with-port".to_string(),
                    action: "ALLOW".to_string(),
                    src: "a".to_string(),
                    dst: "b".to_string(),
                    protocol: "TCP".to_string(),
                    port: Some(443),
                },
                Rule {
                    id: "without-port".to_string(),
                    action: "DENY".to_string(),
                    src: "c".to_string(),
                    dst: "d".to_string(),
                    protocol: "UDP".to_string(),
                    port: None,
                },
            ],
        };

        let canonical = String::from_utf8(canonical_policy_bytes(&policy)).unwrap();

        assert_eq!(
            canonical,
            r#"{"policy_id":"canonical","rules":[{"action":"ALLOW","dst":"b","id":"with-port","port":443,"protocol":"TCP","src":"a"},{"action":"DENY","dst":"d","id":"without-port","port":null,"protocol":"UDP","src":"c"}],"version":"9"}"#
        );
        assert_eq!(
            canonical_policy_bytes(&policy),
            canonical_policy_bytes(&policy)
        );
    }

    #[test]
    fn canonical_policy_digest_matches_sha256_of_canonical_bytes() {
        let policy = one_rule_policy();
        let expected = hex::encode(Sha256::digest(canonical_policy_bytes(&policy)));

        assert_eq!(canonical_policy_digest(&policy), expected);
        assert_eq!(canonical_policy_digest(&policy).len(), 64);
    }

    #[test]
    fn canonical_policy_material_returns_canonical_json_digest_and_source() {
        let policy = one_rule_policy();
        let material = canonical_policy_material(&policy, "unit-test-source");

        assert_eq!(material.source, "unit-test-source");
        assert_eq!(
            material.yaml,
            String::from_utf8(canonical_policy_bytes(&policy)).unwrap()
        );
        assert_eq!(material.digest_hex, canonical_policy_digest(&policy));

        let cloned = material.clone();
        assert_eq!(material, cloned);
    }

    #[test]
    fn load_policy_material_from_path_handles_valid_missing_and_invalid_files() {
        let td = tempdir().expect("create temp dir");
        let valid_path = td.path().join("valid.yaml");
        let invalid_path = td.path().join("invalid.yaml");
        let missing_path = td.path().join("missing.yaml");
        fs::write(&valid_path, SCHEMA_POLICY_YAML).expect("write valid policy");
        fs::write(&invalid_path, "policy_id: invalid\nversion: 1\n").expect("write invalid");

        let material = load_policy_material_from_path(&valid_path, "valid-source")
            .expect("valid policy material");
        let parsed = validate_policy(SCHEMA_POLICY_YAML).expect("parse schema policy");
        assert_eq!(material.source, "valid-source");
        assert_eq!(material.digest_hex, canonical_policy_digest(&parsed));

        assert!(load_policy_material_from_path(&missing_path, "missing-source").is_none());
        assert!(load_policy_material_from_path(&invalid_path, "invalid-source").is_none());
    }

    #[test]
    fn effective_policy_material_falls_back_to_schema_when_active_file_missing_or_invalid() {
        let td = tempdir().expect("create temp dir");
        let missing_active_path = td.path().join("missing-active.yaml");
        let invalid_active_path = td.path().join("invalid-active.yaml");
        let schema_path = td.path().join("schema.yaml");
        fs::write(&invalid_active_path, "policy_id: invalid\nversion: 1\n")
            .expect("write invalid active");
        fs::write(&schema_path, SCHEMA_POLICY_YAML).expect("write schema policy");

        for active_path in [&missing_active_path, &invalid_active_path] {
            let material =
                load_effective_policy_material_from_sources(None, active_path, &schema_path);

            assert_eq!(material.source, "schema-canonical");
            assert_eq!(
                material.yaml,
                canonical_policy_material(
                    &validate_policy(SCHEMA_POLICY_YAML).unwrap(),
                    "schema-canonical"
                )
                .yaml
            );
        }
    }

    #[test]
    fn effective_policy_material_falls_back_to_constant_default_when_files_unusable() {
        let td = tempdir().expect("create temp dir");
        let missing_active_path = td.path().join("missing-active.yaml");
        let missing_schema_path = td.path().join("missing-schema.yaml");

        let material = load_effective_policy_material_from_sources(
            None,
            &missing_active_path,
            &missing_schema_path,
        );
        let default_policy =
            validate_policy(DEFAULT_EFFECTIVE_POLICY_YAML).expect("default policy parses");

        assert_eq!(material.source, "constant-default");
        assert_eq!(
            material.digest_hex,
            canonical_policy_digest(&default_policy)
        );

        let invalid_active_path = td.path().join("invalid-active.yaml");
        let invalid_schema_path = td.path().join("invalid-schema.yaml");
        fs::write(&invalid_active_path, "not: a policy\n").expect("write invalid active");
        fs::write(&invalid_schema_path, "rules: nope\n").expect("write invalid schema");

        let invalid_material = load_effective_policy_material_from_sources(
            None,
            &invalid_active_path,
            &invalid_schema_path,
        );
        assert_eq!(invalid_material, material);
    }

    #[test]
    fn load_policy_runtime_updates_cache_and_invalid_yaml_does_not_replace_existing_policy() {
        // The active-policy cache is a process-global; these two tests both
        // clear and repopulate it, so they must not interleave.
        let _lock = crate::test_support::env_lock();
        clear_active_policy_cache();

        load_policy_runtime(ACTIVE_POLICY_YAML).expect("load runtime policy");
        let active = get_active_policy().expect("active policy should be cached");
        assert_eq!(active.policy_id, "active-policy");

        let err = load_policy_runtime("policy_id: invalid\nversion: 1\n")
            .expect_err("invalid runtime policy should fail");
        assert!(!err.to_string().is_empty());

        let still_active = get_active_policy().expect("active policy should remain cached");
        assert_eq!(still_active.policy_id, "active-policy");

        clear_active_policy_cache();
        assert!(get_active_policy().is_none());
    }

    #[test]
    fn runtime_cache_returns_cloned_policy_not_shared_mutable_state() {
        // The active-policy cache is a process-global; these two tests both
        // clear and repopulate it, so they must not interleave.
        let _lock = crate::test_support::env_lock();
        clear_active_policy_cache();
        load_policy_runtime(ACTIVE_POLICY_YAML).expect("load runtime policy");

        let mut first = get_active_policy().expect("first active policy");
        first.policy_id = "mutated-copy".to_string();
        first.rules.clear();

        let second = get_active_policy().expect("second active policy");
        assert_eq!(second.policy_id, "active-policy");
        assert_eq!(second.rules.len(), 1);

        clear_active_policy_cache();
    }
}
