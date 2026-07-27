use crate::did::doc_sign;
use crate::key_manager::KeyManager;
use crate::rules::errors::{RulesError, RulesResult};
use crate::rules::model::{Rule, RuleDraft, RulePatch, RuleRegistry};
use base64::{engine::general_purpose, Engine as _};
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Mutex;

pub static RULES_WRITE_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

pub fn load_registry(base: &Path, node_id: &str) -> RulesResult<RuleRegistry> {
    let paths = crate::rules::persistence::RulesPaths::from_base(base);
    if !paths.rules_file.exists() {
        return Ok(RuleRegistry::default());
    }
    let km = crate::vc::issue::load_runtime_key_manager(node_id)
        .map_err(|error| RulesError::RegistryRejected(format!("load key manager: {}", error)))?;
    load_registry_with_key(base, node_id, &km)
}

pub fn load_registry_with_key(
    base: &Path,
    node_id: &str,
    km: &KeyManager,
) -> RulesResult<RuleRegistry> {
    let paths = crate::rules::persistence::RulesPaths::from_base(base);
    let Some(registry) =
        crate::rules::persistence::read_json_if_exists::<RuleRegistry>(&paths.rules_file)?
    else {
        return Ok(RuleRegistry::default());
    };
    verify_registry(&registry, km)?;
    tracing::debug!(
        node_id = node_id,
        sequence = registry.sequence,
        rules = registry.rules.len(),
        "rules registry verified"
    );
    Ok(registry)
}

pub fn save_registry(
    base: &Path,
    node_id: &str,
    km: &KeyManager,
    registry: &mut RuleRegistry,
) -> RulesResult<()> {
    registry.sequence = registry.sequence.saturating_add(1);
    sign_registry(registry, node_id, km)?;
    let paths = crate::rules::persistence::RulesPaths::from_base(base);
    let bytes = serde_json::to_vec_pretty(registry)?;
    crate::rules::persistence::write_atomic(&paths.rules_file, &bytes)
}

pub fn create_rule(
    base: &Path,
    node_id: &str,
    km: &KeyManager,
    draft: RuleDraft,
) -> RulesResult<Rule> {
    validate_draft(&draft)?;
    let _guard = RULES_WRITE_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut registry = load_registry_with_key(base, node_id, km)?;
    let rule = Rule::from_draft(draft);
    if registry
        .rules
        .iter()
        .any(|item| item.rule_id == rule.rule_id)
    {
        return Err(RulesError::InvalidRule(format!(
            "duplicate rule_id {}",
            rule.rule_id
        )));
    }
    registry.rules.push(rule.clone());
    save_registry(base, node_id, km, &mut registry)?;
    Ok(rule)
}

pub fn list_rules(base: &Path, node_id: &str, km: &KeyManager) -> RulesResult<Vec<Rule>> {
    let registry = load_registry_with_key(base, node_id, km)?;
    Ok(registry.rules)
}

pub fn get_rule(base: &Path, node_id: &str, km: &KeyManager, id: &str) -> RulesResult<Rule> {
    let registry = load_registry_with_key(base, node_id, km)?;
    registry
        .rules
        .into_iter()
        .find(|rule| rule.rule_id == id)
        .ok_or_else(|| RulesError::NotFound(id.to_string()))
}

pub fn edit_rule(
    base: &Path,
    node_id: &str,
    km: &KeyManager,
    id: &str,
    patch: RulePatch,
) -> RulesResult<Rule> {
    validate_patch(&patch)?;
    let _guard = RULES_WRITE_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut registry = load_registry_with_key(base, node_id, km)?;
    let rule = registry
        .rules
        .iter_mut()
        .find(|rule| rule.rule_id == id)
        .ok_or_else(|| RulesError::NotFound(id.to_string()))?;
    rule.apply_patch(patch);
    let updated = rule.clone();
    save_registry(base, node_id, km, &mut registry)?;
    Ok(updated)
}

pub fn set_enabled(
    base: &Path,
    node_id: &str,
    km: &KeyManager,
    id: &str,
    enabled: bool,
) -> RulesResult<Rule> {
    edit_rule(
        base,
        node_id,
        km,
        id,
        RulePatch {
            enabled: Some(enabled),
            ..RulePatch::default()
        },
    )
}

pub fn delete_rule(base: &Path, node_id: &str, km: &KeyManager, id: &str) -> RulesResult<bool> {
    let _guard = RULES_WRITE_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut registry = load_registry_with_key(base, node_id, km)?;
    let before = registry.rules.len();
    registry.rules.retain(|rule| rule.rule_id != id);
    if registry.rules.len() == before {
        return Err(RulesError::NotFound(id.to_string()));
    }
    save_registry(base, node_id, km, &mut registry)?;
    Ok(true)
}

pub fn sign_registry(
    registry: &mut RuleRegistry,
    node_id: &str,
    km: &KeyManager,
) -> RulesResult<()> {
    let canonical = registry.canonical_bytes_for_sign()?;
    let vm_ref = registry_vm_ref(node_id);
    doc_sign::sign_in_place_generic(&mut registry.proof, &canonical, km, &vm_ref)
        .map_err(|error| RulesError::InvalidProof(error.to_string()))
}

pub fn verify_registry(registry: &RuleRegistry, km: &KeyManager) -> RulesResult<()> {
    if registry.proof.proof_value.trim().is_empty() {
        return Err(RulesError::MissingProof);
    }
    let canonical = registry.canonical_bytes_for_sign()?;
    let digest = Sha256::digest(&canonical);
    let signature = general_purpose::STANDARD.decode(&registry.proof.proof_value)?;
    let public_key = km
        .pubkey_der()
        .map_err(|error| RulesError::InvalidProof(format!("public key: {}", error)))?;
    doc_sign::ecdsa_p256_verify_der_or_raw(&public_key, &digest, &signature)
        .map_err(|error| RulesError::InvalidProof(error.to_string()))
}

fn validate_draft(draft: &RuleDraft) -> RulesResult<()> {
    if draft
        .name
        .as_deref()
        .is_some_and(|name| name.trim().is_empty())
    {
        return Err(RulesError::InvalidRule(
            "name must not be empty".to_string(),
        ));
    }
    if draft.cooldown_secs == Some(0) {
        return Err(RulesError::InvalidRule(
            "cooldown_secs must be greater than zero".to_string(),
        ));
    }
    if draft.max_actions_per_hour == Some(0) {
        return Err(RulesError::InvalidRule(
            "max_actions_per_hour must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

fn validate_patch(patch: &RulePatch) -> RulesResult<()> {
    if patch
        .name
        .as_deref()
        .is_some_and(|name| name.trim().is_empty())
    {
        return Err(RulesError::InvalidRule(
            "name must not be empty".to_string(),
        ));
    }
    if patch.cooldown_secs == Some(0) {
        return Err(RulesError::InvalidRule(
            "cooldown_secs must be greater than zero".to_string(),
        ));
    }
    if patch.max_actions_per_hour == Some(0) {
        return Err(RulesError::InvalidRule(
            "max_actions_per_hour must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

fn registry_vm_ref(node_id: &str) -> String {
    crate::vc::issue::subject_did_for_node(node_id)
        .map(|did| format!("{}#dkp-v1", did))
        .unwrap_or_else(|_| format!("did:guardian:{}#dkp-v1", node_id))
}

#[cfg(test)]
mod tests {
    use super::{validate_draft, validate_patch};
    use crate::rules::errors::RulesError;
    use crate::rules::model::{RuleDraft, RulePatch};

    #[test]
    fn validate_draft_accepts_defaults() {
        assert!(validate_draft(&RuleDraft::default()).is_ok());
    }

    #[test]
    fn validate_draft_rejects_blank_name() {
        let err = validate_draft(&RuleDraft {
            name: Some("   ".to_string()),
            ..RuleDraft::default()
        })
        .unwrap_err();
        assert!(matches!(err, RulesError::InvalidRule(msg) if msg.contains("name")));
    }

    #[test]
    fn validate_draft_accepts_non_empty_name() {
        assert!(validate_draft(&RuleDraft {
            name: Some("Critical alerts".to_string()),
            ..RuleDraft::default()
        })
        .is_ok());
    }

    #[test]
    fn validate_draft_rejects_zero_cooldown_and_zero_rate_cap() {
        let cooldown_err = validate_draft(&RuleDraft {
            cooldown_secs: Some(0),
            ..RuleDraft::default()
        })
        .unwrap_err();
        assert!(matches!(cooldown_err, RulesError::InvalidRule(msg) if msg.contains("cooldown")));

        let rate_err = validate_draft(&RuleDraft {
            max_actions_per_hour: Some(0),
            ..RuleDraft::default()
        })
        .unwrap_err();
        assert!(
            matches!(rate_err, RulesError::InvalidRule(msg) if msg.contains("max_actions_per_hour"))
        );
    }

    #[test]
    fn validate_draft_accepts_nonzero_cooldown_and_rate_cap() {
        assert!(validate_draft(&RuleDraft {
            cooldown_secs: Some(1),
            max_actions_per_hour: Some(1),
            ..RuleDraft::default()
        })
        .is_ok());
    }

    #[test]
    fn validate_patch_mirrors_draft_rules() {
        assert!(validate_patch(&RulePatch::default()).is_ok());

        assert!(matches!(
            validate_patch(&RulePatch {
                name: Some("".to_string()),
                ..RulePatch::default()
            }),
            Err(RulesError::InvalidRule(_))
        ));
        assert!(matches!(
            validate_patch(&RulePatch {
                cooldown_secs: Some(0),
                ..RulePatch::default()
            }),
            Err(RulesError::InvalidRule(_))
        ));
        assert!(matches!(
            validate_patch(&RulePatch {
                max_actions_per_hour: Some(0),
                ..RulePatch::default()
            }),
            Err(RulesError::InvalidRule(_))
        ));
    }

    #[test]
    fn validate_patch_ignores_fields_left_none() {
        assert!(validate_patch(&RulePatch {
            enabled: Some(false),
            ..RulePatch::default()
        })
        .is_ok());
    }
}
