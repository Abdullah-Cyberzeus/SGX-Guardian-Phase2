use crate::api::state::AppState;
use crate::backup::errors::BackupError;
use crate::backup::model::{Component, ComponentManifest, IdentityMeta, COMPONENT_SCHEMA_VERSION};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ComponentPath {
    pub component: Component,
    pub source: PathBuf,
    pub archive_path: String,
    pub recursive: bool,
}

#[derive(Debug, Clone)]
pub struct GatheredFile {
    pub component: Component,
    pub archive_path: String,
    pub source_path: PathBuf,
    pub bytes: Vec<u8>,
}

pub async fn gather_files(state: &AppState) -> Result<Vec<GatheredFile>, BackupError> {
    let mut out = Vec::new();
    for component_path in component_paths(state) {
        if component_path.component != Component::Tls
            && is_sensitive_backup_path(&component_path.source)
        {
            continue;
        }
        if !tokio::fs::try_exists(&component_path.source).await? {
            continue;
        }
        let meta = tokio::fs::metadata(&component_path.source).await?;
        if meta.is_dir() {
            if component_path.recursive {
                gather_tree(&component_path, &mut out).await?;
            }
            continue;
        }
        if meta.is_file() {
            out.push(GatheredFile {
                component: component_path.component,
                archive_path: component_path.archive_path,
                source_path: component_path.source.clone(),
                bytes: tokio::fs::read(&component_path.source).await?,
            });
        }
    }
    Ok(out)
}

async fn gather_tree(root: &ComponentPath, out: &mut Vec<GatheredFile>) -> Result<(), BackupError> {
    let mut stack = vec![root.source.clone()];
    while let Some(dir) = stack.pop() {
        let mut entries = tokio::fs::read_dir(&dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let meta = entry.metadata().await?;
            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            if is_sensitive_backup_path(&path) || is_transient_backup_path(&path) {
                continue;
            }
            let relative = path.strip_prefix(&root.source).map_err(|_| {
                BackupError::InvalidRequest(format!(
                    "could not relativize {} under {}",
                    path.display(),
                    root.source.display()
                ))
            })?;
            let relative = relative.to_string_lossy().replace('\\', "/");
            out.push(GatheredFile {
                component: root.component,
                archive_path: format!("{}/{}", root.archive_path, relative),
                source_path: path.clone(),
                bytes: tokio::fs::read(path).await?,
            });
        }
    }
    Ok(())
}

pub fn component_manifest(files: &[GatheredFile]) -> Vec<ComponentManifest> {
    let mut components = Vec::new();
    for component in all_components() {
        let mut paths = files
            .iter()
            .filter(|file| file.component == component)
            .map(|file| file.archive_path.clone())
            .collect::<Vec<_>>();
        paths.sort();
        if !paths.is_empty() || component == Component::IdentityMeta {
            components.push(ComponentManifest {
                component,
                schema_version: COMPONENT_SCHEMA_VERSION,
                paths,
            });
        }
    }
    components
}

pub fn identity_meta(state: &AppState) -> IdentityMeta {
    let public_hash = hex::encode(Sha256::digest(&state.device_pubkey_point));
    IdentityMeta {
        did: state.device_did.clone(),
        dkp_slot_id: "0x20000010".to_string(),
        dik_slot_id: "0x20000100".to_string(),
        dkp_public_versions: vec![public_hash],
    }
}

pub fn component_paths(state: &AppState) -> Vec<ComponentPath> {
    let mut paths = Vec::new();
    let data_root = data_root_from_state(state);
    let config_dir = Path::new(&state.config_dir);
    let discovery_config_dir = Path::new(&state.discovery_config_dir);
    let discovery_state_dir = Path::new(&state.discovery_state_dir);
    let identity_dir = data_root.join("identity");
    let keys_dir = Path::new(&state.keys_dir);
    let nebula_dir = data_root.join("nebula");
    let vc_dir = identity_dir.join("vc");
    let crl_dir = identity_dir.join("crl");
    let cot_dir = data_root.join("cot");
    let boot_dir = Path::new(&state.boot_dir);
    let sgx_agent_dir = data_root.join("sgx-agent");

    let policy_dir = crate::policy_state::active_policy_file_path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(crate::policy_state::POLICY_DIR));
    add_file(
        &mut paths,
        Component::Policy,
        policy_dir.join("active_policy.yaml"),
        "policy/active_policy.yaml",
    );
    add_file(
        &mut paths,
        Component::Policy,
        policy_dir.join("backup_policy.yaml"),
        "policy/backup_policy.yaml",
    );
    add_file(
        &mut paths,
        Component::Policy,
        policy_dir.join("pending_policy.yaml"),
        "policy/pending_policy.yaml",
    );
    add_file(
        &mut paths,
        Component::Policy,
        policy_dir.join("policy.sig"),
        "policy/policy.sig",
    );
    add_file(
        &mut paths,
        Component::Policy,
        policy_dir.join("pa_admin_pub.der"),
        "policy/pa_admin_pub.der",
    );
    add_file(
        &mut paths,
        Component::Config,
        config_dir.join(format!("{}.yaml", state.node_id)),
        format!("config/{}.yaml", state.node_id),
    );
    add_file(
        &mut paths,
        Component::Config,
        config_dir.join("se050.yaml"),
        "config/se050.yaml",
    );
    add_file(
        &mut paths,
        Component::Config,
        config_dir.join("policy-authority.pub"),
        "config/policy-authority.pub",
    );
    add_file(
        &mut paths,
        Component::Config,
        "/etc/sgx-guardian/guardian_public.key",
        "config/guardian_public.key",
    );
    add_file(
        &mut paths,
        Component::Config,
        discovery_config_dir.join("nmap.yaml"),
        "config/discovery/nmap.yaml",
    );
    add_file(
        &mut paths,
        Component::Config,
        discovery_config_dir.join("whitelist.yaml"),
        "config/discovery/whitelist.yaml",
    );
    add_file(
        &mut paths,
        Component::Tls,
        sgx_agent_dir.join(format!("device_{}.key", state.node_id)),
        format!("tls/device_{}.key", state.node_id),
    );
    add_file(
        &mut paths,
        Component::Tls,
        sgx_agent_dir.join(format!("device_{}_cert.der", state.node_id)),
        format!("tls/device_{}_cert.der", state.node_id),
    );
    add_file(
        &mut paths,
        Component::Nftables,
        data_root.join("nftables/current.nft"),
        "nftables/current.nft",
    );
    add_file(
        &mut paths,
        Component::Nftables,
        data_root.join("nftables/previous.nft"),
        "nftables/previous.nft",
    );
    add_file(
        &mut paths,
        Component::State,
        Path::new(&state.pcr_baseline_dir).join(format!("pcr_{}_baseline.json", state.node_id)),
        format!("state/pcr/pcr_{}_baseline.json", state.node_id),
    );
    add_file(
        &mut paths,
        Component::State,
        Path::new(&state.pcr_dir).join(format!("{}_current.json", state.node_id)),
        format!("state/pcr/{}_current.json", state.node_id),
    );
    add_tree(
        &mut paths,
        Component::State,
        discovery_state_dir,
        "state/discovery",
    );
    add_file(
        &mut paths,
        Component::State,
        identity_dir.join(format!("virtual_id_session_{}.json", state.node_id)),
        format!("state/virtual_id_session_{}.json", state.node_id),
    );
    add_file(
        &mut paths,
        Component::State,
        boot_dir.join(format!("{}_chain_status.json", state.node_id)),
        format!("state/boot/{}_chain_status.json", state.node_id),
    );
    add_file(
        &mut paths,
        Component::State,
        Path::new(&state.log_dir_primary).join(format!("trusted_peers_{}.json", state.node_id)),
        format!("state/trusted_peers_{}.json", state.node_id),
    );
    add_file(
        &mut paths,
        Component::State,
        Path::new(&state.log_dir_primary).join("trusted_peers.json"),
        "state/trusted_peers.json",
    );
    add_file(
        &mut paths,
        Component::State,
        Path::new(&state.log_dir_fallback).join(format!("trusted_peers_{}.json", state.node_id)),
        format!("state/fallback_trusted_peers_{}.json", state.node_id),
    );
    add_file(
        &mut paths,
        Component::State,
        Path::new(&state.log_dir_fallback).join("trusted_peers.json"),
        "state/fallback_trusted_peers.json",
    );
    add_file(
        &mut paths,
        Component::State,
        Path::new(&state.log_dir_primary).join("last_attestation.json"),
        "state/attestation/last_attestation.json",
    );
    add_file(
        &mut paths,
        Component::State,
        Path::new(&state.log_dir_fallback).join("last_attestation.json"),
        "state/attestation/fallback_last_attestation.json",
    );
    add_file(
        &mut paths,
        Component::State,
        Path::new(&state.log_dir_primary).join("attestation_results.json"),
        "state/attestation/attestation_results.json",
    );
    add_file(
        &mut paths,
        Component::IdentityMeta,
        identity_dir.join("did.json"),
        "identity/did.json",
    );
    add_file(
        &mut paths,
        Component::IdentityMeta,
        identity_dir.join("did_doc.json"),
        "identity/did_doc.json",
    );
    add_file(
        &mut paths,
        Component::IdentityMeta,
        identity_dir.join("circle_did_docs.json"),
        "identity/circle_did_docs.json",
    );
    add_file(
        &mut paths,
        Component::IdentityMeta,
        data_root.join("did/self_version_counter"),
        "identity/self_version_counter",
    );
    add_tree(
        &mut paths,
        Component::IdentityMeta,
        identity_dir.join("peers"),
        "identity/peers",
    );
    add_file(
        &mut paths,
        Component::IdentityMeta,
        keys_dir.join("dkp_pub.der"),
        "identity/keys/dkp_pub.der",
    );
    add_file(
        &mut paths,
        Component::IdentityMeta,
        keys_dir.join("dkp_metadata.json"),
        "identity/keys/dkp_metadata.json",
    );
    add_file(
        &mut paths,
        Component::IdentityMeta,
        keys_dir.join("dik_pub.der"),
        "identity/keys/dik_pub.der",
    );
    add_file(
        &mut paths,
        Component::IdentityMeta,
        keys_dir.join("dik_metadata.json"),
        "identity/keys/dik_metadata.json",
    );
    add_tree(
        &mut paths,
        Component::Credentials,
        vc_dir.join("issued"),
        "credentials/vc/issued",
    );
    add_tree(
        &mut paths,
        Component::Credentials,
        vc_dir.join("own"),
        "credentials/vc/own",
    );
    add_tree(
        &mut paths,
        Component::Credentials,
        vc_dir.join("peers"),
        "credentials/vc/peers",
    );
    add_file(
        &mut paths,
        Component::Credentials,
        vc_dir.join("status_list.json"),
        "credentials/vc/status_list.json",
    );
    add_file(
        &mut paths,
        Component::Credentials,
        vc_dir.join("status_list_index.json"),
        "credentials/vc/status_list_index.json",
    );
    add_file(
        &mut paths,
        Component::Credentials,
        cot_dir.join("members.json"),
        "credentials/cot/members.json",
    );
    add_file(
        &mut paths,
        Component::Crl,
        crl_dir.join("crl.json"),
        "crl/crl.json",
    );
    add_tree(
        &mut paths,
        Component::Crl,
        crl_dir.join("entries"),
        "crl/entries",
    );
    add_tree(
        &mut paths,
        Component::Crl,
        crl_dir.join("pending"),
        "crl/pending",
    );
    add_tree(
        &mut paths,
        Component::Crl,
        crl_dir.join("tombstones"),
        "crl/tombstones",
    );
    add_file(
        &mut paths,
        Component::Nebula,
        nebula_dir.join("overlay_registry.json"),
        "nebula/overlay_registry.json",
    );
    add_file(
        &mut paths,
        Component::Nebula,
        nebula_dir.join("lighthouse_registry.json"),
        "nebula/lighthouse_registry.json",
    );
    add_file(
        &mut paths,
        Component::Nebula,
        nebula_dir.join("relay_registry.json"),
        "nebula/relay_registry.json",
    );
    add_file(
        &mut paths,
        Component::Nebula,
        nebula_dir.join("local_ip_cache.json"),
        "nebula/local_ip_cache.json",
    );
    add_file(
        &mut paths,
        Component::Nebula,
        nebula_dir.join("nebula.yaml"),
        "nebula/nebula.yaml",
    );
    add_file(
        &mut paths,
        Component::Nebula,
        nebula_dir.join("relay_stats.json"),
        "nebula/relay_stats.json",
    );
    add_file(
        &mut paths,
        Component::Nebula,
        nebula_dir.join("ca/ca.crt"),
        "nebula/ca/ca.crt",
    );
    add_file(
        &mut paths,
        Component::Nebula,
        nebula_dir.join(format!("nodes/{}.crt", state.node_id)),
        format!("nebula/nodes/{}.crt", state.node_id),
    );
    add_file(
        &mut paths,
        Component::Nebula,
        nebula_dir.join("am_lighthouse"),
        "nebula/am_lighthouse",
    );
    add_file(
        &mut paths,
        Component::Nebula,
        nebula_dir.join("am_relay"),
        "nebula/am_relay",
    );
    paths
}

pub fn assert_no_private_identity_paths(paths: &[ComponentPath]) -> Result<(), BackupError> {
    for path in paths {
        if path.component != Component::Tls && is_sensitive_backup_path(&path.source) {
            return Err(BackupError::InvalidRequest(format!(
                "private key material is not allowed in backups: {}",
                path.source.display()
            )));
        }
    }
    Ok(())
}

fn all_components() -> [Component; 11] {
    [
        Component::Policy,
        Component::Config,
        Component::Nebula,
        Component::Nftables,
        Component::IdentityMeta,
        Component::Tls,
        Component::Credentials,
        Component::Crl,
        Component::State,
        Component::FeatureState,
        Component::Vault,
    ]
}

fn add_file(
    paths: &mut Vec<ComponentPath>,
    component: Component,
    source: impl Into<PathBuf>,
    archive_path: impl Into<String>,
) {
    paths.push(ComponentPath {
        component,
        source: source.into(),
        archive_path: archive_path.into(),
        recursive: false,
    });
}

fn add_tree(
    paths: &mut Vec<ComponentPath>,
    component: Component,
    source: impl Into<PathBuf>,
    archive_path: impl Into<String>,
) {
    paths.push(ComponentPath {
        component,
        source: source.into(),
        archive_path: archive_path.into(),
        recursive: true,
    });
}

fn data_root_from_state(state: &AppState) -> PathBuf {
    Path::new(&state.keys_dir)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/var/lib/sgx-guardian"))
}

fn is_sensitive_backup_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let lower_name = name.to_ascii_lowercase();
    let lower_path = path.to_string_lossy().to_ascii_lowercase();

    if matches!(
        lower_name.as_str(),
        "guardian_public.key" | "pa_admin_pub.der"
    ) {
        return false;
    }

    lower_name == "identity.key"
        || lower_name == "guardian_private.key"
        || lower_name == "pa_admin_priv.der"
        || lower_name == "ca.key"
        || lower_name == "dkp.key"
        || lower_name == "dik.key"
        || lower_name.contains("private")
        || lower_name.contains("_priv")
        || lower_name.contains("-priv")
        || lower_path.contains("/nebula/ca/") && lower_name.ends_with(".key")
        || lower_path.contains("/nebula/nodes/") && lower_name.ends_with(".key")
        || lower_path.contains("/se050/")
        || lower_path.contains("se050_scp_keys")
}

fn is_transient_backup_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| matches!(ext, "tmp" | "lock"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_components_includes_every_manifest_variant_in_order() {
        assert_eq!(
            all_components(),
            [
                Component::Policy,
                Component::Config,
                Component::Nebula,
                Component::Nftables,
                Component::IdentityMeta,
                Component::Tls,
                Component::Credentials,
                Component::Crl,
                Component::State,
                Component::FeatureState,
                Component::Vault,
            ]
        );
    }

    #[test]
    fn add_file_records_non_recursive_component_path() {
        let mut paths = Vec::new();
        add_file(
            &mut paths,
            Component::Config,
            "/tmp/a.yaml",
            "config/a.yaml",
        );
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].component, Component::Config);
        assert_eq!(paths[0].source, PathBuf::from("/tmp/a.yaml"));
        assert_eq!(paths[0].archive_path, "config/a.yaml");
        assert!(!paths[0].recursive);
    }

    #[test]
    fn add_tree_records_recursive_component_path() {
        let mut paths = Vec::new();
        add_tree(&mut paths, Component::State, "/tmp/state", "state");
        assert_eq!(paths[0].component, Component::State);
        assert_eq!(paths[0].source, PathBuf::from("/tmp/state"));
        assert_eq!(paths[0].archive_path, "state");
        assert!(paths[0].recursive);
    }

    #[test]
    fn component_manifest_sorts_paths_and_includes_identity_meta_when_empty() {
        let files = vec![
            GatheredFile {
                component: Component::Config,
                archive_path: "config/z.yaml".into(),
                source_path: PathBuf::from("/tmp/z"),
                bytes: vec![1],
            },
            GatheredFile {
                component: Component::Config,
                archive_path: "config/a.yaml".into(),
                source_path: PathBuf::from("/tmp/a"),
                bytes: vec![2],
            },
        ];
        let manifest = component_manifest(&files);
        let config = manifest
            .iter()
            .find(|item| item.component == Component::Config)
            .unwrap();
        assert_eq!(config.paths, vec!["config/a.yaml", "config/z.yaml"]);
        assert!(manifest
            .iter()
            .any(|item| item.component == Component::IdentityMeta && item.paths.is_empty()));
    }

    #[test]
    fn component_manifest_omits_empty_non_identity_components() {
        let manifest = component_manifest(&[]);
        assert_eq!(manifest.len(), 1);
        assert_eq!(manifest[0].component, Component::IdentityMeta);
    }

    #[test]
    fn public_key_allowlist_is_not_sensitive() {
        assert!(!is_sensitive_backup_path(Path::new(
            "/x/guardian_public.key"
        )));
        assert!(!is_sensitive_backup_path(Path::new("/x/pa_admin_pub.der")));
    }

    #[test]
    fn exact_private_key_names_are_sensitive() {
        for name in [
            "identity.key",
            "guardian_private.key",
            "pa_admin_priv.der",
            "ca.key",
            "dkp.key",
            "dik.key",
        ] {
            assert!(is_sensitive_backup_path(Path::new(name)), "{name}");
        }
    }

    #[test]
    fn private_name_fragments_are_sensitive_case_insensitively() {
        assert!(is_sensitive_backup_path(Path::new("/tmp/MyPrivate.pem")));
        assert!(is_sensitive_backup_path(Path::new("/tmp/node_priv.der")));
        assert!(is_sensitive_backup_path(Path::new("/tmp/node-priv.der")));
    }

    #[test]
    fn nebula_ca_and_node_key_paths_are_sensitive() {
        assert!(is_sensitive_backup_path(Path::new(
            "/data/nebula/ca/ca.key"
        )));
        assert!(is_sensitive_backup_path(Path::new(
            "/data/nebula/nodes/node.key"
        )));
        assert!(!is_sensitive_backup_path(Path::new(
            "/data/nebula/nodes/node.crt"
        )));
    }

    #[test]
    fn se050_paths_are_sensitive() {
        assert!(is_sensitive_backup_path(Path::new(
            "/etc/sgx/se050/config.yaml"
        )));
        assert!(is_sensitive_backup_path(Path::new(
            "/etc/sgx/se050_scp_keys.yaml"
        )));
    }

    #[test]
    fn ordinary_certificate_and_config_paths_are_not_sensitive() {
        assert!(!is_sensitive_backup_path(Path::new("/tmp/node.crt")));
        assert!(!is_sensitive_backup_path(Path::new("/tmp/config.yaml")));
        assert!(!is_sensitive_backup_path(Path::new("/tmp/dkp_pub.der")));
    }

    #[test]
    fn transient_backup_extensions_are_filtered() {
        assert!(is_transient_backup_path(Path::new("/tmp/a.tmp")));
        assert!(is_transient_backup_path(Path::new("/tmp/a.lock")));
        assert!(!is_transient_backup_path(Path::new("/tmp/a.json")));
        assert!(!is_transient_backup_path(Path::new("/tmp/no_extension")));
    }

    #[test]
    fn assert_no_private_identity_paths_allows_tls_private_material() {
        let paths = vec![ComponentPath {
            component: Component::Tls,
            source: PathBuf::from("/tmp/device.key"),
            archive_path: "tls/device.key".into(),
            recursive: false,
        }];
        assert!(assert_no_private_identity_paths(&paths).is_ok());
    }

    #[test]
    fn assert_no_private_identity_paths_rejects_non_tls_private_material() {
        let paths = vec![ComponentPath {
            component: Component::Credentials,
            source: PathBuf::from("/tmp/device_private.key"),
            archive_path: "credentials/device_private.key".into(),
            recursive: false,
        }];
        assert!(matches!(
            assert_no_private_identity_paths(&paths),
            Err(BackupError::InvalidRequest(_))
        ));
    }
}
