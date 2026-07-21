use crate::did::document::Proof;
use crate::vault::errors::VaultError;
use crate::vault::namespace::{validate_folder_id, validate_folder_name, VaultNamespace};
use crate::vault::persistence;
use crate::vault::{write_lock, VaultConfig};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, VecDeque};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FolderNode {
    pub folder_id: String,
    pub parent_id: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FolderIndex {
    pub namespace: String,
    #[serde(default)]
    pub folders: Vec<FolderNode>,
    #[serde(default)]
    pub sequence: u64,
    #[serde(default)]
    pub proof: Proof,
}

impl FolderIndex {
    pub fn new(namespace: &VaultNamespace) -> Self {
        Self {
            namespace: namespace.storage_key(),
            folders: Vec::new(),
            sequence: 0,
            proof: Proof::default(),
        }
    }

    pub fn without_proof(&self) -> Self {
        let mut clone = self.clone();
        clone.proof = Proof::default();
        clone
    }

    pub fn canonical_bytes_for_sign(&self) -> Result<Vec<u8>, VaultError> {
        let value = serde_json::to_value(self.without_proof())?;
        let sorted = sort_value(&value);
        Ok(serde_json::to_vec(&sorted)?)
    }

    pub fn contains_folder(&self, folder_id: &str) -> bool {
        self.folders
            .iter()
            .any(|folder| folder.folder_id == folder_id)
    }

    pub fn folder(&self, folder_id: &str) -> Option<&FolderNode> {
        self.folders
            .iter()
            .find(|folder| folder.folder_id == folder_id)
    }

    pub fn children_of(&self, parent_id: &str) -> Vec<FolderNode> {
        let mut folders = self
            .folders
            .iter()
            .filter(|folder| folder.parent_id == parent_id)
            .cloned()
            .collect::<Vec<_>>();
        folders.sort_by_key(|folder| folder.name.to_lowercase());
        folders
    }

    pub fn breadcrumbs(&self, folder_id: &str) -> Result<Vec<FolderNode>, VaultError> {
        let folder_id = validate_folder_id(folder_id)?;
        if folder_id.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut current = self
            .folder(&folder_id)
            .cloned()
            .ok_or_else(|| VaultError::NotFound(format!("folder not found: {}", folder_id)))?;
        out.push(current.clone());
        while !current.parent_id.is_empty() {
            current = self.folder(&current.parent_id).cloned().ok_or_else(|| {
                VaultError::InvalidStructure(format!(
                    "folder {} has missing parent {}",
                    current.folder_id, current.parent_id
                ))
            })?;
            out.push(current.clone());
        }
        out.reverse();
        Ok(out)
    }

    pub fn subtree_ids(&self, folder_id: &str) -> Result<Vec<String>, VaultError> {
        let folder_id = validate_folder_id(folder_id)?;
        if folder_id.is_empty() {
            return Ok(Vec::new());
        }
        if !self.contains_folder(&folder_id) {
            return Err(VaultError::NotFound(format!(
                "folder not found: {}",
                folder_id
            )));
        }

        let mut out = Vec::new();
        let mut queue = VecDeque::from([folder_id]);
        while let Some(current) = queue.pop_front() {
            out.push(current.clone());
            for child in self
                .folders
                .iter()
                .filter(|folder| folder.parent_id == current)
                .map(|folder| folder.folder_id.clone())
            {
                queue.push_back(child);
            }
        }
        Ok(out)
    }

    pub fn create_folder(&mut self, parent_id: &str, name: &str) -> Result<FolderNode, VaultError> {
        let parent_id = validate_folder_id(parent_id)?;
        let name = validate_folder_name(name)?;
        self.ensure_parent_exists(&parent_id)?;
        self.ensure_unique_child_name(&parent_id, &name, None)?;

        let folder = FolderNode {
            folder_id: format!("urn:uuid:{}", Uuid::new_v4()),
            parent_id,
            name,
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        self.folders.push(folder.clone());
        self.sequence = self.sequence.saturating_add(1);
        Ok(folder)
    }

    pub fn update_folder(
        &mut self,
        folder_id: &str,
        name: Option<&str>,
        parent_id: Option<&str>,
    ) -> Result<FolderNode, VaultError> {
        let folder_id = validate_folder_id(folder_id)?;
        let existing = self
            .folder(&folder_id)
            .cloned()
            .ok_or_else(|| VaultError::NotFound(format!("folder not found: {}", folder_id)))?;

        let next_parent = match parent_id {
            Some(parent_id) => validate_folder_id(parent_id)?,
            None => existing.parent_id.clone(),
        };
        let next_name = match name {
            Some(name) => validate_folder_name(name)?,
            None => existing.name.clone(),
        };

        self.ensure_parent_exists(&next_parent)?;
        self.ensure_no_cycle(&folder_id, &next_parent)?;
        self.ensure_unique_child_name(&next_parent, &next_name, Some(&folder_id))?;

        let folder = self
            .folders
            .iter_mut()
            .find(|folder| folder.folder_id == folder_id)
            .ok_or_else(|| VaultError::NotFound(format!("folder not found: {}", folder_id)))?;
        folder.parent_id = next_parent;
        folder.name = next_name;
        self.sequence = self.sequence.saturating_add(1);
        Ok(folder.clone())
    }

    pub fn delete_folder(
        &mut self,
        folder_id: &str,
        recursive: bool,
    ) -> Result<Vec<String>, VaultError> {
        let folder_id = validate_folder_id(folder_id)?;
        if folder_id.is_empty() {
            return Err(VaultError::InvalidStructure(
                "root folder cannot be deleted".to_string(),
            ));
        }
        let subtree = self.subtree_ids(&folder_id)?;
        if !recursive && subtree.len() > 1 {
            return Err(VaultError::Conflict(format!(
                "folder {} is not empty",
                folder_id
            )));
        }
        let ids = subtree.iter().cloned().collect::<BTreeSet<_>>();
        self.folders
            .retain(|folder| !ids.contains(&folder.folder_id));
        self.sequence = self.sequence.saturating_add(1);
        Ok(subtree)
    }

    fn ensure_parent_exists(&self, parent_id: &str) -> Result<(), VaultError> {
        if parent_id.is_empty() || self.contains_folder(parent_id) {
            Ok(())
        } else {
            Err(VaultError::NotFound(format!(
                "parent folder not found: {}",
                parent_id
            )))
        }
    }

    fn ensure_unique_child_name(
        &self,
        parent_id: &str,
        name: &str,
        exclude_folder_id: Option<&str>,
    ) -> Result<(), VaultError> {
        let duplicate = self.folders.iter().any(|folder| {
            folder.parent_id == parent_id
                && exclude_folder_id != Some(folder.folder_id.as_str())
                && folder.name.eq_ignore_ascii_case(name)
        });
        if duplicate {
            Err(VaultError::Conflict(format!(
                "folder '{}' already exists in the target location",
                name
            )))
        } else {
            Ok(())
        }
    }

    fn ensure_no_cycle(&self, folder_id: &str, next_parent: &str) -> Result<(), VaultError> {
        if next_parent.is_empty() {
            return Ok(());
        }
        if next_parent == folder_id {
            return Err(VaultError::Conflict(
                "folder cannot be moved into itself".to_string(),
            ));
        }
        let subtree = self.subtree_ids(folder_id)?;
        if subtree.iter().any(|candidate| candidate == next_parent) {
            return Err(VaultError::Conflict(
                "folder move would create a cycle".to_string(),
            ));
        }
        Ok(())
    }
}

pub async fn load_index(
    config: &VaultConfig,
    namespace: &VaultNamespace,
    node_id: &str,
) -> Result<FolderIndex, VaultError> {
    let path = persistence::folder_index_path(config, namespace);
    let Some(index) = persistence::read_json_if_exists::<FolderIndex>(&path).await? else {
        return Ok(FolderIndex::new(namespace));
    };
    if index.namespace != namespace.storage_key() {
        return Err(VaultError::Conflict(format!(
            "folder index namespace mismatch: expected {}, got {}",
            namespace.storage_key(),
            index.namespace
        )));
    }
    verify_index(&index, node_id)?;
    Ok(index)
}

pub async fn save_index(
    config: &VaultConfig,
    namespace: &VaultNamespace,
    node_id: &str,
    index: &FolderIndex,
) -> Result<(), VaultError> {
    let mut signed = index.clone();
    sign_index(&mut signed, node_id)?;
    persistence::save_json_pretty(&persistence::folder_index_path(config, namespace), &signed).await
}

pub async fn create_folder(
    config: &VaultConfig,
    namespace: &VaultNamespace,
    node_id: &str,
    parent_id: &str,
    name: &str,
) -> Result<FolderNode, VaultError> {
    let _guard = write_lock().lock().await;
    let mut index = load_index(config, namespace, node_id).await?;
    let folder = index.create_folder(parent_id, name)?;
    save_index(config, namespace, node_id, &index).await?;
    Ok(folder)
}

pub async fn update_folder(
    config: &VaultConfig,
    namespace: &VaultNamespace,
    node_id: &str,
    folder_id: &str,
    name: Option<&str>,
    parent_id: Option<&str>,
) -> Result<FolderNode, VaultError> {
    let _guard = write_lock().lock().await;
    let mut index = load_index(config, namespace, node_id).await?;
    let folder = index.update_folder(folder_id, name, parent_id)?;
    save_index(config, namespace, node_id, &index).await?;
    Ok(folder)
}

pub async fn delete_folder(
    config: &VaultConfig,
    namespace: &VaultNamespace,
    node_id: &str,
    folder_id: &str,
    recursive: bool,
) -> Result<Vec<String>, VaultError> {
    let _guard = write_lock().lock().await;
    let mut index = load_index(config, namespace, node_id).await?;
    let removed = index.delete_folder(folder_id, recursive)?;
    save_index(config, namespace, node_id, &index).await?;
    Ok(removed)
}

pub async fn list_namespaces(config: &VaultConfig) -> Result<Vec<VaultNamespace>, VaultError> {
    let mut out = BTreeSet::new();
    let mut entries = match tokio::fs::read_dir(persistence::meta_dir(config)).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };

    while let Some(entry) = entries.next_entry().await? {
        if !entry.file_type().await?.is_dir() {
            continue;
        }
        let dir_name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path().join("folders.json");
        let namespace = match persistence::read_json_if_exists::<FolderIndex>(&path).await? {
            Some(index) if !index.namespace.trim().is_empty() => {
                VaultNamespace::parse(&index.namespace)?
            }
            _ => VaultNamespace::parse(&dir_name)?,
        };
        out.insert(namespace.storage_key());
    }

    out.into_iter()
        .map(|namespace| VaultNamespace::parse(&namespace))
        .collect::<Result<Vec<_>, _>>()
}

fn sign_index(index: &mut FolderIndex, node_id: &str) -> Result<(), VaultError> {
    let canonical = index.canonical_bytes_for_sign()?;
    let km = crate::vc::issue::load_runtime_key_manager(node_id)
        .map_err(|error| VaultError::InvalidStructure(format!("load key manager: {}", error)))?;
    let vm_ref = folder_vm_ref(node_id);
    crate::did::doc_sign::sign_in_place_generic(&mut index.proof, &canonical, &km, &vm_ref)
        .map_err(|error| VaultError::Crypto(format!("sign folder index: {}", error)))?;
    Ok(())
}

fn verify_index(index: &FolderIndex, node_id: &str) -> Result<(), VaultError> {
    if index.proof.proof_value.trim().is_empty() {
        return Err(VaultError::Integrity {
            expected: "signed folder index".to_string(),
            got: "missing proof".to_string(),
        });
    }
    let canonical = index.canonical_bytes_for_sign()?;
    let digest = Sha256::digest(&canonical);
    let signature = general_purpose::STANDARD
        .decode(&index.proof.proof_value)
        .map_err(VaultError::Base64)?;
    let km = crate::vc::issue::load_runtime_key_manager(node_id)
        .map_err(|error| VaultError::InvalidStructure(format!("load key manager: {}", error)))?;
    let public_key = km
        .pubkey_der()
        .map_err(|error| VaultError::InvalidStructure(format!("folder verify key: {}", error)))?;
    crate::did::doc_sign::ecdsa_p256_verify_der_or_raw(&public_key, &digest, &signature).map_err(
        |error| VaultError::Integrity {
            expected: "valid folder index signature".to_string(),
            got: error.to_string(),
        },
    )?;
    Ok(())
}

fn folder_vm_ref(node_id: &str) -> String {
    crate::vc::issue::subject_did_for_node(node_id)
        .map(|did| format!("{}#dkp-v1", did))
        .unwrap_or_else(|_| format!("did:guardian:{}#dkp-v1", node_id))
}

fn sort_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort();
            let mut out = serde_json::Map::new();
            for key in keys {
                out.insert(key.clone(), sort_value(&map[key]));
            }
            Value::Object(out)
        }
        Value::Array(values) => Value::Array(values.iter().map(sort_value).collect()),
        _ => value.clone(),
    }
}
