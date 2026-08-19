use crate::api::error::ApiError;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::io::ErrorKind;
use std::path::Path;
use std::sync::OnceLock;
use tokio::sync::Mutex;

static CONTACTS_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Contact {
    pub did: String,
    /// Who this saved contact belongs to: `None` for the Guardian device
    /// itself (admin/owner), `Some(member_did)` for a specific browser
    /// member. Contacts are strictly private per-owner — never shared
    /// between the admin and members, or between different members, even
    /// though they're persisted in one file. Older entries predating this
    /// field deserialize as `None` (admin-owned), which matches reality
    /// since only the admin could save contacts before this existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ContactDraft {
    pub did: String,
    pub name: Option<String>,
    pub alias: Option<String>,
    pub notes: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ContactPatch {
    pub name: Option<String>,
    pub alias: Option<String>,
    pub notes: Option<String>,
}

fn clean_optional(value: Option<String>) -> Option<String> {
    value
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
}

fn normalize_did(did: &str) -> Result<String, ApiError> {
    let value = did.trim();
    if value.is_empty() {
        return Err(ApiError::BadRequest("DID is required".to_string()));
    }
    if !value.starts_with("did:") {
        return Err(ApiError::BadRequest("DID must start with did:".to_string()));
    }
    Ok(value.to_string())
}

async fn load(path: &Path) -> Result<Vec<Contact>, ApiError> {
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    Ok(serde_json::from_slice(&bytes)?)
}

async fn save(path: &Path, contacts: &[Contact]) -> Result<(), ApiError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(contacts)?;
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(tmp, path).await?;
    Ok(())
}

pub async fn list(path: &Path, owner: Option<&str>) -> Result<Vec<Contact>, ApiError> {
    let mut contacts = load(path).await?;
    contacts.retain(|contact| contact.owner_did.as_deref() == owner);
    contacts.sort_by(|a, b| {
        let left = a
            .name
            .as_deref()
            .or(a.alias.as_deref())
            .unwrap_or(&a.did)
            .to_lowercase();
        let right = b
            .name
            .as_deref()
            .or(b.alias.as_deref())
            .unwrap_or(&b.did)
            .to_lowercase();
        left.cmp(&right)
    });
    Ok(contacts)
}

pub async fn get(path: &Path, owner: Option<&str>, did: &str) -> Result<Contact, ApiError> {
    let did = normalize_did(did)?;
    load(path)
        .await?
        .into_iter()
        .find(|contact| contact.did == did && contact.owner_did.as_deref() == owner)
        .ok_or_else(|| ApiError::NotFound(format!("Contact not found for DID {}", did)))
}

pub async fn create(
    path: &Path,
    owner: Option<&str>,
    draft: ContactDraft,
) -> Result<Contact, ApiError> {
    let did = normalize_did(&draft.did)?;
    let lock = CONTACTS_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().await;
    let mut contacts = load(path).await?;
    if contacts
        .iter()
        .any(|contact| contact.did == did && contact.owner_did.as_deref() == owner)
    {
        return Err(ApiError::Conflict(format!(
            "Contact already exists for DID {}",
            did
        )));
    }
    let now = Utc::now().to_rfc3339();
    let contact = Contact {
        did,
        owner_did: owner.map(str::to_string),
        name: clean_optional(draft.name),
        alias: clean_optional(draft.alias),
        notes: clean_optional(draft.notes),
        created_at: now.clone(),
        updated_at: now,
    };
    contacts.push(contact.clone());
    save(path, &contacts).await?;
    Ok(contact)
}

pub async fn update(
    path: &Path,
    owner: Option<&str>,
    did: &str,
    patch: ContactPatch,
) -> Result<Contact, ApiError> {
    let did = normalize_did(did)?;
    let lock = CONTACTS_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().await;
    let mut contacts = load(path).await?;
    let contact = contacts
        .iter_mut()
        .find(|contact| contact.did == did && contact.owner_did.as_deref() == owner)
        .ok_or_else(|| ApiError::NotFound(format!("Contact not found for DID {}", did)))?;
    contact.name = clean_optional(patch.name);
    contact.alias = clean_optional(patch.alias);
    contact.notes = clean_optional(patch.notes);
    contact.updated_at = Utc::now().to_rfc3339();
    let updated = contact.clone();
    save(path, &contacts).await?;
    Ok(updated)
}

pub async fn delete(path: &Path, owner: Option<&str>, did: &str) -> Result<bool, ApiError> {
    let did = normalize_did(did)?;
    let lock = CONTACTS_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().await;
    let mut contacts = load(path).await?;
    let before = contacts.len();
    contacts.retain(|contact| !(contact.did == did && contact.owner_did.as_deref() == owner));
    if contacts.len() == before {
        return Err(ApiError::NotFound(format!(
            "Contact not found for DID {}",
            did
        )));
    }
    save(path, &contacts).await?;
    Ok(true)
}
