use crate::vault::errors::VaultError;
use crate::vault::persistence::safe_id;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultNamespace {
    Personal,
    Circle(String),
}

impl VaultNamespace {
    pub const PERSONAL_STORAGE_KEY: &'static str = "personal";

    pub fn parse(raw: &str) -> Result<Self, VaultError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case(Self::PERSONAL_STORAGE_KEY) {
            return Ok(Self::Personal);
        }
        validate_component(trimmed, "namespace")?;
        Ok(Self::Circle(trimmed.to_string()))
    }

    pub fn storage_key(&self) -> String {
        match self {
            Self::Personal => Self::PERSONAL_STORAGE_KEY.to_string(),
            Self::Circle(circle_id) => circle_id.clone(),
        }
    }

    pub fn dir_name(&self) -> String {
        safe_id(&self.storage_key())
    }

    pub fn is_personal(&self) -> bool {
        matches!(self, Self::Personal)
    }
}

pub fn validate_folder_name(name: &str) -> Result<String, VaultError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(VaultError::InvalidStructure(
            "folder name must not be empty".to_string(),
        ));
    }
    validate_component(trimmed, "folder name")?;
    Ok(trimmed.to_string())
}

pub fn validate_folder_id(folder_id: &str) -> Result<String, VaultError> {
    let trimmed = folder_id.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    validate_component(trimmed, "folder id")?;
    Ok(trimmed.to_string())
}

pub fn validate_vault_id(vault_id: &str) -> Result<String, VaultError> {
    let trimmed = vault_id.trim();
    if trimmed.is_empty() {
        return Err(VaultError::InvalidStructure(
            "vault id must not be empty".to_string(),
        ));
    }
    validate_component(trimmed, "vault id")?;
    Ok(trimmed.to_string())
}

fn validate_component(value: &str, label: &str) -> Result<(), VaultError> {
    if value == "." || value == ".." {
        return Err(VaultError::InvalidStructure(format!(
            "{} must not be a relative path segment",
            label
        )));
    }
    if value.contains('/') || value.contains('\\') || value.contains('\0') {
        return Err(VaultError::InvalidStructure(format!(
            "{} must not contain path separators",
            label
        )));
    }
    if value.chars().any(|ch| ch.is_control()) {
        return Err(VaultError::InvalidStructure(format!(
            "{} must not contain control characters",
            label
        )));
    }
    Ok(())
}
