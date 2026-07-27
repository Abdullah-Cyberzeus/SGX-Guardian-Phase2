use thiserror::Error;

pub type RulesResult<T> = Result<T, RulesError>;

#[derive(Debug, Error)]
pub enum RulesError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("rule not found: {0}")]
    NotFound(String),
    #[error("invalid rule: {0}")]
    InvalidRule(String),
    #[error("rules registry proof is missing")]
    MissingProof,
    #[error("rules registry signature is invalid: {0}")]
    InvalidProof(String),
    #[error("rules registry was rejected; no rules will run: {0}")]
    RegistryRejected(String),
    #[error("threat action failed: {0}")]
    Threat(String),
    #[error("discovery action failed: {0}")]
    Discovery(String),
    #[error("CRL action failed: {0}")]
    Crl(String),
    #[error("action failed: {0}")]
    Action(String),
}
