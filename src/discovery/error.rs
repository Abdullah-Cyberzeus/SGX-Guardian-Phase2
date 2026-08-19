use thiserror::Error;

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("Guardian scanner binary not found in PATH - install the required scanner package")]
    BinaryMissing,

    #[error("Guardian scanner exited with status {0}: {1}")]
    NmapFailed(i32, String),

    #[error("XML parse error: {0}")]
    XmlParse(String),

    #[error("invalid configuration: {0}")]
    BadConfig(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("discovery disabled in config")]
    Disabled,
}

pub type DiscoveryResult<T> = Result<T, DiscoveryError>;
