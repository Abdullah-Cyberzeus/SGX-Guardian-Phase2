use thiserror::Error;

#[derive(Debug, Error)]
pub enum ThreatError {
    #[error("suricata binary not found in PATH")]
    BinaryMissing,

    #[error("suricata service failed to start: {0}")]
    ServiceStart(String),

    #[error("eve.json not found at {0} - is Suricata running?")]
    EveLogMissing(String),

    #[error("json parse error on line {line}: {msg}")]
    JsonParse { line: u64, msg: String },

    #[error("nftables command failed (exit {0}): {1}")]
    NftFailed(i32, String),

    #[error("invalid configuration: {0}")]
    BadConfig(String),

    #[error("invalid CIDR/IP: {0}")]
    InvalidCidr(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("threat integration disabled in config")]
    Disabled,
}

pub type ThreatResult<T> = Result<T, ThreatError>;
