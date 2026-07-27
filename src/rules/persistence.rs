use crate::rules::errors::RulesResult;
use serde::de::DeserializeOwned;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const RULES_BASE_ENV: &str = "SGX_GUARDIAN_RULES_BASE";
pub const RULES_DRYRUN_ENV: &str = "SGX_RULES_DRYRUN";
pub const RULES_MAX_EXECUTIONS_ENV: &str = "SGX_RULES_MAX_EXECUTIONS";

#[derive(Debug, Clone)]
pub struct RulesPaths {
    pub base: PathBuf,
    pub rules_file: PathBuf,
    pub executions_file: PathBuf,
    pub state_file: PathBuf,
}

impl RulesPaths {
    pub fn from_base(base: impl Into<PathBuf>) -> Self {
        let base = base.into();
        Self {
            rules_file: base.join("rules.json"),
            executions_file: base.join("executions.jsonl"),
            state_file: base.join("state.json"),
            base,
        }
    }

    pub fn from_env() -> Self {
        let base = std::env::var(RULES_BASE_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/var/lib/sgx-guardian/rules"));
        Self::from_base(base)
    }
}

pub fn read_json_if_exists<T: DeserializeOwned>(path: &Path) -> RulesResult<Option<T>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path)?;
    if bytes.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&bytes)?))
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> RulesResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let tmp = path.with_extension("tmp");
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(tmp, path)?;
    Ok(())
}
