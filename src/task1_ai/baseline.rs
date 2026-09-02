use crate::advisory::{
    AnomalyBaselineProvenance, AnomalyBaselineSelectionMode, AnomalyScoringRuntime,
    AnomalyScoringRuntimeModelKind,
};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use sgx_anomaly_engine::model::IsolationForestModel;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

const BASELINE_CONFIG_FILE: &str = "task1_baseline_lifecycle.json";
const RUNTIME_STATUS_FILE: &str = "task1_full_ml_runtime.json";
pub const FULL_ML_ENGINE_SOURCE: &str = "task1_full_ml_engine";
pub const FULL_ML_SCORER_SOURCE: &str = "tier1_zscore_plus_tier2_isolation_forest";
const HEURISTIC_ENGINE_SOURCE: &str = "sgx-threat-service";
const HEURISTIC_SCORER_SOURCE: &str = "task1-alert-scorer";
const DEFAULT_RELOAD_SECONDS: u64 = 3_600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Task1BaselineKind {
    Global,
    PerNode,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Task1BaselineLifecycleConfig {
    pub global_model: String,
    pub per_node_model_template: String,
    #[serde(default = "default_reload_seconds")]
    pub reload_check_seconds: u64,
}

fn default_reload_seconds() -> u64 {
    DEFAULT_RELOAD_SECONDS
}

impl Task1BaselineLifecycleConfig {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let config: Self = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        if config.reload_check_seconds == 0 {
            bail!("baseline lifecycle reload interval must be positive");
        }
        if !config.per_node_model_template.contains("{node}") {
            bail!("per_node_model_template must contain '{{node}}'");
        }
        Ok(config)
    }

    fn per_node_path(&self, node_id: &str) -> PathBuf {
        PathBuf::from(self.per_node_model_template.replace("{node}", node_id))
    }
}

#[derive(Debug, Clone)]
pub struct Task1BaselineLifecycle {
    node_id: String,
    config: Task1BaselineLifecycleConfig,
    active_path: PathBuf,
    active_modified: SystemTime,
    active_kind: Task1BaselineKind,
    provenance: AnomalyBaselineProvenance,
    last_check: Instant,
}

impl Task1BaselineLifecycle {
    pub fn load(node_id: impl Into<String>, config: Task1BaselineLifecycleConfig) -> Result<Self> {
        let node_id = node_id.into();
        let selection = select_baseline(&node_id, &config)?;
        let active_modified = std::fs::metadata(&selection.path)?.modified()?;
        Ok(Self {
            node_id,
            config,
            active_path: selection.path,
            active_modified,
            active_kind: selection.kind,
            provenance: selection.provenance,
            last_check: Instant::now(),
        })
    }

    pub fn load_from_path(node_id: impl Into<String>, path: impl AsRef<Path>) -> Result<Self> {
        let config = Task1BaselineLifecycleConfig::from_path(path)?;
        Self::load(node_id, config)
    }

    pub fn provenance(&self) -> AnomalyBaselineProvenance {
        self.provenance.clone()
    }

    pub fn active_kind(&self) -> Task1BaselineKind {
        self.active_kind
    }

    pub fn maybe_reload(&mut self) -> Result<Option<AnomalyBaselineProvenance>> {
        if self.last_check.elapsed() < Duration::from_secs(self.config.reload_check_seconds) {
            return Ok(None);
        }
        self.last_check = Instant::now();
        self.reload_if_changed()
    }

    pub fn reload_now(&mut self) -> Result<Option<AnomalyBaselineProvenance>> {
        self.last_check = Instant::now();
        self.reload_if_changed()
    }

    fn reload_if_changed(&mut self) -> Result<Option<AnomalyBaselineProvenance>> {
        let selection = select_baseline(&self.node_id, &self.config)?;
        let candidate_modified = std::fs::metadata(&selection.path)?.modified()?;
        let changed =
            selection.path != self.active_path || candidate_modified > self.active_modified;
        if !changed {
            return Ok(None);
        }

        self.active_path = selection.path;
        self.active_modified = candidate_modified;
        self.active_kind = selection.kind;
        self.provenance = selection.provenance.clone();
        Ok(Some(selection.provenance))
    }
}

#[derive(Debug, Clone)]
pub struct Task1RuntimeTracker {
    config_path: PathBuf,
    runtime_status_path: PathBuf,
    baseline_lifecycle: Option<Task1BaselineLifecycle>,
    baseline_error: Option<String>,
}

impl Task1RuntimeTracker {
    pub fn for_state_dir(node_id: &str, state_dir: impl AsRef<Path>) -> Self {
        let state_dir = state_dir.as_ref();
        let config_path = baseline_config_path(state_dir);
        let runtime_status_path = full_ml_runtime_status_path(state_dir);
        match Task1BaselineLifecycle::load_from_path(node_id.to_string(), &config_path) {
            Ok(baseline_lifecycle) => Self {
                config_path,
                runtime_status_path,
                baseline_lifecycle: Some(baseline_lifecycle),
                baseline_error: None,
            },
            Err(error) => Self {
                config_path,
                runtime_status_path,
                baseline_lifecycle: None,
                baseline_error: Some(error.to_string()),
            },
        }
    }

    pub fn current_runtime(&self) -> AnomalyScoringRuntime {
        self.load_persisted_runtime()
            .unwrap_or_else(|| self.heuristic_runtime())
    }

    pub fn build_full_ml_runtime(&self) -> Option<AnomalyScoringRuntime> {
        let baseline = self
            .baseline_lifecycle
            .as_ref()
            .map(Task1BaselineLifecycle::provenance)?;
        Some(AnomalyScoringRuntime {
            engine_source: FULL_ML_ENGINE_SOURCE.to_string(),
            scorer_source: FULL_ML_SCORER_SOURCE.to_string(),
            model_kind: AnomalyScoringRuntimeModelKind::IsolationForest,
            model_artifact: baseline.artifact.clone(),
            model_version: baseline.version.clone(),
            fallback: baseline.fallback_used,
            fallback_reason: baseline.fallback_reason.clone(),
            baseline: Some(baseline),
        })
    }

    pub fn persist_full_ml_runtime(&self) -> Result<Option<AnomalyScoringRuntime>> {
        let runtime = match self.build_full_ml_runtime() {
            Some(runtime) => runtime,
            None => return Ok(None),
        };
        write_runtime_status_file(&self.runtime_status_path, &runtime)?;
        Ok(Some(runtime))
    }

    pub fn maybe_reload(&mut self) -> Result<Option<AnomalyBaselineProvenance>> {
        match self.baseline_lifecycle.as_mut() {
            Some(lifecycle) => lifecycle.maybe_reload(),
            None => Ok(None),
        }
    }

    pub fn reload_now(&mut self) -> Result<Option<AnomalyBaselineProvenance>> {
        match self.baseline_lifecycle.as_mut() {
            Some(lifecycle) => lifecycle.reload_now(),
            None => Ok(None),
        }
    }

    fn load_persisted_runtime(&self) -> Option<AnomalyScoringRuntime> {
        let text = std::fs::read_to_string(&self.runtime_status_path).ok()?;
        serde_json::from_str(&text).ok()
    }

    fn heuristic_runtime(&self) -> AnomalyScoringRuntime {
        let baseline = self
            .baseline_lifecycle
            .as_ref()
            .map(Task1BaselineLifecycle::provenance);

        let fallback_reason = match (
            baseline.as_ref(),
            self.baseline_error.as_deref(),
            self.config_path.exists(),
        ) {
            (Some(_), _, _) => Some(format!(
                "Task 1 baseline assets are available at '{}' but the persisted full ML runtime status '{}' is missing, so the heuristic alert scorer remains the active reported path.",
                self.config_path.display(),
                self.runtime_status_path.display()
            )),
            (None, Some(error), true) => Some(format!(
                "Task 1 baseline config was found at '{}' but could not be activated: {}; the heuristic alert scorer remains active.",
                self.config_path.display(),
                error
            )),
            (None, Some(_), false) | (None, None, false) => Some(format!(
                "Task 1 baseline config is not present at '{}'; the heuristic alert scorer remains active.",
                self.config_path.display()
            )),
            (None, None, true) => Some(format!(
                "Task 1 baseline assets exist but the full ML runtime status '{}' was not persisted; the heuristic alert scorer remains active.",
                self.runtime_status_path.display()
            )),
        };

        AnomalyScoringRuntime {
            engine_source: HEURISTIC_ENGINE_SOURCE.to_string(),
            scorer_source: HEURISTIC_SCORER_SOURCE.to_string(),
            model_kind: AnomalyScoringRuntimeModelKind::Heuristic,
            model_artifact: None,
            model_version: Some(HEURISTIC_SCORER_SOURCE.to_string()),
            fallback: true,
            fallback_reason,
            baseline,
        }
    }
}

pub fn baseline_config_path(state_dir: impl AsRef<Path>) -> PathBuf {
    std::env::var("SGX_GUARDIAN_TASK1_BASELINE_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| state_dir.as_ref().join(BASELINE_CONFIG_FILE))
}

pub fn full_ml_runtime_status_path(state_dir: impl AsRef<Path>) -> PathBuf {
    state_dir.as_ref().join(RUNTIME_STATUS_FILE)
}

/// Read the already-persisted full ML runtime snapshot without reloading or
/// validating the Isolation Forest model. Intended for read-only API status.
pub fn load_full_ml_runtime_status(state_dir: impl AsRef<Path>) -> Option<AnomalyScoringRuntime> {
    let path = full_ml_runtime_status_path(state_dir);
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn write_runtime_status(
    state_dir: impl AsRef<Path>,
    runtime: &AnomalyScoringRuntime,
) -> Result<()> {
    write_runtime_status_file(&full_ml_runtime_status_path(state_dir), runtime)
}

fn write_runtime_status_file(path: &Path, runtime: &AnomalyScoringRuntime) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temp_path = path.with_extension("tmp");
    let json = serde_json::to_vec_pretty(runtime)?;
    std::fs::write(&temp_path, json)?;
    std::fs::rename(temp_path, path)?;
    Ok(())
}

struct BaselineSelection {
    path: PathBuf,
    kind: Task1BaselineKind,
    provenance: AnomalyBaselineProvenance,
}

fn select_baseline(
    node_id: &str,
    config: &Task1BaselineLifecycleConfig,
) -> Result<BaselineSelection> {
    let per_node = config.per_node_path(node_id);
    if per_node.is_file() {
        match validate_artifact(&per_node) {
            Ok(()) => {
                return Ok(BaselineSelection {
                    path: per_node.clone(),
                    kind: Task1BaselineKind::PerNode,
                    provenance: make_provenance(
                        node_id,
                        Task1BaselineKind::PerNode,
                        &per_node,
                        false,
                        None,
                    ),
                });
            }
            Err(per_node_error) => {
                let global = PathBuf::from(&config.global_model);
                validate_artifact(&global).map_err(|global_error| {
                    anyhow!(
                        "per-node baseline '{}' is invalid ({}); global fallback '{}' also failed ({})",
                        per_node.display(),
                        per_node_error,
                        global.display(),
                        global_error
                    )
                })?;
                return Ok(BaselineSelection {
                    path: global.clone(),
                    kind: Task1BaselineKind::Global,
                    provenance: make_provenance(
                        node_id,
                        Task1BaselineKind::Global,
                        &global,
                        true,
                        Some(format!("per-node baseline invalid: {per_node_error}")),
                    ),
                });
            }
        }
    }

    let global = PathBuf::from(&config.global_model);
    validate_artifact(&global).map_err(|error| {
        anyhow!(
            "no per-node baseline for '{}' and global fallback '{}' is unavailable ({})",
            node_id,
            global.display(),
            error
        )
    })?;
    Ok(BaselineSelection {
        path: global.clone(),
        kind: Task1BaselineKind::Global,
        provenance: make_provenance(
            node_id,
            Task1BaselineKind::Global,
            &global,
            true,
            Some("per-node baseline unavailable".to_string()),
        ),
    })
}

fn validate_artifact(path: &Path) -> Result<()> {
    if !path.is_file() {
        bail!("artifact '{}' is missing", path.display());
    }
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow!("artifact path is not valid UTF-8: '{}'", path.display()))?;
    IsolationForestModel::load_from_json(path_str)?;
    Ok(())
}

fn make_provenance(
    node_id: &str,
    kind: Task1BaselineKind,
    artifact: &Path,
    fallback_used: bool,
    fallback_reason: Option<String>,
) -> AnomalyBaselineProvenance {
    AnomalyBaselineProvenance {
        node_id: node_id.to_string(),
        selection_mode: match kind {
            Task1BaselineKind::Global => AnomalyBaselineSelectionMode::Global,
            Task1BaselineKind::PerNode => AnomalyBaselineSelectionMode::PerNode,
        },
        source: match kind {
            Task1BaselineKind::Global => "global".to_string(),
            Task1BaselineKind::PerNode => node_id.to_string(),
        },
        artifact: Some(artifact.display().to_string()),
        version: artifact_fingerprint(artifact),
        fallback_used,
        fallback_reason,
    }
}

fn artifact_fingerprint(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let digest = Sha256::digest(bytes);
    Some(format!("sha256:{}", hex::encode(&digest[..8])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{Duration, UNIX_EPOCH};

    fn write_json(path: &Path, value: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, value).expect("write json");
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "sgx-task1-baseline-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn baseline_config_path_defaults_under_state_dir() {
        let dir = unique_temp_dir("config-path");
        assert_eq!(
            baseline_config_path(&dir),
            dir.join("task1_baseline_lifecycle.json")
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn tracker_without_config_reports_heuristic_runtime() {
        let dir = unique_temp_dir("tracker-default");

        let tracker = Task1RuntimeTracker::for_state_dir("nodeA", &dir);
        let runtime = tracker.current_runtime();

        assert!(runtime.fallback);
        assert_eq!(runtime.scorer_source, "task1-alert-scorer");
        assert_eq!(
            runtime.model_kind,
            AnomalyScoringRuntimeModelKind::Heuristic
        );
        assert!(runtime.baseline.is_none());
        assert!(runtime
            .fallback_reason
            .as_deref()
            .unwrap_or_default()
            .contains("heuristic alert scorer"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn tracker_persists_full_ml_runtime_snapshot() {
        let dir = unique_temp_dir("runtime-snapshot");
        let global = dir.join("global.json");
        let per_node = dir.join("nodeA.json");
        let config_path = dir.join("task1_baseline_lifecycle.json");

        write_json(
            &global,
            include_str!("../../crates/sgx-anomaly-engine/data/global_forest.json"),
        );
        write_json(
            &per_node,
            include_str!("../../crates/sgx-anomaly-engine/data/nodeA_forest.json"),
        );
        write_json(
            &config_path,
            &format!(
                r#"{{"global_model":"{}","per_node_model_template":"{}","reload_check_seconds":1}}"#,
                global.display(),
                dir.join("{node}.json").display()
            ),
        );

        let tracker = Task1RuntimeTracker::for_state_dir("nodeA", &dir);
        let runtime = tracker
            .persist_full_ml_runtime()
            .expect("persist runtime")
            .expect("runtime");

        assert_eq!(runtime.engine_source, FULL_ML_ENGINE_SOURCE);
        assert_eq!(runtime.scorer_source, FULL_ML_SCORER_SOURCE);
        assert_eq!(
            runtime.model_kind,
            AnomalyScoringRuntimeModelKind::IsolationForest
        );
        assert_eq!(
            runtime
                .baseline
                .as_ref()
                .map(|baseline| baseline.source.as_str()),
            Some("nodeA")
        );

        let reloaded = Task1RuntimeTracker::for_state_dir("nodeA", &dir).current_runtime();
        assert_eq!(reloaded, runtime);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn lifecycle_prefers_per_node_artifact_when_available() {
        let dir = unique_temp_dir("per-node");
        let global = dir.join("global.json");
        let per_node = dir.join("nodeA.json");
        let config_path = dir.join("task1_baseline_lifecycle.json");

        write_json(
            &global,
            include_str!("../../crates/sgx-anomaly-engine/data/global_forest.json"),
        );
        write_json(
            &per_node,
            include_str!("../../crates/sgx-anomaly-engine/data/nodeA_forest.json"),
        );
        write_json(
            &config_path,
            &format!(
                r#"{{"global_model":"{}","per_node_model_template":"{}","reload_check_seconds":1}}"#,
                global.display(),
                dir.join("{node}.json").display()
            ),
        );

        let lifecycle =
            Task1BaselineLifecycle::load_from_path("nodeA", &config_path).expect("load lifecycle");
        let provenance = lifecycle.provenance();

        assert_eq!(
            provenance.selection_mode,
            AnomalyBaselineSelectionMode::PerNode
        );
        assert!(!provenance.fallback_used);
        assert_eq!(
            provenance.artifact.as_deref(),
            Some(per_node.to_string_lossy().as_ref())
        );
        assert!(provenance
            .version
            .as_deref()
            .unwrap_or_default()
            .starts_with("sha256:"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn lifecycle_falls_back_to_global_when_per_node_is_missing() {
        let dir = unique_temp_dir("global-fallback");
        let global = dir.join("global.json");
        let config_path = dir.join("task1_baseline_lifecycle.json");

        write_json(
            &global,
            include_str!("../../crates/sgx-anomaly-engine/data/global_forest.json"),
        );
        write_json(
            &config_path,
            &format!(
                r#"{{"global_model":"{}","per_node_model_template":"{}","reload_check_seconds":1}}"#,
                global.display(),
                dir.join("{node}.json").display()
            ),
        );

        let lifecycle =
            Task1BaselineLifecycle::load_from_path("nodeB", &config_path).expect("load lifecycle");
        let provenance = lifecycle.provenance();

        assert_eq!(
            provenance.selection_mode,
            AnomalyBaselineSelectionMode::Global
        );
        assert!(provenance.fallback_used);
        assert_eq!(
            provenance.fallback_reason.as_deref(),
            Some("per-node baseline unavailable")
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn lifecycle_promotes_global_to_per_node_after_reload() {
        let dir = unique_temp_dir("promotion");
        let global = dir.join("global.json");
        let per_node = dir.join("nodeC.json");
        let config_path = dir.join("task1_baseline_lifecycle.json");

        write_json(
            &global,
            include_str!("../../crates/sgx-anomaly-engine/data/global_forest.json"),
        );
        write_json(
            &config_path,
            &format!(
                r#"{{"global_model":"{}","per_node_model_template":"{}","reload_check_seconds":1}}"#,
                global.display(),
                dir.join("{node}.json").display()
            ),
        );

        let mut lifecycle =
            Task1BaselineLifecycle::load_from_path("nodeC", &config_path).expect("load lifecycle");
        assert_eq!(
            lifecycle.provenance().selection_mode,
            AnomalyBaselineSelectionMode::Global
        );

        std::thread::sleep(Duration::from_millis(5));
        write_json(
            &per_node,
            include_str!("../../crates/sgx-anomaly-engine/data/nodeB_forest.json"),
        );

        let reloaded = lifecycle.reload_now().expect("reload").expect("promotion");
        assert_eq!(
            reloaded.selection_mode,
            AnomalyBaselineSelectionMode::PerNode
        );
        assert!(!reloaded.fallback_used);

        let _ = fs::remove_dir_all(dir);
    }
}
