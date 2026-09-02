//! Global -> per-node -> refresh baseline lifecycle.
//!
//! A node prefers its own exported forest. A new node without one safely
//! falls back to the pooled global forest. Role/admin identity is never used
//! as a model-baseline selector.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::model::IsolationForestModel;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineKind {
    Global,
    PerNode,
}

/// Machine-readable proof of the baseline actually selected at runtime.
/// This is carried alongside scoring output so labels cannot pretend that a
/// per-node model was active when the global fallback was used.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BaselineProvenance {
    pub node_id: String,
    pub baseline_kind: BaselineKind,
    pub baseline_source: String,
    pub baseline_artifact: String,
    /// Exported forests currently carry no semantic version key. `None` is
    /// intentional rather than inventing a version from a filename.
    pub baseline_version: Option<String>,
    pub baseline_fallback: bool,
    pub baseline_fallback_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BaselineLifecycleConfig {
    pub global_model: String,
    /// `{node}` is replaced with the trusted engine node id.
    pub per_node_model_template: String,
    #[serde(default = "default_min_days")]
    pub min_normal_days: u32,
    #[serde(default = "default_refresh_days")]
    pub refresh_days: u32,
    #[serde(default = "default_reload_seconds")]
    pub reload_check_seconds: u64,
    /// Optional audit folder. When configured, initialization and every
    /// accepted replacement are saved as JSON evidence plus a model snapshot.
    #[serde(default)]
    pub evidence_dir: Option<String>,
}

fn default_min_days() -> u32 {
    7
}
fn default_refresh_days() -> u32 {
    30
}
fn default_reload_seconds() -> u64 {
    3_600
}

impl BaselineLifecycleConfig {
    pub fn from_path(path: &str) -> anyhow::Result<Self> {
        let config: Self = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        if config.min_normal_days == 0
            || config.refresh_days == 0
            || config.reload_check_seconds == 0
        {
            anyhow::bail!("baseline lifecycle durations must be positive");
        }
        if !config.per_node_model_template.contains("{node}") {
            anyhow::bail!("per_node_model_template must contain '{{node}}'");
        }
        Ok(config)
    }

    fn per_node_path(&self, node: &str) -> PathBuf {
        PathBuf::from(self.per_node_model_template.replace("{node}", node))
    }
}

/// Runtime selector. D9's external, validated export process writes model
/// files; this only selects and safely reloads them.
pub struct BaselineLifecycle {
    node: String,
    config: BaselineLifecycleConfig,
    active_path: PathBuf,
    active_modified: SystemTime,
    pub active_kind: BaselineKind,
    provenance: BaselineProvenance,
    last_check: Instant,
    evidence_run_dir: Option<PathBuf>,
    evidence_run_number: Option<u32>,
}

impl BaselineLifecycle {
    /// Exact artifact currently selected by the validated baseline lifecycle.
    /// This is audit/API provenance, never a scoring fallback.
    pub fn active_model_source(&self) -> String {
        self.active_path.display().to_string()
    }

    pub fn provenance(&self) -> BaselineProvenance {
        self.provenance.clone()
    }

    pub fn load(
        node: impl Into<String>,
        config: BaselineLifecycleConfig,
    ) -> anyhow::Result<(Self, IsolationForestModel)> {
        let node = node.into();
        let selection = select_model(&node, &config)?;
        let active_modified = std::fs::metadata(&selection.path)?.modified()?;
        let (evidence_run_dir, evidence_run_number) = prepare_evidence_run(&config, &node)?;
        let lifecycle = Self {
            node,
            config,
            active_path: selection.path,
            active_modified,
            active_kind: selection.kind,
            provenance: selection.provenance,
            last_check: Instant::now(),
            evidence_run_dir,
            evidence_run_number,
        };
        lifecycle.write_evidence("initialized", &selection.model)?;
        Ok((lifecycle, selection.model))
    }

    /// Start from the pooled fallback even if a per-node export already
    /// exists. This is only used by a controlled lifecycle demonstration;
    /// normal runtime must use `load`, which selects the best available model.
    pub fn load_global(
        node: impl Into<String>,
        config: BaselineLifecycleConfig,
    ) -> anyhow::Result<(Self, IsolationForestModel)> {
        let node = node.into();
        let path = PathBuf::from(&config.global_model);
        if !path.is_file() {
            anyhow::bail!("global fallback '{}' is missing", path.display());
        }
        let model = load_model(&path)?;
        let active_modified = std::fs::metadata(&path)?.modified()?;
        let provenance = BaselineProvenance {
            node_id: node.clone(),
            baseline_kind: BaselineKind::Global,
            baseline_source: "global".into(),
            baseline_artifact: PathBuf::from(&config.global_model).display().to_string(),
            baseline_version: None,
            baseline_fallback: true,
            baseline_fallback_reason: Some(
                "controlled demo starts from global baseline before promotion check".into(),
            ),
        };
        let (evidence_run_dir, evidence_run_number) = prepare_evidence_run(&config, &node)?;
        let lifecycle = Self {
            node,
            config,
            active_path: path,
            active_modified,
            active_kind: BaselineKind::Global,
            provenance,
            last_check: Instant::now(),
            evidence_run_dir,
            evidence_run_number,
        };
        lifecycle.write_evidence("initialized", &model)?;
        Ok((lifecycle, model))
    }

    /// A bad candidate never replaces the running known-good model.
    pub fn maybe_reload(&mut self) -> anyhow::Result<Option<(BaselineKind, IsolationForestModel)>> {
        if self.last_check.elapsed() < Duration::from_secs(self.config.reload_check_seconds) {
            return Ok(None);
        }
        self.last_check = Instant::now();
        self.reload_if_changed()
    }

    /// Immediately check for a replacement model. Used by controlled demos
    /// and administrative lifecycle triggers; production polling continues to
    /// use `maybe_reload` with its configured interval.
    pub fn reload_now(&mut self) -> anyhow::Result<Option<(BaselineKind, IsolationForestModel)>> {
        self.last_check = Instant::now();
        self.reload_if_changed()
    }

    fn reload_if_changed(
        &mut self,
    ) -> anyhow::Result<Option<(BaselineKind, IsolationForestModel)>> {
        let selection = select_model(&self.node, &self.config)?;
        let candidate_modified = std::fs::metadata(&selection.path)?.modified()?;
        let changed =
            selection.path != self.active_path || candidate_modified > self.active_modified;
        if !changed {
            return Ok(None);
        }
        self.active_path = selection.path;
        self.active_modified = candidate_modified;
        self.active_kind = selection.kind;
        self.provenance = selection.provenance;
        self.write_evidence("updated", &selection.model)?;
        Ok(Some((self.active_kind, selection.model)))
    }

    fn write_evidence(&self, event: &str, model: &IsolationForestModel) -> anyhow::Result<()> {
        let Some(node_dir) = &self.evidence_run_dir else {
            return Ok(());
        };
        let sequence = std::fs::read_dir(node_dir)?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .ends_with("_evidence.json")
            })
            .count()
            + 1;
        let epoch_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let prefix = format!("{sequence:02}_{event}_{:?}", self.active_kind).to_lowercase();
        let snapshot = node_dir.join(format!("{prefix}_model.json"));
        std::fs::copy(&self.active_path, &snapshot)?;
        let record = BaselineEvidence {
            event,
            node: &self.node,
            active_baseline: self.active_kind,
            model_source: self.active_path.display().to_string(),
            baseline_source: &self.provenance.baseline_source,
            baseline_fallback: self.provenance.baseline_fallback,
            baseline_fallback_reason: self.provenance.baseline_fallback_reason.as_deref(),
            model_snapshot: snapshot.display().to_string(),
            tier1_z_alert_threshold: model.tier1_z_alert_threshold(),
            tier2_raw_threshold: model.raw_alert_threshold(),
            selection_rule: match self.active_kind {
                BaselineKind::Global => {
                    "no trusted per-node export available: use pooled Global fallback"
                }
                BaselineKind::PerNode => "trusted per-node export available: use PerNode baseline",
            },
            evidence_run: self.evidence_run_number,
            saved_at_epoch_ms: epoch_ms,
        };
        let record_path = node_dir.join(format!("{prefix}_evidence.json"));
        std::fs::write(record_path, serde_json::to_string_pretty(&record)?)?;
        Ok(())
    }
}

fn prepare_evidence_run(
    config: &BaselineLifecycleConfig,
    node: &str,
) -> anyhow::Result<(Option<PathBuf>, Option<u32>)> {
    let Some(evidence_dir) = &config.evidence_dir else {
        return Ok((None, None));
    };
    let node_dir = PathBuf::from(evidence_dir).join(node);
    std::fs::create_dir_all(&node_dir)?;
    let highest = std::fs::read_dir(&node_dir)?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .filter_map(|name| name.strip_prefix("run_")?.parse::<u32>().ok())
        .max()
        .unwrap_or(0);
    let run_number = highest + 1;
    let run_dir = node_dir.join(format!("run_{run_number:03}"));
    std::fs::create_dir_all(&run_dir)?;
    Ok((Some(run_dir), Some(run_number)))
}

#[derive(Serialize)]
struct BaselineEvidence<'a> {
    event: &'a str,
    node: &'a str,
    active_baseline: BaselineKind,
    model_source: String,
    baseline_source: &'a str,
    baseline_fallback: bool,
    baseline_fallback_reason: Option<&'a str>,
    model_snapshot: String,
    tier1_z_alert_threshold: Option<f64>,
    tier2_raw_threshold: Option<f64>,
    selection_rule: &'a str,
    evidence_run: Option<u32>,
    saved_at_epoch_ms: u128,
}

fn load_model(path: &Path) -> anyhow::Result<IsolationForestModel> {
    IsolationForestModel::load_from_json(
        path.to_str()
            .ok_or_else(|| anyhow::anyhow!("non-UTF8 model path"))?,
    )
}

struct BaselineSelection {
    path: PathBuf,
    kind: BaselineKind,
    model: IsolationForestModel,
    provenance: BaselineProvenance,
}

fn selection_provenance(
    node: &str,
    kind: BaselineKind,
    path: &Path,
    fallback_reason: Option<String>,
) -> BaselineProvenance {
    BaselineProvenance {
        node_id: node.to_string(),
        baseline_kind: kind,
        baseline_source: match kind {
            BaselineKind::PerNode => node.to_string(),
            BaselineKind::Global => "global".to_string(),
        },
        baseline_artifact: path.display().to_string(),
        baseline_version: None,
        baseline_fallback: fallback_reason.is_some(),
        baseline_fallback_reason: fallback_reason,
    }
}

fn select_model(node: &str, config: &BaselineLifecycleConfig) -> anyhow::Result<BaselineSelection> {
    let per_node = config.per_node_path(node);
    if per_node.is_file() {
        match load_model(&per_node) {
            Ok(model) => {
                return Ok(BaselineSelection {
                    path: per_node.clone(),
                    kind: BaselineKind::PerNode,
                    model,
                    provenance: selection_provenance(node, BaselineKind::PerNode, &per_node, None),
                });
            }
            Err(per_node_error) => {
                let global = PathBuf::from(&config.global_model);
                let model = load_model(&global).map_err(|global_error| {
                    anyhow::anyhow!(
                        "per-node baseline '{}' is invalid ({}); global fallback '{}' also failed ({})",
                        per_node.display(),
                        per_node_error,
                        global.display(),
                        global_error
                    )
                })?;
                return Ok(BaselineSelection {
                    path: global.clone(),
                    kind: BaselineKind::Global,
                    model,
                    provenance: selection_provenance(
                        node,
                        BaselineKind::Global,
                        &global,
                        Some(format!("per-node baseline invalid: {per_node_error}")),
                    ),
                });
            }
        }
    }

    let global = PathBuf::from(&config.global_model);
    let model = load_model(&global).map_err(|error| {
        anyhow::anyhow!(
            "no per-node model for '{node}' and global fallback '{}' is unavailable ({error})",
            global.display()
        )
    })?;
    Ok(BaselineSelection {
        path: global.clone(),
        kind: BaselineKind::Global,
        model,
        provenance: selection_provenance(
            node,
            BaselineKind::Global,
            &global,
            Some("per-node baseline unavailable".to_string()),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{Duration, UNIX_EPOCH};

    fn write_model(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, body).expect("write model");
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "sgx-anomaly-engine-baseline-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn path_template_uses_node_id() {
        let config = BaselineLifecycleConfig {
            global_model: "global.json".into(),
            per_node_model_template: "data/{node}_forest.json".into(),
            min_normal_days: 7,
            refresh_days: 30,
            reload_check_seconds: 60,
            evidence_dir: None,
        };
        assert_eq!(
            config.per_node_path("nodeA"),
            PathBuf::from("data/nodeA_forest.json")
        );
    }

    #[test]
    fn valid_per_node_model_is_selected() {
        let dir = unique_temp_dir("per-node");
        let global = dir.join("global.json");
        let per_node = dir.join("nodeA.json");
        write_model(&global, include_str!("../data/global_forest.json"));
        write_model(&per_node, include_str!("../data/nodeA_forest.json"));

        let config = BaselineLifecycleConfig {
            global_model: global.display().to_string(),
            per_node_model_template: dir.join("{node}.json").display().to_string(),
            min_normal_days: 7,
            refresh_days: 30,
            reload_check_seconds: 1,
            evidence_dir: None,
        };

        let (lifecycle, _model) = BaselineLifecycle::load("nodeA", config).expect("load");
        let provenance = lifecycle.provenance();

        assert_eq!(lifecycle.active_kind, BaselineKind::PerNode);
        assert_eq!(provenance.baseline_kind, BaselineKind::PerNode);
        assert_eq!(provenance.baseline_source, "nodeA");
        assert_eq!(provenance.baseline_artifact, per_node.display().to_string());
        assert!(!provenance.baseline_fallback);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_per_node_uses_global_fallback() {
        let dir = unique_temp_dir("global-fallback");
        let global = dir.join("global.json");
        write_model(&global, include_str!("../data/global_forest.json"));

        let config = BaselineLifecycleConfig {
            global_model: global.display().to_string(),
            per_node_model_template: dir.join("{node}.json").display().to_string(),
            min_normal_days: 7,
            refresh_days: 30,
            reload_check_seconds: 1,
            evidence_dir: None,
        };

        let (lifecycle, _model) = BaselineLifecycle::load("nodeB", config).expect("load");
        let provenance = lifecycle.provenance();

        assert_eq!(lifecycle.active_kind, BaselineKind::Global);
        assert_eq!(provenance.baseline_kind, BaselineKind::Global);
        assert!(provenance.baseline_fallback);
        assert_eq!(
            provenance.baseline_fallback_reason.as_deref(),
            Some("per-node baseline unavailable")
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn invalid_per_node_falls_back_to_global() {
        let dir = unique_temp_dir("invalid-fallback");
        let global = dir.join("global.json");
        let per_node = dir.join("nodeA.json");
        write_model(&global, include_str!("../data/global_forest.json"));
        write_model(&per_node, "{\"not\":\"a valid forest\"}");

        let config = BaselineLifecycleConfig {
            global_model: global.display().to_string(),
            per_node_model_template: dir.join("{node}.json").display().to_string(),
            min_normal_days: 7,
            refresh_days: 30,
            reload_check_seconds: 1,
            evidence_dir: None,
        };

        let (lifecycle, _model) = BaselineLifecycle::load("nodeA", config).expect("load");
        let provenance = lifecycle.provenance();

        assert_eq!(lifecycle.active_kind, BaselineKind::Global);
        assert!(provenance.baseline_fallback);
        assert!(provenance
            .baseline_fallback_reason
            .as_deref()
            .unwrap_or_default()
            .contains("per-node baseline invalid"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn updated_per_node_artifact_reloads() {
        let dir = unique_temp_dir("reload");
        let global = dir.join("global.json");
        let per_node = dir.join("nodeA.json");
        write_model(&global, include_str!("../data/global_forest.json"));
        write_model(&per_node, include_str!("../data/nodeA_forest.json"));

        let config = BaselineLifecycleConfig {
            global_model: global.display().to_string(),
            per_node_model_template: dir.join("{node}.json").display().to_string(),
            min_normal_days: 7,
            refresh_days: 30,
            reload_check_seconds: 1,
            evidence_dir: None,
        };

        let (mut lifecycle, _model) = BaselineLifecycle::load("nodeA", config).expect("load");
        std::thread::sleep(Duration::from_millis(5));
        write_model(&per_node, include_str!("../data/nodeB_forest.json"));

        let reloaded = lifecycle.reload_now().expect("reload").expect("updated");
        assert_eq!(reloaded.0, BaselineKind::PerNode);
        assert_eq!(
            lifecycle.provenance().baseline_artifact,
            per_node.display().to_string()
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn global_start_promotes_to_per_node() {
        let dir = unique_temp_dir("promotion");
        let global = dir.join("global.json");
        let per_node = dir.join("nodeC.json");
        write_model(&global, include_str!("../data/global_forest.json"));

        let config = BaselineLifecycleConfig {
            global_model: global.display().to_string(),
            per_node_model_template: dir.join("{node}.json").display().to_string(),
            min_normal_days: 7,
            refresh_days: 30,
            reload_check_seconds: 1,
            evidence_dir: None,
        };

        let (mut lifecycle, _model) =
            BaselineLifecycle::load_global("nodeC", config).expect("load global");
        assert_eq!(lifecycle.active_kind, BaselineKind::Global);
        assert!(lifecycle.provenance().baseline_fallback);

        std::thread::sleep(Duration::from_millis(5));
        write_model(&per_node, include_str!("../data/nodeB_forest.json"));

        let promoted = lifecycle.reload_now().expect("reload").expect("promote");
        assert_eq!(promoted.0, BaselineKind::PerNode);
        let provenance = lifecycle.provenance();
        assert_eq!(provenance.baseline_kind, BaselineKind::PerNode);
        assert!(!provenance.baseline_fallback);
        let _ = fs::remove_dir_all(dir);
    }
}
