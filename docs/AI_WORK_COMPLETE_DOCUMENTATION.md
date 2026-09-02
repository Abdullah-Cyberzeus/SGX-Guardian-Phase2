# AI/ML Work Complete Documentation
## SGX Guardian Anomaly Detection Engine

**Last Updated:** September 2026  
**Project:** SGX Guardian - Circle of Trust  
**Status:** Phase 1 Complete, Phase 2 In Progress

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Core Components](#core-components)
4. [Workflow](#workflow)
5. [Files Created](#files-created)
6. [Features Schema](#features-schema)
7. [Training Data](#training-data)
8. [Model Files](#model-files)
9. [Integration Points](#integration-points)
10. [Current Issues](#current-issues)
11. [Next Steps](#next-steps)

---

## 📌 Overview

The **Anomaly Detection Engine** is the AI/ML component of SGX Guardian that detects security threats by analyzing telemetry data from nodes in a Circle of Trust network.

**Purpose:**
- Detect abnormal behavior patterns on network nodes in real-time
- Score anomalies from 0-1 (higher = more suspicious)
- Provide confidence levels for each detection
- Generate automated security recommendations
- Support policy enforcement decisions

**Core Technology:**
- Two-tier hybrid detection model
- Tier-1: Online Z-Score statistical baseline (always-on)
- Tier-2: Isolation Forest ML model (trained, optional)
- 19-feature telemetry schema
- Rust implementation with Python training side

---

## 🏗️ Architecture

### High-Level Data Flow

```
Raw Telemetry (19 metrics)
        ↓
   Feature Extraction (D3)
        ↓
   Tier-1: Z-Score Scoring (D5)
        ├─ Comparison against per-node baseline
        ├─ Online Welford's algorithm
        └─ Returns anomaly score 0-1
        ↓
   Tier-2: Isolation Forest (D5)
        ├─ Trained ML model (JSON export)
        ├─ Real-time forest scoring
        └─ Returns anomaly score 0-1
        ↓
   Fusion (D6)
        ├─ Worst-tier-wins (max score)
        ├─ Cooldown tracking
        └─ Confidence calculation
        ↓
   Alert Generation (D7)
        ├─ Severity banding
        ├─ Reason explanation
        ├─ Recommendation rules
        └─ JSON alert output
        ↓
   Policy Recommendations (Task 2)
        ├─ Firewall rules
        ├─ Attestation requests
        ├─ Logging level adjustments
        └─ Quarantine decisions
```

### Two-Tier Model Explanation

#### Tier-1: Z-Score Model (Online, Statistical)
- **What it does:** Compares each incoming metric against its historical mean/variance for that node
- **Algorithm:** Welford's algorithm (numerically stable, single-pass mean+variance)
- **Features:** Per-node baseline (different normal for busy node vs. quiet node)
- **Calculation:** |z-score| = |value - mean| / stddev
- **Heavy-tailed Features:** Transformed using log1p to handle traffic/rate spikes
- **Sparse Features:** Variance floor applied so first-ever event doesn't score as infinite
- **Always On:** Runs continuously, even before trained model is available
- **Calibration:** P99/P99.5 threshold computed from normal training data

#### Tier-2: Isolation Forest Model (Trained ML, Optional)
- **What it does:** Multivariate anomaly detection using a trained Isolation Forest
- **Algorithm:** Ensemble of 100 random isolation trees (sklearn-compatible)
- **Training:** Fit on historical normal + attack data using Python
- **Export:** Model serialized to JSON with tree structure + decision rules
- **Scoring:** Raw anomaly score converted to 0-1 normalized value
- **Per-Node Promotion:** Fallback to global model if per-node export missing
- **Automatic Refresh:** Loads new trained models on configured intervals
- **Parity Testing:** Rust implementation validated against Python to 1e-6 tolerance

#### Fusion Strategy (D6)
- **Method:** Worst-tier-wins (maximum score)
- **Tie-breaker:** If both tiers score high, use Tier-2 (more sophisticated)
- **Confidence:** Ramps up from 0 to 1 as node collects more samples (warmup period)
- **Cooldown:** Alert throttling to avoid alert fatigue (e.g., 60 seconds between alerts)
- **Result:** Single anomaly score + confidence + which tier decided

---

## 🔧 Core Components

### Location: `/home/asad/SGX/crates/sgx-anomaly-engine/`

#### 1. **Feature Extraction (`src/features.rs`)**
- Defines 19-feature locked schema
- Converts raw counters to rates (bytes/sec, packets/sec)
- Applies EWMA smoothing (exponential weighted moving average)
- Returns ready-to-score FeatureVector
- **Parity:** Python must use identical feature order

#### 2. **Tier-1 Model (`src/model.rs` - ZScoreModel)**
- Online per-feature, per-node z-score calculation
- Maintains running mean/variance per node (HashMap<node_id, NodeStats>)
- Applies log1p transform to 13 heavy-tailed features
- Variance floor for 5 sparse event-count features
- Warmup logic: ~30 samples before full confidence
- Fix 2: Log transformation applied consistently between Rust and Python sides
- Fix 1: Calibrated z_alert_threshold for raw max|z| cutoff

#### 3. **Tier-2 Model (`src/model.rs` - IsolationForestModel)**
- Loads JSON-serialized Isolation Forest from disk
- Implements same scoring as sklearn's IsolationForest
- Converts raw anomaly scores to [0,1] normalized value
- Extracts top-k anomaly-contributing features
- Returns Score struct with value, confidence, topk, raw_value

#### 4. **Engine Loop (`src/engine.rs`)**
- Main detection loop: poll → extract features → score → fuse → alert
- Configurable poll interval (default: 1s)
- Maintains state across ticks
- Cooldown map to throttle repeated alerts
- Optional role-based baseline (shadow mode)
- Alert threshold: 0.8 (normalized score, configurable)

#### 5. **Alert Generation (`src/alert.rs`)**
- Severity banding: Low/Medium/High/Critical
- Reason generation from top-k anomalous features
- Recommendation matching via rule engine
- Alert struct: JSON-serializable with score, confidence, tier attribution
- AlertSink trait: enables stdout, file, or SGX audit log output

#### 6. **Recommendation Rules (`src/rules.rs`)**
- Runtime-loadable JSON rules (no code rebuild needed)
- Pattern matching: min_overlap between observed features and rule signature
- Built-in defaults if config file missing/invalid
- 5 pre-defined patterns: portscan, flood, resource_exhaustion, protocol_violation, peer_anomaly
- Optional ActionDefinition for policy enforcement

#### 7. **Baseline Lifecycle (`src/baseline.rs`)**
- Manages model file selection: per-node vs. global fallback
- Checks for new exported models at configured interval (default: 1 hour)
- Validates model freshness and correctness before swap
- Audit trail: logs initialization, reload, fallback decisions
- Evidence directory: optional audit capture of model snapshots

#### 8. **Policy Integration (`src/policy.rs` + `src/virtual_shift/`)**
- PolicyAction enum: TightenFirewall, IncreaseAttestation, EnableLogging, QuarantinePeer
- PolicyCandidate: JSON struct from Task 1 recommendation → Task 2 policy draft
- PolicyAuditRecord: tracks approval, application, and results
- VirtualShift integration: structured AnomalyEvent passed downstream

#### 9. **Port Security (`src/port_*.rs`)**
- Analyzes open ports on discovered assets
- Uses port knowledge base (from Common Ports markdown guide)
- Score rules engine for risk assessment
- Port-specific severity and recommendations
- Integration with network inventory nmap data

#### 10. **Virtual Shift Module (`src/virtual_shift/`)**
- Bridge between Task 1 (anomaly detection) and Task 2 (policy)
- Validates anomaly events before downstream use
- Proposes firewall, attestation, logging actions
- Gossip protocol support for policy dissemination
- Member verification and policy application tracking

---

## 🔄 Workflow

### Step-by-Step Process

#### **Phase D1: Schema Definition**
```
Lock 19-feature schema in src/features.rs
  ↓
Python trainer reads same schema from schema/feature_names.json
  ↓
Test validates Rust ↔ Python parity (test/parity.rs)
```

**Files Involved:**
- `crates/sgx-anomaly-engine/src/features.rs` (Rust definition)
- `schema/feature_names.json` (Shared source of truth)
- `anomaly-training/features.py` (Python reads same JSON)

---

#### **Phase D2: Data Collection**
```
Telemetry collector on each node (sgx-agent)
  ↓
Raw samples every 1 second (configurable)
  ↓
Stored as CSV or JSON (test fixtures use CSV)
  ↓
Example: nodeA_normal.csv, nodeA_attacks.csv
```

**Data Points per Sample:**
- net_rx_bytes_total, net_tx_bytes_total
- net_rx_pkts_total, net_tx_pkts_total
- nebula_mbps (overlay bandwidth)
- conn_total (connection count)
- active_peers, relay_ratio
- relay_bytes_total
- cot_switches_total, cot_latency_avg_ms
- policy_event_total, attest_total
- proto_violation_total, error_total
- cpu_util_pct, mem_used_pct
- open_fds, load1
- timestamp (ts_ms)

**Collected From:**
- `/proc/net/` (Linux kernel)
- Network stack counters
- Container orchestration metrics
- Custom agent telemetry

---

#### **Phase D3: Feature Extraction**
```python
Raw sample → Rate calculation (for counters)
          → EWMA smoothing (alpha = 0.3 default)
          → FeatureVector [f64; 19]
```

**Smoothing Formula:**
```
smoothed[t] = alpha * raw[t] + (1 - alpha) * smoothed[t-1]
```

**Why Smoothing?**
- Reduces noise from short-term fluctuations
- Allows anomaly detector to react to sustained activity changes
- Prevents alert fatigue from single spikes

**Parity Note:** Tier-2 scores raw vectors (not smoothed) because Python trainer used raw CSV data. Tier-1 uses smoothed values.

---

#### **Phase D4: Telemetry Polling**
```
Engine loop calls: telemetry_source.poll()
  ↓
Returns most recent RawSample
  ↓
Every 1 second (configurable interval)
```

**Trait:** `TelemetrySource`
- Implementations: real system, mock for tests, CSV replay
- Non-blocking: async/await support

---

#### **Phase D5: Model Scoring**
```
Tier-1 (Z-Score):
  1. Get per-node running mean/stddev
  2. Compute |z| for each feature
  3. Apply log1p transform if heavy-tailed
  4. Return max|z| as raw score
  5. Normalize to [0,1] using sigmoid-like curve

Tier-2 (Isolation Forest):
  1. Load trained JSON model (100 trees)
  2. Traverse each tree with feature vector
  3. Average anomaly scores across ensemble
  4. Normalize to [0,1]
  5. Extract top-k anomalous features
```

**Output (Score struct):**
```rust
pub value: f64,           // Normalized [0, 1]
pub confidence: f64,      // 0 = untrusted, 1 = fully confident
pub topk: Vec<String>,    // Top 3-5 anomalous feature names
pub raw_value: Option<f64> // Pre-normalization score
```

---

#### **Phase D6: Fusion**
```
if tier2_available {
  final_score = max(tier1_score, tier2_score)
  confidence = min(tier1_confidence, tier2_confidence)
  if tier2_score > tier1_score {
    tier = Tier2
  } else {
    tier = Tier1
  }
} else {
  final_score = tier1_score
  tier = Tier1
}

if final_score >= alert_threshold (0.8) {
  check cooldown_until[node]
  if not in cooldown {
    mark cooldown_until[node] = now + cooldown_duration
    emit alert ✓
  }
}
```

**Cooldown Example:**
- Alert fired at t=100s for nodeA
- Cooldown set to 60s
- Next alert for nodeA can fire at t≥160s
- Different nodes have independent cooldown timers

---

#### **Phase D7: Alert & Recommendations**
```
Triggered Alert → Severity Banding:
  score >= 0.95 → Critical
  score >= 0.90 → High
  score >= 0.80 → Medium
  score <  0.80 → Low (unreachable, only fired >= 0.80)

Alert → Top-K Features:
  Identify which 3-5 features drove the score
  Map to human-readable names
  Combine into reason string

Alert → Rule Matching:
  Compare topk against configured rules
  Find best pattern match (highest overlap)
  Generate attack-type-specific recommendation

Alert → JSON Output:
  {
    "ts": 1693036445000,
    "node": "nodeA",
    "role": "gateway",
    "score": 0.87,
    "confidence": 0.92,
    "severity": "High",
    "topk": ["net_rx_bytes_rate", "cpu_util_pct", "load1"],
    "reason": "Incoming traffic volume and CPU spiked together",
    "recommendation": "Check for traffic flood or malicious scanning",
    "tier": "Tier2"
  }
```

**Alert Output Destinations:**
- Stdout (StdoutSink - for CLI demos)
- File (FileSink - JSON lines format)
- SGX audit log (SgxAlertSink - future)

---

#### **Phase D8: Senior Review & Fixes**

**Fix 1 - Tier-1 Calibration:**
- Issue: Raw z-scores not comparable across features
- Solution: P99 threshold computed on normal training data
- Deployed: z_alert_threshold parameter in ZScoreModel

**Fix 2 - Log1p Transformation:**
- Issue: Heavy-tailed features (traffic rates) inflate variance
- Solution: Apply ln(1 + x) to 13 rate/count features before z-scoring
- Parity: Python trainer must apply same transformation

**Fix 3 - Variance Floor:**
- Issue: Sparse event counts score as infinite z-score on first event
- Solution: Floor stddev at 0.5 (sparse) or 1e-6 (others)

**M2 - Alert Rate Reporting:**
- Issue: Alert percentage is misleading
- Solution: Report alerts/hour instead (55 alerts/hour reads different than "1.5%")

**M3 - Tier Attribution:**
- Issue: False positives unattributed to which tier caused them
- Solution: AlertTier enum (Tier1 vs. Tier2) in every alert

---

#### **Phase D9: Model Training (Python Side)**

**Location:** `anomaly-training/` folder

**Process:**

1. **Data Preparation (`prep.py`)**
   - Read normal + attack CSV files
   - Feature alignment with Rust schema
   - Train/test split (80/20)
   - Feature scaling if needed

2. **Tier-1 Calibration**
   - Compute z-scores on normal data only
   - Extract P99/P99.5 of max|z|
   - This becomes tier1_threshold
   - No ground truth label used (unsupervised)

3. **Tier-2 Training (`train_iforest.py`)**
   - Fit Isolation Forest on normal data
   - 100 trees, default parameters
   - No labels used (unsupervised learning)
   - Save to joblib format

4. **Model Export (`export_model.py`)**
   - Convert joblib forest to JSON
   - Serialize tree structure, splits, leaf anomaly scores
   - Include metadata: threshold_raw, score_lo, score_hi
   - Deploy JSON to model directory

5. **Parity Validation (`dump_parity_fixture.py`)**
   - Compute scores on Python side for test vectors
   - Output fixture JSON with python_raw_score
   - Rust test loads fixture and compares: must match ±1e-6

---

#### **Phase D10: Parity Testing (Python ↔ Rust)**

**Location:** `tests/parity.rs`

**Purpose:** Ensure Rust and Python compute same anomaly score

**Process:**
```
Python scores 50-100 test vectors
  ↓
Export to: tests/fixtures/nodeA_parity.json
  ↓
Rust loads same model + fixture
  ↓
For each vector:
  Rust score vs. Python score
  Assert difference < 1e-6
  ✓ PASS if all within tolerance
  ✗ FAIL if any diverges (scoring bug)
```

**Why This Matters:**
- Live deployment uses Rust
- Training happens in Python
- Silent divergence = model works differently in prod vs. training
- This test catches train/serve mismatch before it becomes a problem

---

## 📁 Files Created

### Core Engine Files

#### Anomaly Engine Source (`crates/sgx-anomaly-engine/src/`)

| File | Purpose | Lines | Key Types |
|------|---------|-------|-----------|
| `lib.rs` | Public API, re-exports | 50 | - |
| `main.rs` | CLI binary (demo) | 100 | - |
| `model.rs` | Tier-1 + Tier-2 scoring | 1200+ | ZScoreModel, IsolationForestModel, Score |
| `features.rs` | 19-feature schema + extraction | 500 | FEATURE_NAMES, FeatureVector, FeatureExtractor |
| `engine.rs` | Main loop, fusion, cooldown | 800 | AnomalyEngine, run(), tick() |
| `alert.rs` | Alert structures + generation | 600 | AnomalyAlert, AlertSink, severity_for() |
| `rules.rs` | Runtime-loaded rules | 300 | RuleFile, PatternRule |
| `baseline.rs` | Model lifecycle management | 700 | BaselineLifecycle, BaselineKind |
| `policy.rs` | Policy data types + templates | 500 | PolicyAction, PolicyCandidate, PolicyTemplates |
| `port_security.rs` | Open port risk assessment | 400 | PortSeverity, PortFinding, PortSecurityReport |
| `port_knowledge.rs` | Port knowledge base parser | 150 | PortKnowledgeEntry |
| `port_risk.rs` | Port risk scoring | 400 | PortRiskResult, evaluate() |
| `telemetry.rs` | RawSample definition + sources | 300 | RawSample, TelemetrySource trait |
| `roles.rs` | Node role definitions | 100 | NodeRole enum |
| `alert_handler.rs` | Alert routing | 200 | - |

#### Virtual Shift Integration (`src/virtual_shift/`)

| File | Purpose |
|------|---------|
| `mod.rs` | VirtualShift main module exports |
| `model.rs` | AnomalyEvent, AnomalyEvidence, AnomalyType |
| `errors.rs` | VirtualShiftError definitions |
| `proposal_*.rs` | Firewall/Attestation/Logging proposal logic |
| `gossip.rs` | Peer-to-peer policy dissemination |
| `verification.rs` | Member identity & policy verification |
| `audit.rs` | Audit trail generation |

### Configuration Files

| File | Purpose |
|------|---------|
| `schema/feature_names.json` | 19-feature locked schema (shared with Python) |
| `config/recommendation_rules.json` | Runtime-loadable alert rules |
| `config/port_security_rules.json` | Port severity templates |
| `config/policy_templates.json` | Policy action templates for Task 2 |
| `config/baseline_lifecycle.json` | Model reload configuration |

### Test & Demo Files

| File | Purpose | Type |
|------|---------|------|
| `tests/parity.rs` | Python ↔ Rust score validation | Integration test |
| `tests/fixtures/nodeA_parity.json` | Test vectors + python scores | Fixture (generated) |
| `examples/run_d5_d6_d7_demo.rs` | End-to-end scoring demo | Executable example |
| `examples/run_virtual_shift_lifecycle_demo.rs` | Policy recommendation flow | Executable example |
| `examples/run_policy_recommendation_groups_demo.rs` | Alert grouping demo | Executable example |
| `examples/run_virtual_shift_audit_demo.rs` | Audit trail generation | Executable example |

### Data Files

| File | Purpose | Format |
|------|---------|--------|
| `data/nodeA_forest.json` | Trained Tier-2 model | JSON (Isolation Forest) |
| `data/nodeA_normal.csv` | Training data (normal behavior) | CSV |
| `data/nodeA_attacks.csv` | Training data (attack scenarios) | CSV |
| `data/recommendation_records/*/recommendations.json` | Task 1 output (ground truth) | JSONL |

### Generated Artifacts

| Location | Purpose |
|----------|---------|
| `build/artifacts/sgx-guardian/` | Release binary |
| `build/deb/` | Debian package (if packaged) |
| `/var/lib/sgx-guardian/advisory/recommendations.jsonl` | Runtime output (alerts) |

---

## 📊 Features Schema

### The 19-Feature Locked Schema

**Location:** `schema/feature_names.json` + `src/features.rs`

```json
[
  "net_rx_bytes_rate",       // 0  - Incoming traffic (bytes/sec)
  "net_tx_bytes_rate",       // 1  - Outgoing traffic (bytes/sec)
  "net_rx_pkts_rate",        // 2  - Incoming packets (packets/sec)
  "net_tx_pkts_rate",        // 3  - Outgoing packets (packets/sec)
  "nebula_mbps",             // 4  - Overlay bandwidth (Mbps)
  "conn_rate",               // 5  - New connections (conn/sec)
  "active_peers",            // 6  - Active peer count (integer)
  "relay_ratio",             // 7  - Relay traffic %  (0-1)
  "relay_bytes_rate",        // 8  - Relay volume (bytes/sec)
  "cot_switches_rate",       // 9  - Context switches (sw/sec)
  "cot_latency_avg_ms",      // 10 - Operation latency (ms, gauge)
  "policy_event_rate",       // 11 - Policy updates (events/sec)
  "attest_rate",             // 12 - Attestations (events/sec)
  "proto_violation_rate",    // 13 - Bad packets (packets/sec)
  "error_rate",              // 14 - Errors (events/sec)
  "cpu_util_pct",            // 15 - CPU usage (%, gauge 0-100)
  "mem_used_pct",            // 16 - Memory usage (%, gauge 0-100)
  "open_fds",                // 17 - Open file descriptors (int gauge)
  "load1"                    // 18 - 1-min load average (gauge)
]
```

### Feature Transformation

#### Rate Features (0, 1, 2, 3, 5, 8, 9, 11, 12, 13, 14)
```
rate = (current_counter - previous_counter) / time_delta_seconds
```

#### Gauge Features (4, 6, 7, 10, 15, 16, 17, 18)
```
gauge_value = current_gauge  (used as-is)
```

#### Heavy-Tailed Features (0, 1, 2, 3, 4, 5, 8, 9, 11, 12, 13, 14, 17)
```
Before Tier-1 Z-Score:
  transformed_value = log(1 + raw_value)
  Why: Traffic/rate spikes create long tails in distribution
       Standard deviation inflates with occasional bursts
       Log transformation compresses tail, reveals true baseline
```

#### Sparse Features (9, 11, 12, 13, 14)
```
Variance Floor: 0.5 (not 1e-6)
Why: First-ever policy event would score as infinite z-score without floor
     Early event detection more important than handling noise
```

### Feature Extraction Process (FeatureExtractor)

```rust
pub fn update(&mut self, raw: RawSample) -> FeatureVector {
  // Step 1: Convert counters to rates
  dt_seconds = (raw.ts_ms - prev.ts_ms) / 1000
  net_rx_bytes_rate = (raw.net_rx_bytes_total - prev.net_rx_bytes_total) / dt_seconds
  // ...repeat for all rate features...

  // Step 2: Keep gauge values as-is
  cpu_util_pct = raw.cpu_util_pct  // already a %
  load1 = raw.load1               // already an average

  // Step 3: Apply EWMA smoothing
  smoothed[i] = alpha * raw[i] + (1-alpha) * ewma[i]  // for all 19 features
  
  // Step 4: Return smoothed FeatureVector
  FeatureVector(smoothed)
}
```

---

## 📚 Training Data

### Data Collection Strategy

**Sources:**
- 24-48 hours of normal network operation (nodeA, nodeB, nodeC)
- Synthetic attack simulations (5 attack types)
- Real-world network captures (optional)

**Format:**
- CSV with timestamp + 19 features per row
- One row per second (configurable)
- Example: `nodeA_normal.csv`

### Training Data Files

```
anomaly-training/
├── data/
│   ├── nodeA_normal.csv      # ~86,400 rows (24 hours @ 1 row/sec)
│   ├── nodeA_attacks.csv     # ~5,000 rows (attack scenarios)
│   ├── nodeB_normal.csv
│   ├── nodeB_attacks.csv
│   └── nodeC_normal.csv
├── trained/                  # Joblib-serialized models
│   ├── nodeA/
│   │   ├── model.joblib      # Tier-2 trained forest
│   │   └── preprocessor.joblib
│   ├── nodeB/
│   └── global/               # Fallback model (trained on all nodes)
└── scripts/
    ├── prep.py               # Data preparation
    ├── train_iforest.py      # Tier-2 training
    ├── export_model.py       # JSON export
    └── dump_parity_fixture.py # Python side parity gen
```

### Training Process

1. **Load & Validate**
   - Read CSV (nodeA_normal + nodeA_attacks)
   - Check all 19 features present
   - Handle missing/invalid rows

2. **Tier-1 Calibration (Unsupervised)**
   - Compute z-scores on normal-only data
   - Find P99 of max|z| per feature
   - Store as z_alert_threshold
   - No labels needed

3. **Tier-2 Training (Unsupervised)**
   - Train IsolationForest on normal data only
   - 100 trees, max_samples=256 (default)
   - No attack labels (one-class approach)
   - Model learns "normal" distribution implicitly

4. **Export**
   - Serialize to JSON: tree structure + node thresholds
   - Include: threshold_raw, score_lo, score_hi, n_samples
   - Deploy alongside Rust binary

5. **Validation**
   - Run on test set (unseen normal + known attacks)
   - Compute FPR (false positive rate on normal)
   - Compute TPR (true positive rate on attacks)
   - Cross-validate with senior review

---

## 🤖 Model Files

### Isolation Forest JSON Format

**Location:** `data/nodeA_forest.json`

**Structure:**
```json
{
  "n_trees": 100,
  "n_features": 19,
  "max_samples": 256,
  "threshold_raw": 0.59,
  "score_lo": 0.37,      // Min score in training
  "score_hi": 0.64,      // Max score in training
  "n_samples": 256,      // Samples used for normalization
  "trees": [
    {
      "feature": 0,                    // Split on feature 0 (net_rx_bytes_rate)
      "threshold": 1629005.46,         // Value threshold
      "samples": 128,                  // Samples at this node
      "value": -0.456,                 // Anomaly score if leaf
      "left": { ... },                 // Recurse: feature < threshold
      "right": { ... }                 // Recurse: feature >= threshold
    },
    // ...99 more trees...
  ]
}
```

### Scoring Process (Isolation Forest)

```
For each tree in ensemble:
  Traverse from root to leaf following feature comparisons
  At leaf: extract anomaly score (isolation depth)
  
Raw anomaly score = average across all 100 trees
Normalized score = (raw - score_lo) / (score_hi - score_lo)  // Clamp to [0,1]
```

### Baseline Lifecycle Configuration

**Location:** `config/baseline_lifecycle.json`

```json
{
  "version": 1,
  "global_model": "data/nodeA_forest.json",
  "per_node_model_template": "data/per_node/{node}/forest.json",
  "min_normal_days": 7,
  "refresh_days": 30,
  "reload_check_seconds": 3600,
  "evidence_dir": "/var/lib/sgx-guardian/model_audit"
}
```

**Behavior:**
1. On startup: Load per-node model if exists, else use global
2. Every 3600s: Check if per-node model updated
3. If new model: Validate then swap (no alert disruption)
4. Evidence: Save JSON + model snapshot to audit folder

---

## 🔗 Integration Points

### 1. Task 1 → Task 2 (Policy Recommendations)

**Interface:** `AnomalyEvent` (structured)

```rust
pub struct AnomalyEvent {
    pub anomaly_id: String,
    pub source_node: String,
    pub anomaly_type: AnomalyType,  // ConnectionScan, TrafficFlood, etc.
    pub score: f64,
    pub confidence: f64,
    pub severity: Severity,
    pub affected_peers: Vec<String>,
    pub observed_at_ms: u64,
    pub evidence: Vec<AnomalyEvidence>,  // Feature contributing names
    pub reason: String,
    pub recommendation: String,
    pub proposed_action: Option<ActionDefinition>,  // Firewall, Attest, Log, Quarantine
}
```

**Flow:**
```
AnomalyAlert (from D7) 
  → anomaly_event_from_task1_record() 
  → AnomalyEvent (validated)
  → Virtual Shift (Task 2)
  → Policy recommendations
```

### 2. Recommendation Output Format

**Current (Issue #1: Not Structured):**
```json
{
  "context": [
    "Anomaly score 0.51: task1-alert-scorer",
    "Anomaly: feature_name contribution 1.00 (reason)"
  ]
}
```

**Desired (Issue #1: To Be Fixed):**
```json
{
  "anomaly": {
    "score": 0.51,
    "confidence": 0.87,
    "detector": "task1-alert-scorer",
    "tier": "Tier2",
    "contributors": [
      {
        "feature": "net_rx_bytes_rate",
        "contribution": 1.00,
        "reason": "unusual local signal"
      },
      {
        "feature": "cpu_util_pct",
        "contribution": 0.45,
        "reason": "correlation with traffic"
      }
    ]
  }
}
```

### 3. Real-Time Alert Pipeline

**Source:** Engine loop (1s polling)
```
TelemetrySource.poll() 
  → FeatureExtractor.update() 
  → ZScoreModel.score() + IsolationForestModel.score()
  → Fusion (max score)
  → Cooldown check
  → AlertSink.emit()
```

**Destinations:**
1. **Stdout** (CLI demos)
2. **File** (JSON lines: `/var/lib/sgx-guardian/advisory/recommendations.jsonl`)
3. **SGX Audit Log** (future, secure enclave)
4. **Dashboard** (async webhook/websocket)

### 4. Policy Enforcement

**From Alert → Action:**

```
AnomalyAlert.recommendation 
  → Rule engine match (pattern signature)
  → ActionDefinition extracted
  → Policy candidate created
  → Admin approval workflow (if configured)
  → Policy applied to nodes
  → Audit record created
```

**Policy Actions:**
- TightenFirewall: Add nftables rules, rate-limit traffic
- IncreaseAttestationFrequency: Change attestation interval
- EnableAdditionalLogging: Raise logging level (DEBUG, TRACE)
- QuarantinePeer: Disconnect suspicious peer, flag for review

---

## ⚠️ Current Issues

### Issue #1: Anomaly Data Not Structured (OPEN)

**Status:** Medium-High Priority  
**Area:** Backend API Contract

**Problem:**
- Anomaly score, confidence, contributors buried in text strings
- Client apps must parse English sentences (fragile)
- Text changes break parsing (no schema evolution)

**Example (Current):**
```json
{
  "context": [
    "Anomaly score 0.51: task1-alert-scorer",
    "Anomaly: net_rx_bytes_rate contribution 1.00 (unusual local signal)"
  ]
}
```

**Impact:**
- Dashboard integration difficult
- Automation reliant on string parsing
- Impossible to query by feature programmatically

**Solution (WIP):**
- Add dedicated `anomaly` object with structured fields
- Keep `context[]` for human readability
- Enable both programmatic + readable output

---

### Issue #2: Parity Test Skipped Without Model (KNOWN)

**Status:** Acceptable  
**Area:** Testing

**Problem:**
- `tests/parity.rs` skips if fixture missing (by design)
- Trainer must export parity.json AFTER training
- Order of operations unclear in CI/CD

**Impact:**
- Can't validate Rust ↔ Python match until training complete
- Silent if parity broken before discovered

**Mitigation:**
- Generate fixture in CI before running tests
- Document workflow: `dump_parity_fixture.py` → `parity.rs`

---

### Issue #3: Tier-1 Calibration Not Deployed (OPEN)

**Status:** Medium Priority  
**Area:** Tier-1 Model

**Problem:**
- Fix 1 (calibrated z_alert_threshold) implemented in Rust
- Not yet deployed on Python training side
- Tier-1 running uncalibrated in production

**Impact:**
- Tier-1 threshold mismatch between training + runtime
- False positive rate not controlled for Tier-1
- If Tier-2 unavailable, falls back to uncalibrated Tier-1

**Solution:**
- Compute P99/P99.5 of max|z| on normal data in Python
- Export to model JSON (new `tier1_threshold` field)
- Load in Rust and set via `with_z_alert_threshold()`
- Update parity test to cover Tier-1

---

### Issue #4: Log1p Transform Train/Serve Mismatch (FIXED)

**Status:** Completed (Fix 2)  
**Details:**
- Heavy-tailed features (traffic rates) inflated variance
- Tier-1 z-scores unreliable without log transformation
- **Fix:** Apply log(1+x) identically on both Python + Rust sides
- **Validation:** Parity test now covers log1p behavior

---

### Issue #5: Sparse Feature Variance (FIXED)

**Status:** Completed (Fix 3)  
**Details:**
- First-ever attestation_rate event scored as infinite z-score
- Variance floor (0.5 for sparse, 1e-6 for others) prevents this
- **Applied:** Both Rust ZScoreModel + Python trainer

---

## 🚀 Next Steps

### Phase 2 Roadmap (Immediate - Q1 2026)

#### Task 1: Enhance Anomaly Detection

1. **Deploy Tier-1 Calibration**
   - Compute z_alert_threshold on Python side
   - Export to model JSON
   - Update Rust loader + parity tests
   - Measure FPR improvement

2. **Expand Feature Schema (Optional)**
   - Consider adding container metrics (if available)
   - Add AppArmor/SELinux policy change events
   - Validate with senior review before locking

3. **Improve Alert Context**
   - **Issue #1 Fix:** Structured `anomaly` object
   - Keep text `reason` for humans
   - Query by feature programmatically

4. **Per-Node Model Lifecycle**
   - Generate per-node exports (via `dump_training_data.py`)
   - Validate freshness on each node
   - Automatic promotion when P99 improves

#### Task 2: Policy Recommendations (Virtual Shift)

1. **Firewall Policy Generation**
   - Translate anomaly features → firewall rules
   - Rate-limiting recommendations (bytes/sec, packets/sec)
   - Admin approval workflow

2. **Attestation Tuning**
   - Dynamic attestation intervals based on threat level
   - Critical severity = 1min intervals
   - Normal = 1hr intervals

3. **Logging Enhancement**
   - Propose detailed (TRACE) logging during anomaly window
   - Auto-rotate logs to prevent disk fill
   - Cleanup after escalation resolved

4. **Peer Quarantine Logic**
   - Identify affected_peers from evidence
   - Suggest temporary disconnection + review
   - Gossip notification to other nodes

#### Task 3: Operational Readiness

1. **Documentation**
   - Operator guide: model refresh workflow
   - Troubleshooting: FP reduction steps
   - Integration: API examples for dashboards

2. **Monitoring & Alerts**
   - Alert volume trends (alerts/hour)
   - Tier split (Tier-1 vs. Tier-2 attribution)
   - Model staleness warnings

3. **Testing & Validation**
   - Extended parity tests (multi-node scenarios)
   - Shadow mode for new models before promotion
   - Red-team attack scenarios

---

### Phase 3+ Vision (Q2-Q4 2026)

#### Scalability
- Support 50+ nodes (gossip protocol optimization)
- Hierarchical trust domains (multi-cohort federation)
- Edge-to-cloud training feedback loop

#### Compliance
- FIPS 140-3 certification pathway
- Audit logging for every policy decision
- Retention policies (30-90 day windows)

#### Advanced ML
- Online learning (continuously update baseline)
- Seasonal patterns (different normal for weekends)
- Correlation analysis (multiple features together)
- Explainability (SHAP values for black-box models)

---

## 📖 How to Use This Documentation

### For Operators
1. Read "Architecture" to understand two-tier model
2. Review "Workflow" section for operational phases
3. Check "Next Steps" for upcoming changes

### For Developers
1. Start with "Core Components" to find relevant files
2. Study "Workflow" phases D1-D10 for coding patterns
3. Use "Features Schema" as reference for feature order
4. Run examples: `cargo run --example run_d5_d6_d7_demo`

### For Integration (Dashboard, Policy, etc.)
1. Focus on "Integration Points" section
2. Use `AnomalyEvent` structured type (not text parsing)
3. Monitor parity test results before production deployment

### For Training & Data Science
1. Reference "Training Data" section for collection strategy
2. Follow "Workflow D9" for model training steps
3. Run "Workflow D10" for parity validation before deployment

---

## 🎓 Key Concepts

| Term | Definition |
|------|-----------|
| **Tier-1** | Always-on z-score baseline (online learning) |
| **Tier-2** | Trained Isolation Forest (batch-trained, optional) |
| **Fusion** | Worst-tier-wins: max(score_t1, score_t2) |
| **Anomaly Score** | Normalized [0, 1] value (0=normal, 1=maximally anomalous) |
| **Confidence** | [0, 1] trust in the score (0=untrusted, 1=fully confident) |
| **Cooldown** | Throttle to prevent alert fatigue (e.g., 60s between same-node alerts) |
| **Top-K** | Top 3-5 features contributing most to anomaly score |
| **Raw Score** | Un-normalized pre-sigmoid score (per-tier scale) |
| **Log1p** | log(1+x) transformation for heavy-tailed features |
| **EWMA** | Exponential Weighted Moving Average smoothing |
| **Parity** | Python ↔ Rust scoring must match ±1e-6 (validation) |
| **Baseline** | Per-node historical mean/variance for z-score comparison |
| **Lifecycle** | Model file selection, refresh, and promotion workflow |
| **Virtual Shift** | Task 2: AI-driven policy recommendation system |
| **AnomalyEvent** | Structured hand-off from Task 1 (anomaly) to Task 2 (policy) |

---

## 📞 Support & References

### Key Files to Review
- Main architecture: [crates/sgx-anomaly-engine/src/engine.rs](crates/sgx-anomaly-engine/src/engine.rs)
- Feature schema: [schema/feature_names.json](schema/feature_names.json)
- Model definition: [crates/sgx-anomaly-engine/src/model.rs](crates/sgx-anomaly-engine/src/model.rs)
- Alert generation: [crates/sgx-anomaly-engine/src/alert.rs](crates/sgx-anomaly-engine/src/alert.rs)
- Policy integration: [crates/sgx-anomaly-engine/src/policy.rs](crates/sgx-anomaly-engine/src/policy.rs)

### Running Examples
```bash
# Build the engine
cd crates/sgx-anomaly-engine
cargo build --release

# Run end-to-end demo (scoring + alerting)
cargo run --example run_d5_d6_d7_demo -- \
  data/nodeA_normal.csv data/nodeA_attacks.csv

# Run policy recommendation flow
cargo run --example run_policy_recommendation_groups_demo -- \
  data/recommendation_records/nodeA/run_001/recommendations.json

# Validate Python ↔ Rust parity
cargo test parity --release
```

---

**Last Updated:** 2026-09-01  
**Status:** Phase 1 Complete ✅ | Phase 2 In Progress 🚀
