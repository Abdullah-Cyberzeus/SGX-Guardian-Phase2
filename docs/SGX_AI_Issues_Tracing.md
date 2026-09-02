**# Task 1 AI Application Integration — Issue Tracking**

> **Integration scope:** This tracker focuses on the **AI model and backend changes required so a user-facing application/dashboard can integrate Task 1 safely and reliably**. The user-facing layer should consume structured backend APIs; anomaly scoring, thresholds, confidence, trust decisions, policy triggers, and model logic should remain authoritative in the AI/backend layer.

**## Issue #1 — Anomaly Data Is Not Exposed as Structured JSON Fields**

**### Status**

Open

**### Severity**

Medium–High

**### Area**

Backend API Contract / Application Integration

**---**

**## Problem Summary**

The Task 1 anomaly detection engine is working and its results are being persisted in:

```text

/var/lib/sgx-guardian/advisory/recommendations.jsonl

```

However, anomaly-specific values such as:

- anomaly score

- detector name

- anomaly contributors

- contributor values

- contributor reasons

are not stored as dedicated structured JSON fields.

Instead, they are embedded inside the human-readable `context[]` array as strings.

The current advisory design converts anomaly `Score.topk` information into plain-language context lines.

**---**

**## Current Runtime Evidence**

Example stored recommendation:

```json

{

  "rec_id": "urn:sha256:827916f8a988adce85adb2c29c1a17e4",

  "alert_id": "acd7e1aa55e9700a",

  "title": "Security alert requires review",

  "summary": "Guardian detected a security alert that does not match a more specific advisory rule.",

  "severity": "high",

  "confidence": 0.7695204,

  "steps": [

    {

      "order": 1,

      "action": "Review the alert signature, endpoints, and recent device changes",

      "rationale": "Manual triage can separate expected activity from a new threat",

      "automatable": false

    },

    {

      "order": 2,

      "action": "Preserve logs before taking remediation action",

      "rationale": "Evidence helps confirm scope and supports later audit review",

      "automatable": true

    }

  ],

  "context": [

    "Signature: SGX AI anomaly burst (sid 9100001)",

    "Flow: 203.0.113.77:4444 -> 192.168.100.14:443 TCP",

    "Category: anomaly",

    "Anomaly score 0.51: task1-alert-scorer",

    "Anomaly: alert_count contribution 0.10 (unusual local signal)",

    "Anomaly: signature_repeat contribution 1.00 (unusual local signal)",

    "Anomaly: burst_density contribution 0.10 (unusual local signal)",

    "Anomaly: source_score contribution 0.51 (unusual local signal)"

  ],

  "references": [

    "signature",

    "suricata:sid:9100001"

  ],

  "source": "anomaly-kb",

  "generated_at": "2026-08-21T08:04:05.138132Z"

}

```

**---**

**## Current Data That Is Structured**

The following fields are already directly available:

```text

rec_id

alert_id

title

summary

severity

confidence

steps

context

references

source

generated_at

```

**---**

**## Current Anomaly Data Format**

Anomaly information currently exists only inside `context[]`.

Example:

```text

Anomaly score 0.51: task1-alert-scorer

Anomaly: alert_count contribution 0.10 (unusual local signal)

Anomaly: signature_repeat contribution 1.00 (unusual local signal)

Anomaly: burst_density contribution 0.10 (unusual local signal)

Anomaly: source_score contribution 0.51 (unusual local signal)

```

**---**

**## Why This Is a Problem**

For application integration, the UI needs to display values such as:

```text

Anomaly Score: 0.51

Threshold: 0.50

Confidence: 76.9%

Detector: task1-alert-scorer

```

It also needs to display contributor data such as:

```text

signature_repeat    1.00

source_score        0.51

alert_count         0.10

burst_density       0.10

```

With the current response, the client application would have to parse text strings.

Example client-side parsing requirement:

```text

Input:

"Anomaly score 0.51: task1-alert-scorer"

Client Application must extract:

score = 0.51

detector = task1-alert-scorer

```

Similarly:

```text

Input:

"Anomaly: signature_repeat contribution 1.00 (unusual local signal)"

Client Application must extract:

feature = signature_repeat

contribution = 1.00

reason = unusual local signal

```

This is fragile because the client application becomes dependent on exact English sentence formatting.

**---**

**## Example of How It Can Break**

If backend text changes from:

```text

Anomaly score 0.51: task1-alert-scorer

```

to:

```text

Anomaly score: 0.51 from task1-alert-scorer

```

the client-side parser may break even though the actual AI engine is still working correctly.

The same issue applies to contributor strings.

**---**

**## Expected Backend Structure**

The recommendation response should expose anomaly information as a dedicated structured object.

Recommended structure:

```json

{

  "rec_id": "urn:sha256:827916f8a988adce85adb2c29c1a17e4",

  "alert_id": "acd7e1aa55e9700a",

  "title": "Security alert requires review",

  "summary": "Guardian detected a security alert that does not match a more specific advisory rule.",

  "severity": "high",

  "confidence": 0.7695204,

  "source": "anomaly-kb",

  "anomaly": {

    "detected": true,

    "score": 0.51,

    "threshold": 0.50,

    "detector": "task1-alert-scorer",

    "contributors": [

      {

        "feature": "signature_repeat",

        "contribution": 1.00,

        "reason": "unusual local signal"

      },

      {

        "feature": "source_score",

        "contribution": 0.51,

        "reason": "unusual local signal"

      },

      {

        "feature": "alert_count",

        "contribution": 0.10,

        "reason": "unusual local signal"

      },

      {

        "feature": "burst_density",

        "contribution": 0.10,

        "reason": "unusual local signal"

      }

    ]

  },

  "steps": [

    {

      "order": 1,

      "action": "Review the alert signature, endpoints, and recent device changes",

      "rationale": "Manual triage can separate expected activity from a new threat",

      "automatable": false

    }

  ],

  "context": [

    "Signature: SGX AI anomaly burst (sid 9100001)",

    "Flow: 203.0.113.77:4444 -> 192.168.100.14:443 TCP",

    "Category: anomaly"

  ],

  "references": [

    "signature",

    "suricata:sid:9100001"

  ],

  "generated_at": "2026-08-21T08:04:05.138132Z"

}

```

**---**

**## Expected Non-Anomaly Structure**

If the score is below threshold:

```json

{

  "anomaly": {

    "detected": false,

    "score": 0.32,

    "threshold": 0.50,

    "detector": "task1-alert-scorer",

    "contributors": []

  }

}

```

If no anomaly score is available at all:

```json

{

  "anomaly": null

}

```

**---**

**## Why the Expected Structure Is Better**

The client application can directly access:

```typescript

recommendation.anomaly.score

recommendation.anomaly.threshold

recommendation.anomaly.detector

recommendation.anomaly.contributors

recommendation.confidence

recommendation.source

```

No string parsing is required.

**---**

**## Expected Operator UI**

Example:

```text

AI Anomaly Detection

────────────────────────────

Status        Detected

Score         0.51

Threshold     0.50

Confidence    76.9%

Detector      task1-alert-scorer

```

Contributor section:

```text

Top Contributors

────────────────────────────

signature_repeat    1.00

source_score        0.51

alert_count         0.10

burst_density       0.10

```

**---**

**## Impact**

Current structure causes:

- fragile client-side parsing

- difficult chart rendering

- difficult sorting by anomaly score

- difficult filtering by score

- difficult contributor visualization

- brittle client integration tests

- unnecessary coupling between UI and backend text wording

- harder future schema evolution

**---**

**## What Is Already Working**

This issue does ****not**** mean the anomaly engine is broken.

Current runtime evidence confirms:

- Task 1 anomaly score is being generated

- threshold crossing works

- anomaly context is generated

- confidence is available

- contributor information is available

- recommendations are persisted

- `source = anomaly-kb` is generated after anomaly detection

**---**

**## Root Cause Category**

This is primarily a:

```text

Backend API schema / serialization issue

```

not an ML model failure.

The anomaly engine produces useful information, but that information is flattened into human-readable strings before being exposed to the client application.

**---**

**## Likely Files to Review During Fix**

Based on the current SGX advisory architecture:

```text

src/advisory/model.rs

src/advisory/context.rs

src/advisory/generate.rs

src/advisory/store.rs

src/api/handlers/advisory.rs

```

**---**

**## Recommended Fix Direction**

Do not remove the human-readable `context[]`.

Keep it for:

- operator explanation

- logs

- audit readability

But add structured anomaly data alongside it:

```text

context[]       → human-readable explanation

anomaly{}       → machine-readable client application / API contract

```

Recommended final model:

```text

RemediationRecommendation

├── rec_id

├── alert_id

├── title

├── summary

├── severity

├── confidence

├── source

├── anomaly

│   ├── detected

│   ├── score

│   ├── threshold

│   ├── detector

│   └── contributors[]

├── steps[]

├── context[]

├── references[]

└── generated_at

```

**---**

**## Acceptance Criteria**

Issue #1 will be considered fixed when:

- [ ] Recommendation API exposes an `anomaly` object.

- [ ] `anomaly.score` is numeric.

- [ ] `anomaly.threshold` is numeric.

- [ ] `anomaly.detected` is boolean.

- [ ] `anomaly.detector` is explicitly returned.

- [ ] Contributors are returned as structured objects.

- [ ] Each contributor contains `feature`.

- [ ] Each contributor contains numeric `contribution`.

- [ ] Contributor reason is available where applicable.

- [ ] Existing human-readable `context[]` remains available.

- [ ] Existing recommendation API remains backward-compatible where possible.

- [ ] Client application does not parse anomaly information from text strings.

- [ ] Existing `anomaly-kb` recommendation flow still works.

- [ ] Existing recommendation persistence still works.

**---**

**## Final Verdict**

****Issue #1 confirmed.****

The Task 1 anomaly engine is generating usable anomaly information, but its anomaly score and contributor details are currently exposed mainly as human-readable `context[]` strings instead of a structured client-friendly JSON contract.

The preferred fix is to add a structured `anomaly` object while retaining `context[]` for human-readable explanation.

**-------------------------------**

**# Task 1 AI Application Integration — Issue Tracking**

**## Issue #2 — Important Task 1 Scoring Metadata Is Lost During the `AlertAnomalyScore` → `AnomalyContext` Bridge**

**### Status**

Open

**### Severity**

Medium–High

**### Area**

Task 1 AI Scoring / Advisory Bridge / Client-Facing API Contract

**---**

**## Problem Summary**

The Task 1 scorer produces a structured `AlertAnomalyScore` containing useful anomaly-detection metadata.

Current scorer model:

```rust

pub struct AlertAnomalyScore {

    pub score: f32,

    pub contributing_ip: String,

    pub alert_count: u32,

    pub top_signature_id: u32,

    pub top_signature_count: u32,

    pub category: ThreatCategory,

    pub computed_at: DateTime<Utc>,

    pub window_secs: u64,

}

```

This means the Task 1 scorer knows:

```text

score

contributing_ip

alert_count

top_signature_id

top_signature_count

category

computed_at

window_secs

```

However, when the score is converted into the advisory system's `AnomalyContext`, only a subset of this information is preserved.

Current advisory model:

```rust

pub struct AnomalyContext {

    pub score: f32,

    #[serde(default)]

    pub topk: Vec<(String, f32)>,

    #[serde(default)]

    pub model_version: Option<String>,

}

```

As a result, important scoring metadata is discarded before the recommendation is persisted or exposed through the REST API.

**---**

**## Current Data Flow**

```text

AlertAnomalyScore

        ↓

anomaly_context_from_score(...)

        ↓

AnomalyContext

        ↓

Advisory Generator

        ↓

RemediationRecommendation

        ↓

recommendations.jsonl

        ↓

REST API

        ↓

Client Application

```

The problem occurs at this stage:

```text

AlertAnomalyScore

        ↓

        ↓  METADATA LOSS

        ↓

AnomalyContext

```

**---**

**## Current `AlertAnomalyScore` Data**

The Task 1 scorer currently has the following fields available:

```text

score

contributing_ip

alert_count

top_signature_id

top_signature_count

category

computed_at

window_secs

```

Example conceptual runtime state:

```json

{

  "score": 0.51,

  "contributing_ip": "203.0.113.77",

  "alert_count": 5,

  "top_signature_id": 9100001,

  "top_signature_count": 5,

  "category": "anomaly",

  "computed_at": "2026-08-21T08:04:05Z",

  "window_secs": 300

}

```

**---**

**## Current `AnomalyContext` Data**

After conversion, the advisory bridge retains only:

```text

score

topk

model_version

```

Example:

```json

{

  "score": 0.51,

  "topk": [

    ["alert_count", 0.10],

    ["signature_repeat", 1.00],

    ["burst_density", 0.10],

    ["source_score", 0.51]

  ],

  "model_version": "task1-alert-scorer"

}

```

**---**

**## Data That Is Currently Lost**

The following fields are not preserved as structured fields in `AnomalyContext`:

```text

contributing_ip

alert_count

top_signature_id

top_signature_count

category

computed_at

window_secs

```

In other words:

```text

AlertAnomalyScore

────────────────────────────

score                  ✅

contributing_ip        ✅

alert_count            ✅

top_signature_id       ✅

top_signature_count    ✅

category               ✅

computed_at            ✅

window_secs            ✅

          ↓ conversion

AnomalyContext

────────────────────────────

score                  ✅

topk                   ✅

model_version          ✅

contributing_ip        ❌

alert_count            ❌ direct field lost

top_signature_id       ❌

top_signature_count    ❌

category               ❌

computed_at            ❌

window_secs            ❌

```

**---**

**## Why This Is a Problem**

This metadata is valuable for client visualization, operator analysis, debugging, and auditability.

For example, the client application may need to show:

```text

AI Anomaly Detection

────────────────────────────

Status              Detected

Score               0.51

Source IP           203.0.113.77

Detection Window    300 seconds

Alert Count         5

Top Signature       9100001

Signature Repeats   5

Detected At         2026-08-21 08:04:05

```

The Task 1 scorer already knows these values.

However, because they are not carried forward through `AnomalyContext`, the client application cannot reliably access them from the final recommendation API.

**---**

**## Client Integration Impact**

Without this metadata, the client application cannot cleanly implement:

* anomaly source-IP display

* anomaly detection-window display

* alert burst count

* repeated-signature count

* top signature information

* anomaly detection timestamp

* richer anomaly detail cards

* detailed audit views

* advanced sorting/filtering

* anomaly timeline views

* anomaly investigation panels

**---**

**## Expected Behavior**

The structured anomaly data passed from Task 1 into the advisory layer should preserve useful scoring metadata.

Recommended structure:

```json

{

  "anomaly": {

    "detected": true,

    "score": 0.51,

    "threshold": 0.50,

    "detector": "task1-alert-scorer",

    "computed_at": "2026-08-21T08:04:05Z",

    "window_secs": 300,

    "source": {

      "ip": "203.0.113.77",

      "alert_count": 5

    },

    "top_signature": {

      "id": 9100001,

      "count": 5

    },

    "category": "anomaly",

    "contributors": [

      {

        "feature": "alert_count",

        "contribution": 0.10

      },

      {

        "feature": "signature_repeat",

        "contribution": 1.00

      },

      {

        "feature": "burst_density",

        "contribution": 0.10

      },

      {

        "feature": "source_score",

        "contribution": 0.51

      }

    ]

  }

}

```

**---**

**## Recommended Internal Model**

A possible improved internal bridge model could be:

```rust

pub struct AnomalyContext {

    pub score: f32,

    pub detected: bool,

    pub threshold: f32,

    pub contributing_ip: Option<String>,

    pub alert_count: Option<u32>,

    pub top_signature_id: Option<u32>,

    pub top_signature_count: Option<u32>,

    pub category: Option<String>,

    pub computed_at: Option<DateTime<Utc>>,

    pub window_secs: Option<u64>,

    #[serde(default)]

    pub topk: Vec<(String, f32)>,

    #[serde(default)]

    pub model_version: Option<String>,

}

```

Exact implementation can be decided during the fix phase.

The key requirement is that useful Task 1 scorer metadata must not be discarded before reaching persistence/API layers.

**---**

**## Relationship to Issue #1**

**### Issue #1**

Structured anomaly information exists in `AnomalyContext`, but the final `RemediationRecommendation` does not preserve it as a structured `anomaly` object.

Instead it becomes human-readable `context[]` strings.

```text

AnomalyContext

      ↓

Issue #1

      ↓

context[] strings

```

**### Issue #2**

Even before Issue #1 occurs, the conversion from `AlertAnomalyScore` to `AnomalyContext` already discards important metadata.

```text

AlertAnomalyScore

      ↓

Issue #2

      ↓

AnomalyContext

      ↓

Issue #1

      ↓

RemediationRecommendation

```

So the two issues are different.

**---**

**## Full Problem Flow**

```text

Task 1 Scorer

─────────────────────────────────

AlertAnomalyScore

score

contributing_ip

alert_count

top_signature_id

top_signature_count

category

computed_at

window_secs

            ↓

       ISSUE #2

Structured scoring

metadata is discarded

            ↓

AnomalyContext

─────────────────────────────────

score

topk

model_version

            ↓

       ISSUE #1

Structured anomaly data

is flattened into strings

            ↓

RemediationRecommendation

─────────────────────────────────

confidence

context[]

source

steps[]

...

            ↓

recommendations.jsonl

            ↓

REST API

            ↓

Client Application

```

**---**

**## Root Cause Category**

This is primarily a:

```text

Data-model / bridge-contract information-loss issue

```

It is not evidence that the anomaly scorer itself is broken.

The scorer already computes useful metadata.

The problem is that the bridge object does not preserve all of it.

**---**

**## Likely Files to Review During Fix**

Primary files:

```text

src/task1_ai/scorer.rs

src/advisory/model.rs

src/advisory/context.rs

src/advisory/generate.rs

```

Possible downstream files:

```text

src/advisory/store.rs

src/api/handlers/advisory.rs

```

**---**

**## Recommended Fix Direction**

Do not recompute this information in the client application.

Do not parse it back from human-readable context strings.

Instead:

```text

Task 1 scorer

      ↓

preserve structured metadata

      ↓

AnomalyContext / API model

      ↓

RemediationRecommendation

      ↓

REST API

      ↓

Client Application

```

The backend already owns the source-of-truth values, so it should carry them forward directly.

**---**

**## Acceptance Criteria**

Issue #2 will be considered fixed when:

* [ ] `contributing_ip` can be preserved through the anomaly bridge.

* [ ] raw `alert_count` can be preserved as a structured value.

* [ ] `top_signature_id` can be preserved.

* [ ] `top_signature_count` can be preserved.

* [ ] anomaly category can be preserved.

* [ ] `computed_at` can be preserved.

* [ ] `window_secs` can be preserved.

* [ ] existing `score` remains preserved.

* [ ] existing `topk` contributors remain preserved.

* [ ] existing `model_version` remains preserved.

* [ ] final REST/API representation can expose this metadata where needed.

* [ ] client application does not need to reconstruct the metadata from text.

* [ ] existing Task 1 scoring tests remain green.

* [ ] advisory generation remains backward-compatible where required.

**---**

**## Final Verdict**

****Issue #2 confirmed.****

The Task 1 scorer already generates useful structured metadata, but the current `AlertAnomalyScore` → `AnomalyContext` bridge preserves only `score`, `topk`, and `model_version`.

Important data such as source IP, alert count, signature information, detection time, category, and scoring window is lost before the recommendation reaches persistence and the client-facing API.

The preferred fix is to preserve this metadata through the anomaly bridge and expose it as part of the structured anomaly API model.

**----------------------**

**# Task 1 AI Application Integration — Issue Tracking**

**## Issue #3 — Task 1 Anomaly Thresholds Are Hardcoded and Not Configurable Through the Client Application**

**### Status**

Open

**### Severity**

Medium–High

**### Area**

Task 1 AI Configuration / Backend API / Operator Settings

**---**

**## Problem Summary**

Task 1 currently uses fixed anomaly thresholds directly inside the Rust code.

The runtime search confirmed threshold checks such as:

```rust

if score < 0.50 {

```

and:

```rust

if score.score < 0.50 {

```

Additional response bands are also hardcoded around:

```text

0.50  → anomaly/remediation starts

0.75  → higher response level

0.90  → strongest/critical response

```

These values are currently part of the implementation logic rather than a configurable Task 1 AI settings model.

No dedicated Task 1 environment/config setting such as:

```text

SGX_TASK1_ANOMALY_THRESHOLD

TASK1_AI_THRESHOLD

SGX_AI_THRESHOLD

```

was found in the inspected Task 1/advisory/container-cohort paths.

**---**

**## Current Behavior**

Current Task 1 logic effectively behaves like this:

```text

Score < 0.50

    ↓

No Task 1 remediation plan

Score >= 0.50

    ↓

Anomaly / remediation path starts

Score >= 0.75

    ↓

Higher response band

Score >= 0.90

    ↓

Strongest / critical response band

```

The client application does not currently receive these thresholds as a structured configuration contract.

If the client application wants to show:

```text

Anomaly Score: 0.51

Threshold: 0.50

Status: Detected

```

it would have to hardcode `0.50` itself.

That creates two sources of truth:

```text

Backend threshold

Client Application threshold

```

This should be avoided.

**---**

**## Why This Is a Problem**

If the backend threshold changes but the client application is not updated, the UI may show an incorrect anomaly status.

Example:

```text

Backend detection threshold = 0.65

Current anomaly score       = 0.55

Backend result:

Not detected

Client Application hardcoded threshold = 0.50

Client Application result:

Detected

```

In this situation:

```text

Backend says: Not Detected

Client Application says: Detected

```

This is a correctness problem.

For a security product, the client application should never independently guess or duplicate the active anomaly thresholds.

**---**

**## Desired Behavior**

Task 1 anomaly thresholds should have a single source of truth in the backend.

The client application should:

1. Read the active threshold configuration from the backend.

2. Display the current values.

3. Allow an authorized operator to change them.

4. Submit changes back to the backend.

5. Let the backend validate and persist the new configuration.

6. Let the Task 1 scorer use the updated values.

7. Show the actual threshold used for each anomaly result.

Recommended architecture:

```text

Operator Settings

        ↓

Task 1 AI Config API

        ↓

Backend validation

        ↓

Persisted Task 1 configuration

        ↓

Task 1 scorer

        ↓

Anomaly result

        ↓

Client Application

```

**---**

**# Proposed Operator-Facing Feature**

**## AI Anomaly Threshold Settings**

Example UI:

```text

AI Anomaly Threshold Settings

────────────────────────────────────

Detection Threshold

[ 0.50 ─────────●──────── ]

Current: 0.50

Recommended starting range: 0.45 – 0.60

High Risk Threshold

[ 0.75 ─────────────●──── ]

Current: 0.75

Recommended starting range: 0.70 – 0.85

Critical Threshold

[ 0.90 ───────────────●── ]

Current: 0.90

Recommended starting range: 0.85 – 0.95

[ Save Changes ]   [ Restore Defaults ]

```

**---**

**## Important Note About Recommended Ranges**

The currently verified code supports the fixed values:

```text

Detection = 0.50

High      = 0.75

Critical  = 0.90

```

The following ranges are a ****proposed application/product starting range****, not a range proven by the current project evidence:

```text

Detection recommended starting range: 0.45 – 0.60

High recommended starting range:      0.70 – 0.85

Critical recommended starting range:  0.85 – 0.95

```

These ranges should eventually be tuned using real telemetry, false-positive-rate, recall, and physical-board validation.

The UI should clearly distinguish:

```text

Current value

Default value

Recommended starting range

```

**---**

**# Proposed Default Values**

Suggested defaults should initially match current Task 1 behavior:

```json

{

  "detection_threshold": 0.50,

  "high_threshold": 0.75,

  "critical_threshold": 0.90

}

```

This avoids changing current system behavior while making the values configurable.

**---**

**# Backend Should Remain the Source of Truth**

The client application should NOT contain logic such as:

```typescript

const DETECTION_THRESHOLD = 0.50;

const HIGH_THRESHOLD = 0.75;

const CRITICAL_THRESHOLD = 0.90;

```

Instead, it should load the values from the backend.

Example:

```typescript

const config = await task1AiService.getConfig();

config.detection_threshold;

config.high_threshold;

config.critical_threshold;

```

**---**

**# Proposed Backend Configuration Model**

Example:

```json

{

  "task1_ai": {

    "detection_threshold": 0.50,

    "high_threshold": 0.75,

    "critical_threshold": 0.90

  }

}

```

Possible environment defaults could also exist:

```text

SGX_TASK1_DETECTION_THRESHOLD=0.50

SGX_TASK1_HIGH_THRESHOLD=0.75

SGX_TASK1_CRITICAL_THRESHOLD=0.90

```

The exact persistence mechanism should be decided during implementation.

The important requirement is:

```text

One backend source of truth

```

**---**

**# Required Validation Rules**

Backend validation should enforce:

```text

0.0 <= detection_threshold < high_threshold < critical_threshold <= 1.0

```

Example valid configuration:

```text

Detection = 0.50

High      = 0.75

Critical  = 0.90

```

Example invalid configuration:

```text

Detection = 0.80

High      = 0.60

Critical  = 0.90

```

The invalid example must be rejected by the backend.

Client application should also provide immediate validation feedback, but backend validation remains authoritative.

**---**

**# Proposed REST API**

A dedicated Task 1 AI configuration endpoint is recommended.

Example:

```text

GET /api/v1/task1-ai/config

PUT /api/v1/task1-ai/config

```

**---**

**## Example GET Response**

```json

{

  "detection_threshold": 0.50,

  "high_threshold": 0.75,

  "critical_threshold": 0.90,

  "defaults": {

    "detection_threshold": 0.50,

    "high_threshold": 0.75,

    "critical_threshold": 0.90

  },

  "recommended": {

    "detection": {

      "min": 0.45,

      "max": 0.60

    },

    "high": {

      "min": 0.70,

      "max": 0.85

    },

    "critical": {

      "min": 0.85,

      "max": 0.95

    }

  }

}

```

The exact recommended ranges are product/tuning guidance and should not be treated as mathematically validated until benchmarked with real telemetry.

**---**

**## Example PUT Request**

```json

{

  "detection_threshold": 0.55,

  "high_threshold": 0.78,

  "critical_threshold": 0.92

}

```

**---**

**## Example PUT Response**

```json

{

  "success": true,

  "config": {

    "detection_threshold": 0.55,

    "high_threshold": 0.78,

    "critical_threshold": 0.92

  }

}

```

**---**

**# Recommended Presets**

The client application may optionally provide easy presets.

Example:

```text

Sensitive

Detection  0.40

High       0.65

Critical   0.85

Balanced

Detection  0.50

High       0.75

Critical   0.90

Strict

Detection  0.60

High       0.80

Critical   0.95

```

These presets are proposed UX values only.

They must not be presented as validated security guarantees until they are tested against real Task 1 telemetry and performance metrics.

**---**

**# Suggested Client Application Explanation**

The UI should help operators understand the effect of changing the detection threshold.

Example:

```text

Lower threshold

────────────────────────

More sensitive

More anomalies detected

Potentially more false positives

Balanced threshold

────────────────────────

Recommended starting point

Balances sensitivity and noise

Higher threshold

────────────────────────

Less sensitive

Only stronger anomalies are detected

Potentially fewer false positives

```

**---**

**# Threshold Snapshot Must Be Stored With Each Anomaly**

A particularly important requirement is that each anomaly result should retain the threshold that was used when it was generated.

Example:

```json

{

  "anomaly": {

    "detected": true,

    "score": 0.57,

    "threshold": 0.50,

    "detector": "task1-alert-scorer"

  }

}

```

This matters because the active threshold may later change.

Example:

```text

August 21:

Threshold = 0.50

Score     = 0.57

Detected  = true

August 25:

Threshold changed to 0.60

```

The historical August 21 record must still show:

```text

threshold = 0.50

```

Otherwise an operator reviewing old alerts could incorrectly interpret the original decision.

**---**

**# Why the Threshold Snapshot Is Important**

It improves:

* auditability

* historical investigation

* anomaly explanation

* incident review

* regression testing

* client application correctness

* policy-change traceability

The anomaly record should answer:

```text

What was the score?

What threshold was active?

Was it detected?

Which detector produced it?

When was it computed?

```

**---**

**# Expected Final Anomaly Object**

Recommended structured API result:

```json

{

  "anomaly": {

    "detected": true,

    "score": 0.57,

    "threshold": 0.50,

    "high_threshold": 0.75,

    "critical_threshold": 0.90,

    "risk_level": "detected",

    "detector": "task1-alert-scorer",

    "computed_at": "2026-08-21T08:04:05Z"

  }

}

```

Possible risk-level mapping:

```text

score < detection

    → normal / below-threshold

score >= detection and < high

    → detected

score >= high and < critical

    → high

score >= critical

    → critical

```

The exact labels can be finalized during operator interface design.

**---**

**# Relationship to Issue #1**

Issue #1 is about anomaly values being flattened into `context[]` strings instead of structured JSON.

Issue #3 additionally requires the structured anomaly object to contain the actual threshold used.

Example:

```json

{

  "anomaly": {

    "score": 0.51,

    "threshold": 0.50

  }

}

```

Without Issue #1's structured anomaly object, client application threshold rendering would still be awkward.

**---**

**# Relationship to Issue #2**

Issue #2 is about Task 1 scoring metadata being lost during:

```text

AlertAnomalyScore

      ↓

AnomalyContext

```

Issue #3 adds another important piece of scoring metadata that should be preserved:

```text

threshold used for this decision

```

A combined future model should therefore preserve:

```text

score

threshold

source IP

alert count

signature counts

window

computed_at

contributors

detector

```

**---**

**# Full Desired Flow**

```text

Operator Settings

        ↓

GET / PUT Task 1 AI config

        ↓

Backend validates configuration

        ↓

Persist active thresholds

        ↓

Task 1 scorer reads active thresholds

        ↓

Anomaly score generated

        ↓

Decision uses active threshold

        ↓

Threshold snapshot stored with anomaly

        ↓

Recommendation API

        ↓

Client application displays:

score + threshold + status + confidence

```

**---**

**# Root Cause Category**

This is primarily a:

```text

Configuration architecture + API contract issue

```

The Task 1 scorer currently works with fixed values, but the thresholds are embedded in implementation code rather than managed as runtime configuration.

**---**

**# Likely Files to Review During Fix**

Primary Task 1 logic:

```text

src/task1_ai/scorer.rs

src/task1_ai/remediation.rs

```

Likely configuration/API areas:

```text

src/task1_ai/

src/api/routes.rs

src/api/handlers/

src/advisory/model.rs

src/advisory/generate.rs

```

Container environment may also need changes:

```text

optional/container-cohort/dev.env

optional/container-cohort/docker-compose.dev.yml

```

Exact files should be confirmed before implementation.

**---**

**# Recommended Fix Direction**

Replace direct threshold literals in Task 1 decision logic with a validated backend configuration object.

Example conceptual logic:

```rust

if score.score < config.detection_threshold {

    // below threshold

}

if score.score >= config.high_threshold {

    // high response

}

if score.score >= config.critical_threshold {

    // critical response

}

```

The configuration should be:

```text

validated

persisted

API-readable

API-updateable by authorized users

used by the scorer

recorded with anomaly results

```

**---**

**# Acceptance Criteria**

Issue #3 will be considered fixed when:

* [ ] Task 1 detection threshold is no longer duplicated as an uncontrolled hardcoded value.

* [ ] Detection threshold has a backend configuration source.

* [ ] High threshold has a backend configuration source.

* [ ] Critical threshold has a backend configuration source.

* [ ] Default values preserve current behavior (`0.50`, `0.75`, `0.90`) unless intentionally changed.

* [ ] Backend validates `0 <= detection < high < critical <= 1`.

* [ ] Invalid configurations are rejected.

* [ ] Authorized client application users can read current thresholds.

* [ ] Authorized client application users can update thresholds.

* [ ] Client application does not independently hardcode the active thresholds.

* [ ] Client application displays current values.

* [ ] Client application can display default values.

* [ ] Client application can display recommended starting ranges.

* [ ] Recommended ranges are clearly identified as guidance unless formally benchmarked.

* [ ] Task 1 scorer uses the active backend values.

* [ ] Task 1 remediation logic uses the same active values.

* [ ] Each anomaly result stores the threshold used at detection time.

* [ ] Historical anomaly records remain interpretable after later configuration changes.

* [ ] Existing Task 1 tests are updated to test configurable thresholds.

* [ ] Existing anomaly/remediation behavior remains backward-compatible with the current defaults.

**---**

**# Final Verdict**

****Issue #3 confirmed.****

The current Task 1 anomaly thresholds are implemented as fixed values in the scoring/remediation code.

For proper application integration and future AI tuning, the thresholds should become backend-managed configuration rather than client-side or code-level constants.

The client application should be able to display and update the active values, while the backend remains the single source of truth.

The current values:

```text

Detection = 0.50

High      = 0.75

Critical  = 0.90

```

should initially remain the defaults so existing behavior does not change.

The client application may additionally show recommended starting ranges, but those ranges should be clearly marked as tuning guidance until they are validated using real Task 1 telemetry, false-positive-rate, recall, and physical-board testing.

**----------------------------------------**

---

# Task 1 AI Application Integration — Issue Tracking

## Issue #4 — Existing Task 1 Model Confidence Is Lost in the Current SGX Integration, While the Client Application Shows Advisory Confidence Instead

### Status

Open

### Severity

High

### Area

Task 1 AI Integration / Model Output Bridge / Advisory API / Client Application Semantics

---

## Final Corrected Finding

The original/full Task 1 anomaly engine **already implemented model confidence**.

Git history confirms that the historical Task 1 engine produced and propagated confidence through:

```text
Model Score
    ↓
Anomaly Engine
    ↓
Alert
    ↓
Persisted Task 1 Record
    ↓
Virtual Shift Integration
    ↓
Policy Recommendation / Justification
```

The problem is therefore **not** that Task 1 never had confidence.

The actual integration issue is:

> The current `~/SGX` Task 1 runtime path does not carry the existing Task 1 model confidence into its `AlertAnomalyScore` / `AnomalyContext` / advisory API path, and the client application currently displays a different downstream advisory confidence value instead.

---

# Historical Task 1 Model Confidence Exists

Historical commit:

```text
862d481
Add Task 1 and Task 2 anomaly detection and policy lifecycle
```

Historical file:

```text
sgx-anomaly-engine/src/model.rs
```

defines a model result with dedicated confidence:

```rust
pub struct Score {
    /// Final anomaly score, normalized into [0, 1].
    pub value: f64,

    /// How much to trust `value`.
    pub confidence: f64,

    ...
}
```

So the full Task 1 model contract already distinguished:

```text
anomaly score
≠
model confidence
```

---

# Tier 1 Confidence

The historical Tier 1 model uses an online per-node Z-score baseline.

Its confidence increases as a node accumulates enough normal history.

Historical logic:

```rust
let confidence =
    (stats.count as f64 / warmup_samples)
        .clamp(0.0, 1.0);
```

Meaning:

```text
few baseline samples
        ↓
low confidence

more baseline history
        ↓
higher confidence

warm-up complete
        ↓
confidence approaches 1.0
```

This is useful because a strong anomaly score produced before a node has enough baseline history should not automatically be trusted the same way as a score from a mature per-node baseline.

---

# Tier 2 Confidence

The historical Tier 2 Isolation Forest also has its own confidence concept.

The source comments describe Tier 2 confidence as approximately:

```text
inter-tree agreement
```

This is distinct from Tier 1 warm-up confidence.

Historical Task 1 code intentionally treats them differently.

---

# Important Historical Confidence-Gating Design

The Task 1 engine configuration includes:

```rust
pub min_confidence: f64
```

with historical default evidence showing:

```text
min_confidence = 0.5
```

The historical engine explicitly documents that alert gating must use:

```text
Tier 1 confidence
```

rather than blindly using the fused/Tier 2 confidence.

Historical source comments describe a previously observed failure mode where:

```text
anomaly value = 1.000
Tier 2 confidence ≈ 0.468
```

and gating on the wrong confidence would incorrectly suppress a real attack.

The historical engine therefore intentionally gates on Tier 1's baseline-maturity confidence.

This means confidence was not an incidental field; it was part of the detection logic.

---

# Historical Alert Preserves Confidence

Historical file:

```text
sgx-anomaly-engine/src/alert.rs
```

contains:

```rust
pub confidence: f64
```

The anomaly engine passes confidence into the generated alert.

Historical engine evidence includes:

```text
confidence: fused.confidence
```

when constructing the alert payload.

Therefore:

```text
model confidence
    ↓
alert confidence
```

was already implemented.

---

# Historical Virtual Shift Flow Preserves Confidence

Historical Virtual Shift code also contains dedicated confidence fields.

Examples include:

```text
sgx-anomaly-engine/src/virtual_shift/alert.rs
sgx-anomaly-engine/src/virtual_shift/model.rs
sgx-anomaly-engine/src/virtual_shift/integration.rs
sgx-anomaly-engine/src/virtual_shift/recommendation.rs
sgx-anomaly-engine/src/virtual_shift/justification.rs
```

The Virtual Shift alert validates that confidence is:

```text
finite
and
0.0 <= confidence <= 1.0
```

Older Task 1 records without confidence are explicitly rejected.

Historical integration comments state that Virtual Shift must not invent a confidence value merely to start a policy workflow.

This is strong evidence that model confidence was considered an authoritative Task 1 field.

---

# Persisted Records Preserve Confidence

Historical Task 1 → Virtual Shift integration includes tests such as:

```text
fresh_persisted_task1_record_preserves_score_confidence_and_evidence
```

and:

```text
old_persisted_record_without_confidence_is_refused
```

This confirms that the historical architecture expected persisted Task 1 records to retain:

```text
score
confidence
evidence
```

together.

---

# Historical Policy Recommendation Also Preserves Confidence

Historical policy recommendation models include:

```rust
pub confidence: f64
```

and use the anomaly event confidence in downstream recommendation logic.

The historical code also contains risk logic using confidence, for example restricting some critical recommendations when confidence is below a required level.

Therefore confidence was used for more than display purposes.

It influenced downstream policy reasoning.

---

# Current SGX Integration

The current working-tree Task 1 integration uses:

```text
src/task1_ai/scorer.rs
```

Its result is:

```rust
pub struct AlertAnomalyScore {
    pub score: f32,
    pub contributing_ip: String,
    pub alert_count: u32,
    pub top_signature_id: u32,
    pub top_signature_count: u32,
    pub category: ThreatCategory,
    pub computed_at: DateTime<Utc>,
    pub window_secs: u64,
}
```

Current result:

```text
score                 ✅
confidence            ❌
```

---

# Current Advisory Bridge

Current:

```rust
pub struct AnomalyContext {
    pub score: f32,
    pub topk: Vec<(String, f32)>,
    pub model_version: Option<String>,
}
```

Current bridge:

```text
score                 ✅
top contributors      ✅
model version         ✅
model confidence      ❌
```

So the historical Task 1 confidence contract is no longer represented in the current integration bridge.

---

# Current Advisory Confidence Is a Different Value

The current advisory generator calculates:

```rust
let confidence = anomaly
    .map(|score| {
        (signature_confidence * 0.7)
            + (normalize_anomaly_score(score.score) * 0.3)
    })
    .unwrap_or(signature_confidence)
    .clamp(0.0, 1.0);
```

Therefore:

```text
Current advisory confidence
=
70% Suricata severity certainty
+
30% anomaly score
```

This is not the historical Task 1 model confidence.

---

# Current Client Application Behavior

The client application advisory service receives:

```typescript
confidence: number;
```

and the Alerts screen renders:

```text
Confidence: XX%
```

using:

```typescript
rec.confidence
```

That means the current client application is displaying:

```text
RemediationRecommendation.confidence
```

which is the downstream advisory confidence.

It is not displaying the original Task 1 model confidence.

---

# Correct End-to-End Comparison

## Historical / Full Task 1

```text
19-feature telemetry
        ↓
Tier 1 per-node Z-score baseline
        +
Tier 2 Isolation Forest
        ↓
Score.value
Score.confidence
Score.topk
raw score
calibrated threshold
        ↓
Task 1 Alert
score + confidence
        ↓
Persisted record
score + confidence + evidence
        ↓
Virtual Shift
        ↓
Policy recommendation
```

## Current SGX Integration

```text
Suricata alert
        ↓
src/task1_ai/scorer.rs
heuristic alert-burst score
        ↓
AlertAnomalyScore
score only
        ↓
AnomalyContext
score + topk + model_version
        ↓
Advisory generator
creates new mixed confidence
        ↓
Client Application
shows advisory confidence
```

---

# Why This Matters

If the client application labels the current value as:

```text
AI Confidence
```

an operator could believe:

```text
"The anomaly model is 77% confident."
```

when the actual value means:

```text
"The advisory layer combined Suricata severity and anomaly score into 77%."
```

This is semantically incorrect.

It also hides valuable information that already existed in the full Task 1 implementation.

---

# Expected Client Application Contract

The client application should receive both values separately.

Example:

```json
{
  "anomaly": {
    "detected": true,
    "score": 0.91,
    "confidence": 0.94,
    "threshold": 0.50,
    "detector": "task1-isolation-forest",
    "model_version": "..."
  },

  "recommendation": {
    "confidence": 0.82
  }
}
```

---

# Recommended Client Application Display

```text
AI Anomaly
────────────────────────────
Score:               0.91
Model Confidence:    94%
Detection Threshold: 0.50
Detector:            Isolation Forest


Recommendation
────────────────────────────
Confidence:          82%
Source:              anomaly-kb
```

This avoids mixing two different meanings.

---

# Confidence Threshold vs Anomaly Threshold

These should also remain separate.

Example:

```text
Anomaly score threshold
→ How anomalous must the event be?

Minimum confidence threshold
→ How trustworthy/mature must the model result be?
```

Historical Task 1 already had evidence of:

```text
min_confidence = 0.5
```

for confidence gating.

This is different from the anomaly score detection threshold.

Future operator settings should not combine the two into a single slider.

---

# Relationship to Issue #3

Issue #3 covers configurable anomaly score thresholds such as:

```text
Detection
High
Critical
```

Issue #4 covers model confidence.

A future client application may therefore expose separate settings such as:

```text
Detection Threshold
Minimum Model Confidence
High Threshold
Critical Threshold
```

Any editable ranges/defaults should be backed by backend configuration and clearly documented.

---

# Relationship to Issue #5

Historical evidence proves the full Task 1 Isolation Forest/Z-score engine existed.

The current SGX integration uses a separate heuristic alert-burst scorer.

Because the full model is not currently wired into the runtime integration, its model confidence is also unavailable there.

Therefore Issue #4 is closely related to the broader model-integration gap.

---

# Relationship to Issue #6

Historical evidence also proves global/per-node baseline/model work existed.

Tier 1 confidence depends directly on baseline maturity.

If the current SGX runtime does not load/use those baseline/model components, it cannot reproduce the original confidence semantics correctly.

---

# Root Cause Category

This is primarily an:

```text
integration regression / model-output contract loss
```

not a missing historical Task 1 feature.

---

# Likely Files to Review During Fix

Historical reference implementation:

```text
sgx-anomaly-engine/src/model.rs
sgx-anomaly-engine/src/engine.rs
sgx-anomaly-engine/src/alert.rs
sgx-anomaly-engine/src/virtual_shift/integration.rs
sgx-anomaly-engine/src/virtual_shift/model.rs
sgx-anomaly-engine/src/virtual_shift/recommendation.rs
```

Current integration:

```text
src/task1_ai/scorer.rs
src/advisory/model.rs
src/advisory/generate.rs
src/advisory/context.rs
```

Client Application:

```text
client application/src/app/services/advisoryService.ts
client application/src/app/screens/alerts/AL01AlertsList.tsx
```

---

# Recommended Fix Direction

1. Reconnect the full Task 1 model output contract to the current SGX runtime.
2. Preserve `Score.value`.
3. Preserve `Score.confidence`.
4. Preserve calibrated threshold/raw score where useful.
5. Preserve top contributors.
6. Carry confidence through the current anomaly/advisory bridge.
7. Persist confidence with every anomaly record.
8. Expose model confidence through the REST API.
9. Keep advisory/recommendation confidence as a separate field.
10. Update client application labels to clearly distinguish both values.

---

# Acceptance Criteria

Issue #4 will be considered fixed when:

* [ ] The integrated Task 1 runtime exposes a dedicated model/anomaly confidence.
* [ ] Confidence semantics match the full Task 1 model design.
* [ ] Tier 1 baseline-maturity confidence is not confused with Tier 2 tree-agreement confidence.
* [ ] Alert gating uses the correct confidence semantics.
* [ ] Model confidence is preserved in the anomaly result.
* [ ] Model confidence is persisted.
* [ ] Model confidence reaches the REST/API layer.
* [ ] Client application can display model confidence.
* [ ] Existing advisory confidence remains separate.
* [ ] Client application does not label advisory confidence as model confidence.
* [ ] Old records without model confidence are handled explicitly rather than inventing a fake model confidence.
* [ ] Tests verify score + confidence persistence and API round-tripping.
* [ ] Tests verify confidence stays within `[0,1]`.
* [ ] Tests verify historical/full Task 1 confidence behavior remains compatible.

---

# Final Verdict

**Issue #4 confirmed as an integration loss, not a missing Task 1 capability.**

The full historical Task 1 engine already implemented model confidence and propagated it through alerts, persisted records, Virtual Shift integration, recommendations, and justification.

The current SGX integration path does not preserve that model confidence.

Instead, the current client application displays a different advisory confidence calculated from Suricata severity and anomaly score.

The correct fix is to restore the existing Task 1 model-confidence contract into the current SGX integration and expose model confidence and recommendation confidence as separate values.

---

# Task 1 AI Application Integration — Issue #5

## Title

Historical/full Task 1 ML engine is not wired into the current SGX runtime; the active anomaly path uses the heuristic `src/task1_ai/scorer.rs` implementation.

## Status

Confirmed

## Severity

High

## Area

Task 1 AI Runtime Integration / ThreatService / AI Bridge / ML Engine

---

## Confirmed Current Runtime Path

Current `src/threat/service.rs` creates:

```rust
let mut ai_state = task1_ai::AlertScorerState::default();
```

For an inserted Suricata alert it executes:

```text
ThreatAlert
  ↓
task1_ai::feature_from_alert(...)
  ↓
task1_ai::process_feature(...)
  ↓
task1_ai::generate_plan(...)
  ↓
task1_ai::anomaly_context_from_score(...)
  ↓
advisory generation
```

The active scorer is therefore the current:

```text
src/task1_ai/scorer.rs
```

implementation.

That scorer uses a rolling alert window and fixed weighted factors such as alert frequency, repeated signature ratio, severity, and category weight. It is not the historical 19-feature Isolation Forest + per-node Z-score engine.

---

## AI Bridge Investigation

Current `ThreatService` also calls:

```rust
ai_bridge::forward_to_ai(&self.node_id, &alert);
```

The bridge source defines:

```rust
pub fn subscribe() -> broadcast::Receiver<AlertFeature>
```

and comments that the AI engine should subscribe.

However, a current-source search found no call site for:

```text
ai_bridge::subscribe()
```

outside the bridge definition itself.

The current search found:

```text
src/threat/ai_bridge.rs:31: pub fn subscribe(...)
src/threat/service.rs:189: ai_bridge::forward_to_ai(...)
src/geofence/alerts.rs:44: forward_to_ai(...)
```

but no current runtime consumer of that Task 1 broadcast channel.

Therefore the bridge is producing Task 1 alert features, but no full ML engine subscriber is visible in the current `src` tree.

---

## Historical Task 1 ML Engine Exists

Git history confirms that the full Task 1 implementation existed in commit:

```text
862d481
Add Task 1 and Task 2 anomaly detection and policy lifecycle
```

and original Task 1 commit:

```text
094b2b6
Add Task 1 anomaly detection engine
```

Historical files include:

```text
anomaly-training/train_iforest.py
anomaly-training/trained/global_forest.joblib
anomaly-training/trained/nodeA_forest.joblib
anomaly-training/trained/nodeB_forest.joblib

sgx-anomaly-engine/src/features.rs
sgx-anomaly-engine/src/model.rs
sgx-anomaly-engine/src/baseline.rs
sgx-anomaly-engine/src/engine.rs

sgx-anomaly-engine/data/global_forest.json
sgx-anomaly-engine/data/nodeA_forest.json
sgx-anomaly-engine/data/nodeB_forest.json
```

So this is not a claim that Task 1 ML was never implemented.

The issue is an integration/runtime disconnect.

---

## Historical Model Capabilities Already Confirmed

The historical engine implements:

```text
Tier 1: online per-node Z-score baseline
Tier 2: Isolation Forest
19-feature vector
normalized anomaly score
dedicated model confidence
top contributing features
raw score
calibrated thresholds
global model
per-node models
```

These capabilities are not represented by the currently active `AlertScorerState` path.

---

## Current vs Expected Flow

### Current

```text
Suricata EVE
   ↓
ThreatService
   ↓
AlertScorerState
   ↓
fixed weighted burst heuristic
   ↓
AlertAnomalyScore
   ↓
AnomalyContext
   ↓
Advisory
```

### Historical/full Task 1

```text
Telemetry / feature collection
   ↓
19-feature FeatureVector
   ↓
per-node baseline / Tier 1 Z-score
   +
Isolation Forest / Tier 2
   ↓
fused Score
   ├─ anomaly value
   ├─ confidence
   ├─ top-k contributors
   └─ raw/calibrated model metadata
   ↓
Task 1 alert / persisted record
   ↓
Virtual Shift / recommendation flow
```

---

## Root Cause Classification

```text
Integration regression / incomplete merge of existing Task 1 ML engine
```

not:

```text
Task 1 ML engine never implemented
```

---

## Why This Matters

The Task 1 requirement specifically calls for an ML-based behavioral anomaly engine using lightweight edge-deployable models, including Isolation Forest / One-Class SVM style detection.

The current integrated runtime evidence shows that anomaly decisions used by `ThreatService` are produced by a heuristic alert-burst scorer instead of the historical trained Isolation Forest engine.

As a result, the current client application / API path cannot by itself demonstrate full Task 1 ML acceptance.

---

## Recommended Fix Direction

1. Restore/integrate the historical `sgx-anomaly-engine` model runtime into the current SGX application.
2. Decide the production ownership boundary:

   * embedded Rust crate/module, or
   * dedicated local service with a stable API/channel.
3. Wire current telemetry/Suricata inputs into the full Task 1 feature pipeline.
4. Load the correct global/per-node model and baseline for each node.
5. Preserve full model output:

   * score
   * confidence
   * top contributors
   * detector/model version
   * calibrated threshold
   * computed timestamp
6. Feed the full result into advisory / Virtual Shift.
7. Remove, retire, or explicitly designate the heuristic scorer as fallback/demo-only behavior.
8. Add integration tests proving that the production `ThreatService` reaches the trained model path.

---

## Acceptance Criteria

* [ ] Current SGX runtime loads the trained Task 1 model.
* [ ] Current SGX runtime loads/selects the appropriate global/per-node baseline/model.
* [ ] A real current `ThreatService` event reaches the ML engine.
* [ ] Isolation Forest scoring is executed in the integrated runtime.
* [ ] Per-node Tier 1 baseline scoring is executed where required.
* [ ] Model score reaches the advisory/API layer.
* [ ] Model confidence reaches the advisory/API layer.
* [ ] Structured contributors reach the advisory/API layer.
* [ ] Model/version/threshold metadata is preserved.
* [ ] Integration tests prove the full path.
* [ ] The heuristic scorer is not silently presented as the production ML engine.
* [ ] If retained as fallback, the API clearly identifies it as fallback/heuristic.

---

## Final Verdict

**Confirmed integration gap.**

The full Task 1 ML engine exists in Git history, but the current SGX runtime path visible in `src/threat/service.rs` directly invokes the heuristic `src/task1_ai/scorer.rs` implementation.

Although `ai_bridge::forward_to_ai(...)` publishes alert features, no current `ai_bridge::subscribe()` consumer for the historical/full ML engine was found in the current source tree.

---

# Task 1 AI Application Integration — Issue #6

## Title

Existing Task 1 global/per-node behavioral baseline lifecycle is not wired into the current SGX runtime integration.

## Status

Confirmed

## Severity

High

## Final Corrected Finding

The Task 1 behavioral baseline implementation existed historically. The confirmed problem is that the historical baseline lifecycle — per-node model preference, global fallback, model loading, reload/promotion, and per-node online baseline behavior — is not present in the current active `~/SGX` Task 1 runtime path.

## Historical Baseline Lifecycle

Historical commit:

```text
862d481
Add Task 1 and Task 2 anomaly detection and policy lifecycle
```

Historical `sgx-anomaly-engine/src/baseline.rs` documents a:

```text
Global -> per-node -> refresh baseline lifecycle
```

and defines `BaselineKind::Global` and `BaselineKind::PerNode`.

The configuration includes a per-node model template such as:

```text
data/{node}_forest.json
```

## Historical Model Selection

The selector logic is:

```text
if per-node model exists
    -> use PerNode
else if global model exists
    -> use Global fallback
else
    -> error
```

So, for example:

```text
nodeA
  ↓
nodeA_forest.json available?
  ├─ yes → use nodeA per-node model
  └─ no  → use global_forest.json
```

## Historical Runtime Loading

Historical `engine.rs` integrates the lifecycle with `try_with_baseline_lifecycle(...)`, which loads configuration, calls `BaselineLifecycle::load(...)`, selects the best model, and attaches the selected `IsolationForestModel`.

## Historical Reload / Promotion

The lifecycle supports `maybe_reload(...)` and `reload_now(...)`, allowing:

```text
Global fallback
      ↓
trusted per-node model becomes available
      ↓
PerNode baseline
```

## Historical Evidence Tracking

The lifecycle records `active_baseline` and `model_source`, so the selected baseline is observable/auditable.

## Tier 1 Per-Node Online Baseline

Historical `model.rs` separately implements Tier 1 online per-node Z-score state. Each node maintains its own running statistics, so nodeA and nodeB behavior do not contaminate each other's baselines.

## Tier 2 Model Artifacts

Historical Task 1 includes:

```text
global_forest.json
nodeA_forest.json
nodeB_forest.json
```

and Python training outputs:

```text
global_forest.joblib
nodeA_forest.joblib
nodeB_forest.joblib
```

## Role Baseline Clarification

Historical role baseline code is explicitly shadow-only. The per-node/global baseline path remains the production alert-decision source.

## Current SGX Runtime

Current runtime evidence shows:

```rust
let mut ai_state = task1_ai::AlertScorerState::default();
```

with the active flow:

```text
ThreatAlert
  ↓
feature_from_alert(...)
  ↓
process_feature(...)
  ↓
generate_plan(...)
  ↓
anomaly_context_from_score(...)
```

The current working tree does not expose the historical baseline/model-selection lifecycle in this active path.

## Current vs Historical

### Historical/full Task 1

```text
node id
   ↓
BaselineLifecycleConfig
   ↓
per-node forest if available
   otherwise global fallback
   ↓
IsolationForestModel
   +
Tier 1 online per-node Z-score
   ↓
Task 1 score/confidence
```

### Current integrated SGX

```text
Suricata alert
   ↓
AlertScorerState
   ↓
rolling alert records
   ↓
fixed heuristic weighted score
```

## Why This Matters

Without restoring the existing baseline lifecycle into the current integrated runtime:

* the client application cannot reliably show which baseline/model produced an anomaly,
* global fallback cannot be distinguished from a node-specific model,
* model provenance and baseline maturity are lost,
* historical Task 1 acceptance evidence cannot automatically be claimed for the current runtime.

## Recommended API / Client Application Metadata

Expose baseline/model provenance, for example:

```json
{
  "anomaly": {
    "score": 0.91,
    "confidence": 0.94,
    "baseline": {
      "kind": "per_node",
      "node": "nodeA",
      "model_source": "nodeA_forest.json",
      "fallback_used": false
    }
  }
}
```

For a new node:

```json
{
  "baseline": {
    "kind": "global",
    "fallback_used": true
  }
}
```

## Recommended Fix Direction

1. Restore the historical baseline/model lifecycle into the current SGX runtime.
2. Define where production model artifacts are packaged and loaded.
3. Select the node-specific model when available.
4. Fall back to the global model only when appropriate.
5. Restore Tier 1 per-node online baseline behavior.
6. Preserve baseline/model provenance in anomaly results.
7. Support safe model refresh/promotion.
8. Expose baseline kind and model source/version through the API.
9. Add integration tests for nodeA/nodeB selection, new-node fallback, missing-global failure, and Global → PerNode promotion.
10. Make baseline status visible in client application/admin diagnostics.

## Acceptance Criteria

* [ ] Current runtime loads the Task 1 Isolation Forest model.
* [ ] Per-node model is selected when available.
* [ ] Global model is used as fallback when appropriate.
* [ ] Missing per-node + missing global is handled explicitly.
* [ ] Tier 1 running baseline is isolated per node.
* [ ] Baseline/model source is persisted with anomaly evidence.
* [ ] Baseline kind reaches the API.
* [ ] Client application can show `PerNode` vs `Global fallback`.
* [ ] Model refresh/promotion is tested.
* [ ] Tests verify node baselines do not mix.

## Final Verdict

**Issue #6 confirmed as an integration gap.**

The historical Task 1 engine had a real baseline lifecycle:

```text
per-node model preferred
→ global model fallback
→ reload/promotion when per-node becomes available
```

plus Tier 1's online per-node behavioral baseline. The current active SGX Task 1 path does not expose or use that historical lifecycle.

---

# Task 1 AI Application Integration — Issue #7

## Title

Historical Task 1 supported all four required anomaly categories, but the current SGX integration no longer carries the full traffic, protocol, resource, and peer-behavior feature set into the active anomaly scorer.

## Status

Confirmed

## Severity

High

## Area

Task 1 AI Feature Coverage / Runtime Integration / Client Application Evidence

---

## Requirement Coverage

Task 1 requires detection of:

```text
1. Unusual traffic spikes
2. Unexpected protocol violations
3. Abnormal resource consumption
4. Suspicious peer behavior
```

Historical/full Task 1 implemented all four categories.

The current active SGX scorer does not.

---

## Historical Task 1 Coverage

The historical 19-feature engine included features such as:

```text
net_rx_bytes_rate
net_tx_bytes_rate
net_rx_pkts_rate
net_tx_pkts_rate
conn_rate
active_peers
relay_bytes_rate
proto_violation_rate
cpu_util_pct
mem_used_pct
open_fds
load1
```

This provided direct behavioral coverage for:

```text
Traffic spikes              ✅
Protocol violations          ✅
Resource anomalies           ✅
Peer behavior                ✅
```

---

## Current Active Input Shape

Current `src/threat/ai_bridge.rs` exposes only:

```rust
pub struct AlertFeature {
    pub ts: DateTime<Utc>,
    pub severity_score: u8,
    pub signature_id: u32,
    pub category: ThreatCategory,
    pub src_ip: String,
    pub dst_ip: String,
}
```

Therefore the current Task 1 integration does not carry:

```text
network byte rates
packet rates
connection rate
active peer count
protocol violation rate
CPU usage
memory usage
open file descriptors
system load
peer interaction frequency
protocol sequence behavior
```

into the active scorer.

---

## Current Scorer Behavior

Current `src/task1_ai/scorer.rs` uses a rolling source-IP alert window.

It calculates the score from:

```text
alert frequency
signature repetition
average severity
category weight
```

Conceptually:

```text
raw_score =
    frequency factor      * 0.45
  + signature repetition * 0.25
  + severity factor      * 0.15
  + category weight      * 0.15
```

This is not equivalent to the historical behavioral feature vector.

---

## Final Current Coverage Assessment

| Required anomaly type          | Historical Task 1 | Current SGX integration |
| ------------------------------ | ----------------: | ----------------------: |
| Unusual traffic spikes         |                 ✅ |              ⚠️ Partial |
| Unexpected protocol violations |                 ✅ |   ⚠️ Partial / indirect |
| Abnormal resource consumption  |                 ✅ |               ❌ Missing |
| Suspicious peer behavior       |                 ✅ |         ⚠️ Very limited |

---

## 1. Unusual Traffic Spikes

Historical behavior:

```text
net_rx_bytes_rate
net_tx_bytes_rate
net_rx_pkts_rate
net_tx_pkts_rate
conn_rate
```

Current behavior:

```text
alert_count
burst_density
signature_repeat
```

So the current scorer can detect:

```text
alert bursts
```

but not necessarily:

```text
actual traffic-volume spikes
```

A large increase in bytes/packets that does not produce many Suricata alerts may therefore not be represented in the current Task 1 score.

Status:

```text
PARTIAL
```

---

## 2. Unexpected Protocol Violations

Historical behavior used a dedicated feature:

```text
proto_violation_rate
```

Current scorer does not receive a protocol-violation rate or protocol-sequence feature.

It only sees:

```text
ThreatCategory::PolicyViolation
```

as one weighted alert category.

This is indirect classification, not a behavioral protocol-sequence/rate model.

Status:

```text
PARTIAL / INDIRECT
```

---

## 3. Abnormal Resource Consumption

Historical behavior included:

```text
cpu_util_pct
mem_used_pct
open_fds
load1
```

Current `AlertFeature` and `AlertScorerState` do not contain those fields.

A final wiring search across:

```text
src/task1_ai
src/threat/service.rs
src/threat/ai_bridge.rs
```

for:

```text
cpu_util
mem_used
open_fds
load1
```

returned no matches.

Status:

```text
MISSING
```

---

## 4. Suspicious Peer Behavior

Historical behavior included features such as:

```text
active_peers
connection rate
relay traffic/activity
```

Current scorer groups alerts by:

```text
src_ip
```

and tracks the number of alerts from that source.

That can provide a limited source-level burst signal, but it is not the same as:

```text
typical peer interaction frequency
active peer behavior
peer relationship changes
relay behavior
```

A final wiring search for peer-frequency/active-peer features returned no matches.

Status:

```text
VERY LIMITED
```

---

## Final Wiring Verification

The current full-feature wiring search was:

```bash
grep -RniE 'net_rx_bytes|net_tx_bytes|net_rx_pkts|net_tx_pkts|conn_rate|active_peers|proto_violation|cpu_util|mem_used|open_fds|load1|peer.*frequ|protocol.*sequence' src/task1_ai src/threat/service.rs src/threat/ai_bridge.rs
```

Result:

```text
no matches
```

This confirms that the historical behavioral feature set is not wired into the current active Task 1 path.

---

## Root Cause Classification

```text
Feature-pipeline integration regression / reduced runtime feature contract
```

not:

```text
Historical Task 1 never implemented these anomaly categories
```

---

## Why This Matters for Application Integration

If the client application displays:

```text
Traffic anomaly detected
Protocol anomaly detected
Resource anomaly detected
Peer anomaly detected
```

based only on the current heuristic scorer, it may overstate what the current runtime actually measured.

The client application should not imply full behavioral coverage until the full feature pipeline is restored.

---

## Recommended Fix Direction

1. Restore the historical 19-feature telemetry contract.
2. Feed real traffic-rate metrics into Task 1.
3. Feed protocol violation/sequence telemetry into Task 1.
4. Feed node CPU/memory/open-FD/load telemetry into Task 1.
5. Feed peer interaction / active-peer telemetry into Task 1.
6. Route the restored feature vector into the full Z-score + Isolation Forest engine.
7. Preserve anomaly category/evidence in structured API output.
8. Expose which feature family triggered the anomaly.
9. Add end-to-end tests for each required anomaly class.
10. Ensure client application labels reflect actual measured evidence.

---

## Recommended Structured API Direction

Example:

```json
{
  "anomaly": {
    "detected": true,
    "score": 0.92,
    "confidence": 0.94,
    "type": "resource_consumption",
    "contributors": [
      {
        "feature": "cpu_util_pct",
        "value": 97.2,
        "contribution": 0.88
      },
      {
        "feature": "mem_used_pct",
        "value": 91.4,
        "contribution": 0.61
      }
    ]
  }
}
```

Possible anomaly types:

```text
traffic_spike
protocol_violation
resource_consumption
peer_behavior
```

These should be backend-derived, not guessed by the client application.

---

## Acceptance Criteria

Issue #7 is fixed when:

* [ ] Traffic byte/packet/connection-rate features reach the integrated Task 1 model.
* [ ] Protocol violation/sequence features reach the integrated Task 1 model.
* [ ] CPU/memory/open-FD/load features reach the integrated Task 1 model.
* [ ] Peer interaction/active-peer features reach the integrated Task 1 model.
* [ ] Full feature vector is used by the production anomaly model.
* [ ] Traffic-spike test produces a Task 1 anomaly.
* [ ] Protocol-violation test produces a Task 1 anomaly.
* [ ] Resource-consumption test produces a Task 1 anomaly.
* [ ] Suspicious-peer test produces a Task 1 anomaly.
* [ ] Each result includes structured evidence/contributors.
* [ ] Client application does not overstate coverage when a feature family is unavailable.

---

## Final Verdict

**Issue #7 confirmed as an integration regression.**

Historical/full Task 1 covered all four required anomaly categories, but the current SGX runtime reduces Task 1 input to alert metadata and a rolling alert-burst heuristic.

The full behavioral feature set for traffic, protocol, resource, and peer anomalies is not currently wired into the active Task 1 scorer.

---

# Task 1 AI Application Integration — Issue #8

## Title

Task 1 threshold crossing generates a remediation/policy-update proposal, but does not trigger or apply a Virtual Shift policy update in the current active SGX runtime.

## Status

Confirmed

## Severity

High

## Task 1 Requirement

```text
Trigger Virtual Shift policy updates when anomaly score exceeds threshold.
```

## Confirmed Current Flow

```text
Task 1 anomaly score
        ↓
score >= threshold
        ↓
generate_plan(...)
        ↓
RemediationPlan
        ↓
ProposePolicyUpdate
        ↓
logging only
        ↓
NO verified Virtual Shift consumer
        ↓
NO verified policy application
```

## Evidence

Current Task 1 remediation code defines:

```rust
ProposePolicyUpdate { rule_delta: String }
```

and can create policy proposals such as:

```text
virtual_shift: tighten policy for <target_ip>;
```

`src/threat/service.rs` calls `task1_ai::generate_plan(...)` after threshold crossing and logs that a remediation plan was generated.

A source-wide search for consumers of:

```text
ProposePolicyUpdate
requires_approval
immediate_actions
RemediationPlan
```

outside `src/task1_ai/remediation.rs` returned only the re-export in `src/task1_ai/mod.rs`.

Therefore no active runtime consumer of the generated Task 1 remediation plan was found.

## Requirement Status

```text
Threshold crossed                 ✅
Remediation plan generated        ✅
Policy update proposed            ✅
Virtual Shift update triggered    ❌
Policy actually applied           ❌
```

## Important Clarification

The repository does contain policy enforcement paths such as `enforcement::apply_policy(...)` and `policy_manager.rs`, but the verified Task 1 remediation path is not wired to those consumers.

So existing policy enforcement elsewhere in SGX does not by itself satisfy the Task 1 requirement.

## Root Cause

```text
Task 1 → Virtual Shift integration gap
```

The proposal object exists, but the runtime handoff/consumer is missing.

## Recommended Fix Direction

1. Define a concrete Task 1 → Virtual Shift handoff.
2. On threshold crossing, create a structured Virtual Shift trigger/event.
3. Preserve anomaly score, model confidence, threshold used, node/source identity, evidence, and proposed policy delta.
4. Route the event into the Virtual Shift workflow.
5. Respect approval requirements where applicable.
6. After approval, invoke the existing verified policy/enforcement path.
7. Persist trigger/application state.
8. Expose status through API/client application.
9. Add end-to-end tests for threshold → trigger → approval/apply.

## Acceptance Criteria

* [ ] Threshold crossing creates a Virtual Shift trigger/event.
* [ ] Trigger preserves score, confidence, threshold, identity, and evidence.
* [ ] Policy proposal is consumed by the Virtual Shift workflow.
* [ ] Approval requirements are enforced where required.
* [ ] Approved updates reach the policy/enforcement layer.
* [ ] Applied/rejected/failed state is persisted.
* [ ] API/client application can show trigger/application status.
* [ ] Integration test proves threshold → Virtual Shift trigger.
* [ ] End-to-end test proves approved trigger → policy application.

## Final Verdict

**Issue #8 confirmed.**

The current Task 1 implementation generates a `RemediationPlan` and may include `ProposePolicyUpdate`, but no runtime consumer of that plan was found outside the Task 1 remediation module. Therefore the original Task 1 requirement to trigger Virtual Shift policy updates when the anomaly score exceeds threshold is not currently completed in the active SGX runtime.

---

# Task 1 AI Application Integration — Issue #9

## Title

One-Class SVM is not implemented in the current or historical Task 1 anomaly-detection codebase.

## Status

Confirmed against the literal Task 1 wording

## Severity

Medium

## Area

Task 1 AI / Streaming Anomaly Detection Algorithms

---

## Task 1 Requirement

The original Task 1 description states:

```text
Use streaming anomaly detection algorithms (Isolation Forest, One-Class SVM) to identify deviations.
```

Under a literal reading of this requirement, both named algorithms are expected to be represented in the Task 1 implementation.

---

## Verification Performed

The following terms were searched in both the current tree and the historical Task 1 implementation:

```text
one-class svm
oneclasssvm
ocsvm
svm
support vector
```

### Current tree

No matches were found in:

```text
src
anomaly-training
sgx-anomaly-engine
```

### Historical Task 1 commit

No matches were found in commit:

```text
862d481
```

under:

```text
sgx-anomaly-engine
anomaly-training
```

---

## What Does Exist

Historical/full Task 1 already contains:

```text
Tier 1: online per-node Z-score baseline
Tier 2: Isolation Forest
```

Isolation Forest is therefore implemented and has also been separately verified for model size and inference latency.

However, no One-Class SVM implementation, model artifact, trainer, runtime scorer, configuration, test, or documentation reference was found in the inspected Task 1 code.

---

## Requirement Status

```text
Isolation Forest       ✅ Implemented
One-Class SVM          ❌ Not found
Streaming scoring      ✅ Historical engine
```

Therefore the named-algorithm portion of Task 1 is only partially satisfied if both algorithms are mandatory.

---

## Important Interpretation Note

If the wording:

```text
(Isolation Forest, One-Class SVM)
```

was intended only as examples of acceptable lightweight anomaly-detection algorithms, then the existing Isolation Forest implementation may be sufficient and this issue can be downgraded or closed.

If both named algorithms are acceptance requirements, Issue #9 remains valid.

Because the user requested verification strictly against the supplied Task 1 description, this tracker records the literal requirement gap.

---

## Recommended Fix Direction

If One-Class SVM is required:

1. Add a lightweight One-Class SVM training path.
2. Use the same 19-feature schema or an explicitly versioned compatible subset.
3. Support global and per-node models where appropriate.
4. Add runtime inference behind the existing Task 1 model interface.
5. Add model-selection/configuration support.
6. Preserve anomaly score and model confidence.
7. Benchmark model size against the <=10 MB target.
8. Benchmark inference against the <100 ms target on target hardware.
9. Add parity and regression tests.
10. Define whether OCSVM is:

    * an alternative to Isolation Forest,
    * a fallback,
    * or part of an ensemble.

---

## Acceptance Criteria

* [ ] One-Class SVM training implementation exists, if required by acceptance criteria.
* [ ] A runtime One-Class SVM scorer exists.
* [ ] Model artifacts are versioned.
* [ ] Global/per-node baseline integration is defined.
* [ ] Anomaly score is normalized into the Task 1 score contract.
* [ ] Model confidence semantics are defined.
* [ ] Model size is <=10 MB.
* [ ] Inference is <100 ms on the required target hardware.
* [ ] Tests cover normal and anomalous samples.
* [ ] Documentation clearly states whether Isolation Forest and One-Class SVM are alternatives or both required.

---

## Final Verdict

**Issue #9 confirmed under the literal Task 1 wording.**

Isolation Forest exists, but no One-Class SVM implementation was found in either the current tree or the historical Task 1 implementation.

---

# Task 1 AI Application Integration — Issue #10

## Title

Task 1 edge/embedded hardware acceptance is not validated on an actual target board.

## Status

Confirmed as a validation gap

## Severity

Medium

## Area

Task 1 AI / Edge Deployment / Embedded Hardware Validation

---

## Task 1 Requirement

The original Task 1 requirement states:

```text
Optimize for resource-constrained embedded hardware
(10MB model size, <100ms inference time).
```

---

## What Has Already Passed

### Model size

Historical/full Task 1 Isolation Forest artifacts were measured as:

```text
global_forest.json  -> 1.636 MiB
nodeA_forest.json   -> 1.511 MiB
nodeB_forest.json   -> 1.559 MiB
```

All are comfortably below the 10 MB requirement.

Result:

```text
Model size <= 10 MB  ✅ PASS
```

### Inference latency on the current WSL/PC environment

A release-mode benchmark executed 5,000 Isolation Forest scoring runs.

Observed results:

```text
Min : 0.012411 ms
Avg : 0.013993 ms
P50 : 0.013476 ms
P95 : 0.015117 ms
P99 : 0.023053 ms
Max : 0.242554 ms
```

Result on the current development environment:

```text
Inference < 100 ms  ✅ PASS
```

---

## Embedded / ARM Evidence

Historical Task 1 `Cargo.toml` contains explicit board/aarch64 awareness:

```text
native-tls complicates aarch64 cross-compilation for the board
```

The dependency configuration was intentionally adjusted to avoid a cross-compilation complication.

This is useful evidence that edge-board deployment was considered during implementation.

---

## Missing Evidence

A repository-wide search did not find evidence of an actual Task 1 anomaly-engine benchmark performed on a real target board/device.

No verified evidence was found for:

```text
on-device inference benchmark
on-board latency benchmark
target-board memory/RSS benchmark
peak-memory measurement
actual ARM board performance report
```

The remaining board references found were mainly:

```text
aarch64 cross-compilation comment
mock/replaceable board integration references
```

They do not demonstrate the Task 1 model's real inference latency or memory behavior on the resource-constrained target hardware.

---

## Requirement Status

```text
Small model artifacts                 ✅ PASS
<100ms inference on WSL/PC            ✅ PASS
aarch64/board deployment awareness    ✅ Present
Actual embedded-board benchmark       ❌ Not found
Embedded memory/RSS validation        ❌ Not found
```

Therefore:

```text
Edge optimization implementation evidence  ✅ strong
Target-hardware acceptance evidence        ⚠️ incomplete
```

---

## Why This Is an Issue

A desktop/WSL benchmark cannot prove that the same latency and memory characteristics hold on the intended resource-constrained embedded hardware.

The Task 1 wording specifically targets embedded hardware, so final acceptance should be demonstrated on the target device or on a formally approved equivalent hardware profile.

---

## Recommended Fix / Validation Direction

1. Cross-compile the historical/full Task 1 engine for the intended ARM/aarch64 target.
2. Deploy the exact model artifact intended for production.
3. Benchmark warm inference latency on the device.
4. Record at least:

   * average
   * p50
   * p95
   * p99
   * maximum latency
5. Measure process memory:

   * RSS
   * peak RSS
   * model-memory footprint
6. Run representative normal and anomalous feature vectors.
7. Record target board name, CPU, RAM, OS, architecture, compiler profile, and model version.
8. Verify the exact acceptance targets:

   * model <= 10 MB
   * inference < 100 ms
9. Preserve the benchmark as CI/release evidence where practical.

---

## Acceptance Criteria

* [ ] The Task 1 anomaly engine is built for the intended embedded target.
* [ ] The exact target-board hardware is documented.
* [ ] The deployed model remains <=10 MB.
* [ ] Real on-device inference is measured.
* [ ] p95 inference is <100 ms.
* [ ] Maximum latency is reviewed against the product requirement.
* [ ] Runtime RSS/peak memory is measured.
* [ ] Normal and anomalous inputs are both tested.
* [ ] Benchmark configuration and model version are recorded.
* [ ] Results are reproducible.

---

## Final Verdict

**Issue #10 confirmed as an embedded-hardware validation gap.**

The historical/full Task 1 implementation already satisfies the model-size target and easily satisfies the inference-time target on the current WSL/PC environment. It also contains explicit aarch64/board cross-compilation awareness.

However, no evidence was found that these constraints were validated on the actual resource-constrained embedded target hardware.

This is therefore a **target-hardware acceptance/validation gap**, not evidence that the model itself is too large or too slow.

---

# Architecture Questions & Recommended Answers

> These answers are based on the Phase 4 / Intelligence Layer task descriptions. Where the document does not explicitly define a behavior, the answer is marked as an architecture recommendation rather than a documented requirement.

## Q1 — Critical Attack ke waqt Policy Approval Delay ka masla

### Question

Agar anomaly critical ho aur active damage ho raha ho, lekin full policy approval/signing process mein delay aa raha ho, to node ko policy pohanchne tak kaise protect kiya jaye?

### Recommended Answer

Best design **hybrid approach** hai:

```text
Critical anomaly detected
        ↓
Local temporary containment
        +
Fast-track / emergency approval
        ↓
Signed authoritative policy
        ↓
Circle-wide propagation
```

### 1. Local auto-mitigation hona chahiye — lekin bounded aur temporary

Critical attack ke waqt node ko sirf admin approval ka wait nahi karna chahiye.

Node ke paas pre-authorized emergency actions ho sakte hain, jaise:

```text
temporary source-IP block
rate limiting
suspicious peer isolation
specific protocol deny
extra logging
temporary connection freeze
```

Lekin ye actions:

```text
local only
temporary
TTL-based
reversible
strictly limited
fully audited
```

hone chahiye.

Example:

```text
Critical score >= emergency threshold
        ↓
Node locally blocks attacker for 60–300 sec
        ↓
Full policy recommendation admin ko jati hai
        ↓
Approve hone par signed permanent / Circle-wide policy apply hoti hai
```

### 2. Fast-track approval path bhi hona chahiye

Critical severity ke liye normal workflow se faster emergency path useful hai.

Example:

```text
Normal anomaly
→ normal review queue

Critical anomaly
→ emergency review queue
→ highest priority notification
→ reduced operational delay
→ signed approval
```

Fast-track ka matlab approval/security checks remove karna nahi hai.

Signed policy aur authorization authoritative rehne chahiye.

### Architecture impact

Is design se do policy layers banengi:

```text
Layer 1 — Local Emergency Mitigation
- bounded
- temporary
- node-local
- pre-authorized
- reversible

Layer 2 — Authoritative Virtual Shift Policy
- reviewed
- approved
- signed
- Circle-wide
- persistent
- auditable
```

### Trust-model impact

Node ko unrestricted policy authority dena risky hoga.

Isliye node ko sirf narrow emergency capabilities delegate karni chahiye.

```text
Node can temporarily contain
Node cannot permanently redefine Circle policy
```

Permanent/distributed policy authority approved signed workflow ke paas hi rehni chahiye.

### Final answer

**Recommended design: local temporary auto-mitigation + fast-track emergency approval, dono.**

Sirf auto-mitigation ya sirf approval path par depend karna less robust hoga.

---

## Q2 — Routing Optimization ka Scope: Normal Traffic ya Security-Critical Traffic bhi?

### Documented Task 3 scope

Task 3 network metrics monitor karta hai:

```text
peer latency
packet loss
bandwidth utilization
relay hop counts
```

aur direct P2P vs multi-hop relay path optimize karta hai.

Document high-priority traffic ke liye relay-path load balancing bhi mention karta hai.

Document explicitly ye nahi kehta ke `VSHIFT_ALERT` / signed policy distribution 반드시 Task 3 se route hogi.

### Recommended architecture

Task 3 ko dono traffic classes support karni chahiye:

```text
1. Normal / application traffic
2. Security-critical control traffic
```

Lekin dono ko same priority nahi deni chahiye.

Recommended classes:

```text
CRITICAL CONTROL
- anomaly alerts
- emergency revocation
- signed policy updates
- quarantine commands
- attestation emergency traffic

HIGH
- security telemetry
- normal policy sync
- audit events

NORMAL
- application data
- routine telemetry
```

Security-critical traffic ko:

```text
higher QoS
lower queue delay
priority scheduling
optional multi-path delivery
fast relay selection
```

milna chahiye.

### Important safety rule

AI routing optimization ko policy authenticity decide nahi karni chahiye.

Task 3 sirf:

```text
"kis eligible path se bhejna hai?"
```

decide kare.

Ye decide nahi kare:

```text
"policy valid hai ya nahi?"
"signer trusted hai ya nahi?"
```

Wo cryptographic verification / trust layer ka kaam hai.

### Final answer

**Yes, Task 3 ko security-critical traffic ke liye bhi use kiya ja sakta hai, lekin separate priority/QoS class aur deterministic fallback ke saath.**

---

# “Task 3 routes kis cheez ke liye hain?”

Document ke according Task 3 ka purpose general network path optimization hai.

Example:

```text
NodeA → NodeB telemetry
direct path?
ya
NodeA → NodeC relay → NodeB?
```

Task 3 latency, loss, bandwidth aur hop-count dekh kar route select karta hai.

### Recommended extended use

Task 3 signed policy / security-control traffic ke liye bhi best route select kar sakta hai.

Example:

```text
Signed policy ready
        ↓
Transport asks Task 3:
"Target tak fastest eligible path konsa hai?"
        ↓
Direct / relay / alternate path selected
        ↓
Policy delivered
```

Lekin policy delivery Task 3 par completely dependent nahi honi chahiye.

Fallback hona chahiye:

```text
Task 3 optimized route
        ↓ if unavailable
existing direct / gossip / relay fallback
```

Task 3 optimization layer hai, policy-validity ya policy-authorization layer nahi.

---

# “Agar Task 3 policy ko route nahi karega aur policy late ho rahi hai, to node ko policy pohanchne tak protect kaise karenge?”

Iska answer Q1 ke emergency layer se aata hai.

```text
Critical anomaly
        ↓
Local temporary mitigation immediately
        ↓
Signed policy approval/process parallel mein
        ↓
Policy network tak pohanchti hai
        ↓
Authoritative policy replaces temporary mitigation
```

Isliye node protection ka correctness Task 3 ke upar dependent nahi hona chahiye.

Task 3 delivery ko **faster** bana sakta hai.

Local emergency mitigation node ko **safe** rakhti hai jab tak authoritative policy nahi aati.

---

# “Agar Task 3 ko Task 2 ki policy bhejne ke liye use karein, to trusted/untrusted node state kahan se milegi?”

Yahan do different cheezen separate rakhni zaroori hain:

## A. Routing metrics

Task 3 ko ye chahiye:

```text
latency
packet loss
bandwidth
hop count
link availability
```

Ye Task 3 apne network monitoring se leta hai.

## B. Security / trust state

Task 3 ko route eligibility ke liye ye state chahiye ho sakti hai:

```text
peer trusted?
revoked?
quarantined?
attestation valid?
policy permits relay?
```

Ye state **Task 2 ka exclusive output nahi honi chahiye**.

Trust state already system ke security components se aani chahiye:

```text
attestation state
CRL / revocation state
peer identity / DID state
current policy
quarantine status
```

Task 2 policy adaptation is state ko change/update kar sakta hai, lekin base trust source Task 2 nahi hai.

### Circular dependency avoid karne ka recommended design

```text
Security / Trust State
(attestation + CRL + current policy)
        ↓
Eligible relay peers
        ↓
Task 3 Routing Engine
(latency/loss/bandwidth ke basis par ranking)
        ↓
Best eligible route
```

Task 2 ka flow:

```text
Task 1 anomaly
        ↓
Task 2 recommendation
        ↓
approval + signing
        ↓
policy blob
        ↓
transport / gossip
        ↓
Task 3 may optimize path among eligible peers
```

Isliye Task 3 ko Task 2 se "trusted/untrusted" discover karne ki zaroorat nahi.

Task 3 ko ek local trust/eligibility interface milna chahiye.

Conceptual API:

```text
TrustState:
    peer_A → trusted
    peer_B → quarantined
    peer_C → trusted

Task 3:
    candidates = trusted + policy-allowed peers
    best = rank(candidates by latency/loss/bandwidth)
```

### Example

```text
NodeB critical attack mein hai

Available relay peers:
NodeC = 20ms, trusted
NodeD = 10ms, quarantined
NodeE = 35ms, trusted

Task 3 result:

NodeD fastest hai
BUT security eligibility fail ❌

NodeC next fastest + trusted ✅

Selected route:
Policy → NodeC → NodeB
```

### Final answer

**Routing quality aur trust eligibility ko separate systems rakhna chahiye.**

```text
Trust layer decides:
WHO may be used

Task 3 decides:
WHICH allowed path is best
```

Is separation se circular dependency khatam ho jati hai.

---

# Recommended Combined Architecture

```text
                    ┌───────────────────────┐
                    │ Task 1: Anomaly AI    │
                    │ score + confidence    │
                    └───────────┬───────────┘
                                │
                     threshold exceeded
                                │
               ┌────────────────┴────────────────┐
               │                                 │
               ▼                                 ▼
┌─────────────────────────┐        ┌─────────────────────────┐
│ Local Emergency Guard   │        │ Task 2 Policy Workflow  │
│ temporary containment   │        │ recommend → approve     │
│ TTL + reversible        │        │ sign → policy blob      │
└─────────────────────────┘        └─────────────┬───────────┘
                                                │
                                                ▼
                                  ┌─────────────────────────┐
                                  │ Trust / Eligibility     │
                                  │ attestation / CRL /     │
                                  │ policy / quarantine     │
                                  └─────────────┬───────────┘
                                                │
                                      eligible peers only
                                                │
                                                ▼
                                  ┌─────────────────────────┐
                                  │ Task 3 Routing Engine   │
                                  │ latency / loss / BW /   │
                                  │ hops                    │
                                  └─────────────┬───────────┘
                                                │
                                     best eligible route
                                                │
                                                ▼
                                  ┌─────────────────────────┐
                                  │ Priority Security       │
                                  │ Delivery / Gossip       │
                                  └─────────────────────────┘
```

---

# Short Decision Summary

```text
Critical attack handling
→ Temporary local mitigation + fast-track approval

Permanent Circle-wide policy
→ Must remain signed / authorized

Task 3 scope
→ Normal + security-critical traffic can use it

Security traffic
→ Higher QoS / priority + fallback path

Task 3 responsibility
→ Select best eligible route

Task 3 should NOT decide
→ Trust, policy validity, signer authority

Trusted/untrusted state source
→ Attestation + CRL + current policy + quarantine state

Task 2 role
→ Generate/approve/sign policy changes

Circular dependency solution
→ Trust layer filters peers first; Task 3 ranks only eligible peers
```

## Relationship to the Phase Document

The Phase document explicitly states that:

* Automated Policy Adaptation generates recommendations, requires owner review, then signs and broadcasts `VSHIFT_ALERT`, after which Circle members verify and atomically apply the policy.
* AI Network Optimization monitors latency, packet loss, bandwidth utilization, and relay hop counts, dynamically switching between direct and relay paths and balancing high-priority traffic.
* The Virtual Shift AI demo combines anomaly detection, policy recommendation/approval/propagation, policy application, VirtualID rotation, re-attestation, and AI network rerouting.

The document does **not** explicitly define whether Task 3 must carry signed policy traffic or define a local emergency mitigation layer during approval delay. The recommendations above fill those architecture gaps while preserving the document's signed-policy trust model.
