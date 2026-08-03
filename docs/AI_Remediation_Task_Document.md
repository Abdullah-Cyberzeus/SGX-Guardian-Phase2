# AI-Generated Remediation Recommendations for Security Alerts

**Project**: SG-X Guardian (SGX) — Phase 2 Intelligence Layer  
**Task**: Implement AI-Generated Remediation Recommendations for Security Alerts, Integrating Anomaly Detection Engines with Contextual Response Generation and Advisory Services  
**Document Date**: August 2026  
**Status**: Planned / In Design

---

## Table of Contents

1. [What This Task Is](#1-what-this-task-is)
2. [Why We Need It](#2-why-we-need-it)
3. [How It Fits Into SGX](#3-how-it-fits-into-sgx)
4. [Architecture Overview](#4-architecture-overview)
5. [The Three Core Engines](#5-the-three-core-engines)
   - 5.1 [Anomaly Detection Engine](#51-anomaly-detection-engine)
   - 5.2 [Contextual Response Generator](#52-contextual-response-generator)
   - 5.3 [Advisory Service](#53-advisory-service)
6. [Data Flow — Step by Step](#6-data-flow--step-by-step)
7. [Files to Create](#7-files-to-create)
8. [Files to Modify](#8-files-to-modify)
9. [Key Data Structures](#9-key-data-structures)
10. [Remediation Action Types](#10-remediation-action-types)
11. [Example Scenario (End to End)](#11-example-scenario-end-to-end)
12. [What We Do NOT Need](#12-what-we-do-not-need)
13. [Acceptance Criteria](#13-acceptance-criteria)
14. [Glossary](#14-glossary)

---

## 1. What This Task Is

In plain English, this task is about making **SGX smarter when it detects a threat**.

Today, when Suricata (the embedded IDS/IPS engine inside SGX) detects a suspicious event — such as a port scan or a malware signature — SGX either:
- Blocks the offending IP address using `nftables`, OR
- Logs the alert to a file.

That is a **reactive and rigid** response. It does not explain *why* a threat is dangerous, does not adapt to the overall pattern of events across the network, and does not suggest anything beyond simply blocking an IP.

**This task adds a new intelligence layer** that does the following:

1. **Watches the stream of alerts** and detects abnormal behavioral patterns — not just individual alerts.
2. **Calculates how serious the current situation is** using an anomaly score.
3. **Generates a specific, context-aware remediation plan** for each detected threat.
4. **Presents a human-readable advisory** to the security administrator with actionable options.

---

## 2. Why We Need It

| Without This Feature | With This Feature |
| :--- | :--- |
| SGX blocks IPs blindly based on static rules | SGX understands *patterns* before deciding |
| Administrator gets no explanation for alerts | Administrator gets a clear advisory with justification |
| Response is always the same (block or log) | Response is tailored to the threat type and severity |
| No correlation between multiple related alerts | Multiple related events are grouped and analyzed together |
| Policy updates are manual admin tasks | Remediation recommendations are generated automatically and submitted for approval |

The Phase 2 Statement of Work (SOW) explicitly requires this under **"Virtual Shift AI — Automated Policy Adaptation"**, where:
> *"When anomaly detected, AI engine generates policy update recommendations: tighten firewall rules, increase attestation frequency, enable additional logging, quarantine suspicious peers."*

---

## 3. How It Fits Into SGX

SGX is built around a **Circle of Trust** — a group of edge nodes that mutually authenticate, share signed security policies, and enforce them collectively.

The new AI remediation layer plugs directly into the existing threat pipeline:

```
Suricata IDS/IPS
      │
      ▼
eve_parser.rs   ← Parses EVE JSON log events (alerts, anomalies)
      │
      ▼
ai_bridge.rs    ← Pushes High/Critical alerts into a broadcast channel (feature tap)
      │
      ▼
[NEW] anomaly.rs  ← Scores the stream of alerts for abnormal patterns
      │
      ▼
[NEW] remediation.rs  ← Maps the anomaly + alert context to specific actions
      │
      ▼
[NEW] advisory.rs  ← Formats the actions into a human-readable advisory
      │
      ├──► blocker.rs    (executes nftables block immediately, if auto-mode enabled)
      ├──► policy_manager.rs   (proposes a new UEP policy update)
      ├──► audit logger  (records the advisory with full justification)
      └──► Admin Dashboard / CLI  (presents advisory for review and approval)
```

---

## 4. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                       SG-X Guardian Node                        │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    Threat Pipeline                         │  │
│  │                                                           │  │
│  │  Suricata EVE Log ──► eve_parser ──► AlertInventory       │  │
│  │                                         │                 │  │
│  │                              ai_bridge (feature tap)      │  │
│  │                                         │                 │  │
│  │                           ┌─────────────▼──────────────┐  │  │
│  │                           │   Anomaly Detection Engine  │  │  │
│  │                           │   (anomaly.rs)              │  │  │
│  │                           │   Score: 0.0 → 1.0          │  │  │
│  │                           └─────────────┬──────────────┘  │  │
│  │                                         │ score > threshold│  │
│  │                           ┌─────────────▼──────────────┐  │  │
│  │                           │  Contextual Response Gen   │  │  │
│  │                           │  (remediation.rs)           │  │  │
│  │                           │  → BlockIP                  │  │  │
│  │                           │  → QuarantinePeer           │  │  │
│  │                           │  → TightenAttestation       │  │  │
│  │                           │  → UpdateUEPPolicy          │  │  │
│  │                           └─────────────┬──────────────┘  │  │
│  │                                         │                 │  │
│  │                           ┌─────────────▼──────────────┐  │  │
│  │                           │     Advisory Service        │  │  │
│  │                           │     (advisory.rs)           │  │  │
│  │                           │  → Human-readable report    │  │  │
│  │                           │  → JSON structured payload  │  │  │
│  │                           │  → Audit log entry          │  │  │
│  │                           └─────────────┬──────────────┘  │  │
│  │                                         │                 │  │
│  └─────────────────────────────────────────┼─────────────────┘  │
│                                            │                    │
│            ┌───────────────────────────────┤                    │
│            ▼               ▼               ▼                    │
│       blocker.rs     policy_manager    Audit Logger             │
│     (nftables block) (UEP update)    (tamper-evident)          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. The Three Core Engines

### 5.1 Anomaly Detection Engine

**File**: `src/threat/anomaly.rs`  
**Purpose**: Watch the stream of security alerts over time and calculate a **numerical score** indicating how abnormal the current situation is.

#### How it Works

The engine maintains a **sliding time window** (e.g., the last 5 minutes) and tracks:

- **Alert frequency per source IP**: How many alerts has this IP triggered?
- **Alert rate change**: Is the rate of alerts accelerating suddenly?
- **Category distribution**: Are we seeing an unusual mix of alert types?
- **Repeat signature hits**: Is the same attack signature firing repeatedly?

It then computes an **Anomaly Score** from `0.0` (completely normal) to `1.0` (extremely abnormal):

```
Anomaly Score = weighted average of:
  - IP Alert Rate     (e.g., 50+ alerts/min → contributes 0.4)
  - Signature Repeat  (e.g., same SID 10x  → contributes 0.3)
  - Category Shift    (e.g., sudden Recon  → contributes 0.2)
  - Severity Spike    (e.g., Critical jump → contributes 0.1)
```

#### Score Thresholds

| Score Range | Severity Level | Action |
| :--- | :--- | :--- |
| `0.0 – 0.49` | Normal | No action |
| `0.50 – 0.74` | Suspicious | Log advisory only |
| `0.75 – 0.89` | Elevated | Generate remediation advisory |
| `0.90 – 1.00` | Critical | Auto-block + generate advisory |

#### Important Note on "Training"

This initial implementation uses **statistical baselines** — no ML training is required. The engine simply tracks counters and computes rolling averages. Future versions may use Isolation Forest or One-Class SVM (via the `linfa` Rust crate), but those are optional enhancements.

---

### 5.2 Contextual Response Generator

**File**: `src/threat/remediation.rs`  
**Purpose**: Take the anomaly score + alert details and produce a **specific, actionable remediation plan**.

#### Logic: Threat Category → Remediation Action

The response generator uses the **ThreatCategory** already defined in `threat_alert.rs` to decide the best response:

| Threat Category | Anomaly Score | Recommended Action |
| :--- | :--- | :--- |
| `Reconnaissance` (port scan) | > 0.75 | Block source IP for 1 hour via `nftables` |
| `Exploit` | > 0.80 | Block source IP permanently + alert admin |
| `Malware` | > 0.70 | Block IP + quarantine peer node if internal |
| `PolicyViolation` | > 0.75 | Update UEP policy to close offending port |
| `Anomaly` (Suricata-tagged) | > 0.85 | Increase attestation frequency to 30 seconds |
| Any category (Critical severity) | > 0.90 | Combine all of the above |

#### Remediation Actions Available

1. **NftablesBlockIp**: Add an ephemeral block rule in `inet sgx_threat` table using the existing `blocker.rs`.
2. **QuarantinePeer**: Mark a Circle-of-Trust peer node as untrusted, triggering VirtualID invalidation and re-attestation.
3. **TightenAttestation**: Reduce the attestation interval on the local or target node (e.g., from 5 min to 30 sec).
4. **ProposePolicyUpdate**: Generate a candidate UEP policy blob reducing access to affected ports/protocols.
5. **EnableDebugLogging**: Switch to verbose packet capture logging on the affected network interface.
6. **AlertOnly**: Log an advisory without taking automatic action (for lower-confidence scores).

---

### 5.3 Advisory Service

**File**: `src/threat/advisory.rs`  
**Purpose**: Format the remediation recommendation into a **clear, structured security advisory** for the administrator.

#### Advisory Structure

Each advisory contains:

```json
{
  "advisory_id": "adv-2026-08-02-001",
  "timestamp": "2026-08-02T16:45:00Z",
  "title": "[CRITICAL] Active Port Scan Detected from 192.168.1.105",
  "severity": "critical",
  "anomaly_score": 0.92,
  "threat_summary": {
    "source_ip": "192.168.1.105",
    "alert_count_last_5min": 847,
    "top_signature": "ET SCAN Nmap Scripting Engine User-Agent Detected (SID 2009358)",
    "category": "reconnaissance"
  },
  "justification": "Source IP 192.168.1.105 triggered 847 alerts in 5 minutes (normal baseline: 3/min). Suricata SID 2009358 fired 847 times. Anomaly score 0.92 exceeds critical threshold 0.90.",
  "recommendations": [
    {
      "option": "A",
      "label": "Aggressive — Block + Quarantine",
      "actions": ["NftablesBlockIp (1h)", "QuarantinePeer"],
      "risk": "Low — source is external IP"
    },
    {
      "option": "B",
      "label": "Moderate — Block Only",
      "actions": ["NftablesBlockIp (30min)"],
      "risk": "Low"
    },
    {
      "option": "C",
      "label": "Monitor Only",
      "actions": ["AlertOnly", "EnableDebugLogging"],
      "risk": "Medium — attack continues"
    }
  ],
  "proposed_policy_delta": "deny ip saddr 192.168.1.105 drop;",
  "auto_actioned": true,
  "auto_action_taken": "NftablesBlockIp",
  "requires_approval_for": ["ProposePolicyUpdate", "QuarantinePeer"]
}
```

#### Where Advisories Are Delivered

- **Audit Log**: Every advisory is written to the tamper-evident audit log via `log_audit()`.
- **REST API**: Advisories are exposed on the existing threat REST API endpoint for the dashboard.
- **CLI (`sgx-pa-cli`)**: Administrators can review pending advisories and approve or reject policy updates.
- **In-Memory Store**: Recent advisories are kept in memory for fast API access.

---

## 6. Data Flow — Step by Step

Here is the complete flow from raw network traffic to admin-reviewed advisory:

```
Step 1: Network Traffic Arrives
        Suricata captures packets and writes EVE JSON to:
        /var/log/suricata/eve.json

Step 2: SGX Tails the Log
        eve_tailer.rs reads new lines continuously without blocking.

Step 3: Alert Parsed
        eve_parser.rs parses each JSON line into a ThreatAlert struct
        containing: timestamp, src_ip, dst_ip, signature_id, category, severity.

Step 4: Alert Stored
        AlertInventory stores the alert in a rolling ring buffer (10,000 alerts).

Step 5: Feature Pushed to AI Bridge
        For High/Critical alerts, ai_bridge::forward_to_ai() pushes
        an AlertFeature into the broadcast channel.

Step 6: Anomaly Engine Receives Feature
        anomaly.rs subscribes to the ai_bridge channel.
        It updates rolling counters and recalculates the anomaly score.

Step 7: Score Threshold Check
        If score >= 0.50 → continue to Step 8.
        If score < 0.50 → discard, no action.

Step 8: Remediation Plan Generated
        remediation.rs receives the score + alert context.
        It maps the threat category and score to a RemediationPlan
        containing one or more ActionType values.

Step 9: Advisory Formatted
        advisory.rs takes the RemediationPlan and formats a full
        SecurityAdvisory struct in both human-readable text and JSON.

Step 10: Actions Executed
         a) Auto-actions (score >= 0.90):
            - blocker.rs executes nftables IP block immediately.
            - log_audit() records the advisory with full justification.
         b) Human-approval actions:
            - ProposePolicyUpdate / QuarantinePeer → stored as pending.
            - Available via REST API and CLI for admin review.

Step 11: Admin Approval (for policy changes)
         Circle Owner reviews the advisory via sgx-pa-cli or dashboard.
         On approval → policy_manager.rs signs and broadcasts a new
         UEP policy blob across the entire Circle of Trust.

Step 12: Cohort Enforcement
         All Circle member nodes receive, verify the policy signature,
         and atomically apply the new nftables rules.
         VirtualIDs are rotated, forcing re-attestation of all peers.
```

---

## 7. Files to Create

The following new Rust source files will be added under `src/threat/`:

| File | Purpose |
| :--- | :--- |
| `src/threat/anomaly.rs` | Anomaly scoring engine — consumes AlertFeature events, tracks rolling stats, outputs AnomalyScore |
| `src/threat/remediation.rs` | Response generator — maps anomaly score + ThreatCategory to RemediationPlan |
| `src/threat/advisory.rs` | Advisory formatter — generates SecurityAdvisory structs in JSON and text |

---

## 8. Files to Modify

The following existing files need small additions to wire up the new engines:

| File | Change Required |
| :--- | :--- |
| `src/threat/mod.rs` | Add `pub mod anomaly`, `pub mod remediation`, `pub mod advisory` |
| `src/threat/service.rs` | Spawn the anomaly engine loop; route advisories to audit log and API |
| `src/threat/ai_bridge.rs` | No changes needed — already provides the broadcast channel |
| `src/api/` (REST layer) | Add GET `/api/v1/advisories` endpoint to list pending advisories |

---

## 9. Key Data Structures

### AnomalyScore

```rust
pub struct AnomalyScore {
    pub score: f32,                    // 0.0 → 1.0
    pub contributing_ip: String,       // The IP driving the score highest
    pub alert_count: u32,              // Total alerts in the window
    pub window_secs: u64,              // Time window (e.g., 300s = 5 min)
    pub computed_at: DateTime<Utc>,
}
```

### RemediationPlan

```rust
pub struct RemediationPlan {
    pub plan_id: String,
    pub anomaly_score: f32,
    pub target_ip: String,
    pub actions: Vec<ActionType>,           // Ordered list of all actions
    pub auto_execute: Vec<ActionType>,      // Actions to run immediately
    pub requires_approval: Vec<ActionType>, // Actions needing admin sign-off
    pub justification: String,
}

pub enum ActionType {
    NftablesBlockIp { duration_secs: u64 },
    QuarantinePeer { peer_id: String },
    TightenAttestation { interval_secs: u64 },
    ProposePolicyUpdate { rule_delta: String },
    EnableDebugLogging { interface: String },
    AlertOnly,
}
```

### SecurityAdvisory

```rust
pub struct SecurityAdvisory {
    pub advisory_id: String,
    pub timestamp: DateTime<Utc>,
    pub title: String,
    pub severity: Severity,
    pub anomaly_score: f32,
    pub justification: String,
    pub plan: RemediationPlan,
    pub auto_actioned: bool,
    pub status: AdvisoryStatus,
}

pub enum AdvisoryStatus {
    Pending,
    Approved,
    Rejected,
    AutoExecuted,
}
```

---

## 10. Remediation Action Types

| Action | What It Does | Who Triggers It |
| :--- | :--- | :--- |
| `NftablesBlockIp` | Adds a drop rule in the `inet sgx_threat` nftables table for the source IP | Auto (score >= 0.90) or Admin |
| `QuarantinePeer` | Marks a Circle peer as untrusted; invalidates its VirtualID and triggers re-attestation | Admin approval required |
| `TightenAttestation` | Reduces the attestation check interval from default 5 min to 30 sec | Auto (score >= 0.85) |
| `ProposePolicyUpdate` | Generates a new UEP policy blob that closes vulnerable ports/protocols | Admin approval + Policy Authority signature |
| `EnableDebugLogging` | Enables verbose packet capture on the affected interface | Auto (score >= 0.75) |
| `AlertOnly` | Logs the advisory and delivers a notification; no enforcement action taken | Auto (score 0.50 – 0.74) |

---

## 11. Example Scenario (End to End)

**Scenario**: An attacker on the local network (`192.168.1.105`) launches an NMAP port scan against Guardian node `sgx-node-B`.

### What Happens — Timeline

```
T+0s    Attacker begins NMAP scan.

T+1s    Suricata fires Signature ID 2009358 "ET SCAN Nmap Scripting Engine"
        → EVE JSON written to /var/log/suricata/eve.json

T+2s    eve_tailer.rs detects new line.
        eve_parser.rs parses it → ThreatAlert { src_ip: "192.168.1.105",
        category: Reconnaissance, severity: High }

T+2s    Alert stored in AlertInventory ring buffer.
        ai_bridge::forward_to_ai() pushes AlertFeature to broadcast channel.

T+2s    anomaly.rs receives the AlertFeature.
        First alert → score: 0.10 (normal).

T+30s   847 alerts from the same source IP in 30 seconds.
        anomaly.rs recalculates:
          - IP Alert Rate:     0.40 (500x above baseline)
          - Signature Repeat:  0.35 (same SID 847 times)
          - Category Shift:    0.10 (consistent Reconnaissance)
          - Severity Spike:    0.07 (all High)
          Anomaly Score = 0.92 → CRITICAL

T+30s   remediation.rs receives score 0.92:
          - category: Reconnaissance, score >= 0.90
          - auto_execute: [NftablesBlockIp { duration_secs: 3600 }]
          - requires_approval: [ProposePolicyUpdate, TightenAttestation]

T+30s   advisory.rs generates SecurityAdvisory:
          title: "[CRITICAL] Active Port Scan Detected from 192.168.1.105"
          justification: "847 alerts in 30s (baseline: 3/min). Score: 0.92."
          options: A (Block+Quarantine), B (Block Only), C (Monitor)

T+30s   blocker.rs executes nftables block for 192.168.1.105 immediately.
        log_audit() records the full advisory to the tamper-evident audit log.
        Advisory stored in memory with status: AutoExecuted (for IP block).
        Advisory status: Pending (for policy update — awaiting admin approval).

T+35s   Administrator runs: `sgx-pa-cli advisory list`
        Sees: "[CRITICAL] Active Port Scan — Score 0.92 — 1 action pending approval"

T+40s   Administrator approves ProposePolicyUpdate.
        policy_manager.rs signs a new UEP policy.
        Guardian broadcasts the policy blob to all Circle members.
        All nodes verify signature and atomically apply nftables rules.
        VirtualIDs rotated → full re-attestation across the Circle.

Result: Attack stopped within 30 seconds. Full audit trail preserved.
        Circle-wide policy hardened without manual firewall edits.
```

---

## 12. What We Do NOT Need

To avoid confusion, here is a list of things that are **not required** for this implementation:

| What | Why Not Needed |
| :--- | :--- |
| Training a custom ML model from scratch | The statistical baseline engine is sufficient for Phase 2 |
| A GPU or dedicated AI hardware | All computation runs on the edge node CPU in-process |
| An external AI/LLM API | Advisories are generated locally from templates; no cloud calls |
| Changing the existing Suricata configuration | Suricata already writes EVE JSON; we only read it |
| Replacing `blocker.rs` or `policy_manager.rs` | The new engines call into these existing modules |
| A separate AI microservice | Everything runs inside the existing `sgx-guardian` daemon |

---

## 13. Acceptance Criteria

The feature is considered complete when all of the following pass:

- [ ] `anomaly.rs` correctly calculates an anomaly score >= 0.90 when 500+ identical-SID alerts arrive from a single IP within a 5-minute window.
- [ ] `remediation.rs` produces a `RemediationPlan` containing at least one `ActionType` for every score >= 0.50.
- [ ] `advisory.rs` generates a `SecurityAdvisory` with a non-empty `justification` string for every `RemediationPlan` it receives.
- [ ] For score >= 0.90, `blocker.rs` is called automatically without admin intervention.
- [ ] For `ProposePolicyUpdate` and `QuarantinePeer` actions, the advisory status remains `Pending` until explicit admin approval via `sgx-pa-cli`.
- [ ] Every advisory is recorded in the tamper-evident audit log via `log_audit()`.
- [ ] All existing unit tests (`cargo test`) continue to pass after the integration.
- [ ] `cargo clippy` produces zero warnings on the new modules.

---

## 14. Glossary

| Term | Meaning |
| :--- | :--- |
| **Suricata** | Open-source IDS/IPS engine embedded in SGX; inspects network packets and fires alerts |
| **EVE JSON** | Suricata's structured alert log format written to `/var/log/suricata/eve.json` |
| **ThreatAlert** | SGX's parsed representation of a single Suricata alert event |
| **AlertFeature** | A simplified, normalized version of a `ThreatAlert` pushed into the AI broadcast channel |
| **Anomaly Score** | A number from 0.0 to 1.0 indicating how abnormal the current alert pattern is |
| **RemediationPlan** | A structured list of actions to take in response to a detected anomaly |
| **SecurityAdvisory** | A human-readable + machine-readable report combining the plan, justification, and status |
| **UEP Policy** | Universal Edge Processing policy — a signed set of L3/L4 firewall rules enforced via `nftables` |
| **Circle of Trust** | The cohort of SGX nodes that share policies and mutually attest each other |
| **VirtualID** | A cryptographic session identifier for a peer node; rotated on every policy or state change |
| **mTLS** | Mutual TLS — both the client and server authenticate each other with certificates |
| **nftables** | Linux kernel-level packet filtering framework used by SGX for firewall enforcement |
| **Feature Tap** | The broadcast channel in `ai_bridge.rs` that carries `AlertFeature` events to subscribers |
| **Policy Authority** | The administrator's key used to sign UEP policy blobs before distribution |
