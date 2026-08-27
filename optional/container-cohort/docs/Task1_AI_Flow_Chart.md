# Task 1 AI Flow Diagram

```mermaid
flowchart TB
    A[1. nodeA container starts] --> B[2. ThreatService::start()]
    B --> C{3. recommendation_rules.json exists?}
    C -- No --> C1[Seed default advisory KB]
    C -- Yes --> D{4. SGX_SEED_DEMO_EVE=1?}
    C1 --> D
    D -- Yes --> D1[Write 5 demo alerts to /var/log/suricata/eve.json]
    D -- No --> E[5. EveTailer watches eve.json]
    D1 --> E
    E --> F[6. Parse JSON line into ThreatAlert]
    F --> G{7. Inserted into inventory?}
    G -- Duplicate --> G1[Ignore duplicate alert]
    G -- Updated --> G2[Update existing entry]
    G -- Inserted --> H[8. Continue threat pipeline]
    H --> I[Blocker checks allow / block]
    I --> J[Forward high / critical alerts to Task 1 feature tap]
    J --> K[task1_ai scorer updates rolling burst state]
    K --> L{9. score >= 0.50?}
    L -- No --> L1[No remediation plan yet]
    L -- Yes --> M[Generate Task 1 remediation plan]
    M --> N[Build AnomalyContext]
    N --> O[Advisory generator loads KB]
    O --> P{10. KB rule matched?}
    P -- Yes --> P1[signature-kb]
    P -- No and anomaly exists --> P2[anomaly-kb]
    P -- No and no anomaly --> P3[fallback]
    P1 --> Q[Persist recommendation to recommendations.jsonl]
    P2 --> Q
    P3 --> Q
    Q --> R[GET /api/v1/advisory/recommendations]
    Q --> S[GET /api/v1/threat/alerts/{id}/recommendation]
```

## Reading Guide

- Read the diagram top to bottom.
- The main path stays in one vertical column.
- The two decisions are `KB exists?` and `SGX_SEED_DEMO_EVE=1?`.
- The Task 1 AI branch only activates for high or critical alerts.
- `anomaly-kb` appears when the alert does not match a more specific KB rule but Task 1 anomaly context exists.

## Useful Files

- [Task1_AI_Docker_Verification_Log.md](/home/asad/SGX/optional/container-cohort/docs/Task1_AI_Docker_Verification_Log.md:1)
- [CONTAINERS.md](/home/asad/SGX/optional/container-cohort/docs/CONTAINERS.md:1)
