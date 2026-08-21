# Task 1 AI - Docker Verification Log
**Status:** READY TO RUN  
**Environment:** Docker container cohort (WSL2 / Docker Desktop)  
**Date:** 2026-08-20  
**Tester:** Asad Ali  
**Scope:** Task 1 AI anomaly detection flow, advisory KB seed, demo EVE burst seed, and persisted recommendation API checks.

---

## Task Description

> Verify the Task 1 AI flow in the laptop Docker cohort. The container startup path should seed a default advisory knowledge base when `recommendation_rules.json` is missing, seed a small demo EVE burst on `nodeA` when `SGX_SEED_DEMO_EVE=1`, let the Task 1 scorer cross threshold, and persist a recommendation with `source = "anomaly-kb"`.

This runbook does **not** require a real Suricata daemon. The container cohort uses `/var/log/suricata/eve.json` as the threat input file and auto-seeds it for the Task 1 demo flow.

---

## Docker Notes

- Saari commands host terminal se chalani hain.
- `sgx-nodeA` is the primary Task 1 verification node.
- `SGX_SEED_DEMO_EVE=1` is enabled in `optional/container-cohort/docker-compose.dev.yml` for `nodeA`.
- Fresh volumes are recommended for the first run so the automatic seed behavior is visible.
- If you reuse old volumes, remove:
  - `/var/lib/sgx-guardian/advisory/recommendation_rules.json`
  - `/var/log/suricata/eve.json`
  and restart `sgx-nodeA`.
- Advisory recommendations can be checked through:
  - `GET /api/v1/advisory/recommendations?limit=1`
  - `GET /api/v1/threat/alerts/{id}/recommendation`

---

## Verification Checklist

- [ ] Default advisory rules are auto-seeded when `recommendation_rules.json` is missing.
- [ ] Demo EVE burst is auto-seeded on `nodeA` startup.
- [ ] Task 1 anomaly scorer crosses threshold and emits a remediation plan.
- [ ] Persisted advisory recommendation returns `source = "anomaly-kb"` via API.
- [ ] No manual Suricata daemon setup is required for this Docker demo.

---

## Session Bootstrap

**Working command:**
```bash
# Host shell, repo root
set -euo pipefail

# Optional clean reset for a reproducible seed run.
docker compose -f optional/container-cohort/docker-compose.dev.yml down -v

# Build and start the 3-node container cohort.
./optional/container-cohort/up.sh
sleep 25

docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

set -a
. optional/container-cohort/dev.env
set +a

A="http://localhost:${NODEA_REST_PORT:-18443}/api/v1"
curl -s "$A/health"
```

**Expected:**
```text
sgx-nodeA   Up ...
sgx-nodeB   Up ...
sgx-nodeC   Up ...
ok
```

---

## Requirement 1 - Default advisory rules are auto-seeded

**Working command:**
```bash
docker logs --tail=150 sgx-nodeA | grep -aE "seeded default advisory rules|using built-in advisory rules"
docker exec sgx-nodeA sh -lc 'test -s /var/lib/sgx-guardian/advisory/recommendation_rules.json && echo advisory_rules_seeded'
```

**Expected:**
```text
seeded default advisory rules
advisory_rules_seeded
```

Notes:
- If the first `docker logs` command prints `using built-in advisory rules`, the seed file was not present when the service started.
- On a fresh volume run, the warning should not appear because the file is seeded before the first recommendation is generated.

---

## Requirement 2 - Demo EVE burst is auto-seeded

**Working command:**
```bash
docker exec sgx-nodeA sh -lc 'grep -c "\"event_type\":\"alert\"" /var/log/suricata/eve.json'
docker exec sgx-nodeA sh -lc 'tail -n 2 /var/log/suricata/eve.json'
docker logs --tail=150 sgx-nodeA | grep -aE "seeded demo EVE burst for Task 1 AI"
```

**Expected:**
```text
5
{"timestamp":"...","event_type":"alert",...,"alert":{"severity":1,"signature":"SGX AI anomaly burst",...}}
{"timestamp":"...","event_type":"alert",...,"alert":{"severity":1,"signature":"SGX AI anomaly burst",...}}
seeded demo EVE burst for Task 1 AI
```

Notes:
- The file should contain 5 synthetic alerts from the auto-seed helper.
- Each line should use the same signature and source IP, with unique destination IPs so the inventory does not collapse them into a duplicate.

---

## Requirement 3 - Task 1 scorer crosses threshold and generates a plan

**Working command:**
```bash
docker logs --tail=200 sgx-nodeA | grep -aE "alert sid=9100001 sev=high pushed to AI feature tap|task1 remediation plan generated"
```

**Expected:**
```text
alert sid=9100001 sev=high pushed to AI feature tap
task1 remediation plan generated
```

Notes:
- The seed burst is intentionally tuned so the 5th alert crosses the Task 1 threshold.
- The plan should be generated without any manual Suricata input.

---

## Requirement 4 - Persisted recommendation returns `anomaly-kb`

**Working command:**
```bash
curl -s "$A/advisory/recommendations?limit=1" | python3 -c 'import sys, json; rec=json.load(sys.stdin)[0]; print(rec["source"]); print(rec["title"]); print(rec["context"][0]); print(rec["context"][3])'
```

**Expected:**
```text
anomaly-kb
Security alert requires review
Signature: SGX AI anomaly burst (sid 9100001)
Anomaly score 0.51: task1-alert-scorer
```

Optional direct alert check:

**Working command:**
```bash
ALERT_ID=$(curl -s "$A/advisory/recommendations?limit=1" | python3 -c 'import sys, json; print(json.load(sys.stdin)[0]["alert_id"])')
curl -s "$A/threat/alerts/$ALERT_ID/recommendation" | python3 -c 'import sys, json; rec=json.load(sys.stdin); print(rec["source"]); print(rec["title"])'
```

**Expected:**
```text
source: anomaly-kb
title: Security alert requires review
```

---

## Requirement 5 - No manual Suricata setup is required

**Working command:**
```bash
docker exec sgx-nodeA sh -lc 'test -f /var/log/suricata/eve.json && test -f /var/lib/sgx-guardian/advisory/recommendation_rules.json && echo ready_without_manual_suricata'
```

**Expected:**
```text
ready_without_manual_suricata
```

---

## Quick Failure Guide

- If `recommendation_rules.json` is missing, restart from a fresh volume or remove the file and restart `sgx-nodeA`.
- If `eve.json` has fewer than 5 alerts, confirm `SGX_SEED_DEMO_EVE=1` is present in `docker-compose.dev.yml`.
- If the recommendation API returns an empty list, check `docker logs --tail=200 sgx-nodeA` for `seeded demo EVE burst` and `task1 remediation plan generated`.
- If the plan does not appear, confirm the demo EVE lines were written after the service started and that `sgx-nodeA` is healthy.
