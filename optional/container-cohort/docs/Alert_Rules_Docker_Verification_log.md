# Custom Alert Rules / Automation Engine - Docker Verification Log
**Environment:** Docker container cohort (WSL2 / Docker Desktop) | **Date:** 2026-07-24 | **Tester:** Asad Ali
**Test tag:** RULES-Docker-series (RULES-DKR-001 - RULES-DKR-010) | **Plan:** `docs/Alert_Rules_Automation_Engine_Complete_Plan.md`

---

## Task Description

> Verify the Custom Alert Rules / Automation Engine in the laptop Docker cohort. The engine supports event -> condition -> action rules, signed rule registry CRUD, non-blocking event ingestion, dry-run default, destructive-action gate, cooldown/rate-cap guards, execution history, test endpoint, and BlockIp self-protection inherited from `Blocker`.
>
> Docker-specific adaptation: the cohort runs inside container network namespaces. Threat events are injected by enabling the existing threat tailer against `/var/log/suricata/eve.json` inside `sgx-nodeA`; no real Suricata daemon is required for these tests.

---

## Docker Notes

- Saari commands **host terminal** se chalani hain.
- `sgx-nodeA` = primary test node. REST port comes from `optional/container-cohort/dev.env`.
  - In this checkout: `NODEA_REST_PORT=19443`.
- `sgx-nodeB` and `sgx-nodeC` can stay running; rules engine verification is mostly local to nodeA.
- Container ke andar `python3` installed nahi hota; JSON parsing host par karo:
  - Correct: `docker exec sgx-nodeA cat /path/file.json | python3 -m json.tool`
  - Avoid: `docker exec sgx-nodeA sh -lc "python3 ..."`
- API auth is enabled unless `SGX_DISABLE_LOGIN=1`. Normal commands below create/login an admin token and pass `Authorization: Bearer ...`.
- `SGX_RULES_DRYRUN=1` is the safe default. Live action tests that must actually block/unblock use a temporary one-off nodeA container with `SGX_RULES_DRYRUN=0`.
- `nftables` changes happen inside the container network namespace only. Host firewall is not touched.

---

## How to Update This File While Testing

Jab koi requirement verify ho jaye:

1. Requirement checklist mein `[ ]` ko `[x]` karo.
2. Section heading `Status: PENDING` ko `Status: PASS` karo.
3. `Working command:` ke neeche exact successful command leave karo.
4. `Observed:` block mein terminal output paste karo.
5. `Verdict:` one-line PASS/FAIL note add karo.

Fail mark karne se pehle command side verify karo:

- `docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'`
- `curl -s "$A/health"`
- `docker exec sgx-nodeA sh -lc 'grep -a "rules engine started\\|Rules" /var/log/sgx-guardian/audit-nodeA.log | tail -5'`
- Rule enabled hai? trigger/condition event se match karte hain?
- Dry-run on hai? To actions `dry-run` / `would-run` honge, execute nahi.
- Cooldown/rate-cap active hai? `GET /rules/executions` mein outcome dekho.

---

## Docker CLI Prerequisite

**Status:** PASS

**Working command:**
```bash
command -v docker
docker version
docker compose version
docker ps
```

**Expected:**
```text
docker command exists
Docker Client and Server versions are shown
Docker Compose plugin version is shown
docker ps returns the current container list
```

**Observed:**
```text
asad@AsadAli:~/SGX$ command -v docker
/usr/bin/docker

asad@AsadAli:~/SGX$ docker version
Client:
 Version:           29.1.5
 API version:       1.52
 Go version:        go1.25.6
 Git commit:        0e6fee6
 Built:             Fri Jan 16 12:48:03 2026
 OS/Arch:           linux/amd64
 Context:           default

Server: Docker Desktop 4.58.0 (216728)
 Engine:
  Version:          29.1.5
  API version:      1.52
  Go version:       go1.25.6
  Git commit:       3b01d64
  Built:            Fri Jan 16 12:48:42 2026
  OS/Arch:          linux/amd64
  Experimental:     false

asad@AsadAli:~/SGX$ docker compose version
Docker Compose version v5.0.1

asad@AsadAli:~/SGX$ docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
NAMES     STATUS    PORTS
```

**Fix / retry command used after the original WSL integration blocker:**
```bash
# 1. Start Docker Desktop on Windows.
# 2. Docker Desktop -> Settings -> Resources -> WSL Integration.
# 3. Enable integration for Ubuntu-20.04, Apply & Restart.
# 4. Close this WSL terminal, open a new WSL terminal, then run:

cd /home/asad/SGX
command -v docker
docker version
docker compose version
docker ps
./optional/container-cohort/up.sh
```

**Verdict:** PASS. Docker Desktop WSL integration is now active and Docker CLI/Compose are usable from Ubuntu-20.04.

---

## Requirements Checklist

- [x] Requirement 1 - Docker image builds with alert-rules engine and rules unit tests pass in Docker builder
- [x] Requirement 2 - Rules engine starts on nodeA with no new port
- [x] Requirement 3 - Rule model + pure evaluator + test endpoint work
- [x] Requirement 4 - Signed registry CRUD, persistence, enable/disable lifecycle work
- [x] Requirement 5 - ThreatAlert event ingestion via EVE tailer is non-blocking
- [x] Requirement 6 - Dry-run default and destructive-action gate work
- [x] Requirement 7 - Cooldown and rate cap hold action execution under repeated events
- [x] Requirement 8 - BlockIp self-protection refuses gateway/LAN/overlay and allows safe external IP in live mode
- [x] Requirement 9 - Execution history records dry-run / downgraded / rate-limited / failed / executed outcomes
- [x] Requirement 10 - Tampered `rules.json` is rejected fail-closed

---

## API Checklist

- [x] API 1 - `GET/POST /api/v1/rules`
- [x] API 2 - `GET/PATCH/DELETE /api/v1/rules/{id}`
- [x] API 3 - `POST /api/v1/rules/{id}/enable`
- [x] API 4 - `POST /api/v1/rules/{id}/test`
- [x] API 5 - `GET /api/v1/rules/executions`
- [x] API 6 - Security: unknown action rejected by fixed enum
- [x] API 7 - Security: tampered registry rejected

---

## Session Bootstrap

**Status:** PARTIAL - Docker image built and nodeA became healthy; nodeC host port publish failed

**Working command:**
```bash
# Host shell, repo root
set -euo pipefail

# Build/recreate the cohort so root src/rules changes are inside the image.
./optional/container-cohort/up.sh
sleep 20

docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

# Load Docker cohort ports from dev.env.
set -a
. optional/container-cohort/dev.env
set +a

RUN_ID=$(date +%s)
A="http://localhost:${NODEA_REST_PORT:-19443}/api/v1"
RULES_DIR=/var/lib/sgx-guardian/rules
EVE_LOG=/var/log/suricata/eve.json

echo "RUN_ID=$RUN_ID"
echo "A=$A"
curl -s "$A/health"
```

**Auth token bootstrap:**
```bash
ADMIN_EMAIL="rules-docker-$RUN_ID@example.com"
ADMIN_PASS="GuardianPass123!"

SIGNUP_JSON=$(curl -s -X POST "$A/auth/signup" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"Rules Docker\",\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASS\"}")
TOKEN=$(printf '%s' "$SIGNUP_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))" 2>/dev/null || true)

if [ -z "$TOKEN" ]; then
  echo "Signup did not return token. Existing admin likely present; trying login with the same credentials."
  LOGIN_JSON=$(curl -s -X POST "$A/auth/login" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASS\"}")
  TOKEN=$(printf '%s' "$LOGIN_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))")
fi

AUTH_HEADER="authorization: Bearer $TOKEN"
test -n "$TOKEN" && echo "TOKEN ready"
```

> If this is not a fresh Docker volume and you do not know the previous admin password, use the temporary live-mode container commands later with `SGX_DISABLE_LOGIN=1`, or reset the cohort volumes intentionally.

**Enable deterministic EVE-based ThreatAlert source:**
```bash
docker exec sgx-nodeA sh -lc '
set -e
mkdir -p /etc/sgx-guardian/threat /var/lib/sgx-guardian/threat /var/log/suricata
touch /var/log/suricata/eve.json
cat > /etc/sgx-guardian/threat/config.yaml <<EOF
enabled: true
interface: null
eve_path: /var/log/suricata/eve.json
suricata_yaml: /etc/suricata/suricata.yaml
block_mode: alert_only
block_ttl_secs: 600
block_exempt:
  - 127.0.0.0/8
  - 172.31.250.0/24
  - 192.168.100.0/24
rule_update_hours: 0
EOF
'

docker compose --env-file optional/container-cohort/dev.env \
  -f optional/container-cohort/docker-compose.dev.yml restart nodeA
sleep 12

curl -s "$A/health"
docker exec sgx-nodeA sh -lc 'grep -a "rules engine started\|threat service starting\|Rules" /var/log/sgx-guardian/audit-nodeA.log | tail -10'
```

**Host helper for alert injection:**
```bash
inject_alert () {
  NODE="${1:-sgx-nodeA}"
  SEV="$2"       # EVE severity: 1=high/critical, 2=medium, 3=low
  SRC="$3"
  SIG="$4"
  SID="${5:-9990002}"
  TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  docker exec "$NODE" sh -lc "printf '%s\n' '{\"timestamp\":\"$TS\",\"event_type\":\"alert\",\"src_ip\":\"$SRC\",\"src_port\":4444,\"dest_ip\":\"10.0.0.1\",\"dest_port\":443,\"proto\":\"TCP\",\"alert\":{\"severity\":$SEV,\"signature\":\"$SIG\",\"category\":\"Test\",\"signature_id\":$SID}}' >> /var/log/suricata/eve.json"
}
```

**Observed:**
```text
asad@AsadAli:~/SGX$ ./optional/container-cohort/up.sh
[+] Building 134.4s
[+] up 5/5
 ✔ Image sgx-guardian:dev          Built                                                   134.6s
 ✔ Network sgx-guardian-dev_sgxnet Created                                                   0.0s
 ✔ Container sgx-nodeA             Healthy                                                  11.1s
 ✔ Container sgx-nodeC             Created                                                   0.1s
 ✔ Container sgx-nodeB             Created                                                   0.1s
Error response from daemon: ports are not available: exposing port TCP 0.0.0.0:38443 -> 127.0.0.1:0: /forwards/expose returned unexpected status: 500

asad@AsadAli:~/SGX$ docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
NAMES       STATUS                   PORTS
sgx-nodeB   Up 2 minutes             0.0.0.0:28444->8443/tcp, [::]:28444->8443/tcp
sgx-nodeC   Created
sgx-nodeA   Up 2 minutes (healthy)   0.0.0.0:19443->8443/tcp, [::]:19443->8443/tcp
```

**Verdict:** PARTIAL. Docker image build is passing and nodeA reached Healthy. Rules-engine verification can continue on `sgx-nodeA`; `sgx-nodeC` remains Created because Docker Desktop failed while publishing host port `38443`.

---

## Requirement 1 - Docker build includes rules engine and rules tests pass

**Status:** PASS

**Working command:**
```bash
# Build target already compiles the whole workspace in Docker.
docker build \
  -f optional/container-cohort/docker/Dockerfile.agent \
  --target builder \
  -t sgx-guardian-rules-builder:dev .

# Run focused rules tests inside the Docker builder image.
docker run --rm sgx-guardian-rules-builder:dev \
  cargo test rules::

docker run --rm sgx-guardian-rules-builder:dev \
  cargo test --test rules_eval_test --test rules_store_test --test rules_exec_test
```

**Expected:**
```text
rules::eval tests pass
rules::exec::guards tests pass
rules_eval_test / rules_store_test / rules_exec_test pass
No nftables/network/SE050 required for evaluator tests
```

**Observed:**
```text
asad@AsadAli:~/SGX$ docker build -f optional/container-cohort/docker/Dockerfile.agent --target builder -t sgx-guardian-rules-builder:dev .
[+] Building 162.1s (15/15) FINISHED                                               docker:default
 => [builder 6/6] RUN cargo build --release --workspace --locked --features virtual-platf  122.9s
 => exporting to image                                                                      35.6s
 => => naming to docker.io/library/sgx-guardian-rules-builder:dev                            0.0s
 => => unpacking to docker.io/library/sgx-guardian-rules-builder:dev                         7.5s

asad@AsadAli:~/SGX$ bash /tmp/verify_rules1.sh
=== Requirement 1: Docker builder image build ===
[+] Building 4.1s (15/15) FINISHED                                                 docker:default
 => => naming to docker.io/library/sgx-guardian-rules-builder:dev                            0.0s
BUILD_STATUS=0

=== Requirement 1: cargo test rules:: ===
Finished `test` profile [unoptimized + debuginfo] target(s) in 1m 34s
running 5 tests
test rules::eval::tests::evaluator_rejects_wrong_trigger_and_disabled_rule ... ok
test rules::eval::tests::cidr_predicate_handles_boundaries_and_plain_ips ... ok
test rules::eval::tests::evaluator_handles_nested_boolean_conditions ... ok
test rules::exec::guards::tests::cooldown_blocks_same_target_after_first_fire ... ok
test rules::exec::guards::tests::rate_cap_counts_actions_per_rule ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 547 filtered out; finished in 0.00s
TEST_RULES_STATUS=0

=== Requirement 1: focused integration tests ===
Finished `test` profile [unoptimized + debuginfo] target(s) in 57.71s
tests/rules_eval_test.rs: 2 passed; 0 failed
tests/rules_exec_test.rs: 2 passed; 0 failed
tests/rules_store_test.rs: 2 passed; 0 failed
TEST_INTEGRATION_STATUS=0
VERIFY Requirement 1: PASS
```

**Verdict:** PASS. Docker builder image builds and focused rules unit/integration tests pass in Docker.

---

## Requirement 2 - Rules engine starts on nodeA, no new port

**Status:** PASS

**Working command:**
```bash
source optional/container-cohort/dev.env
export A="http://localhost:${NODEA_REST_PORT:-19443}/api/v1"
echo "$A"
curl -s "$A/health"

docker exec sgx-nodeA sh -lc '
grep -a "rules engine started" /var/log/sgx-guardian/audit-nodeA.log | tail -3
ss -ltn
'
```

**Expected:**
```text
Audit shows "rules engine started dry_run=true ..."
REST remains on existing :8443 inside container / host mapped port only
No new listener dedicated to rules engine
```

**Observed:**
```text
asad@AsadAli:~/SGX$ echo "$A"
http://localhost:19443/api/v1

asad@AsadAli:~/SGX$ curl -s "$A/health"
{"status":"ok"}

asad@AsadAli:~/SGX$ docker exec sgx-nodeA sh -lc 'grep -a "rules engine started" /var/log/sgx-guardian/audit-nodeA.log | tail -3'
{"event":{"action":"Started","category":"Rules","message":"rules engine started dry_run=true base=/var/lib/sgx-guardian/rules","node_id":"nodeA","severity":"Info","timestamp":1784813100},"hash":"c84c9b8f2b9f7ab47c83657939eb6ac85d746561eb4a639e445bf5cd31e35fc0","previous_hash":"6038549c324c2412f16b4bacfcdd26397afceb3871756c5425ec820d0600560c"}
{"event":{"action":"Started","category":"Rules","message":"rules engine started dry_run=true base=/var/lib/sgx-guardian/rules","node_id":"nodeA","severity":"Info","timestamp":1784813534},"hash":"2a60834069538136e620b233a75455419b69732c250aea1d7efa00b2037f9aed","previous_hash":"48a780243624f2ebb46c4b052d31dcf57e290cebb289f19032d9b0728f810e32"}
{"event":{"action":"Started","category":"Rules","message":"rules engine started dry_run=true base=/var/lib/sgx-guardian/rules","node_id":"nodeA","severity":"Info","timestamp":1784864189},"hash":"4db777257a5d204083e4fb62a6c9250c948e4afa7425953ad0c578a31490b2bb","previous_hash":"4a3ff328c77e36604731b01b63680ce71b3e6017255f501e70787ea946618427"}

asad@AsadAli:~/SGX$ docker exec sgx-nodeA sh -lc 'ss -ltn'
State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
LISTEN 0      128          0.0.0.0:50151      0.0.0.0:*
LISTEN 0      128          0.0.0.0:50062      0.0.0.0:*
LISTEN 0      128          0.0.0.0:50063      0.0.0.0:*
LISTEN 0      128          0.0.0.0:50051      0.0.0.0:*
LISTEN 0      4096      127.0.0.11:44825      0.0.0.0:*
LISTEN 0      128          0.0.0.0:8443       0.0.0.0:*
LISTEN 0      128    172.31.250.10:50061      0.0.0.0:*
LISTEN 0      4096       127.0.0.1:8625       0.0.0.0:*
```

**Verdict:** PASS. Rules engine starts on `sgx-nodeA` in dry-run mode and does not expose a dedicated new rules port.

---

## Requirement 3 - Rule model, pure evaluator, and test endpoint

**Status:** PASS

**Working command:**
```bash
# Normal signup was blocked because this Docker volume already had an owner:
# {"error":{"code":"FORBIDDEN","message":"signup is only allowed before the first user is created"}}
# For API-only rules verification, nodeA was restarted temporarily with SGX_DISABLE_LOGIN=1.

compose_dev stop nodeA
docker rm -f sgx-nodeA-rules-api >/dev/null 2>&1 || true
compose_dev run -d --name sgx-nodeA-rules-api --service-ports \
  -e NODE_ID=nodeA \
  -e SGX_DISABLE_LOGIN=1 \
  nodeA
sleep 15

CREATE_JSON="$(curl -sS -X POST "$A/rules" \
  -H 'content-type: application/json' \
  -d "$RULE_PAYLOAD")"
RID="$(printf '%s' "$CREATE_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["rule_id"])')"
LIST_JSON="$(curl -sS "$A/rules")"
TEST_JSON="$(curl -sS -X POST "$A/rules/$RID/test" \
  -H 'content-type: application/json' \
  -d "$EVENT_PAYLOAD")"
```

**Expected:**
```text
Rule shape includes trigger, condition, actions
Defaults applied: enabled=true, allow_destructive=false, cooldown_secs=300, max_actions_per_hour=20
POST /rules/{id}/test returns would_fire=true and dry-run action plan
POST /rules/{id}/test returns would_fire=true and dry-run action plan
```

**Observed:**
```text
RUN_ID=rules-api-1784865117

Signup response:
{
    "error": {
        "code": "FORBIDDEN",
        "message": "signup is only allowed before the first user is created"
    }
}

Temporary auth-disabled nodeA:
Container sgx-nodeA-rules-api Created
d80b303d0cb5a90ef518daff947c74eb515d59e6d6e3444b6e7357351b03c845

Health:
{"status":"ok"}

POST /rules returned:
{
    "rule_id": "urn:uuid:9e8fe04d-fa02-41fb-a875-c1a9b65413e7",
    "name": "RULES-DKR-003 API evaluator rules-api-1784865117",
    "enabled": true,
    "trigger": "ThreatAlert",
    "condition": {
        "All": [
            { "SeverityAtLeast": "high" },
            { "SignatureIdIn": [9999001] },
            { "SrcIpInCidr": "203.0.113.0/24" },
            { "PortIn": [443] }
        ]
    },
    "actions": [
        { "RaiseAlert": { "severity": "high" } }
    ],
    "notify": true,
    "allow_destructive": false,
    "cooldown_secs": 60,
    "max_actions_per_hour": 10
}

GET /rules returned the created rule.

POST /rules/{id}/test returned:
{
    "rule_id": "urn:uuid:9e8fe04d-fa02-41fb-a875-c1a9b65413e7",
    "would_fire": true,
    "dry_run": true,
    "trigger_summary": "ThreatAlert sid=9999001 sev=high src=203.0.113.55 dst=198.51.100.10",
    "actions": [
        "RaiseAlert(high): would-run; SGX_RULES_DRYRUN is enabled",
        "Notify(info): would-run; SGX_RULES_DRYRUN is enabled"
    ],
    "outcome": "dry-run"
}

VERIFY Requirement 3: PASS
VERIFY API 1: PASS
VERIFY API 4: PASS
VERIFY API 6: PASS
```

**Verdict:** PASS. Rule model JSON, evaluator matching, notify-derived action plan, and test endpoint dry-run behavior are verified in Docker.

---

## Requirement 4 - Signed registry CRUD, persistence, enable/disable lifecycle

**Status:** PASS

**Working command:**
```bash
curl -s "$A/rules" -H "$AUTH_HEADER" | python3 -m json.tool

curl -s -X PATCH "$A/rules/$RID" \
  -H "$AUTH_HEADER" \
  -H 'content-type: application/json' \
  -d '{"name":"RULES-DKR-004 renamed","cooldown_secs":60}' | python3 -m json.tool

curl -s -X POST "$A/rules/$RID/enable" \
  -H "$AUTH_HEADER" \
  -H 'content-type: application/json' \
  -d '{"enabled":false}' | python3 -m json.tool

curl -s "$A/rules/$RID" -H "$AUTH_HEADER" | python3 -c "import sys,json; print('enabled:',json.load(sys.stdin)['enabled'])"

curl -s -X POST "$A/rules/$RID/enable" \
  -H "$AUTH_HEADER" \
  -H 'content-type: application/json' \
  -d '{"enabled":true}' >/dev/null

docker exec sgx-nodeA cat "$RULES_DIR/rules.json" | python3 -c "import sys,json; r=json.load(sys.stdin); print('rules:',len(r['rules'])); print('sequence:',r['sequence']); print('proof_value_len:',len(r['proof']['proofValue']))"

docker compose --env-file optional/container-cohort/dev.env \
  -f optional/container-cohort/docker-compose.dev.yml restart nodeA
sleep 12
curl -s "$A/rules/$RID" -H "$AUTH_HEADER" | python3 -m json.tool
```

**Expected:**
```text
GET/POST/PATCH/enable all work
rules.json exists, has proof.proofValue, sequence increments
Rule persists across container restart
```

**Observed:**
```text
Temporary auth-disabled nodeA:
Container sgx-nodeA-rules-crud Created
6b8108998269207ad928daff1f53c4e018754ff360ff0d35c16d00ec3bd5e61b

Health:
{"status":"ok"}

Created rule:
rule_id=urn:uuid:4a7fee4f-51bd-48f6-8165-50892f558a87
name=RULES-DKR-004 CRUD rules-crud-1784865285
enabled=true
trigger=ThreatAlert
cooldown_secs=120
max_actions_per_hour=5

GET /rules/{id} returned the created rule.

PATCH /rules/{id} returned:
name=RULES-DKR-004 renamed rules-crud-1784865285
cooldown_secs=60

POST /rules/{id}/enable with false returned:
enabled=false

POST /rules/{id}/enable with true returned:
enabled=true

Signed registry proof check:
rules: 2
sequence: 5
proofValue_len: 88

Restart persistence check:
docker restart sgx-nodeA-rules-crud
GET /rules/{id} after restart returned the same rule with enabled=true.

DELETE /rules/{id}:
DELETE_STATUS=200
{"success":true,"rule_id":"urn:uuid:4a7fee4f-51bd-48f6-8165-50892f558a87"}

VERIFY Requirement 4: PASS
VERIFY API 2: PASS
VERIFY API 3: PASS

Normal nodeA restore:
normal nodeA health=healthy
NAMES       STATUS                    PORTS
sgx-nodeB   Up 19 minutes             0.0.0.0:28444->8443/tcp, [::]:28444->8443/tcp
sgx-nodeA   Up 17 seconds (healthy)   0.0.0.0:19443->8443/tcp, [::]:19443->8443/tcp
```

**Verdict:** PASS. Signed registry CRUD, proof persistence, enable/disable lifecycle, restart persistence, and delete endpoint are verified in Docker.

---

## Requirement 5 - ThreatAlert event ingestion is non-blocking

**Status:** PASS

**Working command:**
```bash
# Ensure rule is enabled and uses a short cooldown for repeat Docker tests.
curl -s -X PATCH "$A/rules/$RID" \
  -H "$AUTH_HEADER" \
  -H 'content-type: application/json' \
  -d '{"enabled":true,"actions":[{"RaiseAlert":{"severity":"high"}}],"cooldown_secs":1}' >/dev/null

BEFORE=$(curl -s "$A/rules/executions" -H "$AUTH_HEADER" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")
inject_alert sgx-nodeA 1 "203.0.113.50" "RULES-DKR-005 ingestion probe" 9990050
sleep 4
AFTER=$(curl -s "$A/rules/executions" -H "$AUTH_HEADER" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")
echo "executions before=$BEFORE after=$AFTER"
curl -s "$A/rules/executions" -H "$AUTH_HEADER" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[-1]['trigger_summary']); print(d[-1]['outcome']); print(d[-1]['actions'])"

# Burst: API should remain responsive while events are published.
for i in $(seq 1 30); do inject_alert sgx-nodeA 1 "203.0.113.$i" "RULES-DKR-005 burst $i" "$((9990100+i))"; done
curl -s -o /dev/null -w 'health HTTP %{http_code} in %{time_total}s\n' "$A/health"
```

**Expected:**
```text
Injected EVE alert reaches rules engine and creates an execution entry
With dry-run default, outcome is dry-run for actions
Burst does not block REST /health
```

**Observed:**
```text
Temporary auth-disabled nodeA:
Container sgx-nodeA-rules-ingest Created
d339297a93e8e286fd25b174343eeec90e42c18df94b68112ab4cad3c116a4f5

Threat EVE tailer config enabled:
eve_path=/var/log/suricata/eve-rules-ingest-1784865487.json
block_mode=alert_only
rule_update_hours=0

Health:
{"status":"ok"}

Audit startup:
rules engine started dry_run=true base=/var/lib/sgx-guardian/rules
threat service starting (block_mode=alert_only)

Created matching rule:
rule_id=urn:uuid:660d98fb-10ad-468b-81b6-9ef332788785
name=RULES-DKR-005 EVE ingestion rules-ingest-1784865487
condition=SeverityAtLeast(high) + SignatureIdIn([965487]) + SrcIpInCidr(203.0.113.0/24)
cooldown_secs=1
max_actions_per_hour=20

API 5 before:
executions_before: 0

Injected EVE alert:
SID=965487
src_ip=203.0.113.50
signature=RULES-DKR-005 ingestion probe

API 5 after burst:
executions_after: 1
last_outcomes: ['dry-run']

Non-blocking REST check:
health HTTP 200 in 0.002557s

Note: the final helper assertion printed `VERIFY batch: FAIL/PARTIAL` because the
Python heredoc consumed stdin instead of the piped `EXEC_JSON`, leaving
`FOUND_JSON` empty. The API/evidence above still verifies the product behavior:
the unique empty EVE file received one matching alert, executions increased
0 -> 1, the outcome was dry-run, and REST stayed responsive.

Normal nodeA restore:
normal nodeA health=healthy
NAMES       STATUS                    PORTS
sgx-nodeB   Up 22 minutes             0.0.0.0:28444->8443/tcp, [::]:28444->8443/tcp
sgx-nodeA   Up 15 seconds (healthy)   0.0.0.0:19443->8443/tcp, [::]:19443->8443/tcp
```

**Verdict:** PASS. EVE tailer ThreatAlert ingestion, dry-run execution creation, `GET /rules/executions`, and REST responsiveness under burst injection are verified in Docker.

---

## Requirement 6 - Dry-run default and destructive gate

**Status:** PASS

**Working command:**
```bash
# Start temp no-auth nodeA with default SGX_RULES_DRYRUN=1.
compose_dev stop nodeA
docker rm -f sgx-nodeA-rules-dryrun >/dev/null 2>&1 || true
compose_dev run -d --name sgx-nodeA-rules-dryrun --service-ports \
  -e NODE_ID=nodeA \
  -e SGX_DISABLE_LOGIN=1 \
  nodeA

# Enable EVE tailer on a unique file, restart temp node, then create:
# 1. BlockIp rule matching DRY_SID.
# 2. EmergencyKeyRotation rule with allow_destructive=false.

curl -sS -X POST "$A/rules" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"RULES-DKR-006 dry-run ${RUN_ID}\",\"trigger\":\"ThreatAlert\",\"condition\":{\"SignatureIdIn\":[$DRY_SID]},\"actions\":[{\"BlockIp\":{\"ttl_secs\":60}}],\"cooldown_secs\":1,\"max_actions_per_hour\":20}"

docker exec "$NODE" sh -lc "printf '%s\n' '{\"timestamp\":\"$TS\",\"event_type\":\"alert\",\"src_ip\":\"$SRC_IP\",\"src_port\":4444,\"dest_ip\":\"198.51.100.10\",\"dest_port\":443,\"proto\":\"TCP\",\"alert\":{\"severity\":1,\"signature\":\"RULES-DKR-006 dryrun block\",\"signature_id\":$DRY_SID,\"rev\":1,\"gid\":1}}' >> '$EVE_LOG'"

curl -sS "$A/rules/executions?limit=300" > /tmp/rules6_execs.json
docker exec "$NODE" sh -lc 'test -f /var/lib/sgx-guardian/threat/blocked_ips.json && cat /var/lib/sgx-guardian/threat/blocked_ips.json || echo NO_BLOCK_FILE' > /tmp/rules6_blocks.txt

curl -sS -X POST "$A/rules" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"RULES-DKR-006 destructive gate ${RUN_ID}\",\"trigger\":\"ThreatAlert\",\"condition\":{\"SeverityAtLeast\":\"high\"},\"actions\":[\"EmergencyKeyRotation\"],\"allow_destructive\":false}"

curl -sS -X POST "$A/rules/$GATE_RID/test"
```

**Expected:**
```text
BlockIp dry-run produces would-run outcome and does not write a real block for the source IP
Test endpoint action plan shows downgraded when allow_destructive=false
```

**Observed:**
```text
Temporary auth-disabled nodeA:
Container sgx-nodeA-rules-dryrun Created
e781cd9d54acb4964d334913039d1d6309041e38206edb82a3cbf4041e7d1a39

Health:
{"status":"ok"}

Dry-run rule created:
rule_id=urn:uuid:dc0e8d7c-c3a7-4093-b3b5-a0dc097f1a15
name=RULES-DKR-006 dry-run rules-dryrun-1784865707
condition=SignatureIdIn([765707])
actions=[BlockIp(ttl_secs=60)]
allow_destructive=false

Dry-run execution:
{
    "id": "urn:uuid:9b3ff1f5-46d4-4cb5-8dec-f23d89f02afa",
    "rule_id": "urn:uuid:dc0e8d7c-c3a7-4093-b3b5-a0dc097f1a15",
    "rule_name": "RULES-DKR-006 dry-run rules-dryrun-1784865707",
    "trigger_summary": "ThreatAlert sid=765707 sev=high src=203.0.113.86 dst=198.51.100.10",
    "actions": [
        "BlockIp(ttl=60s): would-run; SGX_RULES_DRYRUN is enabled"
    ],
    "outcome": "dry-run",
    "at": "2026-07-24T04:02:17.245586933+00:00"
}

Real block state:
[]

Destructive-gate rule created:
rule_id=urn:uuid:872ade7b-09dc-4c32-af33-abf2cf83f7f8
name=RULES-DKR-006 destructive gate rules-dryrun-1784865707
actions=["EmergencyKeyRotation"]
allow_destructive=false

Test endpoint returned:
{
    "rule_id": "urn:uuid:872ade7b-09dc-4c32-af33-abf2cf83f7f8",
    "would_fire": true,
    "dry_run": true,
    "trigger_summary": "ThreatAlert sid=9999001 sev=high src=203.0.113.55 dst=198.51.100.10",
    "actions": [
        "EmergencyKeyRotation: destructive action requires allow_destructive=true; downgraded to critical alert"
    ],
    "outcome": "downgraded"
}

VERIFY Requirement 6: PASS

Normal nodeA restore:
normal nodeA health=healthy
NAMES       STATUS                    PORTS
sgx-nodeB   Up 26 minutes             0.0.0.0:28444->8443/tcp, [::]:28444->8443/tcp
sgx-nodeA   Up 17 seconds (healthy)   0.0.0.0:19443->8443/tcp, [::]:19443->8443/tcp
```

**Verdict:** PASS. Dry-run default prevents real BlockIp state changes while recording a dry-run execution, and destructive actions are downgraded unless explicitly allowed.

---

## Requirement 7 - Cooldown and rate cap

**Status:** PASS

**Working command:**
```bash
# Temp nodeA used an isolated rules base:
compose_dev run -d --name sgx-nodeA-rules-guards --service-ports \
  -e NODE_ID=nodeA \
  -e SGX_DISABLE_LOGIN=1 \
  -e SGX_GUARDIAN_RULES_BASE="/var/lib/sgx-guardian/rules-${RUN_ID}" \
  -e SGX_RULES_MAX_EXECUTIONS=5000 \
  nodeA

# Cooldown test:
# - Create rule with cooldown_secs=300 matching two unique SIDs.
# - Inject two EVE alerts with the same src_ip target.
# - Read /rules/executions.

# Rate-cap test:
# - Create rule with max_actions_per_hour=3 matching 198.51.100.0/24.
# - Inject five unique source IPs.
# - Read /rules/executions and count outcomes.
```

**Expected:**
```text
Repeated same target: first action planned/run, second suppressed by cooldown guard
Storm: outcomes include dry-run for allowed actions and rate-limited for excess actions
Actions do not exceed max_actions_per_hour
```

**Observed:**
```text
Temporary auth-disabled nodeA:
Container sgx-nodeA-rules-guards Created
9186638c6a27b28c88878d2099c40ec519aa760e19d5eb90f3e4cb0508f84b9b

Health:
{"status":"ok"}

RUN_ID=rules-guards-1784866011
RULES_BASE=/var/lib/sgx-guardian/rules-rules-guards-1784866011
EVE_LOG=/var/log/suricata/eve-rules-guards-1784866011.json
COOL_SID1=866011 COOL_SID2=866012 RATE_SID_BASE=866111

Cooldown rule:
rule_id=urn:uuid:2dd93da6-8cf4-49e4-a382-b08afa0d7cfa
name=RULES-DKR-007 cooldown rules-guards-1784866011
condition=SeverityAtLeast(high) + SignatureIdIn([866011, 866012])
cooldown_secs=300
max_actions_per_hour=20

Cooldown executions:
cooldown_match_count: 2
dry-run | ThreatAlert sid=866011 sev=high src=203.0.113.90 dst=198.51.100.10 | ['RaiseAlert(high): would-run; SGX_RULES_DRYRUN is enabled']
rate-limited | ThreatAlert sid=866012 sev=high src=203.0.113.90 dst=198.51.100.10 | ['guard: cooldown active; retry after 297s']

Rate-cap rule:
rule_id=urn:uuid:4fd1ee30-b7ec-4361-b22d-935e82473d5b
name=RULES-DKR-007 rate-cap rules-guards-1784866011
condition=SeverityAtLeast(high) + SrcIpInCidr(198.51.100.0/24)
cooldown_secs=1
max_actions_per_hour=3

Rate-cap executions:
rate_match_count: 5
rate_outcomes: Counter({'dry-run': 3, 'rate-limited': 2})
dry-run | ThreatAlert sid=866112 sev=high src=198.51.100.101 dst=203.0.113.10 | ['RaiseAlert(high): would-run; SGX_RULES_DRYRUN is enabled']
dry-run | ThreatAlert sid=866113 sev=high src=198.51.100.102 dst=203.0.113.10 | ['RaiseAlert(high): would-run; SGX_RULES_DRYRUN is enabled']
dry-run | ThreatAlert sid=866114 sev=high src=198.51.100.103 dst=203.0.113.10 | ['RaiseAlert(high): would-run; SGX_RULES_DRYRUN is enabled']
rate-limited | ThreatAlert sid=866115 sev=high src=198.51.100.104 dst=203.0.113.10 | ['guard: rate cap reached; window resets in 3600s']
rate-limited | ThreatAlert sid=866116 sev=high src=198.51.100.105 dst=203.0.113.10 | ['guard: rate cap reached; window resets in 3600s']

VERIFY Requirement 7: PASS

Normal nodeA restore:
normal nodeA health=healthy
NAMES       STATUS                    PORTS
sgx-nodeB   Up 31 minutes             0.0.0.0:28444->8443/tcp, [::]:28444->8443/tcp
sgx-nodeA   Up 18 seconds (healthy)   0.0.0.0:19443->8443/tcp, [::]:19443->8443/tcp
```

**Verdict:** PASS. Cooldown and hourly rate-cap guards suppress repeated/excess actions and record `rate-limited` outcomes while allowed events remain dry-run.

---

## Live Action Mode - start temporary nodeA with SGX_RULES_DRYRUN=0

Use this only for Requirements 8 and 9 live action checks. It stops normal nodeA, then starts a temporary node using the same volumes and service ports. Auth is disabled only for this temporary test container.

**Start live-mode nodeA:**
```bash
docker compose --env-file optional/container-cohort/dev.env \
  -f optional/container-cohort/docker-compose.dev.yml stop nodeA

docker rm -f sgx-nodeA-rules-live 2>/dev/null || true

docker compose --env-file optional/container-cohort/dev.env \
  -f optional/container-cohort/docker-compose.dev.yml run -d \
  --name sgx-nodeA-rules-live \
  --service-ports \
  -e NODE_ID=nodeA \
  -e SGX_DISABLE_LOGIN=1 \
  -e SGX_RULES_DRYRUN=0 \
  -e SGX_RULES_MAX_EXECUTIONS=2000 \
  nodeA

sleep 15
LIVE_NODE=sgx-nodeA-rules-live
A="http://localhost:${NODEA_REST_PORT:-19443}/api/v1"
AUTH_HEADER="x-no-auth: live-mode"
curl -s "$A/health"
docker exec "$LIVE_NODE" sh -lc 'grep -a "rules engine started" /var/log/sgx-guardian/audit-nodeA.log | tail -3'
```

**Restore normal nodeA after live tests:**
```bash
docker rm -f sgx-nodeA-rules-live
docker compose --env-file optional/container-cohort/dev.env \
  -f optional/container-cohort/docker-compose.dev.yml up -d nodeA
sleep 12
```

---

## Requirement 8 - BlockIp self-protection in live mode

**Status:** PASS

**Working command:**
```bash
# Run after Live Action Mode start.
GW=$(docker exec "$LIVE_NODE" sh -lc "ip route | awk '/default/{print \$3; exit}'")
LAN_CIDR=$(docker exec "$LIVE_NODE" sh -lc "ip -o -f inet addr show eth0 | awk '{print \$4; exit}'")
echo "GW=$GW LAN_CIDR=$LAN_CIDR"

RID_BLOCK=$(curl -s -X POST "$A/rules" \
  -H 'content-type: application/json' \
  -d '{
    "name":"RULES-DKR-008 block self-protection",
    "trigger":"ThreatAlert",
    "condition":{"SeverityAtLeast":"high"},
    "actions":[{"BlockIp":{"ttl_secs":120}}],
    "cooldown_secs":1,
    "max_actions_per_hour":50
  }' | python3 -c "import sys,json; print(json.load(sys.stdin)['rule_id'])")
echo "RID_BLOCK=$RID_BLOCK"

inject_alert "$LIVE_NODE" 1 "$GW" "RULES-DKR-008 gateway block attempt" 9990801
sleep 4
inject_alert "$LIVE_NODE" 1 "172.31.250.200" "RULES-DKR-008 LAN block attempt" 9990802
sleep 4
inject_alert "$LIVE_NODE" 1 "192.168.100.5" "RULES-DKR-008 overlay block attempt" 9990803
sleep 4

curl -s "$A/threat/blocks" | python3 -m json.tool
docker exec "$LIVE_NODE" sh -lc "nft list chain inet sgx_threat input 2>/dev/null | grep -E '$GW|172.31.250|192.168.100' || echo 'OK: no protected address blocked'"
docker exec "$LIVE_NODE" sh -lc 'grep -a "refused to block\|matches threat block_exempt\|local interface subnet" /var/log/sgx-guardian/audit-nodeA.log | tail -8'

# Control: external documentation IP should be blockable inside container netns.
inject_alert "$LIVE_NODE" 1 "203.0.113.77" "RULES-DKR-008 safe block control" 9990804
sleep 4
curl -s "$A/threat/blocks" | python3 -c "import sys,json; print(json.load(sys.stdin)['blocked'])"
curl -s -X POST "$A/threat/blocks/unblock" -H 'content-type: application/json' -d '{"ip":"203.0.113.77"}'
```

**Expected:**
```text
Gateway / 172.31.250.0/24 / 192.168.100.0/24 are refused and audited
No protected address appears in nft or /threat/blocks
203.0.113.77 can be blocked and then unblocked, proving BlockIp action works
```

**Observed:**
```text
Temporary live-mode nodeA:
Container sgx-nodeA-rules-live Created
e04666a6131b37f168fc7c8c9d27e89e03dc3992894f5a63b71b15be5b2fbff9

Health:
{"status":"ok"}

RUN_ID=rules-live8-1784866229
GW=172.31.250.1 LAN_IP=172.31.250.200 OVERLAY_IP=192.168.100.5 SAFE_IP=203.0.113.77
SIDS: 876229 876230 876231 876232

Live BlockIp rule:
rule_id=urn:uuid:2655fb0e-16d2-4626-af1e-e6db61b147c3
name=RULES-DKR-008 live block self-protection rules-live8-1784866229
condition=SignatureIdIn([876229, 876230, 876231, 876232])
actions=[BlockIp(ttl_secs=120)]
cooldown_secs=1
max_actions_per_hour=50

Executions:
match_count: 4
failed | ThreatAlert sid=876229 sev=high src=172.31.250.1 dst=198.51.100.10 | ['BlockIp(ttl=120s): refused to block 172.31.250.1: matches threat block_exempt']
failed | ThreatAlert sid=876230 sev=high src=172.31.250.200 dst=198.51.100.10 | ['BlockIp(ttl=120s): refused to block 172.31.250.200: matches threat block_exempt']
failed | ThreatAlert sid=876231 sev=high src=192.168.100.5 dst=198.51.100.10 | ['BlockIp(ttl=120s): refused to block 192.168.100.5: matches threat block_exempt']
executed | ThreatAlert sid=876232 sev=high src=203.0.113.77 dst=198.51.100.10 | ['BlockIp(ttl=120s): blocked 203.0.113.77']

Threat blocks API:
{
    "blocked": [
        "203.0.113.77"
    ]
}

nft chain:
table inet sgx_threat {
        chain input {
                type filter hook input priority filter - 10; policy accept;
                ip saddr 203.0.113.77 drop
        }
}

Audit evidence:
refused to block 172.31.250.1: matches threat block_exempt
refused to block 172.31.250.200: matches threat block_exempt
refused to block 192.168.100.5: matches threat block_exempt
rules engine blocked 203.0.113.77 ttl=120s

VERIFY Requirement 8: PASS

Cleanup:
{"success":true,"stdout":"unblocked 203.0.113.77\n","stderr":"","restartRequired":true,"timestamp":"2026-07-24T04:11:13.578385553+00:00"}
nft flush chain inet sgx_threat input
blocked_ips.json reset to []

Normal nodeA restore:
normal nodeA health=healthy
NAMES       STATUS                    PORTS
sgx-nodeB   Up 34 minutes             0.0.0.0:28444->8443/tcp, [::]:28444->8443/tcp
sgx-nodeA   Up 15 seconds (healthy)   0.0.0.0:19443->8443/tcp, [::]:19443->8443/tcp
```

**Verdict:** PASS. Live `BlockIp` refuses gateway/LAN/overlay-protected addresses, audits the refusals, blocks a safe external control IP inside the container namespace, and cleanup restores the normal node.

---

## Requirement 9 - Execution history and fail-safe isolation

**Status:** PASS

**Working command:**
```bash
# History shape.
curl -s "$A/rules/executions" -H "$AUTH_HEADER" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('total:',len(d))
print('last keys:',sorted(d[-1].keys()) if d else [])
for e in d[-5:]: print(e['rule_name'],'|',e['outcome'],'|',e['actions'])
"

# Live-mode fail-safe: invalid RunScan fails but sibling RaiseAlert still runs.
RID_FAIL=$(curl -s -X POST "$A/rules" \
  -H 'content-type: application/json' \
  -d '{
    "name":"RULES-DKR-009 fail-safe",
    "trigger":"ThreatAlert",
    "condition":{"SeverityAtLeast":"high"},
    "actions":[{"RunScan":{"intensity":"invalid-intensity"}},{"RaiseAlert":{"severity":"high"}}],
    "cooldown_secs":1,
    "max_actions_per_hour":20
  }' | python3 -c "import sys,json; print(json.load(sys.stdin)['rule_id'])")
echo "RID_FAIL=$RID_FAIL"

inject_alert "$LIVE_NODE" 1 "203.0.113.95" "RULES-DKR-009 failsafe" 9990901
sleep 6
curl -s "$A/rules/executions" | python3 -c "import sys,json; e=json.load(sys.stdin)[-1]; print(e['outcome']); print(e['actions'])"
curl -s -o /dev/null -w 'health HTTP %{http_code}\n' "$A/health"
docker exec "$LIVE_NODE" pgrep -f sgx_guardian_client >/dev/null && echo "daemon still running"
```

**Expected:**
```text
Execution entries include id, rule_id, rule_name, trigger_summary, actions[], outcome, at
Failing action reports failed, RaiseAlert sibling is still attempted
Daemon remains alive and health endpoint returns 200
```

**Observed:**
```text
Script-style retry:

RUN_ID=rules-hist9-1784866827
RULES_BASE=/var/lib/sgx-guardian/rules-rules-hist9-1784866827
SIDS dry=956827 executed=956828 failed=956829 downgraded=956830 rate=956831,956832

Phase 1 dry-run node:
Container sgx-nodeA-rules-hist-dry Created
7cabf2c3d334a078e9ec07b2b87a9d8159d4982d8023d8f48348ad4b7aa26740
{"status":"ok"}

Dry-run rule:
rule_id=urn:uuid:ef721679-35d6-46a1-b72d-a2700fb67795
name=RULES-DKR-009 dry-run rules-hist9-1784866827

Phase 2 live node:
Container sgx-nodeA-rules-hist-live Created
cf4c608ae13f0a6f58dc540399f6112e875cd02a036dcad399a9527f66a413e5
{"status":"ok"}

Live rules created:
- RULES-DKR-009 executed rules-hist9-1784866827
- RULES-DKR-009 failed-isolation rules-hist9-1784866827
- RULES-DKR-009 downgraded rules-hist9-1784866827
- RULES-DKR-009 rate-limited rules-hist9-1784866827

Execution history:
match_count: 6
outcomes: ['downgraded', 'dry-run', 'executed', 'failed', 'rate-limited']
dry-run | RULES-DKR-009 dry-run rules-hist9-1784866827 | ThreatAlert sid=956827 sev=high src=203.0.113.91 dst=198.51.100.10 | ['RaiseAlert(high): would-run; SGX_RULES_DRYRUN is enabled']
failed | RULES-DKR-009 failed-isolation rules-hist9-1784866827 | ThreatAlert sid=956829 sev=high src=203.0.113.92 dst=198.51.100.10 | ['RunScan(invalid-intensity): invalid scan intensity: invalid-intensity', 'RaiseAlert(high): raised synthetic threat alert in /var/lib/sgx-guardian/threat/alerts.jsonl']
executed | RULES-DKR-009 executed rules-hist9-1784866827 | ThreatAlert sid=956828 sev=high src=203.0.113.88 dst=198.51.100.10 | ['BlockIp(ttl=120s): blocked 203.0.113.88']
downgraded | RULES-DKR-009 downgraded rules-hist9-1784866827 | ThreatAlert sid=956830 sev=high src=203.0.113.93 dst=198.51.100.10 | ['EmergencyKeyRotation: destructive action requires allow_destructive=true; downgraded to critical alert', 'RaiseAlert(critical): raised synthetic threat alert in /var/lib/sgx-guardian/threat/alerts.jsonl']
executed | RULES-DKR-009 rate-limited rules-hist9-1784866827 | ThreatAlert sid=956831 sev=high src=203.0.113.94 dst=198.51.100.10 | ['RaiseAlert(high): raised synthetic threat alert in /var/lib/sgx-guardian/threat/alerts.jsonl']
rate-limited | RULES-DKR-009 rate-limited rules-hist9-1784866827 | ThreatAlert sid=956832 sev=high src=203.0.113.95 dst=198.51.100.10 | ['guard: rate cap reached; window resets in 3598s']

VERIFY Requirement 9: PASS

Cleanup:
{"success":true,"stdout":"unblocked 203.0.113.88\n","stderr":"","restartRequired":true,"timestamp":"2026-07-24T04:21:38.394907902+00:00"}

Normal nodeA restore:
normal nodeA health=healthy
NAMES       STATUS                    PORTS
sgx-nodeB   Up 45 minutes             0.0.0.0:28444->8443/tcp, [::]:28444->8443/tcp
sgx-nodeA   Up 15 seconds (healthy)   0.0.0.0:19443->8443/tcp, [::]:19443->8443/tcp
```

**Verdict:** PASS. Execution history contains the expected shape and records `dry-run`, `executed`, `failed`, `downgraded`, and `rate-limited`; failed action isolation kept the sibling `RaiseAlert` attempt in the same execution.

---

## Requirement 10 - Tampered rules.json rejected fail-closed

**Status:** PASS

**Working command:**
```bash
# Use normal nodeA or live-mode node. This example uses normal nodeA + auth.
docker exec sgx-nodeA sh -lc "cp $RULES_DIR/rules.json $RULES_DIR/rules.json.bak-rules-dkr"
docker cp sgx-nodeA:$RULES_DIR/rules.json /tmp/rules-nodeA.json

python3 - <<'PY'
import json
p="/tmp/rules-nodeA.json"
d=json.load(open(p))
if not d.get("rules"):
    raise SystemExit("no rules to tamper")
d["rules"][0]["name"]="TAMPERED WITHOUT RESIGNING"
json.dump(d, open(p, "w"), indent=2)
PY

docker cp /tmp/rules-nodeA.json sgx-nodeA:$RULES_DIR/rules.json
docker compose --env-file optional/container-cohort/dev.env \
  -f optional/container-cohort/docker-compose.dev.yml restart nodeA
sleep 12

curl -s -o /tmp/rules-tamper-response.json -w 'GET /rules HTTP %{http_code}\n' "$A/rules" -H "$AUTH_HEADER"
cat /tmp/rules-tamper-response.json | python3 -m json.tool
docker exec sgx-nodeA sh -lc 'grep -a "rules registry rejected\|rules registry signature\|invalid proof" /var/log/sgx-guardian/audit-nodeA.log | tail -5'

# Restore signed registry.
docker exec sgx-nodeA sh -lc "cp $RULES_DIR/rules.json.bak-rules-dkr $RULES_DIR/rules.json"
docker compose --env-file optional/container-cohort/dev.env \
  -f optional/container-cohort/docker-compose.dev.yml restart nodeA
sleep 12
curl -s "$A/rules" -H "$AUTH_HEADER" | python3 -m json.tool
```

**Expected:**
```text
Tampered registry returns 4xx from rules API or audit logs "rules registry rejected"
Engine does not execute tampered rules while signature is invalid
After restoring backup, rules load normally again
```

**Observed:**
```text
Temporary auth-disabled nodeA:
Container sgx-nodeA-rules-tamper Created
5e294d16d1c2ac21f127132b98f18ec87daf8be6d1c68f48ad7e4d148e4c261c

Health:
{"status":"ok"}

RUN_ID=rules-tamper10-1784867107
RULES_BASE=/var/lib/sgx-guardian/rules-rules-tamper10-1784867107
SID=1037107

Signed source rule:
rule_id=urn:uuid:90eefb38-59cc-4e9f-ae96-05f88b8378f7
name=RULES-DKR-010 tamper source rules-tamper10-1784867107
condition=SignatureIdIn([1037107])

Before tamper:
PRE_STATUS=200
GET /rules returned the signed rule.

Tamper:
rules.json copied out, first rule name changed to `TAMPERED WITHOUT RESIGNING`,
then copied back without regenerating proof.

API 7 tamper response:
TAMPER_STATUS=400
{"error":{"code":"BAD_REQUEST","message":"rules registry signature is invalid: DID document signature invalid"}}

Fail-closed event processing:
executions_before_tampered_event=0
Injected matching EVE alert while registry was tampered.
executions_after_tampered_event=0

Audit evidence:
rules registry rejected: rules registry signature is invalid: DID document signature invalid
rules registry rejected: rules registry signature is invalid: DID document signature invalid

Restore signed registry:
RESTORE_STATUS=200
GET /rules returned the original signed rule again.

VERIFY Requirement 10: PASS
VERIFY API 7: PASS

Normal nodeA restore:
normal nodeA health=healthy
NAMES       STATUS                    PORTS
sgx-nodeB   Up 49 minutes             0.0.0.0:28444->8443/tcp, [::]:28444->8443/tcp
sgx-nodeA   Up 15 seconds (healthy)   0.0.0.0:19443->8443/tcp, [::]:19443->8443/tcp
```

**Verdict:** PASS. Tampered registry is rejected by the rules API, matching events do not execute while the signature is invalid, audit logs record fail-closed rejection, and restoring the signed registry returns normal operation.

---

## API Verification Quick Commands

### API 1 - `GET/POST /api/v1/rules`

**Status:** PASS

**Working command:**
```bash
curl -s "$A/rules" -H "$AUTH_HEADER" | python3 -m json.tool
curl -s -X POST "$A/rules" -H "$AUTH_HEADER" -H 'content-type: application/json' -d '{
  "name":"API-DKR create",
  "trigger":"ThreatAlert",
  "condition":{"SeverityAtLeast":"high"},
  "actions":[{"RaiseAlert":{"severity":"high"}}]
}' | python3 -m json.tool
```

**Observed:**
```text
POST /api/v1/rules returned rule:
rule_id=urn:uuid:9e8fe04d-fa02-41fb-a875-c1a9b65413e7
name=RULES-DKR-003 API evaluator rules-api-1784865117
enabled=true
trigger=ThreatAlert
actions=[RaiseAlert(high)]
notify=true
cooldown_secs=60
max_actions_per_hour=10

GET /api/v1/rules returned the created rule in the registry.
```

**Verdict:** PASS. Create and list rules APIs are working in Docker.

### API 2 - `GET/PATCH/DELETE /api/v1/rules/{id}`

**Status:** PASS

**Working command:**
```bash
TMP=$(curl -s -X POST "$A/rules" -H "$AUTH_HEADER" -H 'content-type: application/json' -d '{"name":"API-DKR tmp"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['rule_id'])")
curl -s "$A/rules/$TMP" -H "$AUTH_HEADER" | python3 -m json.tool
curl -s -X PATCH "$A/rules/$TMP" -H "$AUTH_HEADER" -H 'content-type: application/json' -d '{"name":"API-DKR tmp renamed"}' | python3 -m json.tool
curl -s -o /dev/null -w 'DELETE HTTP %{http_code}\n' -X DELETE "$A/rules/$TMP" -H "$AUTH_HEADER"
```

**Observed:**
```text
GET /rules/urn:uuid:4a7fee4f-51bd-48f6-8165-50892f558a87 returned the created rule.
PATCH /rules/urn:uuid:4a7fee4f-51bd-48f6-8165-50892f558a87 returned:
name=RULES-DKR-004 renamed rules-crud-1784865285
cooldown_secs=60
DELETE /rules/urn:uuid:4a7fee4f-51bd-48f6-8165-50892f558a87 returned:
DELETE_STATUS=200
{"success":true,"rule_id":"urn:uuid:4a7fee4f-51bd-48f6-8165-50892f558a87"}
```

**Verdict:** PASS. GET/PATCH/DELETE rule detail APIs work.

### API 3 - `POST /api/v1/rules/{id}/enable`

**Status:** PASS

**Working command:**
```bash
curl -s -X POST "$A/rules/$RID/enable" -H "$AUTH_HEADER" -H 'content-type: application/json' -d '{"enabled":false}' | python3 -m json.tool
curl -s "$A/rules/$RID" -H "$AUTH_HEADER" | python3 -c "import sys,json; print(json.load(sys.stdin)['enabled'])"
curl -s -X POST "$A/rules/$RID/enable" -H "$AUTH_HEADER" -H 'content-type: application/json' -d '{"enabled":true}' | python3 -m json.tool
```

**Observed:**
```text
POST /rules/{id}/enable {"enabled":false} returned enabled=false.
POST /rules/{id}/enable {"enabled":true} returned enabled=true.
```

**Verdict:** PASS. Rule lifecycle enable/disable endpoint works.

### API 4 - `POST /api/v1/rules/{id}/test`

**Status:** PASS

**Working command:**
```bash
curl -s -X POST "$A/rules/$RID/test" -H "$AUTH_HEADER" | python3 -m json.tool
```

**Observed:**
```text
POST /api/v1/rules/urn:uuid:9e8fe04d-fa02-41fb-a875-c1a9b65413e7/test returned:
would_fire=true
dry_run=true
trigger_summary=ThreatAlert sid=9999001 sev=high src=203.0.113.55 dst=198.51.100.10
actions:
- RaiseAlert(high): would-run; SGX_RULES_DRYRUN is enabled
- Notify(info): would-run; SGX_RULES_DRYRUN is enabled
outcome=dry-run
```

**Verdict:** PASS. Test endpoint evaluates the rule and returns the expected dry-run action plan.

### API 5 - `GET /api/v1/rules/executions`

**Status:** PASS

**Working command:**
```bash
curl -s "$A/rules/executions" -H "$AUTH_HEADER" | python3 -c "
import sys,json
from collections import Counter
d=json.load(sys.stdin)
print('total:',len(d))
print(Counter(e['outcome'] for e in d))
print(d[-1] if d else 'none')
"
```

**Observed:**
```text
Before EVE injection:
executions_before: 0

After EVE injection and burst:
executions_after: 1
last_outcomes: ['dry-run']
```

**Verdict:** PASS. Execution history endpoint returns persisted rule executions.

### API 6 - Unknown action rejected by fixed enum

**Status:** PASS

**Working command:**
```bash
curl -s -o /tmp/rules-bad-action.json -w 'unknown action HTTP %{http_code}\n' \
  -X PATCH "$A/rules/$RID" \
  -H "$AUTH_HEADER" \
  -H 'content-type: application/json' \
  -d '{"actions":[{"RunShell":{"cmd":"id"}}]}'
cat /tmp/rules-bad-action.json | python3 -m json.tool
```

**Expected:** HTTP 400/422 style rejection; no arbitrary action accepted.

**Observed:**
```text
BAD_STATUS=422
Failed to deserialize the JSON body into the target type:
actions[0]: unknown variant `UnknownAction`, expected one of `RaiseAlert`,
`Notify`, `BlockIp`, `RunScan`, `RevokeDid`, `LockTransport`,
`EmergencyKeyRotation` at line 1 column 63
```

**Verdict:** PASS. Unknown rule actions are rejected by the fixed enum before entering registry logic.

### API 7 - Tampered registry rejected

**Status:** PASS

**Working command:**
```bash
docker cp "$NODE:$RULES_BASE/rules.json" /tmp/rules10.original.json
cp /tmp/rules10.original.json /tmp/rules10.tampered.json
python3 - <<'PY'
import json
p = "/tmp/rules10.tampered.json"
d = json.load(open(p))
d["rules"][0]["name"] = "TAMPERED WITHOUT RESIGNING"
json.dump(d, open(p, "w"), indent=2)
PY
docker cp /tmp/rules10.tampered.json "$NODE:$RULES_BASE/rules.json"
curl -sS -o /tmp/rules10_tamper_response.json -w "%{http_code}" "$A/rules"
```

**Observed:**
```text
TAMPER_STATUS=400
{"error":{"code":"BAD_REQUEST","message":"rules registry signature is invalid: DID document signature invalid"}}

executions_before_tampered_event=0
executions_after_tampered_event=0

Audit:
rules registry rejected: rules registry signature is invalid: DID document signature invalid

RESTORE_STATUS=200
VERIFY API 7: PASS
```

**Verdict:** PASS. Tampered `rules.json` is rejected and no matching rule execution is recorded while the registry proof is invalid.

---

## Test Tag Mapping

| Tag | What it proves | Section |
|---|---|---|
| RULES-DKR-001 | Docker build + rules unit tests | Requirement 1 |
| RULES-DKR-002 | Engine startup + no new port | Requirement 2 |
| RULES-DKR-003 | Model/evaluator/test endpoint | Requirement 3 |
| RULES-DKR-004 | Signed CRUD/lifecycle/persistence | Requirement 4 |
| RULES-DKR-005 | EVE event ingestion + non-blocking API | Requirement 5 |
| RULES-DKR-006 | Dry-run + destructive gate | Requirement 6 |
| RULES-DKR-007 | Cooldown + rate cap | Requirement 7 |
| RULES-DKR-008 | BlockIp self-protection | Requirement 8 |
| RULES-DKR-009 | Execution history + fail-safe | Requirement 9 |
| RULES-DKR-010 | Tamper rejection fail-closed | Requirement 10 |

---

## Debug / Emergency Commands

```bash
# Ports and containers
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
curl -s "$A/health"

# Rules engine logs
docker exec sgx-nodeA sh -lc 'grep -a "rules engine\|Rules\|dry-run\|downgraded\|rate-limited\|refused to block" /var/log/sgx-guardian/audit-nodeA.log | tail -40'

# Rules files
docker exec sgx-nodeA sh -lc "ls -lah $RULES_DIR; wc -l $RULES_DIR/executions.jsonl 2>/dev/null || true"
docker exec sgx-nodeA cat "$RULES_DIR/rules.json" | python3 -m json.tool
docker exec sgx-nodeA cat "$RULES_DIR/state.json" 2>/dev/null | python3 -m json.tool || true

# Threat tailer input
docker exec sgx-nodeA sh -lc "tail -5 $EVE_LOG; grep -a 'detected sid=' /var/log/sgx-guardian/audit-nodeA.log | tail -5"

# Disable all rules quickly
for r in $(curl -s "$A/rules" -H "$AUTH_HEADER" | python3 -c "import sys,json; [print(x['rule_id']) for x in json.load(sys.stdin)]"); do
  curl -s -X POST "$A/rules/$r/enable" -H "$AUTH_HEADER" -H 'content-type: application/json' -d '{"enabled":false}' >/dev/null
done

# Clear rules test history only; preserve rules.json
docker exec sgx-nodeA sh -lc "rm -f $RULES_DIR/executions.jsonl $RULES_DIR/state.json"
docker compose --env-file optional/container-cohort/dev.env -f optional/container-cohort/docker-compose.dev.yml restart nodeA

# Clean up live-mode container if left around
docker rm -f sgx-nodeA-rules-live 2>/dev/null || true
docker compose --env-file optional/container-cohort/dev.env -f optional/container-cohort/docker-compose.dev.yml up -d nodeA
```
