# Container Nodes Stabilization Commands

Commands used to stabilize the `sgx-nodeA` / `sgx-nodeB` / `sgx-nodeC` container cohort:
fix nodeC's port conflict, sign PCR baselines, and resolve the policy digest
mismatch. No source code was changed — only config (`dev.env`) and runtime
commands/file copies.

## 1. nodeC port fix (38443 → 39443)

`38443` fell inside a Windows Hyper-V excluded TCP port range
(`netsh interface ipv4 show excludedportrange protocol=tcp`), so Docker Desktop
could never bind it — hence the `forwards/expose ... 500` error on `start.sh`.

```bash
# In optional/container-cohort/dev.env, change:
#   NODEC_REST_PORT=38443
# to:
#   NODEC_REST_PORT=39443

cd optional/container-cohort
docker compose -f docker-compose.dev.yml --env-file dev.env rm -f nodeC
docker compose -f docker-compose.dev.yml --env-file dev.env up -d nodeC
```

## 2. PCR golden baseline — create (all three nodes)

```bash
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli pcr-baseline-create
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeB sgx-pa-cli pcr-baseline-create
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeC sgx-pa-cli pcr-baseline-create
```

## 3. PCR golden baseline — verify

```bash
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli pcr-baseline-verify
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeB sgx-pa-cli pcr-baseline-verify
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeC sgx-pa-cli pcr-baseline-verify
```

Expect `✅ ALL PCRs MATCH — device integrity verified` on each node.

## 4. Policy digest mismatch — diagnose

```bash
docker exec sgx-nodeA sgx-pa-cli attestation
docker exec sgx-nodeB sgx-pa-cli attestation
docker exec sgx-nodeC sgx-pa-cli attestation

docker logs sgx-nodeA 2>&1 | grep -iE "mismatch|digest.*fail|attest.*(fail|error|reject)"

docker exec sgx-nodeA ls -la /etc/sgx-guardian/policies/
docker exec sgx-nodeB ls -la /etc/sgx-guardian/policies/
docker exec sgx-nodeC ls -la /etc/sgx-guardian/policies/
```

Root cause: only `nodeA` (Policy Authority) had an `active_policy.yaml`.
`nodeB`/`nodeC` had no such file and fell back to the shared default schema,
so their computed policy digest never matched nodeA's.

## 5. Policy digest mismatch — fix

```bash
docker cp sgx-nodeA:/etc/sgx-guardian/policies/active_policy.yaml /tmp/active_policy_nodeA.yaml
docker cp /tmp/active_policy_nodeA.yaml sgx-nodeB:/etc/sgx-guardian/policies/active_policy.yaml
docker cp /tmp/active_policy_nodeA.yaml sgx-nodeC:/etc/sgx-guardian/policies/active_policy.yaml
```

## 6. Final confirmation

```bash
docker exec sgx-nodeA sgx-pa-cli peers
docker exec sgx-nodeB sgx-pa-cli peers
docker exec sgx-nodeC sgx-pa-cli peers
```

All three nodes should show each other as `verified` peers, with matching
`Policy Digest` and `Result: success` in `sgx-pa-cli attestation`.

## Notes

- `sgx-pa-cli policy-sign-and-deploy <file>` and `docker restart sgx-nodeA`
  were also tried mid-troubleshooting but were **not** the actual fix — they
  re-sign the same file (new signature/envelope) without changing the
  underlying YAML content, so they don't resolve a propagation gap. The real
  fix is step 5: copying nodeA's policy file onto nodeB/nodeC.
- If the cohort is rebuilt from scratch (`docker compose down -v`), this
  policy-file gap will reappear and step 5 needs to be repeated after nodeA's
  `active_policy.yaml` is (re)created.
