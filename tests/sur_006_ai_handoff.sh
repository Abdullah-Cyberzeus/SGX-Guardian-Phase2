#!/usr/bin/env bash
set -euo pipefail

echo "[SUR-006] ai handoff"
grep -q "AI bridge (stub)" /var/log/sgx-guardian/audit-nodeA.log
echo "[SUR-006] ok"
