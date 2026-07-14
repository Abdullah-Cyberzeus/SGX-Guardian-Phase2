#!/usr/bin/env bash
set -euo pipefail

echo "[SUR-005] persistence"
test -f /var/lib/sgx-guardian/threat/last_offset.json
systemctl restart sgx-guardian
sleep 3
test -f /var/lib/sgx-guardian/threat/last_offset.json
echo "[SUR-005] ok"
