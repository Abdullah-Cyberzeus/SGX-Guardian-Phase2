#!/usr/bin/env bash
set -euo pipefail

echo "[SUR-001] install + config validate"
command -v suricata >/dev/null 2>&1 || { echo "suricata not installed"; exit 1; }
suricata -T -c /etc/suricata/suricata.yaml
test -f /etc/sgx-guardian/threat/config.yaml
echo "[SUR-001] ok"
