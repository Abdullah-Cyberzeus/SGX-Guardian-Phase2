#!/usr/bin/env bash
set -euo pipefail

echo "[SUR-002] eve json ingestion"
test -f /var/log/suricata/eve.json
tail -n 5 /var/log/suricata/eve.json >/dev/null
curl -fsS http://127.0.0.1:8443/api/v1/threat/alerts >/dev/null
echo "[SUR-002] ok"
