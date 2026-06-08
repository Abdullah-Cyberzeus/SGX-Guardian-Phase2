#!/usr/bin/env bash
set -euo pipefail

echo "[SUR-004] rule update"
sgx-pa-cli threat rules-update >/dev/null
test -f /etc/suricata/rules/suricata.rules
echo "[SUR-004] ok"
