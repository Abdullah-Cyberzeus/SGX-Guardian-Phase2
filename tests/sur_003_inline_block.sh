#!/usr/bin/env bash
set -euo pipefail

echo "[SUR-003] inline block"
nft list chain inet sgx_threat input >/dev/null
sgx-pa-cli threat blocks >/dev/null
echo "[SUR-003] ok"
