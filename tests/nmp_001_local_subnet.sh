#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Validate parser behavior first so scan issues are isolated from XML parsing.
echo "[NMP-001] Running discovery parser fixture test..."
cargo test --test discovery_parser_test

# Run a minimal localhost scan as an environment-safe smoke test.
echo "[NMP-001] Running localhost ad-hoc scan..."
scan_ok=1
if scan_output="$(cargo run -q -p sgx-pa-cli -- discovery scan --target 127.0.0.1/32 2>&1)"; then
  echo "$scan_output"
  echo "$scan_output" | grep -q "Discovery scan completed"
else
  echo "$scan_output"
  if echo "$scan_output" | grep -Eq "requires root privileges|Operation not permitted|BinaryMissing"; then
    echo "[NMP-001] Scan skipped in this environment (missing scan privileges)."
    scan_ok=0
  else
    echo "[NMP-001] Unexpected scan error."
    exit 1
  fi
fi

# Confirm inventory output after scan.
echo "[NMP-001] Verifying localhost appears in inventory listing..."
list_output="$(cargo run -q -p sgx-pa-cli -- discovery list 2>&1)"
echo "$list_output"
if echo "$list_output" | grep -q "127.0.0.1"; then
  :
elif [ "$scan_ok" -eq 0 ] && echo "$list_output" | grep -q "No inventory found"; then
  echo "[NMP-001] Inventory assertion skipped because scan could not run."
else
  echo "[NMP-001] Expected localhost entry in inventory."
  exit 1
fi

echo "[NMP-001] PASS"
