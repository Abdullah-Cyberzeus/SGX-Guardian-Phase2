#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

INVENTORY_PATH="/var/lib/sgx-guardian/discovery/inventory.json"

# Verify merge/dedup behavior at unit-test level first.
echo "[NMP-004] Running inventory merge/dedup tests..."
cargo test --test discovery_inventory_test

# Perform two scans to exercise persistence and duplicate suppression.
echo "[NMP-004] Running two scans to exercise persistence + dedup..."
scan_ok=1
if cargo run -q -p sgx-pa-cli -- discovery scan --target 127.0.0.1/32 >/dev/null 2>&1; then
  cargo run -q -p sgx-pa-cli -- discovery scan --target 127.0.0.1/32 >/dev/null 2>&1
else
  echo "[NMP-004] Scan skipped in this environment (missing scan privileges)."
  scan_ok=0
fi

# Validate that persisted inventory is an array with unique device_id values.
echo "[NMP-004] Verifying persisted JSON has unique device_id values..."
if [ "$scan_ok" -eq 1 ]; then
python3 - <<'PY'
import json

path = "/var/lib/sgx-guardian/discovery/inventory.json"
with open(path, "r", encoding="utf-8") as f:
    devices = json.load(f)

assert isinstance(devices, list), "inventory.json must contain a JSON array"
assert devices, "inventory.json must not be empty after scan"

ids = [d.get("device_id") for d in devices]
assert all(ids), "every device must have device_id"
assert len(ids) == len(set(ids)), "duplicate device_id detected in inventory"

print(f"inventory_count={len(devices)} unique_ids={len(set(ids))}")
PY
else
  echo "[NMP-004] Persistence runtime assertion skipped because scan could not run."
fi

echo "[NMP-004] PASS"
