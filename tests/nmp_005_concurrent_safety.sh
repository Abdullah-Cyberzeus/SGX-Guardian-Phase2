#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Ensure scheduler run_one remains timeout-bounded and does not hang the runtime.
echo "[NMP-005] Running timeout-bounded scheduler safety test..."
RUST_TEST_THREADS=1 cargo test --test discovery_scheduler_test -- --nocapture

echo "[NMP-005] PASS"
