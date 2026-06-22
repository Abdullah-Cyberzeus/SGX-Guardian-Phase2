#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Validate that each intensity profile maps to the expected Nmap flags.
echo "[NMP-003] Verifying stealth intensity flags..."
cargo test --lib nmap_args_stealth_profile_flags

echo "[NMP-003] Verifying standard intensity flags..."
cargo test --lib nmap_args_standard_profile_flags

echo "[NMP-003] Verifying aggressive intensity flags..."
cargo test --lib nmap_args_aggressive_profile_flags

echo "[NMP-003] PASS"
