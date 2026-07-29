#!/usr/bin/env bash
set -euo pipefail

workflow=".github/workflows/ci.yml"
cache_sha="55cc8345863c7cc4c66a329aec7e433d2d1c52a9"

restore_count="$(grep -c "uses: actions/cache/restore@$cache_sha" "$workflow")"
save_count="$(grep -c "uses: actions/cache/save@$cache_sha" "$workflow")"
registry_id_count="$(grep -c "id: cargo-registry" "$workflow")"

[[ "$restore_count" -eq 5 ]]
[[ "$save_count" -eq 1 ]]
[[ "$registry_id_count" -eq 5 ]]

unit_job="$(
  awk '
    /^  tests:$/ { capture = 1 }
    /^  coverage:$/ { capture = 0 }
    capture { print }
  ' "$workflow"
)"

grep -Fq -- "- name: Save Cargo registry" <<<"$unit_job"
grep -Fq "if: steps.cargo-registry.outputs.cache-hit != 'true'" <<<"$unit_job"
grep -Fq 'key: ${{ steps.cargo-registry.outputs.cache-primary-key }}' <<<"$unit_job"

test_line="$(grep -n -- "- name: Run unit tests" <<<"$unit_job" | cut -d: -f1)"
save_line="$(grep -n -- "- name: Save Cargo registry" <<<"$unit_job" | cut -d: -f1)"
((save_line > test_line))

echo "Cargo cache workflow tests passed"
