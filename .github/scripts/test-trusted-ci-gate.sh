#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
source "$script_dir/ci-gate-lib.sh"

success_jobs='{"jobs":[
  {"name":"Classify Changes","conclusion":"success"},
  {"name":"Format & Clippy","conclusion":"success"},
  {"name":"Unit Tests","conclusion":"success"},
  {"name":"Coverage","conclusion":"success"},
  {"name":"Dependency Policy","conclusion":"success"},
  {"name":"Semgrep","conclusion":"success"},
  {"name":"Release Build","conclusion":"success"}
]}'

docs_jobs="$(jq -c '
  .jobs |= map(
    if .name == "Classify Changes" then .
    else .conclusion = "skipped"
    end
  )' <<<"$success_jobs")"

validate_ci_jobs full success "$success_jobs"
validate_ci_jobs docs success "$docs_jobs"

skipped_coverage="$(jq -c '
  .jobs |= map(
    if .name == "Coverage" then .conclusion = "skipped"
    else .
    end
  )' <<<"$success_jobs")"
if validate_ci_jobs full success "$skipped_coverage" >/dev/null 2>&1; then
  echo "full CI accepted an adversarially skipped Coverage job" >&2
  exit 1
fi

missing_tests="$(jq -c '
  .jobs |= map(select(.name != "Unit Tests"))' <<<"$success_jobs")"
if validate_ci_jobs full success "$missing_tests" >/dev/null 2>&1; then
  echo "full CI accepted a missing Unit Tests job" >&2
  exit 1
fi

duplicate_lint="$(jq -c '
  .jobs += [{"name":"Format & Clippy","conclusion":"success"}]' <<<"$success_jobs")"
if validate_ci_jobs full success "$duplicate_lint" >/dev/null 2>&1; then
  echo "full CI accepted a duplicate required job name" >&2
  exit 1
fi

if validate_ci_jobs full failure "$success_jobs" >/dev/null 2>&1; then
  echo "full CI accepted a failed workflow conclusion" >&2
  exit 1
fi

assert_full_ci() {
  if ! requires_full_ci "$@"; then
    echo "expected full CI for paths: $*" >&2
    exit 1
  fi
}

assert_full_ci
assert_full_ci .github/workflows/ci.yml
assert_full_ci .github/workflows/trusted-ci-required.yml
assert_full_ci .github/scripts/trusted-ci-gate.sh
if requires_full_ci README.md docs/ci-benchmarks.md NEXT/2026-07-27-ci.md; then
  echo "documentation-only paths unexpectedly required full CI" >&2
  exit 1
fi

old_sha="1111111111111111111111111111111111111111"
head_sha="2222222222222222222222222222222222222222"
runs_json='{"workflow_runs":[
  {"id":10,"workflow_id":42,"head_sha":"1111111111111111111111111111111111111111","event":"pull_request","run_number":10,"run_attempt":1},
  {"id":11,"workflow_id":7,"head_sha":"2222222222222222222222222222222222222222","event":"pull_request","run_number":11,"run_attempt":1},
  {"id":12,"workflow_id":42,"head_sha":"2222222222222222222222222222222222222222","event":"pull_request","run_number":12,"run_attempt":1},
  {"id":12,"workflow_id":42,"head_sha":"2222222222222222222222222222222222222222","event":"pull_request","run_number":12,"run_attempt":2}
]}'
selected_run="$(select_ci_run "$runs_json" 42 "$head_sha")"
[[ "$(jq -r .head_sha <<<"$selected_run")" == "$head_sha" ]]
[[ "$(jq -r .run_attempt <<<"$selected_run")" == "2" ]]
if select_ci_run "$runs_json" 42 "3333333333333333333333333333333333333333" \
  >/dev/null 2>&1; then
  echo "gate selected a stale run for a missing head SHA" >&2
  exit 1
fi
if [[ "$(select_ci_run "$runs_json" 42 "$old_sha" | jq -r .id)" != "10" ]]; then
  echo "gate did not select the exact requested head SHA" >&2
  exit 1
fi

echo "trusted CI gate tests passed"
