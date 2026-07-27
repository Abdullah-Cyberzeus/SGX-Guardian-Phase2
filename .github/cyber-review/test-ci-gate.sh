#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
source "$script_dir/ci-gate.sh"

head_sha="2222222222222222222222222222222222222222"

snapshot() {
  local contexts="$1"
  local pr_head="${2:-$head_sha}"
  local object_head="${3:-$head_sha}"

  jq -cn \
    --argjson contexts "$contexts" \
    --arg pr_head "$pr_head" \
    --arg object_head "$object_head" \
    '{
      data: {
        repository: {
          pullRequest: {headRefOid: $pr_head},
          object: {
            oid: $object_head,
            statusCheckRollup: {contexts: {nodes: $contexts}}
          }
        }
      }
    }'
}

success_contexts='[
  {"__typename":"StatusContext","context":"CI Required","state":"SUCCESS"},
  {"__typename":"CheckRun","name":"Static Analysis (CodeQL)","status":"COMPLETED","conclusion":"SUCCESS"}
]'

assert_state() {
  local expected="$1"
  local payload="$2"

  evaluate_ci_snapshot "$payload" "$head_sha"
  if [[ "$GATE_STATE" != "$expected" ]]; then
    echo "expected $expected, got $GATE_STATE: $GATE_DETAILS" >&2
    exit 1
  fi
}

assert_state success "$(snapshot "$success_contexts")"

assert_state pending "$(snapshot '[
  {"__typename":"StatusContext","context":"CI Required","state":"SUCCESS"}
]')"

assert_state pending "$(snapshot '[
  {"__typename":"StatusContext","context":"CI Required","state":"PENDING"},
  {"__typename":"CheckRun","name":"Static Analysis (CodeQL)","status":"IN_PROGRESS","conclusion":null}
]')"

assert_state failure "$(snapshot '[
  {"__typename":"StatusContext","context":"CI Required","state":"FAILURE"},
  {"__typename":"CheckRun","name":"Static Analysis (CodeQL)","status":"COMPLETED","conclusion":"SUCCESS"}
]')"

assert_state failure "$(snapshot '[
  {"__typename":"StatusContext","context":"CI Required","state":"SUCCESS"},
  {"__typename":"CheckRun","name":"Static Analysis (CodeQL)","status":"COMPLETED","conclusion":"NEUTRAL"}
]')"

assert_state failure "$(snapshot "$success_contexts" \
  "1111111111111111111111111111111111111111")"

assert_state failure "$(snapshot "$success_contexts" "$head_sha" \
  "1111111111111111111111111111111111111111")"

duplicate_status="$(jq -c \
  '. + [{"__typename":"StatusContext","context":"CI Required","state":"SUCCESS"}]' \
  <<<"$success_contexts")"
assert_state failure "$(snapshot "$duplicate_status")"

duplicate_check="$(jq -c \
  '. + [{"__typename":"CheckRun","name":"Static Analysis (CodeQL)","status":"COMPLETED","conclusion":"SUCCESS"}]' \
  <<<"$success_contexts")"
assert_state failure "$(snapshot "$duplicate_check")"

stale_noise="$(jq -c \
  '. + [
    {"__typename":"StatusContext","context":"Other Required","state":"FAILURE"},
    {"__typename":"CheckRun","name":"Static Analysis (CodeQL old SHA)","status":"COMPLETED","conclusion":"FAILURE"}
  ]' <<<"$success_contexts")"
assert_state success "$(snapshot "$stale_noise")"

echo "cyber-review CI gate tests passed"
