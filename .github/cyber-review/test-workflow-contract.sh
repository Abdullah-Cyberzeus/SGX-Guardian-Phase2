#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
workflow="$repo_root/.github/workflows/cyber-review.yml"

assert_contains() {
  local expected="$1"

  if ! grep -Fq -- "$expected" "$workflow"; then
    echo "cyber-review workflow is missing required contract: $expected" >&2
    exit 1
  fi
}

assert_absent() {
  local rejected="$1"

  if grep -Fq -- "$rejected" "$workflow"; then
    echo "cyber-review workflow contains rejected contract: $rejected" >&2
    exit 1
  fi
}

assert_line() {
  local expected="$1"

  if ! grep -Fxq -- "$expected" "$workflow"; then
    echo "cyber-review workflow is missing required line: $expected" >&2
    exit 1
  fi
}

assert_line_absent() {
  local rejected="$1"

  if grep -Fxq -- "$rejected" "$workflow"; then
    echo "cyber-review workflow contains rejected line: $rejected" >&2
    exit 1
  fi
}

assert_line "  pull_request_target:"
assert_line_absent "  pull_request:"
assert_line_absent "  workflow_dispatch:"
assert_line "    branches: [ main ]"
assert_line "    types: [ opened, reopened, ready_for_review, labeled ]"
assert_line '  group: cyber-review-${{ github.event.pull_request.number }}'
assert_line "  cancel-in-progress: true"
assert_line '  PR_NUMBER: ${{ github.event.pull_request.number }}'
assert_absent "inputs.pr_number"
assert_absent "github.event_name == 'workflow_dispatch'"

top_permissions="$(
  awk '
    /^permissions:$/ { capture = 1; next }
    /^env:$/ && capture { exit }
    capture { print }
  ' "$workflow"
)"
if [[ "$top_permissions" != "  contents: read" ]]; then
  echo "cyber-review top-level permissions must remain contents: read" >&2
  exit 1
fi

assert_contains "id: review"
assert_contains "--json-schema"
assert_contains '--allowedTools "Read,Grep,Glob"'
assert_contains '--disallowedTools "Bash,Write,Edit,NotebookEdit,mcp__*"'
assert_absent '--tools "'
assert_line '          ref: ${{ needs.classify.outputs.head_sha }}'
assert_line "          persist-credentials: false"
assert_absent "run: bash .github/"
assert_absent "python3 .github/"
assert_absent 'bash "$GITHUB_WORKSPACE'
assert_absent 'python3 "$GITHUB_WORKSPACE'
assert_contains 'STRUCTURED_FINDINGS: ${{ steps.review.outputs.structured_output }}'
assert_contains 'if [ -z "$STRUCTURED_FINDINGS" ]; then'
assert_contains 'exit 1'
assert_contains '> "$RUNNER_TEMP/cyber-review-findings.json"'
assert_contains '"$RUNNER_TEMP/cyber-review-findings.json"'
assert_absent ".github/cyber-review/findings.json"

schema="$(sed -n "s/^[[:space:]]*--json-schema '\\(.*\\)'$/\\1/p" "$workflow")"
if [[ -z "$schema" ]] || ! jq -e \
  '.type == "object"
   and .additionalProperties == false
   and (.required == ["findings"])
   and (.properties.findings.type == "array")' \
  <<<"$schema" >/dev/null; then
  echo "cyber-review findings schema is missing or invalid" >&2
  exit 1
fi

materialize_findings() {
  local structured_findings="$1"
  local destination="$2"

  if [[ -z "$structured_findings" ]]; then
    return 1
  fi
  printf '%s\n' "$structured_findings" > "$destination"
}

fixture='{"findings":[]}'
materialized="$(mktemp)"
trap 'rm -f "$materialized"' EXIT
materialize_findings "$fixture" "$materialized"
if [[ "$(jq -c . "$materialized")" != "$fixture" ]]; then
  echo "structured findings fixture did not materialize unchanged" >&2
  exit 1
fi

if materialize_findings "" "$materialized"; then
  echo "empty structured findings did not fail closed" >&2
  exit 1
fi

echo "cyber-review workflow contract tests passed"
