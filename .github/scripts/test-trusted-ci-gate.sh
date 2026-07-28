#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
source "$script_dir/ci-gate-lib.sh"

mapfile -t executed_ci_scripts < <(
  grep -Eo '\.github/[A-Za-z0-9_./-]+\.(sh|ps1|py)' \
    "$script_dir/../workflows/ci.yml" |
    sort -u
)
for executed_script in "${executed_ci_scripts[@]}"; do
  if [[ ! " ${CI_TRUSTED_DEFINITION_PATHS[*]} " =~ " $executed_script " ]]; then
    echo "trusted definition manifest omits CI-executed script: $executed_script" >&2
    exit 1
  fi
done

success_jobs='{"jobs":[
  {"name":"Classify Changes","conclusion":"success"},
  {"name":"Format & Clippy","conclusion":"success"},
  {"name":"Unit Tests","conclusion":"success"},
  {"name":"Windows Workspace Tests","conclusion":"success"},
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

commit_sha="1111111111111111111111111111111111111111"
tree_sha="2222222222222222222222222222222222222222"
commit_response='{
  "sha": "1111111111111111111111111111111111111111",
  "tree": {
    "sha": "2222222222222222222222222222222222222222"
  }
}'
[[ "$(git_commit_tree_sha "$commit_sha" "$commit_response")" == "$tree_sha" ]]
if git_commit_tree_sha \
  "$commit_sha" '{"sha":"1111111111111111111111111111111111111111"}' \
  >/dev/null 2>&1; then
  echo "gate accepted a malformed commit response" >&2
  exit 1
fi
if git_commit_tree_sha \
  "3333333333333333333333333333333333333333" "$commit_response" \
  >/dev/null 2>&1; then
  echo "gate accepted a commit response for the wrong SHA" >&2
  exit 1
fi

base_tree='{
  "truncated": false,
  "tree": [
    {
      "path": ".github/workflows/ci.yml",
      "mode": "100644",
      "type": "blob",
      "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    {
      "path": ".github/scripts/install-protoc.sh",
      "mode": "100755",
      "type": "blob",
      "sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
  ]
}'
matching_head_tree="$base_tree"
changed_helper_tree="${base_tree/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/cccccccccccccccccccccccccccccccccccccccc}"
deleted_helper_tree="$(jq -c '
  .tree |= map(select(.path != ".github/scripts/install-protoc.sh"))
' <<<"$base_tree")"
symlinked_helper_tree="$(jq -c '
  .tree |= map(
    if .path == ".github/scripts/install-protoc.sh"
    then .mode = "120000"
    else .
    end
  )
' <<<"$base_tree")"

base_manifest="$(ci_trusted_definition_manifest "$base_tree")"
grep -Fqx $'.github/workflows/ci.yml\t100644\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  <<<"$base_manifest"
grep -Fqx $'.github/scripts/install-protoc.sh\t100755\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
  <<<"$base_manifest"
[[ "$(wc -l <<<"$base_manifest")" -eq "${#CI_TRUSTED_DEFINITION_PATHS[@]}" ]]

docs_base_tree="$(jq -c '
  .tree += [{
    "path": "docs/guide.md",
    "mode": "100644",
    "type": "blob",
    "sha": "dddddddddddddddddddddddddddddddddddddddd"
  }]
' <<<"$base_tree")"
docs_head_tree="${docs_base_tree/dddddddddddddddddddddddddddddddddddddddd/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee}"
mapfile -t docs_changed_paths < <(
  changed_paths_from_trees "$docs_base_tree" "$docs_head_tree"
)
[[ "${docs_changed_paths[*]}" == "docs/guide.md" ]]
if requires_full_ci "${docs_changed_paths[@]}"; then
  echo "exact-tree classifier rejected a docs-only change" >&2
  exit 1
fi

mapfile -t helper_changed_paths < <(
  changed_paths_from_trees "$base_tree" "$changed_helper_tree"
)
[[ "${helper_changed_paths[*]}" == ".github/scripts/install-protoc.sh" ]]
if ! requires_full_ci "${helper_changed_paths[@]}"; then
  echo "exact-tree classifier accepted a CI helper as docs-only" >&2
  exit 1
fi

enforce_base_owned_ci_definition "$base_tree" "$matching_head_tree"
if enforce_base_owned_ci_definition \
  "$base_tree" "$changed_helper_tree" >/dev/null 2>&1; then
  echo "gate accepted a PR-controlled CI helper" >&2
  exit 1
fi
if enforce_base_owned_ci_definition \
  "$base_tree" "$deleted_helper_tree" >/dev/null 2>&1; then
  echo "gate accepted a deleted CI helper" >&2
  exit 1
fi
if enforce_base_owned_ci_definition \
  "$base_tree" "$symlinked_helper_tree" >/dev/null 2>&1; then
  echo "gate accepted a symlinked CI helper" >&2
  exit 1
fi
if enforce_base_owned_ci_definition \
  "$base_tree" '{"truncated":true,"tree":[]}' >/dev/null 2>&1; then
  echo "gate accepted a truncated Git tree response" >&2
  exit 1
fi
if enforce_base_owned_ci_definition \
  "$base_tree" '{"truncated":false,"tree":"invalid"}' >/dev/null 2>&1; then
  echo "gate accepted a malformed Git tree response" >&2
  exit 1
fi
if changed_paths_from_trees \
  "$base_tree" '{"truncated":true,"tree":[]}' >/dev/null 2>&1; then
  echo "classifier accepted a truncated head Git tree" >&2
  exit 1
fi

base_sha="1111111111111111111111111111111111111111"
current_base_ref='{
  "object": {
    "type": "commit",
    "sha": "1111111111111111111111111111111111111111"
  }
}'
enforce_current_base_sha "$base_sha" "$current_base_ref"
if enforce_current_base_sha \
  "2222222222222222222222222222222222222222" \
  "$current_base_ref" >/dev/null 2>&1; then
  echo "gate accepted a stale pull request base SHA" >&2
  exit 1
fi

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
