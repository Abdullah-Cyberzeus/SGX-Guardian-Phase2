#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
source "$script_dir/ci-gate-lib.sh"

: "${REPO:?REPO is required}"
: "${HEAD_REPO:?HEAD_REPO is required}"
: "${DEFAULT_BRANCH:?DEFAULT_BRANCH is required}"
: "${PR_NUMBER:?PR_NUMBER is required}"
: "${BASE_SHA:?BASE_SHA is required}"
: "${HEAD_SHA:?HEAD_SHA is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"

if [[ ! "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ||
  ! "$HEAD_REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "invalid base or head repository name" >&2
  exit 2
fi
if [[ ! "$DEFAULT_BRANCH" =~ ^[A-Za-z0-9._/-]+$ ||
  "$DEFAULT_BRANCH" == *..* ||
  "$DEFAULT_BRANCH" == /* ||
  "$DEFAULT_BRANCH" == */ ]]; then
  echo "invalid default branch name" >&2
  exit 2
fi
if [[ ! "$PR_NUMBER" =~ ^[0-9]+$ ]]; then
  echo "invalid pull request number" >&2
  exit 2
fi
if [[ ! "$BASE_SHA" =~ ^[0-9a-f]{40}$ ||
  ! "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "invalid pull request base or head SHA" >&2
  exit 2
fi

poll_seconds="${CI_GATE_POLL_SECONDS:-10}"
max_attempts="${CI_GATE_MAX_ATTEMPTS:-180}"
if [[ ! "$poll_seconds" =~ ^[1-9][0-9]*$ ||
  ! "$max_attempts" =~ ^[1-9][0-9]*$ ]]; then
  echo "invalid polling configuration" >&2
  exit 2
fi

api() {
  gh api \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$@"
}

status_target_url="${GITHUB_SERVER_URL:-https://github.com}/$REPO/pull/$PR_NUMBER"

publish_status() {
  local state="$1"
  local description="$2"

  api --method POST "repos/$REPO/statuses/$HEAD_SHA" \
    -f state="$state" \
    -f context="CI Required" \
    -f description="$description" \
    -f target_url="$status_target_url" >/dev/null
}

evaluate_gate() {
  local current_base_ref_json
  local base_commit_json
  local head_commit_json
  local base_tree_sha
  local head_tree_sha
  local base_tree_json
  local head_tree_json
  local workflow_id
  local runs_json
  local run_json
  local run_id
  local run_status
  local run_conclusion
  local jobs_json
  local mode="docs"
  local attempt
  local changed_paths_output
  local changed_paths=()

  current_base_ref_json="$(api \
    "repos/$REPO/git/ref/heads/$DEFAULT_BRANCH")" || return 1
  enforce_current_base_sha "$BASE_SHA" "$current_base_ref_json" || return 1

  base_commit_json="$(api "repos/$REPO/git/commits/$BASE_SHA")" || return 1
  head_commit_json="$(api "repos/$HEAD_REPO/git/commits/$HEAD_SHA")" || return 1
  base_tree_sha="$(git_commit_tree_sha "$BASE_SHA" "$base_commit_json")" || {
    echo "invalid base commit response" >&2
    return 1
  }
  head_tree_sha="$(git_commit_tree_sha "$HEAD_SHA" "$head_commit_json")" || {
    echo "invalid pull request head commit response" >&2
    return 1
  }
  base_tree_json="$(api \
    "repos/$REPO/git/trees/$base_tree_sha?recursive=1")" || return 1
  head_tree_json="$(api \
    "repos/$HEAD_REPO/git/trees/$head_tree_sha?recursive=1")" || return 1
  enforce_base_owned_ci_definition \
    "$base_tree_json" "$head_tree_json" || return 1

  changed_paths_output="$(
    changed_paths_from_trees "$base_tree_json" "$head_tree_json"
  )" || return 1
  mapfile -t changed_paths < <(printf '%s' "$changed_paths_output")
  if requires_full_ci "${changed_paths[@]}"; then
    mode="full"
  fi
  echo "Trusted path classification: $mode"

  workflow_id="$(api "repos/$REPO/actions/workflows/ci.yml" --jq .id)" ||
    return 1
  if [[ ! "$workflow_id" =~ ^[0-9]+$ ]]; then
    echo "invalid CI workflow id" >&2
    return 1
  fi

  for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    runs_json="$(api \
      "repos/$REPO/actions/runs?event=pull_request&head_sha=$HEAD_SHA&per_page=100")" ||
      return 1
    if run_json="$(select_ci_run "$runs_json" "$workflow_id" "$HEAD_SHA" 2>/dev/null)"; then
      run_status="$(jq -r '.status // ""' <<<"$run_json")"
      status_target_url="$(jq -r '.html_url' <<<"$run_json")"
      if [[ "$run_status" == "completed" ]]; then
        run_id="$(jq -r '.id' <<<"$run_json")"
        run_conclusion="$(jq -r '.conclusion // ""' <<<"$run_json")"
        jobs_json="$(api "repos/$REPO/actions/runs/$run_id/jobs?filter=latest&per_page=100")" ||
          return 1
        validate_ci_jobs "$mode" "$run_conclusion" "$jobs_json"
        return
      fi
      echo "Waiting for CI Pipeline run $(jq -r '.id' <<<"$run_json"): $run_status"
    else
      echo "Waiting for CI Pipeline run on exact head $HEAD_SHA"
    fi
    sleep "$poll_seconds"
  done

  echo "Timed out waiting for CI Pipeline on exact head $HEAD_SHA" >&2
  return 1
}

publish_status "pending" "Waiting for trusted evaluation of CI Pipeline"

if evaluate_gate; then
  publish_status "success" "Required CI Pipeline jobs passed"
  echo "Trusted CI gate passed for $HEAD_SHA"
else
  publish_status "failure" "Required CI Pipeline jobs failed or were missing" || true
  echo "Trusted CI gate failed for $HEAD_SHA" >&2
  exit 1
fi
