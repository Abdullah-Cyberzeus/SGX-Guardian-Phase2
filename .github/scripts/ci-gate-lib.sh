#!/usr/bin/env bash

CI_REQUIRED_JOBS=(
  "Format & Clippy"
  "Unit Tests"
  "Coverage"
  "Dependency Policy"
  "Semgrep"
  "Release Build"
)

requires_full_ci() {
  local path

  if [[ "$#" -eq 0 ]]; then
    return 0
  fi

  for path in "$@"; do
    case "$path" in
      .gitignore|*.md|docs/*|NEXT/*)
        ;;
      *)
        return 0
        ;;
    esac
  done

  return 1
}

select_ci_run() {
  local runs_json="$1"
  local workflow_id="$2"
  local head_sha="$3"

  jq -ce \
    --argjson workflow_id "$workflow_id" \
    --arg head_sha "$head_sha" \
    '[.workflow_runs[]
      | select(.workflow_id == $workflow_id)
      | select(.head_sha == $head_sha)
      | select(.event == "pull_request")]
     | sort_by(.run_number, .run_attempt, .id)
     | last' <<<"$runs_json"
}

job_conclusion() {
  local jobs_json="$1"
  local job_name="$2"
  local matches

  matches="$(jq -c --arg job_name "$job_name" \
    '[.jobs[] | select(.name == $job_name)]' <<<"$jobs_json")"
  if [[ "$(jq 'length' <<<"$matches")" -ne 1 ]]; then
    echo "expected exactly one '$job_name' job" >&2
    return 1
  fi

  jq -r '.[0].conclusion // ""' <<<"$matches"
}

validate_ci_jobs() {
  local mode="$1"
  local workflow_conclusion="$2"
  local jobs_json="$3"
  local job_name
  local conclusion

  if [[ "$mode" != "full" && "$mode" != "docs" ]]; then
    echo "invalid CI mode: $mode" >&2
    return 1
  fi
  if [[ "$workflow_conclusion" != "success" ]]; then
    echo "CI Pipeline conclusion was '$workflow_conclusion'" >&2
    return 1
  fi

  conclusion="$(job_conclusion "$jobs_json" "Classify Changes")" || return 1
  if [[ "$conclusion" != "success" ]]; then
    echo "Classify Changes concluded '$conclusion'" >&2
    return 1
  fi

  for job_name in "${CI_REQUIRED_JOBS[@]}"; do
    conclusion="$(job_conclusion "$jobs_json" "$job_name")" || return 1
    if [[ "$mode" == "full" && "$conclusion" != "success" ]]; then
      echo "$job_name concluded '$conclusion' for a full-CI change" >&2
      return 1
    fi
    if [[ "$mode" == "docs" &&
      "$conclusion" != "success" &&
      "$conclusion" != "skipped" ]]; then
      echo "$job_name concluded '$conclusion' for a docs-only change" >&2
      return 1
    fi
  done
}
