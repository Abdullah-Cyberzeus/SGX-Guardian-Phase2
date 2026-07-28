#!/usr/bin/env bash

CI_REQUIRED_JOBS=(
  "Format & Clippy"
  "Unit Tests"
  "Windows Workspace Tests"
  "Coverage"
  "Dependency Policy"
  "Semgrep"
  "Release Build"
)

CI_TRUSTED_DEFINITION_PATHS=(
  ".github/workflows/ci.yml"
  ".github/workflows/codeql.yml"
  ".github/workflows/trusted-ci-required.yml"
  ".github/cyber-review/test-ci-gate.sh"
  ".github/cyber-review/test-workflow-contract.sh"
  ".github/scripts/ci-gate-lib.sh"
  ".github/scripts/classify-ci-changes.sh"
  ".github/scripts/install-protoc.ps1"
  ".github/scripts/install-protoc.sh"
  ".github/scripts/test-cargo-cache-workflow.sh"
  ".github/scripts/test-classify-ci-changes.sh"
  ".github/scripts/test-install-protoc.ps1"
  ".github/scripts/test-install-protoc.sh"
  ".github/scripts/test-release-packages.sh"
  ".github/scripts/test-release-ref.sh"
  ".github/scripts/test-trusted-ci-gate.sh"
  ".github/scripts/trusted-ci-gate.sh"
  ".cargo/audit.toml"
  ".cargo/config"
  ".cargo/config.toml"
  ".clippy.toml"
  ".gitignore"
  ".rustfmt.toml"
  ".semgrepignore"
  ".tarpaulin.toml"
  "audit.toml"
  "clippy.toml"
  "deny.toml"
  "rust-toolchain"
  "rust-toolchain.toml"
  "rustfmt.toml"
  "tarpaulin.toml"
)

git_commit_tree_sha() {
  local expected_commit_sha="$1"
  local commit_json="$2"

  jq -er --arg expected_commit_sha "$expected_commit_sha" '
    select(
      type == "object" and
      .sha == $expected_commit_sha and
      (.tree.sha | type) == "string" and
      (.tree.sha | test("^[0-9a-f]{40}$"))
    ) | .tree.sha
  ' <<<"$commit_json"
}

ci_trusted_definition_manifest() {
  local tree_json="$1"
  local trusted_paths_json

  trusted_paths_json="$(
    jq -cn '$ARGS.positional' --args "${CI_TRUSTED_DEFINITION_PATHS[@]}"
  )"
  jq -er --argjson trusted_paths "$trusted_paths_json" '
    if type != "object" or .truncated != false or (.tree | type) != "array"
    then
      error("invalid or truncated Git tree response")
    else
      .tree as $tree |
      $trusted_paths[] as $path |
      [$tree[] | select(.path == $path)] |
      if length == 0 then
        "\($path)\tmissing"
      elif length == 1 and
           .[0].type == "blob" and
           (.[0].mode == "100644" or .[0].mode == "100755") and
           (.[0].sha | type) == "string" and
           (.[0].sha | test("^[0-9a-f]{40}$"))
      then
        "\($path)\t\(.[0].mode)\t\(.[0].sha)"
      else
        error("trusted CI path is not exactly one regular file: \($path)")
      end
    end
  ' <<<"$tree_json"
}

enforce_base_owned_ci_definition() {
  local base_tree_json="$1"
  local head_tree_json="$2"
  local base_manifest
  local head_manifest

  base_manifest="$(ci_trusted_definition_manifest "$base_tree_json")" || {
    echo "invalid base trusted-CI tree" >&2
    return 1
  }
  head_manifest="$(ci_trusted_definition_manifest "$head_tree_json")" || {
    echo "invalid pull request trusted-CI tree" >&2
    return 1
  }
  if [[ "$head_manifest" != "$base_manifest" ]]; then
    echo "trusted CI definition changes require a trusted ruleset bypass" >&2
    return 1
  fi
}

changed_paths_from_trees() {
  local base_tree_json="$1"
  local head_tree_json="$2"

  jq -er -n \
    --argjson base "$base_tree_json" \
    --argjson head "$head_tree_json" '
      def valid_tree:
        type == "object" and
        .truncated == false and
        (.tree | type) == "array" and
        all(.tree[];
          (.path | type) == "string" and
          (.mode | type) == "string" and
          (.type | type) == "string" and
          (.sha | type) == "string");
      def files:
        [.tree[] | select(.type != "tree") | {
          key: .path,
          value: {mode, type, sha}
        }] |
        if (map(.key) | unique | length) != length
        then error("duplicate Git tree path")
        else from_entries
        end;
      if ($base | valid_tree) and ($head | valid_tree)
      then
        ($base | files) as $base_files |
        ($head | files) as $head_files |
        (($base_files | keys) + ($head_files | keys) | unique[]) as $path |
        select(($base_files[$path] // null) != ($head_files[$path] // null)) |
        $path
      else
        error("invalid or truncated Git tree response")
      end
    '
}

enforce_current_base_sha() {
  local expected_base_sha="$1"
  local default_branch_ref_json="$2"
  local current_base_sha

  current_base_sha="$(jq -er '
    select(
      type == "object" and
      .object.type == "commit" and
      (.object.sha | type) == "string" and
      (.object.sha | test("^[0-9a-f]{40}$"))
    ) | .object.sha
  ' <<<"$default_branch_ref_json")" || {
    echo "invalid default branch ref response" >&2
    return 1
  }
  if [[ "$current_base_sha" != "$expected_base_sha" ]]; then
    echo "pull request base SHA is stale; update the branch before evaluation" >&2
    return 1
  fi
}

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
