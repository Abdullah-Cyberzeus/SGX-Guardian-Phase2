#!/usr/bin/env bash
set -euo pipefail

readonly REQUIRED_STATUS_CONTEXT="CI Required"
readonly REQUIRED_CHECK_RUN="Static Analysis (CodeQL)"

evaluate_ci_snapshot() {
  local snapshot="$1"
  local expected_sha="$2"
  local head_sha
  local commit_sha
  local contexts
  local match_count
  local state
  local pending=()

  GATE_STATE="failure"
  GATE_DETAILS=""

  if ! jq -e '.data.repository.pullRequest and .data.repository.object' \
    <<<"$snapshot" >/dev/null; then
    GATE_DETAILS="invalid or incomplete GitHub status response"
    return
  fi

  head_sha="$(jq -r '.data.repository.pullRequest.headRefOid // ""' \
    <<<"$snapshot")"
  commit_sha="$(jq -r '.data.repository.object.oid // ""' <<<"$snapshot")"
  if [[ "$head_sha" != "$expected_sha" ]]; then
    GATE_DETAILS="pull request head moved from $expected_sha to $head_sha"
    return
  fi
  if [[ "$commit_sha" != "$expected_sha" ]]; then
    GATE_DETAILS="status rollup resolved commit $commit_sha instead of $expected_sha"
    return
  fi

  contexts="$(jq -c \
    '.data.repository.object.statusCheckRollup.contexts.nodes // []' \
    <<<"$snapshot")"

  match_count="$(jq --arg name "$REQUIRED_STATUS_CONTEXT" \
    '[.[] | select(.__typename == "StatusContext" and .context == $name)] | length' \
    <<<"$contexts")"
  if [[ "$match_count" -gt 1 ]]; then
    GATE_DETAILS="duplicate $REQUIRED_STATUS_CONTEXT status contexts"
    return
  fi
  if [[ "$match_count" -eq 0 ]]; then
    pending+=("$REQUIRED_STATUS_CONTEXT (missing)")
  else
    state="$(jq -r --arg name "$REQUIRED_STATUS_CONTEXT" \
      '.[] | select(.__typename == "StatusContext" and .context == $name) | .state' \
      <<<"$contexts")"
    case "$state" in
      SUCCESS)
        ;;
      EXPECTED | PENDING)
        pending+=("$REQUIRED_STATUS_CONTEXT ($state)")
        ;;
      *)
        GATE_DETAILS="$REQUIRED_STATUS_CONTEXT concluded $state"
        return
        ;;
    esac
  fi

  match_count="$(jq --arg name "$REQUIRED_CHECK_RUN" \
    '[.[] | select(.__typename == "CheckRun" and .name == $name)] | length' \
    <<<"$contexts")"
  if [[ "$match_count" -gt 1 ]]; then
    GATE_DETAILS="duplicate $REQUIRED_CHECK_RUN check runs"
    return
  fi
  if [[ "$match_count" -eq 0 ]]; then
    pending+=("$REQUIRED_CHECK_RUN (missing)")
  else
    state="$(jq -r --arg name "$REQUIRED_CHECK_RUN" \
      '.[] | select(.__typename == "CheckRun" and .name == $name)
       | if .status != "COMPLETED" then .status else (.conclusion // "") end' \
      <<<"$contexts")"
    case "$state" in
      SUCCESS)
        ;;
      QUEUED | IN_PROGRESS | PENDING | WAITING | REQUESTED)
        pending+=("$REQUIRED_CHECK_RUN ($state)")
        ;;
      *)
        GATE_DETAILS="$REQUIRED_CHECK_RUN concluded $state"
        return
        ;;
    esac
  fi

  if [[ "${#pending[@]}" -gt 0 ]]; then
    GATE_STATE="pending"
    GATE_DETAILS="$(IFS=", "; echo "${pending[*]}")"
    return
  fi

  GATE_STATE="success"
  GATE_DETAILS="$REQUIRED_STATUS_CONTEXT and $REQUIRED_CHECK_RUN passed on $expected_sha"
}

query_ci_snapshot() {
  local owner="${REPO%%/*}"
  local repository="${REPO#*/}"
  local query

  read -r -d '' query <<'GRAPHQL' || true
query($owner: String!, $repository: String!, $prNumber: Int!, $headSha: String!) {
  repository(owner: $owner, name: $repository) {
    pullRequest(number: $prNumber) {
      headRefOid
    }
    object(expression: $headSha) {
      ... on Commit {
        oid
        statusCheckRollup {
          contexts(first: 100) {
            nodes {
              __typename
              ... on StatusContext {
                context
                state
              }
              ... on CheckRun {
                name
                status
                conclusion
              }
            }
          }
        }
      }
    }
  }
}
GRAPHQL

  gh api graphql \
    -f query="$query" \
    -f owner="$owner" \
    -f repository="$repository" \
    -F prNumber="$PR_NUMBER" \
    -f headSha="$HEAD_SHA"
}

wait_for_required_ci() {
  local poll_seconds="${CI_GATE_POLL_SECONDS:-10}"
  local max_attempts="${CI_GATE_MAX_ATTEMPTS:-240}"
  local attempt
  local snapshot

  if [[ ! "$poll_seconds" =~ ^[1-9][0-9]*$ ||
    ! "$max_attempts" =~ ^[1-9][0-9]*$ ]]; then
    echo "invalid polling configuration" >&2
    return 2
  fi

  for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    snapshot="$(query_ci_snapshot)" || {
      echo "GitHub status query failed; failing closed" >&2
      return 1
    }
    evaluate_ci_snapshot "$snapshot" "$HEAD_SHA"
    case "$GATE_STATE" in
      success)
        echo "$GATE_DETAILS"
        return
        ;;
      failure)
        echo "$GATE_DETAILS" >&2
        return 1
        ;;
      pending)
        echo "Waiting for exact-SHA CI: $GATE_DETAILS"
        ;;
    esac
    sleep "$poll_seconds"
  done

  echo "Timed out waiting for exact-SHA CI: $GATE_DETAILS" >&2
  return 1
}

main() {
  : "${REPO:?REPO is required}"
  : "${PR_NUMBER:?PR_NUMBER is required}"
  : "${HEAD_SHA:?HEAD_SHA is required}"
  : "${GH_TOKEN:?GH_TOKEN is required}"

  if [[ ! "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    echo "invalid repository name" >&2
    return 2
  fi
  if [[ ! "$PR_NUMBER" =~ ^[0-9]+$ ]]; then
    echo "invalid pull request number" >&2
    return 2
  fi
  if [[ ! "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]; then
    echo "invalid pull request head SHA" >&2
    return 2
  fi

  wait_for_required_ci
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
