#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
source "$script_dir/ci-gate-lib.sh"

if [[ "${1:-}" == "--paths" ]]; then
  shift
  if requires_full_ci "$@"; then
    echo "true"
  else
    echo "false"
  fi
  exit 0
fi

if [[ "$#" -ne 2 ]]; then
  echo "usage: $0 <base-sha> <head-sha> | --paths [path ...]" >&2
  exit 2
fi

base_sha="$1"
head_sha="$2"
zero_sha="0000000000000000000000000000000000000000"

if [[ "$base_sha" == "$zero_sha" ]] ||
  ! git cat-file -e "${base_sha}^{commit}" 2>/dev/null ||
  ! git cat-file -e "${head_sha}^{commit}" 2>/dev/null; then
  echo "true"
  exit 0
fi

changed_paths=()
while IFS= read -r -d '' path; do
  changed_paths+=("$path")
done < <(git diff --name-only -z "$base_sha" "$head_sha")

if requires_full_ci "${changed_paths[@]}"; then
  echo "true"
else
  echo "false"
fi
