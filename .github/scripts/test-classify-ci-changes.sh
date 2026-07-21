#!/usr/bin/env bash
set -euo pipefail

classifier="$(dirname "$0")/classify-ci-changes.sh"

assert_classification() {
  local expected="$1"
  shift
  local actual
  actual="$(bash "$classifier" --paths "$@")"

  if [[ "$actual" != "$expected" ]]; then
    echo "expected '$expected' for paths '$*', got '$actual'" >&2
    exit 1
  fi
}

assert_classification true
assert_classification false .gitignore
assert_classification false README.md docs/architecture.md NEXT/2026-07-27-ci.md
assert_classification true src/main.rs
assert_classification true Cargo.toml
assert_classification true .github/workflows/ci.yml
assert_classification true scripts/build.sh
assert_classification true README.md src/lib.rs

zero_sha="0000000000000000000000000000000000000000"
if [[ "$(bash "$classifier" "$zero_sha" "$zero_sha")" != "true" ]]; then
  echo "missing comparison commits must fail closed to full CI" >&2
  exit 1
fi

echo "changed-path classifier tests passed"
