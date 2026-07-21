#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/release-ref-test.XXXXXX")"
trap 'rm -rf -- "$fixture_dir"' EXIT

git -C "$fixture_dir" init --quiet --initial-branch=main
git -C "$fixture_dir" config user.name "Release Ref Test"
git -C "$fixture_dir" config user.email "release-ref@example.invalid"
printf 'trusted\n' > "$fixture_dir/trusted.txt"
git -C "$fixture_dir" add trusted.txt
git -C "$fixture_dir" commit --quiet -m "trusted"
trusted_sha="$(git -C "$fixture_dir" rev-parse HEAD)"
git -C "$fixture_dir" tag v1.2.3
git -C "$fixture_dir" branch origin/main

(
  cd "$fixture_dir"
  output="$(bash "$script_dir/validate-release-ref.sh" v1.2.3 "$trusted_sha" origin/main)"
  grep -qx 'version=1.2.3' <<<"$output"
  grep -qx "commit-sha=$trusted_sha" <<<"$output"
)

printf 'untrusted\n' > "$fixture_dir/untrusted.txt"
git -C "$fixture_dir" add untrusted.txt
git -C "$fixture_dir" commit --quiet -m "untrusted"
untrusted_sha="$(git -C "$fixture_dir" rev-parse HEAD)"
git -C "$fixture_dir" tag v1.2.4

if (
  cd "$fixture_dir"
  bash "$script_dir/validate-release-ref.sh" v1.2.4 "$untrusted_sha" origin/main
) >/dev/null 2>&1; then
  echo "Release validator accepted a commit outside main" >&2
  exit 1
fi

if (
  cd "$fixture_dir"
  bash "$script_dir/validate-release-ref.sh" v1.2.3 "$untrusted_sha" origin/main
) >/dev/null 2>&1; then
  echo "Release validator accepted a mismatched event SHA" >&2
  exit 1
fi

if (
  cd "$fixture_dir"
  bash "$script_dir/validate-release-ref.sh" v1.2.3-rc1 "$trusted_sha" origin/main
) >/dev/null 2>&1; then
  echo "Release validator accepted a prerelease tag" >&2
  exit 1
fi

echo "release ref validation tests passed"
