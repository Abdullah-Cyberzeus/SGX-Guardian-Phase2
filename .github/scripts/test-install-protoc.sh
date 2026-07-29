#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
source "$script_dir/install-protoc.sh"

select_protoc_artifact "35.1" "Linux" "x86_64"
[[ "$PROTOC_ARCHIVE_NAME" == "protoc-35.1-linux-x86_64.zip" ]]
[[ "$PROTOC_DOWNLOAD_URL" == "https://github.com/protocolbuffers/protobuf/releases/download/v35.1/$PROTOC_ARCHIVE_NAME" ]]
[[ "$PROTOC_SHA256" == "6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7" ]]

fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/protoc-checksum-test.XXXXXX")"
trap 'rm -rf -- "$fixture_dir"' EXIT
fixture="$fixture_dir/archive.zip"
printf 'protoc fixture' > "$fixture"
fixture_sha256="$(sha256sum "$fixture" | cut -d ' ' -f 1)"
verify_sha256 "$fixture" "$fixture_sha256"

printf 'tampered' >> "$fixture"
if verify_sha256 "$fixture" "$fixture_sha256"; then
  echo "checksum verification accepted a modified archive" >&2
  exit 1
fi

if select_protoc_artifact "35.0" "Linux" "x86_64" >/dev/null 2>&1; then
  echo "unsupported protoc version was accepted" >&2
  exit 1
fi

echo "protoc installer tests passed"
