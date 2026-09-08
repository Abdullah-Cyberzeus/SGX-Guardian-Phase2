#!/usr/bin/env bash
set -euo pipefail

select_protoc_artifact() {
  local version="$1"
  local os="${2:-$(uname -s)}"
  local architecture="${3:-$(uname -m)}"

  if [[ "$version" != "35.1" || "$os" != "Linux" || "$architecture" != "x86_64" ]]; then
    echo "unsupported protoc release or platform: $version $os $architecture" >&2
    return 1
  fi

  PROTOC_ARCHIVE_NAME="protoc-35.1-linux-x86_64.zip"
  PROTOC_DOWNLOAD_URL="https://github.com/protocolbuffers/protobuf/releases/download/v35.1/$PROTOC_ARCHIVE_NAME"
  PROTOC_SHA256="6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7"
}

verify_sha256() {
  local archive="$1"
  local expected_sha256="$2"

  printf '%s  %s\n' "$expected_sha256" "$archive" | sha256sum --check --status
}

install_protoc() (
  local version="$1"
  local temp_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
  local work_dir
  local archive
  local install_dir="${PROTOC_INSTALL_DIR:-$temp_root/protoc-$version}"
  local actual_version

  select_protoc_artifact "$version"
  work_dir="$(mktemp -d "$temp_root/protoc-download.XXXXXX")"
  trap 'rm -rf -- "$work_dir"' EXIT
  archive="$work_dir/$PROTOC_ARCHIVE_NAME"

  curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
    "$PROTOC_DOWNLOAD_URL" \
    --output "$archive"
  verify_sha256 "$archive" "$PROTOC_SHA256"

  mkdir -p "$install_dir"
  unzip -oq "$archive" -d "$install_dir"
  actual_version="$("$install_dir/bin/protoc" --version)"
  if [[ "$actual_version" != "libprotoc $version" ]]; then
    echo "unexpected protoc version: $actual_version" >&2
    return 1
  fi

  if [[ -n "${GITHUB_PATH:-}" ]]; then
    echo "$install_dir/bin" >> "$GITHUB_PATH"
  fi

  echo "Installed $actual_version from verified official release."
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  install_protoc "${1:-35.1}"
fi
