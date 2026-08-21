#!/usr/bin/env bash
set -euo pipefail

# Builds the SG-X Guardian agent image from docker/Dockerfile.agent for one or
# both architectures. Each run replaces the previously built local image and
# previously exported tar for that arch, and drops the fresh tar + checksum
# into its own folder: build/sgx-guardian/<arch>/.
#
# Usage:
#   bash scripts/build_docker.sh                 # build amd64 + arm64
#   ARCHES=amd64 bash scripts/build_docker.sh     # build amd64 only
#   ARCHES=arm64 bash scripts/build_docker.sh     # build arm64 only
#   NO_CACHE=1 bash scripts/build_docker.sh       # force a clean rebuild

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_NAME="sgx-guardian"
BASE_OUT_DIR="${REPO_ROOT}/build/${IMAGE_NAME}"
DOCKER_CONFIG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sgx-docker-config.XXXXXX")"

# Some Linux shells inherit a Windows/Docker Desktop credential helper entry
# (for example `docker-credential-desktop.exe`) that cannot execute here. A
# tiny throwaway config keeps the build isolated from that host-side setting
# while still allowing public image pulls from Docker Hub.
printf '%s\n' '{"auths":{}}' > "${DOCKER_CONFIG_DIR}/config.json"
trap 'rm -rf "${DOCKER_CONFIG_DIR}"' EXIT

docker_cmd() {
  DOCKER_CONFIG="${DOCKER_CONFIG_DIR}" docker "$@"
}

IFS=' ' read -r -a ARCH_LIST <<< "${ARCHES:-amd64 arm64}"

log() {
  echo "==> $*"
}

build_arch() {
  local arch="$1"
  local tag="${IMAGE_NAME}:${arch}"
  local out_dir="${BASE_OUT_DIR}/${arch}"
  local tar_path="${out_dir}/${IMAGE_NAME}-${arch}.tar"

  local old_id
  old_id="$(docker_cmd images -q "${tag}" | head -n1 || true)"

  local build_args=(--platform "linux/${arch}" -f docker/Dockerfile.agent -t "${tag}" --load .)
  if [[ "${NO_CACHE:-0}" == "1" ]]; then
    build_args=(--no-cache "${build_args[@]}")
  fi

  log "[${arch}] Building ${tag}..."
  docker_cmd buildx build "${build_args[@]}"

  if [[ -n "${old_id}" ]]; then
    local new_id
    new_id="$(docker_cmd images -q "${tag}" | head -n1 || true)"
    if [[ "${old_id}" != "${new_id}" ]]; then
      log "[${arch}] Removing superseded local image ${old_id}..."
      docker_cmd image rm -f "${old_id}" >/dev/null 2>&1 || true
    fi
  fi

  log "[${arch}] Clearing previous export in ${out_dir}..."
  mkdir -p "${out_dir}"
  rm -f "${out_dir}/${IMAGE_NAME}-"*.tar "${out_dir}/${IMAGE_NAME}-"*.tar.sha256

  log "[${arch}] Exporting image to ${tar_path}..."
  docker_cmd save "${tag}" -o "${tar_path}"

  log "[${arch}] Writing checksum..."
  sha256sum "${tar_path}" > "${tar_path}.sha256"

  log "[${arch}] Done."
  ls -lh "${tar_path}"
  cat "${tar_path}.sha256"
}

cd "${REPO_ROOT}"

for arch in "${ARCH_LIST[@]}"; do
  case "${arch}" in
    amd64|arm64) ;;
    *) echo "ERROR: unsupported arch '${arch}' (expected amd64 or arm64)" >&2; exit 1 ;;
  esac
  build_arch "${arch}"
done

log "All builds complete."
