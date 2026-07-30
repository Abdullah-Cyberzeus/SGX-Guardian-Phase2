#!/usr/bin/env bash
set -euo pipefail

# Builds the SG-X Guardian agent image (linux/amd64) from docker/Dockerfile.agent
# and exports it into build/sgx-guardian/, alongside a sha256 checksum.
#
# Usage:
#   bash scripts/build_docker.sh
#   NO_CACHE=1 bash scripts/build_docker.sh   # force a clean rebuild

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_TAG="sgx-guardian:amd64"
OUT_DIR="${REPO_ROOT}/build/sgx-guardian"
TAR_PATH="${OUT_DIR}/sgx-guardian-amd64.tar"

log() {
  echo "==> $*"
}

cd "${REPO_ROOT}"

BUILD_ARGS=(--platform linux/amd64 -f docker/Dockerfile.agent -t "${IMAGE_TAG}" --load .)
if [[ "${NO_CACHE:-0}" == "1" ]]; then
  BUILD_ARGS=(--no-cache "${BUILD_ARGS[@]}")
fi

log "Building ${IMAGE_TAG}..."
docker buildx build "${BUILD_ARGS[@]}"

mkdir -p "${OUT_DIR}"

log "Exporting image to ${TAR_PATH}..."
docker save "${IMAGE_TAG}" -o "${TAR_PATH}"

log "Writing checksum..."
sha256sum "${TAR_PATH}" > "${TAR_PATH}.sha256"

log "Done."
ls -lh "${TAR_PATH}"
cat "${TAR_PATH}.sha256"
