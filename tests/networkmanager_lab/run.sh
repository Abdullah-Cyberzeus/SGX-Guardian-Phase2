#!/usr/bin/env bash
set -euo pipefail

readonly LAB_IMAGE="sgx-networkmanager-netns:local"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Host networking is used only while downloading Debian packages during image
# construction; the test container itself remains isolated below.
docker build \
    --network=host \
    --tag "${LAB_IMAGE}" \
    "${SCRIPT_DIR}"

# The container needs mount/network namespace capabilities to create its nested
# upstream namespace. It receives no host mounts and does not use host networking.
docker run --rm --privileged "${LAB_IMAGE}"
