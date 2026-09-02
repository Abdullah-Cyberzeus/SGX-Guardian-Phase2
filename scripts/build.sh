#!/usr/bin/env bash
set -euo pipefail

# One-shot bootstrap + build script for fresh Debian/Ubuntu environments.
# It installs missing dependencies automatically and builds BOTH ARM64 binaries.
#
# Usage:
#   bash scripts/build.sh
#   CLEAN=1 bash scripts/build.sh
#   USE_ZIGBUILD=1 GLIBC_VERSION=2.34 bash scripts/build.sh

TARGET_TRIPLE="aarch64-unknown-linux-gnu"
GLIBC_VERSION="${GLIBC_VERSION:-2.34}"
USE_ZIGBUILD="${USE_ZIGBUILD:-0}"
ZIG_TARGET="${TARGET_TRIPLE}.${GLIBC_VERSION}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_DIR="${REPO_ROOT}/frontend"
FRONTEND_DIST_DIR="${FRONTEND_DIR}/dist"
ARTIFACT_DIR="${REPO_ROOT}/build/artifacts/arm64"
DAEMON_BINARY_NAME="sgx_guardian_client"

APT_UPDATED=0
SUDO=()
RETRY_INITIAL_DELAY="${RETRY_INITIAL_DELAY:-5}"
RETRY_MAX_DELAY="${RETRY_MAX_DELAY:-60}"

log() {
  echo "==> $*"
}

warn() {
  echo "WARN: $*" >&2
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

setup_privilege() {
  if [[ "$(id -u)" -eq 0 ]]; then
    SUDO=()
    return
  fi

  if need_cmd sudo; then
    SUDO=(sudo)
    return
  fi

  die "This script needs root access for package install. Re-run as root or install sudo."
}

as_root() {
  if [[ "${#SUDO[@]}" -eq 0 ]]; then
    "$@"
  else
    "${SUDO[@]}" "$@"
  fi
}

next_delay() {
  local current="$1"
  local max="$2"
  local doubled=$((current * 2))
  if (( doubled > max )); then
    echo "${max}"
  else
    echo "${doubled}"
  fi
}

retry_forever() {
  local what="$1"
  shift
  local attempt=1
  local delay="${RETRY_INITIAL_DELAY}"

  while true; do
    if (( attempt >= ${RETRY_MAX_ATTEMPTS:-20} )); then
      die "${what} failed after ${attempt} attempts"
    fi

    if "$@"; then
      if (( attempt > 1 )); then
        log "${what} succeeded on attempt ${attempt}"
      fi
      return 0
    fi

    warn "${what} failed (attempt ${attempt}). Retrying in ${delay}s..."
    sleep "${delay}"
    attempt=$((attempt + 1))
    delay="$(next_delay "${delay}" "${RETRY_MAX_DELAY}")"
  done
}

retry_shell_forever() {
  local what="$1"
  local cmd="$2"
  retry_forever "${what}" bash -o pipefail -lc "${cmd}"
}

is_transient_network_error() {
  local output="$1"
  echo "${output}" | grep -Eiq \
    "timed out|timeout|temporary failure resolving|could not resolve|connection reset|connection refused|network is unreachable|failed to download|spurious network error|SSL connect error|Connection timed out"
}

apt_update_once() {
  if [[ "${APT_UPDATED}" -eq 0 ]]; then
    log "Running apt-get update..."
    retry_forever "apt-get update" as_root apt-get update -y
    APT_UPDATED=1
  fi
}

pkg_installed() {
  local pkg="$1"
  dpkg-query -W -f='${Status}' "${pkg}" 2>/dev/null | grep -q "install ok installed"
}

install_missing_packages() {
  local missing=()
  local pkg

  for pkg in "$@"; do
    if ! pkg_installed "${pkg}"; then
      missing+=("${pkg}")
    fi
  done

  if [[ "${#missing[@]}" -eq 0 ]]; then
    return 0
  fi

  apt_update_once
  log "Installing missing packages: ${missing[*]}"

  local attempt=1
  local delay="${RETRY_INITIAL_DELAY}"
  local output=""
  local rc=0

  while true; do
    set +e
    output="$(as_root apt-get install -y "${missing[@]}" 2>&1)"
    rc=$?
    set -e

    if [[ ${rc} -eq 0 ]]; then
      [[ -n "${output}" ]] && echo "${output}"
      return 0
    fi

    echo "${output}" >&2

    # Permanent package-resolution errors should not loop forever.
    if echo "${output}" | grep -Eiq \
      "Unable to locate package|has no installation candidate|Couldn't find any package by"; then
      return 1
    fi

    warn "apt-get install failed (attempt ${attempt}). Retrying in ${delay}s..."
    sleep "${delay}"
    attempt=$((attempt + 1))
    delay="$(next_delay "${delay}" "${RETRY_MAX_DELAY}")"
  done
}

verify_required_commands() {
  local cmd
  local required_cmds=(
    curl
    git
    cmake
    pkg-config
    protoc
    nmap
    setcap
  )

  if [[ "${USE_ZIGBUILD}" == "1" ]]; then
    required_cmds+=(
      aarch64-linux-gnu-objdump
      aarch64-linux-gnu-strip
    )
  else
    required_cmds+=(
      aarch64-linux-gnu-gcc
      aarch64-linux-gnu-g++
      aarch64-linux-gnu-strip
    )
  fi

  for cmd in "${required_cmds[@]}"; do
    need_cmd "${cmd}" || die "Required command missing after install: ${cmd}"
  done
}

ensure_zigbuild_tools() {
  if [[ "${USE_ZIGBUILD}" != "1" ]]; then
    return 0
  fi

  need_cmd cargo-zigbuild || die "cargo-zigbuild is required for USE_ZIGBUILD=1. Install it with: cargo install cargo-zigbuild"
  need_cmd zig || die "zig is required for USE_ZIGBUILD=1. Install Zig 0.13+ or use: pipx install ziglang"
}

install_apt_prereqs() {
  if ! need_cmd apt-get; then
    die "apt-get not found. This script supports Debian/Ubuntu environments."
  fi

  local base_packages=(
    ca-certificates
    curl
    git
    build-essential
    pkg-config
    cmake
    protobuf-compiler
    nmap
    libcap2-bin
  )

  local cross_packages_primary=(
    gcc-aarch64-linux-gnu
    g++-aarch64-linux-gnu
    libc6-dev-arm64-cross
    binutils-aarch64-linux-gnu
  )

  local cross_packages_fallback=(
    gcc-aarch64-linux-gnu
    g++-aarch64-linux-gnu
    crossbuild-essential-arm64
    binutils-aarch64-linux-gnu
  )

  log "Checking/installing base build dependencies..."
  install_missing_packages "${base_packages[@]}"

  log "Checking/installing ARM64 cross-build dependencies..."
  if ! install_missing_packages "${cross_packages_primary[@]}"; then
    warn "Primary cross package set failed, trying fallback set..."
    install_missing_packages "${cross_packages_fallback[@]}"
  fi

  verify_required_commands
}

load_cargo_env() {
  export PATH="${HOME}/.cargo/bin:${PATH}"
  if [[ -f "${HOME}/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    source "${HOME}/.cargo/env"
  fi
}

install_rust_toolchain() {
  load_cargo_env

  if ! need_cmd rustup; then
    log "Installing rustup (Rust toolchain manager)..."
    retry_shell_forever \
      "rustup installer download/install" \
      "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable --no-modify-path"
  fi

  load_cargo_env

  need_cmd rustup || die "rustup is still not available after installation."
  need_cmd cargo || die "cargo is still not available after installation."

  log "Ensuring Rust stable toolchain + ARM64 target..."
  retry_forever "rustup toolchain install stable" rustup toolchain install stable --profile minimal
  retry_forever "rustup default stable" rustup default stable
  retry_forever "rustup target add ${TARGET_TRIPLE}" rustup target add "${TARGET_TRIPLE}"
}

print_versions() {
  log "Toolchain versions"
  rustc -Vv
  cargo -V
  protoc --version
  if [[ "${USE_ZIGBUILD}" == "1" ]]; then
    cargo zigbuild --help | head -n 1
    zig version
    aarch64-linux-gnu-objdump --version | head -n 1
  else
    aarch64-linux-gnu-gcc --version | head -n 1
  fi
}

ensure_frontend_dist() {
  if [[ -s "${FRONTEND_DIST_DIR}/index.html" ]]; then
    log "Using existing embedded frontend bundle at ${FRONTEND_DIST_DIR}"
    return 0
  fi

  [[ -f "${FRONTEND_DIR}/package.json" ]] \
    || die "Frontend dist missing and ${FRONTEND_DIR}/package.json was not found"
  [[ -f "${FRONTEND_DIR}/package-lock.json" ]] \
    || die "Frontend dist missing and ${FRONTEND_DIR}/package-lock.json was not found"

  need_cmd node || die "Frontend dist missing and Node.js is not installed"
  need_cmd npm || die "Frontend dist missing and npm is not installed"

  log "Building embedded frontend bundle..."
  retry_forever \
    "npm ci (frontend)" \
    npm --prefix "${FRONTEND_DIR}" ci --no-audit --no-fund
  VITE_API_URL=/api/v1 npm --prefix "${FRONTEND_DIR}" run build

  [[ -s "${FRONTEND_DIST_DIR}/index.html" ]] \
    || die "Frontend build did not produce ${FRONTEND_DIST_DIR}/index.html"
}

build_workspace() {
  cd "${REPO_ROOT}"
  local out_dir="${REPO_ROOT}/target/${TARGET_TRIPLE}/release"
  local zig_out_dir="${REPO_ROOT}/target/${ZIG_TARGET}/release"

  # Always remove previously generated binaries so output is guaranteed fresh.
  rm -f \
    "${out_dir}/${DAEMON_BINARY_NAME}" \
    "${out_dir}/sgx-pa-cli" \
    "${out_dir}/sgx-broker" \
    "${zig_out_dir}/${DAEMON_BINARY_NAME}" \
    "${zig_out_dir}/sgx-pa-cli" \
    "${zig_out_dir}/sgx-broker" \
    "${ARTIFACT_DIR}/${DAEMON_BINARY_NAME}" \
    "${ARTIFACT_DIR}/sgx-pa-cli" \
    "${ARTIFACT_DIR}/sgx-broker"

  if [[ "${CLEAN:-0}" == "1" ]]; then
    log "CLEAN=1 detected; running cargo clean..."
    cargo clean
  fi

  if [[ "${USE_ZIGBUILD}" == "1" ]]; then
    log "Building ALL binaries for ${ZIG_TARGET} with cargo-zigbuild (release)..."
  else
    log "Building ALL binaries for ${TARGET_TRIPLE} (release)..."
  fi

  local attempt=1
  local delay="${RETRY_INITIAL_DELAY}"
  local output=""
  local rc=0

  while true; do
    set +e
    if [[ "${USE_ZIGBUILD}" == "1" ]]; then
      output="$(
        cargo zigbuild --release --workspace --locked --target "${ZIG_TARGET}" --features secure-element 2>&1
      )"
    else
      output="$(
        CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
        CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
        cargo build --release --workspace --locked --target "${TARGET_TRIPLE}" --features secure-element 2>&1
      )"
    fi
    rc=$?
    set -e

    if [[ ${rc} -eq 0 ]]; then
      [[ -n "${output}" ]] && echo "${output}"
      return 0
    fi

    echo "${output}" >&2

    if is_transient_network_error "${output}"; then
      warn "cargo build failed due to transient network issue (attempt ${attempt}). Retrying in ${delay}s..."
      sleep "${delay}"
      attempt=$((attempt + 1))
      delay="$(next_delay "${delay}" "${RETRY_MAX_DELAY}")"
      continue
    fi

    if [[ "${ALLOW_UNLOCKED_FALLBACK:-0}" == "1" ]]; then
      warn "Retrying without --locked (ALLOW_UNLOCKED_FALLBACK=1)..."
      if [[ "${USE_ZIGBUILD}" == "1" ]]; then
        cargo zigbuild --release --workspace --target "${ZIG_TARGET}" --features secure-element
      else
        CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
        CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
        cargo build --release --workspace --target "${TARGET_TRIPLE}" --features secure-element
      fi
      return 0
    else
      die "Build with --locked failed."
    fi
  done
}

collect_artifacts() {
  local out_dir="${REPO_ROOT}/target/${TARGET_TRIPLE}/release"
  if [[ "${USE_ZIGBUILD}" == "1" && -d "${REPO_ROOT}/target/${ZIG_TARGET}/release" ]]; then
    out_dir="${REPO_ROOT}/target/${ZIG_TARGET}/release"
  fi
  local daemon_src="${out_dir}/${DAEMON_BINARY_NAME}"
  local cli_src="${out_dir}/sgx-pa-cli"
  local broker_src="${out_dir}/sgx-broker"

  [[ -f "${daemon_src}" ]] || die "Missing built binary: ${daemon_src}"
  [[ -f "${cli_src}" ]] || die "Missing built binary: ${cli_src}"
  [[ -f "${broker_src}" ]] || die "Missing built binary: ${broker_src}"

  mkdir -p "${ARTIFACT_DIR}"

  cp "${daemon_src}" "${ARTIFACT_DIR}/${DAEMON_BINARY_NAME}"
  cp "${cli_src}" "${ARTIFACT_DIR}/sgx-pa-cli"
  cp "${broker_src}" "${ARTIFACT_DIR}/sgx-broker"

  log "Artifacts ready"
  ls -lh "${ARTIFACT_DIR}/${DAEMON_BINARY_NAME}" "${ARTIFACT_DIR}/sgx-pa-cli" "${ARTIFACT_DIR}/sgx-broker"
  file "${ARTIFACT_DIR}/${DAEMON_BINARY_NAME}" "${ARTIFACT_DIR}/sgx-pa-cli" "${ARTIFACT_DIR}/sgx-broker"

  log "SHA256"
  sha256sum "${ARTIFACT_DIR}/${DAEMON_BINARY_NAME}" "${ARTIFACT_DIR}/sgx-pa-cli" "${ARTIFACT_DIR}/sgx-broker"

  if need_cmd aarch64-linux-gnu-objdump; then
    log "Max GLIBC symbol version required"
    aarch64-linux-gnu-objdump -T "${ARTIFACT_DIR}/${DAEMON_BINARY_NAME}" \
      | grep -o 'GLIBC_[0-9.]*' \
      | sort -uV \
      | tail -1
  fi
}

main() {
  log "SGX ARM64 bootstrap+build started"
  setup_privilege
  install_apt_prereqs
  install_rust_toolchain
  ensure_zigbuild_tools
  print_versions
  ensure_frontend_dist
  build_workspace
  collect_artifacts
  log "Done."
}

main "$@"
